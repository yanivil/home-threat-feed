"""capture_watcher.py: the live watcher of today's capture (alerts out, under the caps), driven with a
fake clock and, for follow(), a thread reading the capture as a test writes it.

The capture lines and the feed are the ones the bot's tests use (tests/test_telegram_bot.py)."""

import json
import os
import tempfile
import threading
import time
import unicodedata
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import capture_watcher
import spark_logs
from tests.test_spark_logs import INBOUND_DROP, INBOUND_PREVENT, STATS, SYSTEM_LINES
from tests.test_telegram_bot import (FEED, FEED_HIT_DETECTED, INBOUND_PREVENTED, LAN_DETECTION, LAN_DEVICE, MALFORMED,
                                     MONITORED_DETECTION, OUTBOUND_DETECTED, OUTBOUND_DETECTION, OUTBOUND_IPS,
                                     OUTBOUND_TO_C2, OUTBOUND_TO_FEED_IP, OUTBOUND_TO_RANGE, TODAY, WAN, Clock,
                                     IdleCount, detection)

DEVICE = spark_logs.parse_entry(OUTBOUND_TO_C2)["src"]  # the LAN device of the outbound fixtures


class WatcherTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.feed_path = self.dir / "spark-ioc-feed.csv"
        self.feed_path.write_text(FEED)
        self.clock = Clock()
        self.day = TODAY
        self.alerts, self.batches = [], []
        self.logged = []
        self.watcher = self.make_watcher()

    def make_watcher(self):
        return capture_watcher.Watcher(self.dir, capture_watcher.FeedFile(self.feed_path), self.deliver,
                                    today=lambda: self.day, clock=self.clock.now, log=self.logged.append)

    def deliver(self, batch):
        """The watcher's `alert`: it gets each batch's Alerts in one call."""
        self.batches.append(list(batch))
        self.alerts.extend(batch)

    def summary(self, alerts):
        return [(a.kind, a.device, a.indicator, a.action) for a in alerts]

    def test_watcher_alerts_a_device_reaching_a_feed_member_once_an_hour(self):
        alerts = self.watcher.scan([OUTBOUND_TO_C2, OUTBOUND_TO_C2])   # destination_domain_name c2.example.net, in the feed
        self.assertEqual([(a.kind, a.device, a.indicator, a.action) for a in alerts], [("feed", DEVICE, "c2.example.net", "drop")])

        self.clock.time += 3599
        self.assertEqual(self.watcher.scan([OUTBOUND_TO_C2]), [])
        self.clock.time += 1
        self.assertEqual(len(self.watcher.scan([OUTBOUND_TO_C2])), 1)

    def test_watcher_matches_the_address_when_the_feed_holds_the_ip(self):
        self.assertEqual(self.summary(self.watcher.scan([OUTBOUND_TO_FEED_IP])),
                         [("feed", DEVICE, "185.1.2.7", "accept")])

    def test_an_address_inside_an_ip_range_row_alerts_with_the_range_label(self):
        [alert] = self.watcher.scan([OUTBOUND_TO_RANGE])

        self.assertEqual(alert.indicator, "45.155.205.233")
        self.assertIn("(Colocatel)", self.watcher.describe(alert))

    def test_inbound_probes_from_feed_members_are_not_alerted(self):
        probe = INBOUND_DROP.replace("109.205.211.205", "93.152.221.36")

        self.assertEqual(self.watcher.scan([probe]), [])

    def test_watcher_alerts_threat_prevention_detections_not_statistics(self):
        alerts = self.watcher.scan([INBOUND_PREVENTED, STATS, INBOUND_PREVENTED])

        self.assertEqual(self.summary(alerts), [("detection", WAN, "185.1.2.66", "prevent")])
        self.assertEqual(self.watcher.describe(alerts[0]),
                         "08:12:40 — Threat Prevention: Anti-Malware Scanner from 185.1.2.66 to 203.0.113.47 — prevent")

    def test_a_detection_alerts_live_only_with_an_explicit_action(self):
        for action, alerted in (("prevent", "prevent"), ("Drop", "drop"), ("reject", "reject"), ("block", "block"),
                                (" Detect ", "detect"), ("", None), (" ", None), ("monitor", None),
                                ("accept", None), ("inspect", None), ("log", None)):
            with self.subTest(action=action):
                self.watcher.alerted.clear()
                line = INBOUND_PREVENTED.replace('Action="Prevent"', f'Action="{action}"')

                self.assertEqual([a.action for a in self.watcher.scan([line])], [alerted] if alerted else [])

    def test_a_blank_action_detection_is_left_to_the_brief(self):
        # spark_logs' INBOUND_PREVENT: an IP-reputation row on a probe, logged with a blank Action.
        self.assertEqual(self.watcher.scan([INBOUND_PREVENT, STATS]), [])

    def test_a_detection_of_a_lan_device_reaching_out_alerts(self):
        self.assertEqual([(a.kind, a.indicator, a.action) for a in self.watcher.scan([OUTBOUND_DETECTED])],
                         [("detection", "104.18.32.47", "detect")])
        self.assertEqual(self.summary(self.watcher.scan([OUTBOUND_IPS])),
                         [("detection", LAN_DEVICE, "185.1.2.73", "drop")])

    def test_monitor_accept_and_lan_only_detections_are_left_to_the_brief(self):
        self.assertEqual(self.watcher.scan([MONITORED_DETECTION, OUTBOUND_DETECTION, LAN_DETECTION]), [])

    def test_two_protections_on_the_same_pair_both_alert(self):
        other = INBOUND_PREVENTED.replace('Protection Name="Scanner"', 'Protection Name="Port Scan"')

        self.assertEqual(len(self.watcher.scan([INBOUND_PREVENTED, other])), 2)

    def test_text_from_the_capture_reaches_the_alert_on_one_short_clean_line(self):
        forged = detection("11:00:00", "prevent\u200b", "185.1.2.66", "x\x1b]0;pwn\x07\u202eLAN",
                           "Anti Malware", "Bad\x1b[2J\u202e" + "P" * 300)

        [alert] = self.watcher.scan([forged])
        text = self.watcher.describe(alert)

        self.assertEqual(text, "11:00:00 — Threat Prevention: Anti-Malware Bad[2J" + "P" * 94 + "… from 185.1.2.66 "
                               "to x]0;pwnLAN — prevent")
        self.assertFalse(any(unicodedata.category(c).startswith("C") for c in text), repr(text))

    def test_a_feed_hit_logged_as_a_detection_gives_the_feed_alert_only(self):
        self.assertEqual(self.summary(self.watcher.scan([FEED_HIT_DETECTED])),
                         [("feed", DEVICE, "c2.example.net", "drop")])

    def test_cooldowns_older_than_the_cooldown_are_dropped_at_midnight(self):
        self.watcher.scan([OUTBOUND_TO_C2])
        self.clock.time += 1800
        self.watcher.scan([INBOUND_PREVENTED])
        self.clock.time += 1800
        self.day += timedelta(days=1)

        self.watcher.scan([])

        self.assertEqual([key[0] for key in self.watcher.alerted], ["detection"])

    def test_the_alert_text_counts_the_pair_today(self):
        alerts = self.watcher.scan([OUTBOUND_TO_C2, OUTBOUND_TO_C2])

        self.assertEqual(self.watcher.describe(alerts[0]),
                         f"09:15:02 — {DEVICE} tried to reach c2.example.net "
                         "(MuddyWater - VT 9/94 malicious 2026-10-01) — drop; 2× today")

    def test_the_count_starts_again_at_midnight(self):
        self.watcher.scan([OUTBOUND_TO_C2, OUTBOUND_TO_C2])
        self.day += timedelta(days=1)
        self.clock.time += 3600

        [alert] = self.watcher.scan([OUTBOUND_TO_C2])

        self.assertTrue(self.watcher.describe(alert).endswith("; 1× today"))

    def test_a_row_added_to_the_feed_is_seen_without_a_restart(self):
        self.assertEqual(self.watcher.scan([OUTBOUND_TO_C2.replace("c2.example.net", "new.example.org")]), [])
        with self.feed_path.open("a") as f:
            f.write("x,new.example.org,Domain,high,high,AB,News - VT 7/94 malicious 2026-10-28\n")
        later = time.time() + 5
        os.utime(self.feed_path, (later, later))

        [alert] = self.watcher.scan([OUTBOUND_TO_C2.replace("c2.example.net", "new.example.org")])

        self.assertIn("(News - VT 7/94 malicious 2026-10-28)", self.watcher.describe(alert))

    def test_system_log_lines_raise_no_alert_and_nothing_else(self):
        alerts = self.watcher.scan(SYSTEM_LINES + [OUTBOUND_TO_C2] + SYSTEM_LINES)

        self.assertEqual([(a.kind, a.indicator) for a in alerts], [("feed", "c2.example.net")])

    def probes(self, first, count):
        """`count` inbound detections from distinct sources: distinct pairs, each past the cooldown."""
        return [INBOUND_PREVENTED.replace('src="185.1.2.66"', f'src="185.1.3.{i}"') for i in range(first, first + count)]

    def test_at_most_ten_alerts_in_ten_minutes_then_one_message_then_the_count(self):
        self.clock.time = datetime(2026, 10, 28, 9, 0).timestamp()

        items = self.watcher.gate(self.watcher.scan(self.probes(0, 12)))

        self.assertEqual([type(item).__name__ for item in items], ["Alert"] * 10 + ["Notice"])
        self.assertEqual(items[-1].text, "Alert cap reached: further alerts in the next 10 minutes are counted, not sent")
        self.clock.time += 300
        self.assertEqual(self.watcher.gate(self.watcher.scan(self.probes(12, 2))), [], "counted, not sent")
        self.clock.time += 299
        self.assertEqual(self.watcher.gate([]), [])
        self.clock.time += 1

        [cleared] = self.watcher.gate([])

        self.assertEqual(cleared.text, "\n".join(["4 alerts suppressed between 09:00 and 09:10:"]
                                                 + [f"  {WAN} → 185.1.3.{i}, prevent" for i in range(10, 14)]))
        self.assertEqual(len(self.watcher.gate(self.watcher.scan(self.probes(14, 1)))), 1, "alerts flow again")
        self.assertEqual(self.watcher.gate([]), [], "said once")

    def test_a_suppressed_feed_hit_is_named_in_the_summary(self):
        # The brief never counts a feed hit the gateway logged only as a firewall row: the summary must say it.
        self.clock.time = datetime(2026, 10, 28, 9, 0).timestamp()
        self.watcher.gate(self.watcher.scan(self.probes(0, 10)))

        self.assertEqual([type(item).__name__ for item in self.watcher.gate(self.watcher.scan([OUTBOUND_TO_C2]))],
                         ["Notice"])
        self.watcher.alerted.clear()
        self.watcher.gate(self.watcher.scan([OUTBOUND_TO_C2]))  # the same pair again: counted, listed once
        self.clock.time += 600
        [cleared] = self.watcher.gate([])

        self.assertEqual(cleared.text.splitlines(), ["2 alerts suppressed between 09:00 and 09:10:",
                                                     f"  {DEVICE} → c2.example.net, drop"])
        self.assertNotIn("morning brief", cleared.text)

    def test_the_summary_lists_ten_pairs_at_most(self):
        self.clock.time = datetime(2026, 10, 28, 9, 0).timestamp()
        self.watcher.gate(self.watcher.scan(self.probes(0, 10)))
        self.watcher.gate(self.watcher.scan(self.probes(10, 13)))
        self.clock.time += 600

        [cleared] = self.watcher.gate([])
        lines = cleared.text.splitlines()

        self.assertEqual(lines[0], "13 alerts suppressed between 09:00 and 09:10:")
        self.assertEqual(lines[1:11], [f"  {WAN} → 185.1.3.{i}, prevent" for i in range(10, 20)])
        self.assertEqual(lines[11:], ["  … and 3 more"])

    def test_the_alert_window_slides(self):
        self.assertEqual(len(self.watcher.gate(self.watcher.scan(self.probes(0, 5)))), 5)
        self.clock.time += 300
        self.assertEqual(len(self.watcher.gate(self.watcher.scan(self.probes(5, 5)))), 5)
        self.clock.time += 301

        self.assertEqual([type(item).__name__ for item in self.watcher.gate(self.watcher.scan(self.probes(10, 6)))],
                         ["Alert"] * 5 + ["Notice"], "the first five slid out of the window, the second five did not")

    def test_notes_are_capped_at_six_an_hour(self):
        notes = []
        for i in range(8):
            notes += [alert.note for alert in self.watcher.gate(self.watcher.scan(self.probes(i, 1)))]
            self.clock.time += 60

        self.assertEqual(notes, [f"185.1.3.{i}" for i in range(6)] + [None, None])
        self.clock.time += 3600 - 7 * 60
        [alert] = self.watcher.gate(self.watcher.scan(self.probes(8, 1)))
        self.assertEqual(alert.note, "185.1.3.8", "the first note left the hour")

    def test_an_alert_whose_note_was_refused_still_goes_out(self):
        for i in range(6):
            self.watcher.gate(self.watcher.scan(self.probes(i, 1)))

        [alert] = self.watcher.gate(self.watcher.scan(self.probes(6, 1)))

        self.assertEqual((alert.indicator, alert.note), ("185.1.3.6", None))

    def test_notes_are_capped_at_thirty_a_day_and_one_per_indicator_a_day(self):
        cap = capture_watcher.NoteCap()
        start = datetime(2026, 10, 28, 1, 0).timestamp()

        admitted = [cap.admit(f"185.1.3.{i}", start + i * 601) for i in range(31)]

        self.assertEqual(admitted, [True] * 30 + [False])
        self.assertTrue(cap.admit("185.1.3.99", datetime(2026, 10, 29, 0, 1).timestamp()), "a new day")
        cap = capture_watcher.NoteCap()
        self.assertTrue(cap.admit("Evil.example", start))
        self.assertFalse(cap.admit("evil.example", start + 86399))
        self.assertTrue(cap.admit("evil.example", start + 86400))

    def test_a_malformed_line_does_not_stop_the_scan(self):
        self.assertEqual(len(self.watcher.scan([MALFORMED, "", "garbage", OUTBOUND_TO_C2])), 1)

    def test_a_line_that_fails_in_any_way_costs_only_itself_and_is_logged_once_without_its_content(self):
        real = capture_watcher.spark_logs.candidate

        def candidate(entry, *args):
            if entry.get("Uuid") == "{0xBAD}":
                raise KeyError("SECRET-CONTENT")
            return real(entry, *args)

        bad = OUTBOUND_TO_C2.replace("{0x3}", "{0xBAD}")
        with patch("spark_logs.candidate", candidate):
            alerts = self.watcher.scan([bad, OUTBOUND_TO_C2, bad, OUTBOUND_TO_FEED_IP], first_line=41)

        self.assertEqual([a.indicator for a in alerts], ["c2.example.net", "185.1.2.7"])
        self.assertEqual(self.logged, ["the watcher skipped 2 capture lines it could not read, "
                                       "the first at line 41 (KeyError)"])

    def test_a_late_alert_says_so_and_gets_no_note(self):
        [alert] = self.watcher.gate(self.watcher.scan([OUTBOUND_TO_C2]), late=True)

        self.assertEqual((alert.late, alert.note), (True, None))
        self.assertTrue(self.watcher.describe(alert).startswith("late: 09:15:02 — "), self.watcher.describe(alert))

    def test_late_alerts_count_under_the_alert_cap(self):
        items = self.watcher.gate(self.watcher.scan(self.probes(0, 11)), late=True)

        self.assertEqual([type(item).__name__ for item in items], ["Alert"] * 10 + ["Notice"])

    # follow(): a thread reading the capture as the receiver writes it, polling every 10 ms. The stop
    # event counts the watcher's idle waits: once it waits, it has read everything there was.

    def capture(self, day=TODAY):
        return self.dir / f"spark-{day:%Y-%m-%d}.log"

    def append(self, text, day=TODAY):
        with self.capture(day).open("a") as f:
            f.write(text)

    def follow(self, watcher=None):
        stop = IdleCount()
        thread = threading.Thread(target=(watcher or self.watcher).follow, args=(stop, 0.01))
        thread.start()

        def end():
            stop.set()
            thread.join(5)
            self.assertFalse(thread.is_alive())

        self.addCleanup(end)
        return stop, thread

    def wait_until(self, condition, what):
        deadline = time.monotonic() + 5
        while not condition():
            if time.monotonic() > deadline:
                self.fail(f"waited for {what}; alerts: {self.summary(self.alerts)}")
            time.sleep(0.005)

    def idle(self, stop, passes=2):
        """Return once the watcher has gone idle `passes` more times (two: a full pass began after the call)."""
        target = stop.waits + passes
        self.wait_until(lambda: stop.waits >= target, f"{passes} idle passes")

    def wait_for(self, count):
        self.wait_until(lambda: len(self.alerts) >= count, f"{count} alert(s)")

    def test_watcher_waits_for_a_missing_capture(self):
        stop, thread = self.follow()
        self.idle(stop)
        self.assertEqual(self.alerts, [])

        self.append(OUTBOUND_TO_C2 + "\n")
        self.wait_for(1)
        stop.set()
        thread.join(5)

        self.assertFalse(thread.is_alive())
        self.assertEqual(self.summary(self.alerts), [("feed", DEVICE, "c2.example.net", "drop")])

    def test_watcher_moves_to_the_new_file_at_midnight(self):
        self.append("")
        stop, _ = self.follow()
        self.idle(stop)
        self.append(OUTBOUND_TO_C2 + "\n")
        self.wait_for(1)

        self.day += timedelta(days=1)
        self.append(OUTBOUND_TO_FEED_IP + "\n", day=self.day)
        self.wait_for(2)

        self.assertEqual([a.indicator for a in self.alerts], ["c2.example.net", "185.1.2.7"])

    def test_what_the_capture_held_at_start_is_counted_not_alerted(self):
        self.append(OUTBOUND_TO_C2 + "\n")
        stop, _ = self.follow()
        self.idle(stop)
        self.assertEqual(self.alerts, [])

        # No cooldown started for what was only counted: a new hit on that pair alerts at once.
        self.append(OUTBOUND_TO_C2 + "\n")
        self.wait_for(1)

        self.assertEqual([a.indicator for a in self.alerts], ["c2.example.net"])
        self.assertTrue(self.watcher.describe(self.alerts[0]).endswith("; 2× today"))

    def position(self):
        return json.loads((self.dir / "watcher-offset.json").read_text())

    def test_the_position_is_saved_after_each_pass(self):
        self.append(OUTBOUND_TO_C2 + "\n")
        stop, _ = self.follow()
        self.idle(stop)
        self.append(OUTBOUND_TO_FEED_IP + "\n" + OUTBOUND_TO_RANGE[:40])
        self.wait_for(1)
        self.idle(stop)

        self.assertEqual(self.position(), {"day": "2026-10-28", "inode": self.capture().stat().st_ino,
                                           "offset": len((OUTBOUND_TO_C2 + "\n" + OUTBOUND_TO_FEED_IP + "\n").encode())},
                         "up to the last whole line")

    def test_a_same_day_restart_alerts_what_it_missed_as_late_and_without_notes(self):
        self.append(OUTBOUND_TO_C2 + "\n")
        stop, thread = self.follow()
        self.idle(stop)
        self.append(OUTBOUND_TO_FEED_IP + "\n")
        self.wait_for(1)
        self.idle(stop)
        stop.set()
        thread.join(5)
        self.append(INBOUND_PREVENTED + "\n")  # while the watcher was down

        restarted = self.make_watcher()
        stop, _ = self.follow(restarted)
        self.wait_for(2)
        self.idle(stop)

        late = self.alerts[1]
        self.assertEqual((late.kind, late.indicator, late.late, late.note), ("detection", "185.1.2.66", True, None))
        self.assertTrue(restarted.describe(late).startswith("late: 08:12:40 — Threat Prevention"))
        self.assertEqual(len(self.alerts), 2, "what came before the saved position is not alerted again")

        self.append(OUTBOUND_TO_RANGE + "\n")
        self.wait_for(3)
        self.assertFalse(self.alerts[2].late, "after the gap, alerts are live again")

    def test_a_restart_after_a_day_change_only_counts(self):
        self.append(OUTBOUND_TO_C2 + "\n" + INBOUND_PREVENTED + "\n")
        (self.dir / "watcher-offset.json").write_text(json.dumps(
            {"day": "2026-10-27", "inode": self.capture().stat().st_ino, "offset": 0}))

        stop, _ = self.follow()
        self.idle(stop)

        self.assertEqual(self.alerts, [])
        self.assertEqual(sum(self.watcher.counts.values()), 1, "the feed hit is counted")

    def test_a_position_for_another_file_or_an_unreadable_one_only_counts(self):
        for position in ({"day": "2026-10-28", "inode": -1, "offset": 0}, {"day": "2026-10-28"}, "garbage",
                         {"day": "2026-10-28", "inode": "x", "offset": 0}):
            with self.subTest(position=position):
                self.alerts.clear()
                self.capture().write_text(INBOUND_PREVENTED + "\n")
                (self.dir / "watcher-offset.json").write_text(json.dumps(position))
                watcher = self.make_watcher()
                stop, thread = self.follow(watcher)
                self.idle(stop)
                stop.set()
                thread.join(5)

                self.assertEqual(self.alerts, [])

    def test_the_lines_of_one_pass_are_handed_over_together(self):
        self.append("")
        stop, _ = self.follow()
        self.idle(stop)

        self.append(OUTBOUND_TO_C2 + "\n" + OUTBOUND_TO_FEED_IP + "\n")
        self.wait_for(2)

        self.assertEqual([[a.indicator for a in batch] for batch in self.batches], [["c2.example.net", "185.1.2.7"]])

    def test_a_line_still_being_written_waits_for_its_end(self):
        self.append("")
        stop, _ = self.follow()
        self.idle(stop)
        self.append(OUTBOUND_TO_C2[:60])
        self.idle(stop)
        self.assertEqual(self.alerts, [])

        self.append(OUTBOUND_TO_C2[60:] + "\n")
        self.wait_for(1)

        self.assertEqual(self.summary(self.alerts), [("feed", DEVICE, "c2.example.net", "drop")])

    def test_a_replaced_capture_is_read_again_from_its_start(self):
        self.append("")
        stop, _ = self.follow()
        self.idle(stop)
        self.capture().unlink()
        self.idle(stop)

        self.append(OUTBOUND_TO_C2 + "\n")
        self.wait_for(1)


if __name__ == "__main__":
    unittest.main()
