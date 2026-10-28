"""telegram_bot.py: the bot the owner talks to (indicators in, replies out), the live watcher of
today's capture (alerts out), and the LaunchAgent that keeps both running.

The addresses are public ones (185.1.2.x): vt_check.classify refuses the documentation ranges, and
spark_logs.candidate never takes them for an outbound destination."""

import contextlib
import io
import json
import os
import plistlib
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
from datetime import date, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import feed_lock
import telegram_api
import telegram_bot
import vt_check
from tests.test_spark_logs import INBOUND_DROP, INBOUND_PREVENT, STATS
from tests.test_vt_check import HEADER, FakeVT, vt_object

REPO = Path(__file__).resolve().parent.parent
TODAY = date(2026, 10, 28)
OWNER = 42

# A LAN device reaching a feed member by name, shaped like spark_logs' OUTBOUND_DOMAIN.
OUTBOUND_TO_C2 = ('2026-10-28T09:15:02 Action="drop" Uuid="{0x3}" inzone="Internal" outzone="External" '
                  'service_id="HTTPS" src="10.68.144.121" dst="104.18.32.47" proto="6" xlatesrc="176.230.223.47" '
                  'dst_domain_name="*.example.net" destination_domain_name="c2.example.net" '
                  'ProductName="VPN-1 & FireWall-1"')
# The same device reaching a feed address under a name the feed does not hold.
OUTBOUND_TO_FEED_IP = OUTBOUND_TO_C2.replace('dst="104.18.32.47"', 'dst="185.1.2.7"').replace(
    "c2.example.net", "cdn.example.org").replace('Action="drop"', 'Action="accept"')
OUTBOUND_TO_RANGE = OUTBOUND_TO_C2.replace('dst="104.18.32.47"', 'dst="45.155.205.233"').replace(
    'destination_domain_name="c2.example.net" ', "")
MALFORMED = OUTBOUND_TO_C2.replace('destination_domain_name="c2.example.net"', 'resource="http://[::1"')

FEED = (HEADER
        + "vt-domain-c2,c2.example.net,Domain,high,high,AB,MuddyWater - VT 9/94 malicious 2026-10-01\n"
        + "vt-ip-scanner,93.152.221.36,IP,medium,high,AB,VT 6/86 malicious 2026-10-19\n"
        + "trusted-ip-x,185.1.2.7,IP,high,high,AB,Cyberint - added without VirusTotal check 2026-10-01\n"
        + "colocatel,45.155.205.0-45.155.205.255,IP Range,high,medium,AB,Colocatel\n")

DAILY_LOG = """\
2026-10-27 07:30:00 Daily check starting: last 2 day(s)
Added to the feed: 1  clean: 9  unknown to VirusTotal: 0  left for another day: 0
2026-10-27 09:02:41 Daily check done
2026-10-28 16:20:05 Daily check starting: last 2 day(s)
evil.example: added (Domain 11/94 malicious)
Added to the feed: 2  clean: 40  unknown to VirusTotal: 3  left for another day: 0
Brief sent to Telegram
2026-10-28 16:58:13 Daily check done
"""


def message(text, chat=OWNER, update_id=1):
    return {"update_id": update_id, "message": {"chat": {"id": chat}, "text": text}}


class FakeTelegram:
    """Stands in for telegram_api.Telegram: records what was sent, serves scripted batches of updates
    (an exception in the script is raised instead), then empty ones."""

    def __init__(self, chat_id=OWNER, token="123456:SECRET-token"):
        self.chat_id = chat_id
        self.token = token
        self.sent, self.documents, self.polls, self.batches = [], [], [], []

    def send_message(self, text):
        self.sent.append(text)
        return [len(self.sent)]

    def send_document(self, filename, data, caption=""):
        self.documents.append((filename, data, caption))
        return len(self.documents)

    def get_updates(self, offset, timeout=50):
        self.polls.append((offset, timeout))
        batch = self.batches.pop(0) if self.batches else []
        if isinstance(batch, BaseException):
            raise batch
        return batch


class FakeGit:
    """Stands in for subprocess.run on git: records each argument list and whether the feed lock was
    held then; the subcommands in `failing` exit 1."""

    def __init__(self, lock_path):
        self.lock_path = lock_path
        self.calls, self.kwargs, self.locked = [], [], []
        self.failing = set()

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        self.kwargs.append(kwargs)
        self.locked.append(self.lock_path.exists())
        fails = args[1] in self.failing
        return subprocess.CompletedProcess(args, 1 if fails else 0, "", f"fatal: {args[1]} refused" if fails else "")


class Clock:
    """A fake `clock` and `sleep` starting at the real time (the lock and the capture carry real mtimes):
    sleeping records the wait and moves the time on by it."""

    def __init__(self):
        self.time = time.time()
        self.sleeps = []

    def now(self):
        return self.time

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.time += seconds


class IdleCount(threading.Event):
    """A stop event that counts the waits on it: the watcher waits only when it found nothing new."""

    def __init__(self):
        super().__init__()
        self.waits = 0

    def wait(self, timeout=None):
        self.waits += 1
        return super().wait(timeout)


def quiet(test):
    """Send the code's log lines (stderr) to a buffer for the length of the test; returns the buffer."""
    err = io.StringIO()
    redirect = contextlib.redirect_stderr(err)
    redirect.__enter__()
    test.addCleanup(redirect.__exit__, None, None, None)
    return err


class ParseMessageTest(unittest.TestCase):
    def test_bare_text_is_a_check_of_the_leading_indicators_and_the_rest_is_the_label(self):
        self.assertEqual(telegram_bot.parse_message("evil[.]com 185.1.2.9 MuddyWater - Unit 42"),
                         ("check", ["evil.com", "185.1.2.9"], "MuddyWater - Unit 42"))

    def test_defanged_urls_are_refanged(self):
        self.assertEqual(telegram_bot.parse_message("hxxps://bad[.]example/x"), ("check", ["https://bad.example/x"], ""))

    def test_commands_with_or_without_the_bot_name(self):
        for text, verb in (("/trust 185.1.2.9", "trust"), ("/trust@SparkIocBot 185.1.2.9", "trust"),
                           ("/who 93.152.221.36", "who"), ("/sources", "sources"), ("/status", "status"),
                           ("/help", "help"), ("/STATUS@SparkIocBot", "status")):
            with self.subTest(text=text):
                self.assertEqual(telegram_bot.parse_message(text)[0], verb)

    def test_an_unknown_command_is_help(self):
        self.assertEqual(telegram_bot.parse_message("/start")[0], "help")
        self.assertEqual(telegram_bot.parse_message("/delete evil.com")[0], "help")

    def test_commas_and_newlines_in_the_label_become_spaces(self):
        self.assertEqual(telegram_bot.parse_message("evil.com Unit 42,\nMuddyWater, APT34"),
                         ("check", ["evil.com"], "Unit 42 MuddyWater APT34"))

    def test_the_label_starts_at_the_first_token_that_is_not_an_indicator(self):
        self.assertEqual(telegram_bot.parse_message("/trust 185.1.2.9 Cyberint report on bad.example"),
                         ("trust", ["185.1.2.9"], "Cyberint report on bad.example"))

    def test_a_date_argument_is_left_in_the_label(self):
        self.assertEqual(telegram_bot.parse_message("/sources 2026-10-20"), ("sources", [], "2026-10-20"))


class BotTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name)
        self.syslog = self.repo / "syslog"
        self.syslog.mkdir()
        self.feed = self.repo / "spark-ioc-feed.csv"
        self.feed.write_text(FEED)
        self.lock = self.syslog / feed_lock.LOCK_NAME
        self.tg = FakeTelegram()
        self.vt = FakeVT({
            vt_check.api_path("Domain", "evil.com"): vt_object("domain", "evil.com", 11, undetected=23),
            vt_check.api_path("IP", "185.1.2.9"): vt_object("ip_address", "185.1.2.9", 1, undetected=33),
        })
        self.git = FakeGit(self.lock)
        self.clock = Clock()
        self.daily_log = self.repo / "daily-check.log"
        self.err = quiet(self)
        self.bot = self.make_bot()

    def make_bot(self, **kwargs):
        options = dict(fetch=self.vt, git=self.git, today=lambda: TODAY, clock=self.clock.now,
                       sleep=self.clock.sleep, daily_log=self.daily_log)
        return telegram_bot.Bot(self.tg, self.repo, **dict(options, **kwargs))

    def updates(self, batch):
        self.tg.batches.append(batch)

    def send(self, text):
        self.updates([message(text)])
        return self.bot.run_once()


class AddTest(BotTestCase):
    def test_bare_text_is_checked_and_added_then_committed_and_pushed(self):
        self.updates([{"update_id": 1, "message": {"chat": {"id": 42}, "text": "evil[.]com 185.1.2.9 MuddyWater - Unit 42"}}])
        self.bot.run_once()
        self.assertIn("evil.com: added (Domain 11/94 malicious)", self.tg.sent[-1])
        self.assertIn("185.1.2.9: clean (IP 1/94 malicious)", self.tg.sent[-1])
        self.assertEqual([c[:3] for c in self.git.calls], [["git", "pull", "--rebase"], ["git", "add", "spark-ioc-feed.csv"], ["git", "commit", "-m"], ["git", "push", "--quiet"]])
        self.assertIn("MuddyWater - Unit 42", self.feed.read_text())
        self.assertFalse((self.repo / "syslog" / ".feed-lock").exists())

    def test_the_row_says_it_came_from_telegram_and_the_commit_names_the_label(self):
        self.send("evil[.]com 185.1.2.9 MuddyWater - Unit 42")

        self.assertTrue(self.feed.read_text().endswith(
            ",evil.com,Domain,high,high,AB,MuddyWater - Unit 42 - sent from Telegram - VT 11/94 malicious 2026-10-28\n"))
        commit = self.git.calls[2]
        self.assertEqual(commit, ["git", "commit", "-m", "Add 1 indicator sent from Telegram: MuddyWater - Unit 42",
                                  "--", "spark-ioc-feed.csv"])
        self.assertEqual(self.git.calls[0], ["git", "pull", "--rebase", "--autostash", "--quiet"])
        for kwargs in self.git.kwargs:
            self.assertEqual((kwargs["cwd"], kwargs["capture_output"], kwargs["text"]), (self.repo, True, True))

    def test_the_check_is_announced_and_the_reply_ends_with_the_counts_and_the_push(self):
        self.send("evil[.]com 185.1.2.9")

        self.assertEqual(self.tg.sent[0], "Checking 2 indicators on VirusTotal, about 1 minute.")
        self.assertEqual(self.tg.sent[1].splitlines()[-2:],
                         ["1 added, 1 clean, 0 unknown to VirusTotal, 0 already in the feed", "Committed and pushed."])

    def test_a_label_less_check_is_marked_sent_from_telegram(self):
        self.send("evil.com")

        self.assertIn(",AB,sent from Telegram - VT 11/94 malicious 2026-10-28\n", self.feed.read_text())
        self.assertEqual(self.git.calls[2][3], "Add 1 indicator sent from Telegram")

    def test_trust_adds_without_a_lookup(self):
        self.send("/trust 185.1.2.10 Cyberint")

        self.assertEqual(self.vt.calls, [])
        row = self.feed.read_text().splitlines()[-1]
        self.assertTrue(row.endswith(",185.1.2.10,IP,high,high,AB,Cyberint - sent from Telegram - "
                                     "added without VirusTotal check 2026-10-28"), row)
        self.assertEqual([c[1] for c in self.git.calls], ["pull", "add", "commit", "push"])
        self.assertEqual(self.tg.sent[-1].splitlines()[-2:], ["1 added, 0 already in the feed", "Committed and pushed."])

    def test_nothing_added_means_no_commit_and_no_push(self):
        self.send("185.1.2.9 93.152.221.36")

        self.assertEqual([c[1] for c in self.git.calls], ["pull"])
        self.assertEqual(self.feed.read_text(), FEED)
        self.assertIn("93.152.221.36: in-feed", self.tg.sent[-1])
        self.assertEqual(self.tg.sent[-1].splitlines()[-2:],
                         ["0 added, 1 clean, 0 unknown to VirusTotal, 1 already in the feed",
                          "Nothing added, nothing committed."])

    def test_at_most_fifty_indicators_per_message(self):
        self.send(" ".join(f"185.2.0.{i}" for i in range(1, 61)))

        self.assertEqual(len(self.vt.calls), 50)
        self.assertEqual(self.clock.sleeps, [vt_check.FREE_API_DELAY] * 49)
        self.assertTrue(self.tg.sent[-1].endswith("10 not checked, send them again"), self.tg.sent[-1][-200:])
        self.assertIn("0 added, 0 clean, 50 unknown to VirusTotal, 0 already in the feed", self.tg.sent[-1])
        self.assertTrue(self.tg.sent[0].startswith("Checking 50 indicators on VirusTotal, about 13 minutes"))

    def test_commit_message_is_safe_with_odd_labels(self):
        reply = self.bot.add(["185.1.2.10"], 'x" ; rm -rf / \n y\r', trusted=True)

        self.assertIn("Committed and pushed.", reply)
        commit = self.git.calls[2]
        self.assertIsInstance(commit, list)
        self.assertEqual(commit[:3], ["git", "commit", "-m"])
        self.assertEqual(commit[3], 'Add 1 indicator sent from Telegram: x" ; rm -rf / y')
        self.assertEqual(commit[4:], ["--", "spark-ioc-feed.csv"])

    def test_the_feed_is_locked_while_it_is_pulled_written_and_committed(self):
        seen = []
        fetch = lambda path: (seen.append(self.lock.exists()), self.vt(path))[1]
        bot = self.make_bot(fetch=fetch)

        bot.add(["evil.com"], "", trusted=False)

        self.assertEqual(seen, [True])
        self.assertEqual(self.git.locked, [True] * 4)
        self.assertFalse(self.lock.exists())

    def test_a_lock_held_by_the_daily_check_turns_the_indicators_away_after_a_minute(self):
        self.lock.mkdir()
        taken = self.clock.time - 25 * 60
        os.utime(self.lock, (taken, taken))

        self.send("evil.com")

        self.assertEqual(sum(self.clock.sleeps), 60)
        self.assertEqual(self.tg.sent[-1], "The daily check has been writing the feed for 26 minutes; "
                                           "send the indicators again later.")
        self.assertEqual((self.git.calls, self.vt.calls), ([], []))
        self.assertEqual(self.feed.read_text(), FEED)
        self.assertTrue(self.lock.exists(), "the daily check's lock is not ours to remove")

    def test_a_failed_pull_writes_nothing(self):
        self.git.failing = {"pull"}

        self.send("evil.com")

        self.assertEqual(self.tg.sent[-1], "git pull failed, nothing was added: fatal: pull refused")
        self.assertEqual(([c[1] for c in self.git.calls], self.vt.calls), (["pull"], []))
        self.assertEqual(self.feed.read_text(), FEED)
        self.assertFalse(self.lock.exists())
        self.assertIn("git pull failed: fatal: pull refused", self.bot.status().splitlines()[-1])

    def test_a_failed_push_leaves_the_commit_for_the_daily_check(self):
        self.git.failing = {"push"}

        self.send("evil.com")

        self.assertEqual(self.tg.sent[-1].splitlines()[-1],
                         "Committed, but the push failed (fatal: push refused); the daily check will push it.")
        self.assertIn("git push failed: fatal: push refused", self.bot.status().splitlines()[-1])

    def test_a_failed_commit_says_the_rows_are_in_the_file(self):
        self.git.failing = {"commit"}

        self.send("evil.com")

        self.assertEqual([c[1] for c in self.git.calls], ["pull", "add", "commit"])
        self.assertIn("git commit failed", self.tg.sent[-1])

    def test_a_refused_virustotal_key_stops_the_check_and_still_commits_what_was_added(self):
        self.vt.responses[vt_check.api_path("IP", "185.1.2.9")] = (401, {"error": {"code": "WrongCredentialsError"}})

        self.send("evil.com 185.1.2.9")

        self.assertIn("stopped: VirusTotal refused the API key: HTTP 401 WrongCredentialsError", self.tg.sent[-1])
        self.assertEqual([c[1] for c in self.git.calls], ["pull", "add", "commit", "push"])

    def test_without_a_virustotal_key_nothing_is_done(self):
        bot = self.make_bot(fetch=None)

        with patch("vt_check.api_key", return_value=""):
            reply = bot.add(["evil.com"], "", trusted=False)

        self.assertIn("security add-generic-password -s spark-ioc-feed -a VT_API_KEY", reply)
        self.assertEqual((self.git.calls, self.tg.sent), ([], []))

    def test_a_message_without_an_indicator_gets_the_help(self):
        self.send("hello there")

        self.assertTrue(self.tg.sent[-1].startswith("No indicator in that message."))
        self.assertIn(telegram_bot.HELP, self.tg.sent[-1])
        self.assertEqual(self.git.calls, [])


class UpdatesTest(BotTestCase):
    def test_messages_from_other_chats_are_ignored(self):
        self.updates([message("evil.com", chat=7, update_id=1), message("/status", chat=7, update_id=2)])

        self.assertEqual(self.bot.run_once(), 2)

        self.assertEqual((self.tg.sent, self.git.calls, self.vt.calls), ([], [], []))
        self.assertEqual(self.err.getvalue().count("chat 7"), 1, "logged once a day")

    def test_updates_without_text_are_ignored(self):
        self.updates([{"update_id": 1, "edited_message": {"chat": {"id": OWNER}, "text": "x"}},
                      {"update_id": 2, "message": {"chat": {"id": OWNER}, "sticker": {}}}])

        self.bot.run_once()

        self.assertEqual(self.tg.sent, [])

    def test_offset_survives_a_restart(self):
        self.updates([message("/help", update_id=1)])

        self.assertEqual(self.bot.run_once(), 1)

        self.assertEqual(json.loads((self.repo / "syslog" / "telegram-offset.json").read_text()), {"offset": 2})
        restarted = self.make_bot()
        restarted.run_once()
        self.assertEqual(self.tg.polls, [(0, 50), (2, 50)])

    def test_unknown_commands_and_help_reply_with_the_command_list(self):
        for text in ("/help", "/frobnicate"):
            with self.subTest(text=text):
                self.send(text)
                self.assertEqual(self.tg.sent[-1], telegram_bot.HELP)
        for command in ("/trust", "/who", "/sources", "/status"):
            self.assertIn(command, telegram_bot.HELP)

    def test_a_failing_command_is_reported_and_the_bot_carries_on(self):
        with patch.object(self.bot, "status", side_effect=RuntimeError("disk gone")):
            self.updates([message("/status", update_id=1), message("/help", update_id=2)])
            self.bot.run_once()

        self.assertEqual(self.tg.sent, ["status failed: disk gone", telegram_bot.HELP])
        self.assertIn("disk gone", self.err.getvalue())

    def test_a_reply_telegram_refuses_is_logged(self):
        self.tg.send_message = lambda text: (_ for _ in ()).throw(telegram_api.TelegramError("Forbidden"))

        self.send("/help")

        self.assertIn("Forbidden", self.err.getvalue())


class SourcesTest(BotTestCase):
    def setUp(self):
        super().setUp()
        probe = lambda src: INBOUND_DROP.replace("109.205.211.205", src).replace("2026-10-20", "2026-10-27")
        lines = [probe("185.1.2.20"), probe("93.152.221.36"), probe("93.152.221.36"), probe("93.152.221.36")]
        (self.syslog / "spark-2026-10-27.log").write_text("\n".join(lines) + "\n")

    def test_sources_replies_with_a_file_of_yesterdays_probers(self):
        self.send("/sources")

        [(filename, data, caption)] = self.tg.documents
        self.assertEqual(filename, "sources-2026-10-27.txt")
        self.assertEqual(data.decode().splitlines(), ["93.152.221.36 3 (in feed)", "185.1.2.20 1"])
        self.assertEqual(self.tg.sent, [])

    def test_a_day_can_be_named_and_an_empty_day_says_so(self):
        self.send("/sources 2026-10-20")

        self.assertEqual(self.tg.documents, [])
        self.assertEqual(self.tg.sent[-1], "No inbound sources in the capture of 2026-10-20.")

    def test_a_bad_date_gets_the_usage(self):
        self.send("/sources yesterday")

        self.assertEqual(self.tg.sent[-1], "Send /sources, or /sources YYYY-MM-DD for another day.")


class StatusTest(BotTestCase):
    def capture(self, age):
        path = self.syslog / "spark-2026-10-28.log"
        path.write_text(INBOUND_DROP + "\n")
        os.utime(path, (self.clock.time - age, self.clock.time - age))

    def test_status_reports_receiver_daily_run_and_next_recheck(self):
        self.capture(age=30)
        self.daily_log.write_text(DAILY_LOG)

        self.send("/status")

        lines = self.tg.sent[-1].splitlines()
        self.assertEqual(lines[:3], ["receiver: writing", "last daily check: 2026-10-28 16:20 done, 45 lookups",
                                     "next re-check 2026-12-18"])
        self.assertRegex(lines[3], r"^bot: up since \d{4}-\d{2}-\d{2} \d{2}:\d{2}$")
        self.assertEqual(lines[4:], ["last error: none"])

    def test_status_shows_the_last_error(self):
        self.send("/status")
        self.assertEqual(self.tg.sent[-1].splitlines()[-1], "last error: none")

        self.tg.batches = [telegram_api.TelegramError("getUpdates: 502"), [message("/status", update_id=2)],
                           KeyboardInterrupt()]
        failed_at = datetime.fromtimestamp(self.clock.time)
        self.bot.run_forever()

        self.assertEqual(self.clock.sleeps, [10])
        last = self.tg.sent[-1].splitlines()[-1]
        self.assertTrue(last.startswith(f"last error: {failed_at:%Y-%m-%d %H:%M} Telegram: getUpdates: 502"), last)

    def test_a_quiet_receiver(self):
        self.capture(age=10 * 60)
        self.assertEqual(self.bot.status().splitlines()[0], "receiver: no capture for 10 minutes")
        (self.syslog / "spark-2026-10-28.log").unlink()
        self.assertEqual(self.bot.status().splitlines()[0], "receiver: no capture today")

    def test_a_failed_or_running_or_missing_daily_check(self):
        failed = DAILY_LOG.split("evil.example")[0] + (
            "2026-10-28 16:20:09 ERROR: git pull failed; the feed was not checked (see daily-check.log)\n")
        running = DAILY_LOG.split("Brief sent")[0]
        for text, line in ((failed, "last daily check: 2026-10-28 16:20 failed: git pull failed; the feed was not "
                                    "checked (see daily-check.log)"),
                           (running, "last daily check: 2026-10-28 16:20 running"),
                           ("", "last daily check: none in the log")):
            with self.subTest(line=line):
                self.daily_log.write_text(text)
                self.assertEqual(self.bot.status().splitlines()[1], line)
        self.daily_log.unlink()
        self.assertEqual(self.bot.status().splitlines()[1], "last daily check: no log")

    def test_a_feed_with_nothing_to_recheck(self):
        self.feed.write_text(HEADER + "colocatel,45.155.205.0-45.155.205.255,IP Range,high,medium,AB,Colocatel\n")

        self.assertEqual(self.bot.status().splitlines()[2], "no re-check due")


class WhoTest(BotTestCase):
    def test_who_sends_the_context_note(self):
        with patch("attacker_context.note", return_value="93.152.221.36 is a scanner") as note:
            self.send("/who 93.152.221.36")

        self.assertEqual(self.tg.sent, ["93.152.221.36 is a scanner"])
        note.assert_called_once_with("93.152.221.36", self.syslog, "2026-10-28")

    def test_who_without_an_indicator_gets_the_usage(self):
        with patch("attacker_context.note") as note:
            self.send("/who")

        self.assertEqual(self.tg.sent, ["Send /who <indicator>, e.g. /who 93.152.221.36"])
        note.assert_not_called()


class AlertTest(BotTestCase):
    def test_an_alert_goes_out_then_the_context_note_on_the_indicator(self):
        [alert] = self.bot.watcher.scan([OUTBOUND_TO_C2])

        with patch("attacker_context.note", return_value="note on c2") as note:
            self.bot.on_alert(alert)

        self.assertEqual(self.tg.sent, ["09:15:02 — 10.68.144.121 tried to reach c2.example.net "
                                        "(MuddyWater - VT 9/94 malicious 2026-10-01) — drop; 1× today", "note on c2"])
        note.assert_called_once_with("c2.example.net", self.syslog, "2026-10-28")

    def test_a_detection_gets_the_note_on_its_external_address(self):
        [alert] = self.bot.watcher.scan([INBOUND_PREVENT])

        with patch("attacker_context.note", return_value="note") as note:
            self.bot.on_alert(alert)

        note.assert_called_once_with("31.14.32.6", self.syslog, "2026-10-28")

    def test_an_alert_telegram_refuses_is_logged(self):
        [alert] = self.bot.watcher.scan([OUTBOUND_TO_C2])
        self.tg.send_message = lambda text: (_ for _ in ()).throw(telegram_api.TelegramError("Too Many Requests"))

        with patch("attacker_context.note", return_value="note"):
            self.bot.on_alert(alert)

        self.assertIn("Too Many Requests", self.err.getvalue())
        self.assertIn("Too Many Requests", self.bot.status().splitlines()[-1])


class RunForeverTest(BotTestCase):
    def test_telegram_failures_back_off_and_ctrl_c_stops_the_bot_and_its_watcher(self):
        self.tg.batches = [telegram_api.TelegramError("Bad Gateway"), urllib.error.URLError("no route"),
                           [message("/help")], KeyboardInterrupt()]
        threads = threading.active_count()

        self.bot.run_forever()

        self.assertEqual(self.clock.sleeps, [10, 10])
        self.assertEqual(self.tg.sent, [telegram_bot.HELP])
        self.assertEqual([offset for offset, _ in self.tg.polls], [0, 0, 0, 2])
        self.assertIn("Bad Gateway", self.err.getvalue())
        self.assertIn("no route", self.err.getvalue())
        self.assertEqual(threading.active_count(), threads, "the watcher thread was joined")

    def test_the_watcher_thread_survives_an_exception(self):
        stop = threading.Event()
        calls = []

        def follow(stop_event, poll=2.0):
            calls.append(poll)
            if len(calls) == 1:
                raise RuntimeError("bad line")
            stop_event.set()

        with patch.object(self.bot.watcher, "follow", follow), patch("telegram_bot.BACKOFF", 0):
            self.bot.watch(stop)

        self.assertEqual(len(calls), 2)
        self.assertRegex(self.err.getvalue(), r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} .*bad line")
        self.assertIn("bad line", self.bot.status().splitlines()[-1], "the watcher thread records it too")


class WatcherTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.feed_path = self.dir / "spark-ioc-feed.csv"
        self.feed_path.write_text(FEED)
        self.clock = Clock()
        self.day = TODAY
        self.alerts = []
        self.watcher = telegram_bot.Watcher(self.dir, telegram_bot.FeedFile(self.feed_path), self.alerts.append,
                                            today=lambda: self.day, clock=self.clock.now)

    def summary(self, alerts):
        return [(a.kind, a.device, a.indicator, a.action) for a in alerts]

    def test_watcher_alerts_a_device_reaching_a_feed_member_once_an_hour(self):
        alerts = self.watcher.scan([OUTBOUND_TO_C2, OUTBOUND_TO_C2])   # destination_domain_name c2.example.net, in the feed
        self.assertEqual([(a.kind, a.device, a.indicator, a.action) for a in alerts], [("feed", "10.68.144.121", "c2.example.net", "drop")])

        self.clock.time += 3599
        self.assertEqual(self.watcher.scan([OUTBOUND_TO_C2]), [])
        self.clock.time += 1
        self.assertEqual(len(self.watcher.scan([OUTBOUND_TO_C2])), 1)

    def test_watcher_matches_the_address_when_the_feed_holds_the_ip(self):
        self.assertEqual(self.summary(self.watcher.scan([OUTBOUND_TO_FEED_IP])),
                         [("feed", "10.68.144.121", "185.1.2.7", "accept")])

    def test_an_address_inside_an_ip_range_row_alerts_with_the_range_label(self):
        [alert] = self.watcher.scan([OUTBOUND_TO_RANGE])

        self.assertEqual(alert.indicator, "45.155.205.233")
        self.assertIn("(Colocatel)", self.watcher.describe(alert))

    def test_inbound_probes_from_feed_members_are_not_alerted(self):
        probe = INBOUND_DROP.replace("109.205.211.205", "93.152.221.36")

        self.assertEqual(self.watcher.scan([probe]), [])

    def test_watcher_alerts_threat_prevention_detections_not_statistics(self):
        alerts = self.watcher.scan([INBOUND_PREVENT, STATS, INBOUND_PREVENT])

        self.assertEqual(self.summary(alerts), [("detection", "176.230.223.47", "31.14.32.6", "detected")])
        self.assertEqual(self.watcher.describe(alerts[0]),
                         "20:57:09 — Threat Prevention: Anti-Malware IP reputation from 31.14.32.6 to 176.230.223.47"
                         " — detected")

    def test_the_alert_text_counts_the_pair_today(self):
        alerts = self.watcher.scan([OUTBOUND_TO_C2, OUTBOUND_TO_C2])

        self.assertEqual(self.watcher.describe(alerts[0]),
                         "09:15:02 — 10.68.144.121 tried to reach c2.example.net "
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

    def test_a_malformed_line_does_not_stop_the_scan(self):
        self.assertEqual(len(self.watcher.scan([MALFORMED, "", "garbage", OUTBOUND_TO_C2])), 1)

    # follow(): a thread reading the capture as the receiver writes it, polling every 10 ms. The stop
    # event counts the watcher's idle waits: once it waits, it has read everything there was.

    def capture(self, day=TODAY):
        return self.dir / f"spark-{day:%Y-%m-%d}.log"

    def append(self, text, day=TODAY):
        with self.capture(day).open("a") as f:
            f.write(text)

    def follow(self):
        stop = IdleCount()
        thread = threading.Thread(target=self.watcher.follow, args=(stop, 0.01))
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
        self.assertEqual(self.summary(self.alerts), [("feed", "10.68.144.121", "c2.example.net", "drop")])

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
        self.append(OUTBOUND_TO_FEED_IP + "\n")
        self.wait_for(1)
        self.clock.time += 3600
        self.append(OUTBOUND_TO_C2 + "\n")
        self.wait_for(2)

        self.assertEqual([a.indicator for a in self.alerts], ["185.1.2.7", "c2.example.net"])
        self.assertTrue(self.watcher.describe(self.alerts[1]).endswith("; 2× today"))

    def test_a_line_still_being_written_waits_for_its_end(self):
        self.append("")
        stop, _ = self.follow()
        self.idle(stop)
        self.append(OUTBOUND_TO_C2[:60])
        self.idle(stop)
        self.assertEqual(self.alerts, [])

        self.append(OUTBOUND_TO_C2[60:] + "\n")
        self.wait_for(1)

        self.assertEqual(self.summary(self.alerts), [("feed", "10.68.144.121", "c2.example.net", "drop")])

    def test_a_replaced_capture_is_read_again_from_its_start(self):
        self.append("")
        stop, _ = self.follow()
        self.idle(stop)
        self.capture().unlink()
        self.idle(stop)

        self.append(OUTBOUND_TO_C2 + "\n")
        self.wait_for(1)


class MainTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name)
        (self.repo / "syslog").mkdir()
        (self.repo / "spark-ioc-feed.csv").write_text(FEED)
        self.tg = FakeTelegram()

    def main(self, argv, telegram=None, stored=None):
        out, err = io.StringIO(), io.StringIO()
        stored = stored or {}
        with patch("telegram_api.from_keychain", return_value=telegram), \
                patch("telegram_api.Telegram", side_effect=lambda token, chat_id: self.paired(token, chat_id)), \
                patch("keychain.item", side_effect=lambda account, *a, **k: stored.get(account, "")), \
                patch("telegram_bot.REPO", self.repo), patch("time.sleep") as sleep, \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = telegram_bot.main(argv)
        return code, out.getvalue(), err.getvalue(), sleep

    def paired(self, token, chat_id):
        self.client = (token, chat_id)
        return self.tg

    def test_once_handles_the_waiting_messages_and_exits(self):
        self.tg.batches = [[message("/help")]]

        code, out, err, sleep = self.main(["--once"], telegram=self.tg)

        self.assertEqual(code, 0, err)
        self.assertEqual(self.tg.sent, [telegram_bot.HELP])
        self.assertEqual(self.tg.polls, [(0, 0)])
        self.assertEqual(json.loads((self.repo / "syslog" / "telegram-offset.json").read_text()), {"offset": 2})

    def test_without_the_bot_in_the_keychain_it_says_what_is_missing_and_waits_before_exiting(self):
        code, out, err, sleep = self.main([])

        self.assertEqual(code, 1)
        self.assertIn("TELEGRAM_BOT_TOKEN", err)
        self.assertIn("TELEGRAM_CHAT_ID", err)
        self.assertIn("--pair", err)
        sleep.assert_called_once_with(300)

    def test_pair_prints_the_chat_id_and_the_command_that_stores_it(self):
        self.tg.batches = [[message("hello", chat=4242)]]

        code, out, err, sleep = self.main(["--pair"], stored={"TELEGRAM_BOT_TOKEN": "123456:SECRET-token"})

        self.assertEqual(code, 0, err)
        self.assertEqual(self.client, ("123456:SECRET-token", None))
        self.assertEqual(self.tg.polls, [(0, 50)])
        self.assertIn("4242", out)
        self.assertIn("security add-generic-password -s spark-ioc-feed -a TELEGRAM_CHAT_ID -w '4242' -U", out)
        self.assertNotIn("SECRET", out + err)
        self.assertEqual(self.tg.sent, [])

    def test_pair_before_any_message_asks_for_one(self):
        code, out, err, sleep = self.main(["--pair"], stored={"TELEGRAM_BOT_TOKEN": "123456:SECRET-token"})

        self.assertEqual(code, 1)
        self.assertIn("Send the bot a message first", out)

    def test_pair_without_a_token_explains_botfather(self):
        code, out, err, sleep = self.main(["--pair"])

        self.assertEqual(code, 1)
        self.assertIn("BotFather", out)
        self.assertIn("security add-generic-password -s spark-ioc-feed -a TELEGRAM_BOT_TOKEN -w '<token>' -U", out)
        self.assertEqual(self.tg.polls, [])


class PlistTest(unittest.TestCase):
    def test_plist_keeps_the_bot_alive_under_python_app(self):
        with (REPO / "launchd" / "com.spark-ioc-feed.telegram.plist").open("rb") as f:
            plist = plistlib.load(f)
        with (REPO / "launchd" / "com.spark-ioc-feed.syslog.plist").open("rb") as f:
            receiver = plistlib.load(f)

        self.assertEqual(plist["Label"], "com.spark-ioc-feed.telegram")
        program, script = plist["ProgramArguments"]
        self.assertTrue(program.endswith("Python.app/Contents/MacOS/Python"))
        self.assertEqual(program, receiver["ProgramArguments"][0])
        self.assertTrue(script.endswith("/telegram_bot.py"))
        self.assertEqual(plist["WorkingDirectory"], receiver["WorkingDirectory"])
        self.assertEqual(script, plist["WorkingDirectory"] + "/telegram_bot.py")
        self.assertIs(plist["RunAtLoad"], True)
        self.assertIs(plist["KeepAlive"], True)
        for key in ("StandardOutPath", "StandardErrorPath"):
            self.assertTrue(plist[key].endswith("Library/Logs/spark-ioc-feed/telegram-bot.log"), plist[key])

    def test_the_install_comment_uses_bootstrap_and_bootout(self):
        text = (REPO / "launchd" / "com.spark-ioc-feed.telegram.plist").read_text()

        self.assertIn("launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.spark-ioc-feed.telegram.plist", text)
        self.assertIn("launchctl bootout gui/$(id -u)/com.spark-ioc-feed.telegram", text)


if __name__ == "__main__":
    unittest.main()
