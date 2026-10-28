"""telegram_bot.py: the bot the owner talks to (indicators in, replies out), the live watcher of
today's capture (alerts out), and the LaunchAgent that keeps both running.

The addresses are public ones (185.1.2.x): vt_check.classify refuses the documentation ranges, and
spark_logs.candidate never takes them for an outbound destination."""

import contextlib
import http.client
import io
import json
import os
import plistlib
import signal
import subprocess
import tempfile
import threading
import time
import unicodedata
import unittest
import urllib.error
from datetime import date, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import feed_lock
import telegram_api
import telegram_bot
import vt_check
from tests.test_spark_logs import INBOUND_DROP, INBOUND_PREVENT, STATS, SYSTEM_LINES
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
# Threat Prevention rows shaped like spark_logs' INBOUND_PREVENT: a LAN device's request the IPS let
# through (accept: the brief's alone), the same detected, in monitor mode, and one between two LAN addresses.
OUTBOUND_DETECTION = (INBOUND_PREVENT.replace("2026-10-20T20:57:09", "2026-10-28T10:02:11")
                      .replace('Action=" "', 'Action="accept"').replace('src="31.14.32.6"', 'src="10.68.144.121"')
                      .replace('dst="176.230.223.47"', 'dst="104.18.32.47"')
                      .replace('Protection Name=""', 'Protection Name="Header Spoofing"')
                      .replace('ProductName="Anti Malware"', 'ProductName="SmartDefense"'))
MONITORED_DETECTION = OUTBOUND_DETECTION.replace('Action="accept"', 'Action="monitor"')
LAN_DETECTION = (OUTBOUND_DETECTION.replace('src="10.68.144.121"', 'src="10.68.144.100"')
                 .replace('dst="104.18.32.47"', 'dst="10.68.144.1"').replace("Header Spoofing", "Max Ping Size")
                 .replace('Action="accept"', 'Action="drop"'))
OUTBOUND_DETECTED = OUTBOUND_DETECTION.replace('Action="accept"', 'Action="detect"')
# The Spark enforces the feed through Anti-Bot, so a feed hit can come as a detection row too.
FEED_HIT_DETECTED = OUTBOUND_TO_C2.replace('ProductName="VPN-1 & FireWall-1"',
                                           'Protection Name="spark-ioc-feed" ProductName="Anti-Bot"')

# Threat Prevention rows with an explicit action, written with a private LAN device and the documentation
# WAN address: an inbound one, and outbound ones from each blade (Anti-Bot, Anti-Virus and Threat
# Emulation get a note on the destination, IPS does not).
LAN_DEVICE, WAN = "192.168.50.20", "203.0.113.47"


def detection(at, action, src, dst, blade, protection, **extra):
    fields = {"Action": action, "Uuid": "{0x20}", "src": src, "dst": dst, "proto": "6",
              "Protection Name": protection, "severity": "3", "ProductName": blade, **extra}
    return f"2026-10-28T{at} " + " ".join(f'{key}="{value}"' for key, value in fields.items())


INBOUND_PREVENTED = detection("08:12:40", "Prevent", "185.1.2.66", WAN, "Anti Malware", "Scanner")
OUTBOUND_BOT = detection("10:20:00", "prevent", LAN_DEVICE, "185.1.2.70", "Anti-Bot", "Trojan.Win32.Agent.C2",
                         resource="http://c2.example.org/gate.php")
OUTBOUND_VIRUS = detection("10:21:00", "prevent", LAN_DEVICE, "185.1.2.71", "Anti Virus", "EICAR-Test-File")
OUTBOUND_EMULATION = detection("10:22:00", "detect", LAN_DEVICE, "185.1.2.72", "Threat Emulation", "Generic.TC.a")
OUTBOUND_IPS = detection("10:23:00", "drop", LAN_DEVICE, "185.1.2.73", "IPS", "Header Spoofing")

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


def message(text, chat=OWNER, update_id=1, chat_type="private", sender=None):
    """An update carrying a text message, by default from the owner's private chat."""
    sender = sender or {"id": chat if chat_type == "private" else OWNER, "username": "owner", "first_name": "Owner"}
    return {"update_id": update_id, "message": {"chat": {"id": chat, "type": chat_type}, "from": sender, "text": text}}


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


class LogTest(unittest.TestCase):
    def test_a_log_line_is_one_write_so_the_two_threads_do_not_interleave(self):
        writes = []
        stream = type("Stream", (), {"write": lambda self, text: writes.append(text), "flush": lambda self: None})()

        with patch("sys.stderr", stream):
            telegram_bot.log("watcher failed")

        self.assertEqual(len(writes), 1, writes)
        self.assertRegex(writes[0], r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} watcher failed\n$")


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

    def test_a_comma_after_an_indicator_separates_it_from_the_next(self):
        self.assertEqual(telegram_bot.parse_message("a.example, b.example, Campaign"),
                         ("check", ["a.example", "b.example"], "Campaign"))

    def test_a_url_with_a_comma_is_not_shortened_into_another_url(self):
        verb, indicators, label = telegram_bot.parse_message("hxxps://bad[.]example/a?x=1,2 Campaign")

        self.assertEqual(indicators, [])
        self.assertEqual(label, "hxxps://bad[.]example/a?x=1 2 Campaign")

    def test_the_label_starts_at_the_first_token_that_is_not_an_indicator(self):
        self.assertEqual(telegram_bot.parse_message("/trust 185.1.2.9 Cyberint report on bad.example"),
                         ("trust", ["185.1.2.9"], "Cyberint report on bad.example"))

    def test_a_date_argument_is_left_in_the_label(self):
        self.assertEqual(telegram_bot.parse_message("/sources 2026-10-20"), ("sources", [], "2026-10-20"))

    def test_the_label_loses_quotes_and_control_format_and_bidi_marks(self):
        # The label lands in the gateway's CSV and in the public commit subject.
        text = 'evil.com "APT\x1b[31m34"‮ report​, \x00x'

        self.assertEqual(telegram_bot.parse_message(text), ("check", ["evil.com"], "APT[31m34 report x"))

    def test_a_token_with_a_quote_or_a_hidden_mark_is_no_indicator(self):
        for token in ('hxxps://bad[.]example/"x', "hxxps://bad[.]example/\x1b[2J", "evil​.com"):
            with self.subTest(token=token):
                verb, indicators, label = telegram_bot.parse_message(f"185.1.2.9 {token} Campaign")

                self.assertEqual(indicators, ["185.1.2.9"])
                self.assertTrue(label.endswith("Campaign"), label)

    def test_the_label_is_cut_to_120_characters(self):
        verb, indicators, label = telegram_bot.parse_message("evil.com " + "word " * 60)

        self.assertEqual(len(label), 119, "cut at 120, the trailing space dropped")
        self.assertTrue(label.startswith("word word"))


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
        bot = telegram_bot.Bot(self.tg, self.repo, **dict(options, **kwargs))
        self.addCleanup(bot.stop_notes)
        return bot

    def updates(self, batch):
        self.tg.batches.append(batch)

    def send(self, text):
        self.updates([message(text)])
        return self.bot.run_once()


class AddTest(BotTestCase):
    def test_bare_text_is_checked_and_added_then_committed_and_pushed(self):
        self.updates([message("evil[.]com 185.1.2.9 MuddyWater - Unit 42")])
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

    def test_a_label_with_quotes_and_hidden_marks_reaches_the_feed_and_the_commit_clean(self):
        self.send('/trust 185.1.2.10 "Unit\x1b 42"‮​')

        row = self.feed.read_text().splitlines()[-1]
        self.assertEqual(row.split(",")[6], "Unit 42 - sent from Telegram - added without VirusTotal check 2026-10-28")
        self.assertEqual(self.git.calls[2], ["git", "commit", "-m", "Add 1 indicator sent from Telegram: Unit 42",
                                             "--", "spark-ioc-feed.csv"])
        for text in (row, self.git.calls[2][3]):
            self.assertFalse(any(c in text for c in '"\x1b‮​'), repr(text))

    def test_trust_refuses_what_must_never_be_blocked(self):
        (self.syslog / "allow.txt").write_text("vendor.example.net\n")
        for value in ("github.com", "raw.githubusercontent.com", "api.telegram.org", "api.anthropic.com",
                      "www.virustotal.com", "gsp-ssl.ls.apple.com", "cdn.vendor.example.net",
                      "https://raw.githubusercontent.com/owner/spark-ioc-feed/main/spark-ioc-feed.csv"):
            with self.subTest(value=value):
                self.send(f"/trust {value} oops")

                self.assertEqual(self.tg.sent[-1], f"refused: {value} is on the never-block list")
        self.assertEqual((self.git.calls, self.vt.calls), ([], []))
        self.assertEqual(self.feed.read_text(), FEED)
        self.assertFalse(self.lock.exists())
        self.assertFalse(self.bot.never_block("https://[::1"), "a URL without a readable host is no refusal")
        self.assertFalse(self.bot.never_block("notgithub.com"))

    def test_a_check_refuses_a_never_block_value_and_checks_the_rest(self):
        self.send("raw.githubusercontent.com evil[.]com")

        self.assertEqual(self.tg.sent[0], "Checking 1 indicator on VirusTotal, about 1 minute.")
        self.assertEqual(self.tg.sent[1].splitlines()[:2], ["refused: raw.githubusercontent.com is on the never-block list",
                                                            "evil.com: added (Domain 11/94 malicious)"])
        self.assertEqual(self.vt.calls, [vt_check.api_path("Domain", "evil.com")])
        self.assertNotIn("githubusercontent", self.feed.read_text())

    def test_a_git_argument_that_subprocess_refuses_is_a_failed_git_command(self):
        def git(args, **kwargs):
            if args[1] == "commit":
                raise ValueError("embedded null byte")
            return subprocess.CompletedProcess(args, 0, "", "")

        reply = self.make_bot(git=git).add(["185.1.2.10"], "Unit 42", trusted=True)

        self.assertIn("git commit failed, the rows are in the feed file but not committed: embedded null byte", reply)

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
        self.assertEqual(self.tg.sent, ["The daily check has been writing the feed for 26 minutes; "
                                        "send the indicators again later."], "no 'Checking…' before the lock is ours")
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

        self.assertEqual(self.tg.sent[-1].splitlines(), [
            "evil.com: added (Domain 11/94 malicious)",
            "stopped: VirusTotal refused the API key: HTTP 401 WrongCredentialsError",
            "1 added, 0 clean, 0 unknown to VirusTotal, 0 already in the feed",
            "Committed and pushed."])
        self.assertEqual([c[1] for c in self.git.calls], ["pull", "add", "commit", "push"])

    def test_a_network_error_mid_check_keeps_and_commits_what_was_added(self):
        def fetch(path):
            if path == vt_check.api_path("IP", "185.1.2.9"):
                raise urllib.error.URLError("timed out")
            return self.vt(path)

        bot = self.make_bot(fetch=fetch)
        reply = bot.add(["evil.com", "185.1.2.9"], "", trusted=False)

        self.assertEqual(reply.splitlines(), [
            "evil.com: added (Domain 11/94 malicious)",
            "stopped: <urlopen error timed out>",
            "1 added, 0 clean, 0 unknown to VirusTotal, 0 already in the feed",
            "Committed and pushed."])
        self.assertIn(",evil.com,Domain,high,high,AB,sent from Telegram - VT 11/94 malicious 2026-10-28\n",
                      self.feed.read_text())
        self.assertEqual(self.git.calls[2][3], "Add 1 indicator sent from Telegram")
        self.assertFalse(self.lock.exists())
        self.assertRegex(bot.status().splitlines()[-1],
                         r"^last error: \d{4}-\d{2}-\d{2} \d{2}:\d{2} .*stopped: <urlopen error timed out>$")

    def test_a_systemexit_mid_check_still_releases_the_lock(self):
        def fetch(path):
            raise SystemExit(0)  # what SIGTERM raises (see main)

        with self.assertRaises(SystemExit):
            self.make_bot(fetch=fetch).add(["evil.com"], "", trusted=False)

        self.assertFalse(self.lock.exists())

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

    def test_only_the_owners_private_chat_is_served(self):
        # In a group the owner's own messages carry the group's chat: every member could use the bot there.
        self.updates([message("/trust 185.1.2.10", chat=-100123, chat_type="supergroup", update_id=1),
                      message("/trust 185.1.2.10", chat=OWNER, chat_type="group", update_id=2),
                      message("/status", chat=OWNER, chat_type="channel", update_id=3),
                      {"update_id": 4, "message": {"chat": {"id": OWNER}, "text": "/help"}}])

        self.assertEqual(self.bot.run_once(), 4)

        self.assertEqual((self.tg.sent, self.git.calls), ([], []))
        self.assertEqual(self.feed.read_text(), FEED)
        self.assertEqual(self.bot.offset, 5)

    def test_updates_without_text_are_ignored(self):
        self.updates([{"update_id": 1, "edited_message": {"chat": {"id": OWNER, "type": "private"}, "text": "x"}},
                      {"update_id": 2, "message": {"chat": {"id": OWNER, "type": "private"}, "sticker": {}}}])

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

    def test_a_reply_that_fails_oddly_is_logged_and_the_next_update_handled(self):
        replies = []

        def send_message(text):
            if not replies:
                replies.append(text)
                raise TypeError("odd body")
            replies.append(text)

        self.tg.send_message = send_message
        self.updates([message("/help", update_id=1), message("/status", update_id=2)])

        self.assertEqual(self.bot.run_once(), 2)

        self.assertEqual(len(replies), 2)
        self.assertIn("odd body", self.bot.status().splitlines()[-1])
        self.assertEqual(self.bot.offset, 3)


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
    """The watcher hands the bot each batch's alerts in one call (on_alerts); the notes go to a queue
    that a thread of their own works through."""

    def deliver(self, items):
        self.bot.on_alerts(items)
        self.bot.note_queue.join()

    def test_an_alert_is_sent_while_a_slow_note_is_still_running(self):
        started, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def slow_note(indicator, *args):
            started.set()
            release.wait(5)
            return f"note on {indicator}"

        with patch("attacker_context.note", side_effect=slow_note):
            self.bot.on_alerts(self.bot.watcher.scan([OUTBOUND_TO_C2]))
            self.assertTrue(started.wait(5))
            self.bot.on_alerts(self.bot.watcher.scan([INBOUND_PREVENTED]))

            self.assertEqual(len(self.tg.sent), 2, "the second alert did not wait for the first note")
            self.assertIn("Threat Prevention: Anti-Malware Scanner", self.tg.sent[1])
            release.set()
            self.bot.note_queue.join()

        self.assertEqual(self.tg.sent[2:], ["note on c2.example.net", "note on 185.1.2.66"])

    def test_a_note_that_does_not_fit_the_queue_is_dropped_and_logged(self):
        started, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def slow_note(indicator, *args):
            started.set()
            release.wait(5)
            return f"note on {indicator}"

        probes = [INBOUND_PREVENTED.replace('src="185.1.2.66"', f'src="185.1.3.{i}"') for i in range(11)]
        with patch("attacker_context.note", side_effect=slow_note):
            self.bot.on_alerts(self.bot.watcher.scan([OUTBOUND_TO_C2]))
            self.assertTrue(started.wait(5))
            self.bot.on_alerts(self.bot.watcher.scan(probes))
            release.set()
            self.bot.note_queue.join()

        self.assertEqual(len([text for text in self.tg.sent if text.startswith("note on")]), 11)
        self.assertNotIn("note on 185.1.3.10", self.tg.sent)
        self.assertIn("the note on 185.1.3.10 was dropped: 10 notes are already waiting", self.err.getvalue())

    def test_the_cap_messages_go_out_like_alerts(self):
        notice = telegram_bot.Notice(telegram_bot.CAP_REACHED)

        with patch("attacker_context.note") as note:
            self.deliver([notice])

        self.assertEqual(self.tg.sent, ["Alert cap reached: further alerts in the next 10 minutes are counted, not sent"])
        note.assert_not_called()

    def test_a_note_that_fails_is_logged_and_the_next_one_still_runs(self):
        with patch("attacker_context.note", side_effect=[RuntimeError("odd"), "note two"]):
            self.deliver(self.bot.watcher.scan([OUTBOUND_TO_C2, INBOUND_PREVENTED]))

        self.assertEqual(self.tg.sent[-1], "note two")
        self.assertIn("the note on c2.example.net failed: RuntimeError('odd')", self.bot.status().splitlines()[-1])

    def test_an_alert_goes_out_then_the_context_note_on_the_indicator(self):
        alerts = self.bot.watcher.scan([OUTBOUND_TO_C2])

        with patch("attacker_context.note", return_value="note on c2") as note:
            self.deliver(alerts)

        self.assertEqual(self.tg.sent, ["09:15:02 — 10.68.144.121 tried to reach c2.example.net "
                                        "(MuddyWater - VT 9/94 malicious 2026-10-01) — drop; 1× today", "note on c2"])
        note.assert_called_once_with("c2.example.net", self.syslog, "2026-10-28")

    def test_an_inbound_detection_gets_the_note_on_its_source(self):
        alerts = self.bot.watcher.scan([INBOUND_PREVENTED])

        with patch("attacker_context.note", return_value="note") as note:
            self.deliver(alerts)

        self.assertEqual(self.tg.sent, ["08:12:40 — Threat Prevention: Anti-Malware Scanner from 185.1.2.66 to "
                                        "203.0.113.47 — prevent", "note"])
        note.assert_called_once_with("185.1.2.66", self.syslog, "2026-10-28")

    def test_an_outbound_ips_detection_gets_its_alert_but_no_note(self):
        alerts = self.bot.watcher.scan([OUTBOUND_IPS, OUTBOUND_DETECTED])

        with patch("attacker_context.note", return_value="note") as note:
            self.deliver(alerts)

        self.assertEqual(len(self.tg.sent), 2)
        self.assertEqual(self.tg.sent[0], "10:23:00 — Threat Prevention: IPS Header Spoofing from 192.168.50.20 to "
                                          "185.1.2.73 — drop")
        self.assertIn("Threat Prevention: SmartDefense Header Spoofing", self.tg.sent[1])
        note.assert_not_called()

    def test_outbound_anti_bot_virus_and_emulation_detections_get_a_note_on_the_destination(self):
        alerts = self.bot.watcher.scan([OUTBOUND_BOT, OUTBOUND_VIRUS, OUTBOUND_EMULATION])

        with patch("attacker_context.note", side_effect=lambda indicator, *a: f"note on {indicator}") as note:
            self.deliver(alerts)

        self.assertEqual(self.tg.sent[3:], ["note on c2.example.org", "note on 185.1.2.71", "note on 185.1.2.72"],
                         "the host name the row names, else the address")
        self.assertEqual(self.tg.sent[0], "10:20:00 — Threat Prevention: Anti-Bot Trojan.Win32.Agent.C2 from "
                                          "192.168.50.20 to 185.1.2.70 — prevent")
        self.assertEqual(note.call_count, 3)

    def test_a_burst_sends_every_alert_before_the_first_note(self):
        alerts = self.bot.watcher.scan([OUTBOUND_TO_C2, OUTBOUND_TO_FEED_IP, INBOUND_PREVENTED])

        with patch("attacker_context.note", side_effect=lambda indicator, *a: f"note on {indicator}"):
            self.deliver(alerts)

        self.assertEqual([text.split(" — ")[1] if " — " in text else text for text in self.tg.sent], [
            "10.68.144.121 tried to reach c2.example.net (MuddyWater - VT 9/94 malicious 2026-10-01)",
            "10.68.144.121 tried to reach 185.1.2.7 (Cyberint - added without VirusTotal check 2026-10-01)",
            "Threat Prevention: Anti-Malware Scanner from 185.1.2.66 to 203.0.113.47",
            "note on c2.example.net", "note on 185.1.2.7", "note on 185.1.2.66"])

    def test_an_alert_telegram_refuses_is_logged(self):
        alerts = self.bot.watcher.scan([OUTBOUND_TO_C2])
        self.tg.send_message = lambda text: (_ for _ in ()).throw(telegram_api.TelegramError("Too Many Requests"))

        with patch("attacker_context.note", return_value="note"):
            self.deliver(alerts)

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

    def test_an_odd_failure_of_a_poll_is_logged_and_the_loop_goes_on(self):
        self.tg.batches = [http.client.IncompleteRead(b"partial"), [message("/help")], KeyboardInterrupt()]

        self.bot.run_forever()

        self.assertEqual(self.clock.sleeps, [10])
        self.assertEqual(self.tg.sent, [telegram_bot.HELP])
        self.assertIn("IncompleteRead", self.bot.status().splitlines()[-1])

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
        self.alerts, self.batches = [], []
        self.watcher = telegram_bot.Watcher(self.dir, telegram_bot.FeedFile(self.feed_path), self.deliver,
                                            today=lambda: self.day, clock=self.clock.now)

    def deliver(self, batch):
        """The watcher's `alert`: it gets each batch's Alerts in one call."""
        self.batches.append(list(batch))
        self.alerts.extend(batch)

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
                         [("feed", "10.68.144.121", "c2.example.net", "drop")])

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

        self.assertEqual(cleared.text, "4 alerts suppressed between 09:00 and 09:10; the morning brief has the counts")
        self.assertEqual(len(self.watcher.gate(self.watcher.scan(self.probes(14, 1)))), 1, "alerts flow again")
        self.assertEqual(self.watcher.gate([]), [], "said once")

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
        cap = telegram_bot.NoteCap()
        start = datetime(2026, 10, 28, 1, 0).timestamp()

        admitted = [cap.admit(f"185.1.3.{i}", start + i * 601) for i in range(31)]

        self.assertEqual(admitted, [True] * 30 + [False])
        self.assertTrue(cap.admit("185.1.3.99", datetime(2026, 10, 29, 0, 1).timestamp()), "a new day")
        cap = telegram_bot.NoteCap()
        self.assertTrue(cap.admit("Evil.example", start))
        self.assertFalse(cap.admit("evil.example", start + 86399))
        self.assertTrue(cap.admit("evil.example", start + 86400))

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
        self.assertEqual(self.alerts, [])

        # No cooldown started for what was only counted: a new hit on that pair alerts at once.
        self.append(OUTBOUND_TO_C2 + "\n")
        self.wait_for(1)

        self.assertEqual([a.indicator for a in self.alerts], ["c2.example.net"])
        self.assertTrue(self.watcher.describe(self.alerts[0]).endswith("; 2× today"))

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

    def main(self, argv, telegram=None, stored=None, real_client=False):
        """Run main with the client `telegram` (with `real_client`, the one telegram_api.from_keychain
        builds from the `stored` Keychain items) and time.sleep patched."""
        out, err = io.StringIO(), io.StringIO()
        stored = stored or {}
        with contextlib.ExitStack() as stack:
            if not real_client:
                stack.enter_context(patch("telegram_api.from_keychain", return_value=telegram))
            stack.enter_context(patch("telegram_api.Telegram",
                                      side_effect=lambda token, chat_id: self.paired(token, chat_id)))
            stack.enter_context(patch("keychain.item", side_effect=lambda account, *a, **k: stored.get(account, "")))
            stack.enter_context(patch("telegram_bot.REPO", self.repo))
            sleep = stack.enter_context(patch("time.sleep"))
            stack.enter_context(contextlib.redirect_stdout(out))
            stack.enter_context(contextlib.redirect_stderr(err))
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

    def test_launchds_sigterm_becomes_an_exit_that_runs_the_finally_blocks(self):
        # signal.signal is patched: the test process keeps its own SIGTERM handling.
        with patch("signal.signal") as install, patch.object(telegram_bot.Bot, "run_forever") as run_forever:
            code, out, err, sleep = self.main([], telegram=self.tg)

        self.assertEqual(code, 0, err)
        run_forever.assert_called_once_with()
        signum, handler = install.call_args[0]
        self.assertEqual(signum, signal.SIGTERM)
        with self.assertRaises(SystemExit):
            handler(signal.SIGTERM, None)

    def test_without_the_bot_in_the_keychain_it_says_what_is_missing_and_waits_before_exiting(self):
        code, out, err, sleep = self.main([])

        self.assertEqual(code, 1)
        self.assertIn("TELEGRAM_BOT_TOKEN", err)
        self.assertIn("TELEGRAM_CHAT_ID", err)
        self.assertIn("--pair", err)
        sleep.assert_called_once_with(300)

    def test_a_chat_id_that_is_not_a_number_is_logged_without_its_value_and_waits_before_exiting(self):
        stored = {"TELEGRAM_BOT_TOKEN": "123456:SECRET-token", "TELEGRAM_CHAT_ID": "abc-123-secret"}

        code, out, err, sleep = self.main([], stored=stored, real_client=True)

        self.assertEqual(code, 1)
        self.assertIn("TELEGRAM_CHAT_ID is not a number", err)
        self.assertNotIn("abc-123-secret", out + err)
        self.assertNotIn("SECRET", out + err)
        sleep.assert_called_once_with(300)

    def pair(self, *updates):
        self.tg.batches = [list(updates)]
        return self.main(["--pair"], stored={"TELEGRAM_BOT_TOKEN": "123456:SECRET-token"})

    def test_pair_prints_the_chat_id_and_the_command_that_stores_it(self):
        code, out, err, sleep = self.pair(message("hello", chat=4242, sender={"id": 4242, "username": "owner_handle",
                                                                               "first_name": "Owner"}))

        self.assertEqual(code, 0, err)
        self.assertEqual(self.client, ("123456:SECRET-token", None))
        self.assertEqual(self.tg.polls, [(0, 50)])
        self.assertIn("private chat 4242 from @owner_handle (Owner)", out)
        self.assertIn("security add-generic-password -s spark-ioc-feed -a TELEGRAM_CHAT_ID -w '4242' -U", out)
        self.assertNotIn("SECRET", out + err)
        self.assertEqual(self.tg.sent, [])

    def test_pair_refuses_a_group_and_prints_no_id_for_it(self):
        code, out, err, sleep = self.pair(message("/start", chat=-100123, chat_type="supergroup",
                                                  sender={"id": 7, "username": "member", "first_name": "M"}))

        self.assertEqual(code, 1)
        self.assertIn("supergroup chat from @member (M): refused", out)
        self.assertIn("send /start to the bot from your own account, not from a group", out)
        self.assertNotIn("100123", out)
        self.assertNotIn("TELEGRAM_CHAT_ID -w", out)

    def test_pair_lists_every_candidate_and_prints_only_the_private_ones_id(self):
        code, out, err, sleep = self.pair(
            message("/start", chat=-100123, chat_type="group", update_id=1,
                    sender={"id": 7, "username": "member", "first_name": "M"}),
            message("/start", chat=4242, update_id=2, sender={"id": 4242, "first_name": "Owner"}),
            message("again", chat=4242, update_id=3, sender={"id": 4242, "first_name": "Owner"}))

        self.assertEqual(code, 0, err)
        self.assertIn("group chat from @member (M): refused", out)
        self.assertEqual(out.count("private chat 4242 from Owner"), 1)
        self.assertNotIn("100123", out)
        self.assertIn("-w '4242' -U", out)

    def test_pair_with_two_private_chats_asks_which_is_yours(self):
        code, out, err, sleep = self.pair(
            message("/start", chat=4242, update_id=1, sender={"id": 4242, "username": "owner_handle", "first_name": "Y"}),
            message("hi", chat=5151, update_id=2, sender={"id": 5151, "username": "stranger", "first_name": "S"}))

        self.assertEqual(code, 0, err)
        self.assertIn("private chat 4242 from @owner_handle (Y)", out)
        self.assertIn("private chat 5151 from @stranger (S)", out)
        self.assertIn("-w '<the id of your own account>' -U", out)
        self.assertNotIn("-w '4242'", out)

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
