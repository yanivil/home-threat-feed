"""spark_brief.py: the morning brief, composed from the previous day's capture, the daily run's
log and the feed, and posted to Telegram (or printed when there is no bot token)."""

import contextlib
import gzip
import io
import json
import os
import subprocess
import sys
import tempfile
import traceback
import types
import unittest
from collections import Counter
from datetime import date, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import spark_brief
import spark_logs
import telegram_api
import vt_check
from tests.test_spark_logs import (INBOUND_DROP, INBOUND_PREVENT, OUTBOUND_DOMAIN, OUTBOUND_IP_ONLY, OUTBOUND_URL,
                                   STATS, SYSTEM_LINES)
from tests.test_vt_check import HEADER, FakeVT, aged, cli_env, vt_error, vt_object

REPO = Path(__file__).resolve().parent.parent
DAY = date(2026, 10, 28)  # a Wednesday: the day the brief reports, sent on the morning of the 29th
TODAY = date(2026, 10, 29)
HEAVY, LIGHT, NEW = "93.152.221.36", "109.205.211.205", "47.79.34.208"
FEED = HEADER + (f"vt-ip-0a1b2c3d4e,{HEAVY},IP,high,high,AB,"
                 "Inbound probe of WAN - Spark syslog 2026-09-01 - VT 12/94 malicious 2026-09-01\n")
RUN_LOG = """2026-10-29 07:30:01 Daily check starting: last 2 day(s)
47.79.34.208: added (IP 11/94 malicious)
118.69.26.133: clean (IP 1/94 malicious)
OUTBOUND HIT  c2.example.net  (Domain 9/94 malicious)  reached by 10.68.144.121  <- check these devices
Added to the feed: 1  clean: 1  unknown to VirusTotal: 0  left for another day: 0
"""


def drop(src, action="drop"):
    return INBOUND_DROP.replace(LIGHT, src).replace('Action="drop"', f'Action="{action}"')


# Eight entries: three drops from two External sources and one reject from the first, one
# Threat Prevention row, three accepts.
CAPTURE = [drop(HEAVY), drop(HEAVY), drop(LIGHT), drop(HEAVY, "reject"), INBOUND_PREVENT,
           OUTBOUND_DOMAIN, OUTBOUND_IP_ONLY, INBOUND_DROP.replace('Action="drop"', 'Action="accept"')]


def entries(*lines):
    return [spark_logs.parse_entry(line) for line in lines]


def lookup_errors(count, code="ServiceUnavailable", status=503):
    """The lines vt_check.run prints when VirusTotal fails `count` lookups in a row."""
    names = [f"host{i}.example.net" for i in range(count)]
    fake = FakeVT({f"/domains/{name}": vt_error(status, code) for name in names})
    lines = []
    with tempfile.TemporaryDirectory() as tmp:
        feed = Path(tmp, "feed.csv")
        feed.write_text(HEADER)
        vt_check.run(names, feed, fake, delay=0, sleep=lambda seconds: None, out=lines.append)
    return lines


def check_output(responses):
    """What `spark_logs.py --check` prints for the daily run's $run_log, against a VirusTotal that
    answers `responses`: one outbound name and one inbound source to look up. A crash adds its
    traceback after the output, as the script's 2>&1 does."""
    out = io.StringIO()
    with tempfile.TemporaryDirectory() as tmp:
        write_capture(tmp, date(2026, 10, 20), [OUTBOUND_URL] + [INBOUND_DROP] * 5)
        feed = Path(tmp, "feed.csv")
        feed.write_text(HEADER)
        with patch.object(vt_check, "make_fetch", return_value=FakeVT(responses)), \
                patch.dict(os.environ, cli_env("k"), clear=True), contextlib.redirect_stdout(out):
            try:
                spark_logs.main(["--dir", tmp, "--check", "--today", "2026-10-20", "--feed", str(feed), "--delay", "0"])
            except Exception:
                out.write(traceback.format_exc())
    return out.getvalue()


GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.com",
           "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.com"}


def git(repo, *args, when=None):
    env = dict(GIT_ENV)
    if when:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = when
    return subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True, text=True).stdout


def commit_feed(repo, text, when=None):
    """Write the feed in the repository at `repo` and commit it; the new HEAD."""
    Path(repo, "spark-ioc-feed.csv").write_text(text)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "feed", when=when)
    return git(repo, "rev-parse", "HEAD").strip()


def write_capture(directory, day, lines, gz=False):
    path = Path(directory) / f"spark-{day:%Y-%m-%d}.log"
    text = "\n".join(lines) + "\n"
    if gz:
        path = path.with_name(path.name + ".gz")
        path.write_bytes(gzip.compress(text.encode()))
    else:
        path.write_text(text)
    return path


class AttacksTest(unittest.TestCase):
    def setUp(self):
        self.feed = spark_logs.feed_members(FEED)

    def test_attacks_count_external_drops_and_rejects_and_rank_sources(self):
        a = spark_brief.attacks(entries(*CAPTURE), self.feed)

        self.assertEqual((a["dropped"], len(a["sources"])), (4, 2))
        self.assertEqual(a["top"][0], (HEAVY, 3, True))
        self.assertEqual(a["top"][1], (LIGHT, 1, False))
        self.assertEqual(len(a["detections"]), 1)
        self.assertEqual(a["detections"][0]["ProductName"], "Anti Malware")

    def test_only_drops_and_rejects_from_the_external_zone_are_probes(self):
        inside = drop(HEAVY).replace('inzone="External"', 'inzone="Internal"')

        a = spark_brief.attacks(entries(inside, drop(HEAVY, "accept"), drop(LIGHT, "reject")), self.feed)

        self.assertEqual((a["dropped"], list(a["sources"])), (1, [LIGHT]))

    def test_statistics_rows_are_neither_probes_nor_detections(self):
        a = spark_brief.attacks(entries(STATS), self.feed)

        self.assertEqual((a["dropped"], a["sources"], a["detections"], a["top"]), (0, Counter(), [], []))

    def test_system_log_lines_are_counted_apart_and_are_neither_probes_nor_detections(self):
        a = spark_brief.attacks(entries(*SYSTEM_LINES, drop(HEAVY)), self.feed)

        self.assertEqual((a["dropped"], list(a["sources"]), a["detections"], a["system"]), (1, [HEAVY], [], 6))

    def test_the_top_list_is_the_ten_busiest_sources(self):
        lines = [drop(f"198.51.100.{n}") for n in range(1, 13) for _ in range(n)]

        a = spark_brief.attacks(entries(*lines), self.feed)

        self.assertEqual((a["dropped"], len(a["sources"]), len(a["top"])), (78, 12, 10))
        self.assertEqual([ip for ip, _, _ in a["top"]], [f"198.51.100.{n}" for n in range(12, 2, -1)])
        self.assertEqual(a["top"][0], ("198.51.100.12", 12, False))

    def test_a_feed_ip_range_marks_its_members_in_feed(self):
        feed = spark_logs.feed_members(HEADER + "scanner-x,198.51.100.0-198.51.100.255,IP Range,high,medium,AB,Modat\n")

        a = spark_brief.attacks(entries(drop("198.51.100.7"), drop("203.0.113.9")), feed)

        self.assertEqual(sorted(a["top"]), [("198.51.100.7", 1, True), ("203.0.113.9", 1, False)])


class ParseRunLogTest(unittest.TestCase):
    def test_run_log_yields_added_hits_lookups_and_errors(self):
        run = spark_brief.parse_run_log(RUN_LOG)

        self.assertEqual(run["added"], [(NEW, "IP 11/94 malicious")])
        self.assertEqual(run["outbound_hits"], [("c2.example.net", "Domain 9/94 malicious", ["10.68.144.121"])])
        self.assertEqual((run["lookups"], run["errors"]), (2, []))

    def test_an_outbound_hit_lists_every_device(self):
        run = spark_brief.parse_run_log("OUTBOUND HIT  198.51.100.9  (IP 7/94 malicious)  "
                                        "reached by 10.0.0.1, 10.0.0.2  <- check these devices\n")

        self.assertEqual(run["outbound_hits"], [("198.51.100.9", "IP 7/94 malicious", ["10.0.0.1", "10.0.0.2"])])

    def test_lookups_are_added_plus_clean_plus_unknown_to_virustotal(self):
        run = spark_brief.parse_run_log("Added to the feed: 2  clean: 5  unknown to VirusTotal: 3  left for another day: 9\n")

        self.assertEqual(run["lookups"], 10)

    def test_outbound_dry_run_lines_and_other_statuses_are_not_added_rows(self):
        run = spark_brief.parse_run_log(
            "c2.example.net: would-add (Domain 9/94 malicious -> vt-domain-1,c2.example.net,Domain,...)\n"
            "198.51.100.5: not-found (VirusTotal has no record)\n"
            "198.51.100.6: in-feed\n"
            "198.51.100.7: added (IP 7/94 malicious)\n")

        self.assertEqual(run["added"], [("198.51.100.7", "IP 7/94 malicious")])

    def test_error_lines_are_kept_whole(self):
        run = spark_brief.parse_run_log("ok\n2026-10-29 07:31:00 ERROR: git push failed\nERROR VT refused the key\n")

        self.assertEqual(run["errors"], ["2026-10-29 07:31:00 ERROR: git push failed", "ERROR VT refused the key"])

    def test_a_quota_stop_reads_as_errors_in_the_producers_own_words(self):
        log = check_output({"/domains/evil.example": vt_error(500, "InternalError"),
                            "/ip_addresses/109.205.211.205": vt_error(429, "QuotaExceededError")})

        self.assertEqual(spark_brief.parse_run_log(log)["errors"], [
            "evil.example: error (HTTP 500 InternalError)",
            "109.205.211.205: quota (QuotaExceededError - stopping)",
            "VirusTotal quota reached; rerun tomorrow for the rest.",
        ])

    def test_a_crash_reads_as_its_exception_line(self):
        log = check_output({"/domains/evil.example": vt_error(401, "WrongCredentialsError")})

        self.assertIn("Traceback (most recent call last):", log)
        self.assertEqual(spark_brief.parse_run_log(log)["errors"],
                         ["vt_check.VTError: VirusTotal refused the API key: HTTP 401 WrongCredentialsError"])

    def test_a_chained_crash_gives_each_exception_once(self):
        try:
            try:
                raise KeyError("a")
            except KeyError:
                raise RuntimeError("ERROR in b")
        except RuntimeError:
            log = "ok\n" + traceback.format_exc()

        self.assertEqual(spark_brief.parse_run_log(log)["errors"], ["KeyError: 'a'", "RuntimeError: ERROR in b"])

    def test_an_ordinary_run_has_no_errors(self):
        log = check_output({"/domains/evil.example": vt_object("domain", "evil.example", malicious=0)})

        self.assertIn("evil.example: clean", log)
        self.assertIn("109.205.211.205: not-found", log)
        self.assertEqual(spark_brief.parse_run_log(log)["errors"], [])

    def test_an_empty_log_yields_nothing(self):
        self.assertEqual(spark_brief.parse_run_log(""),
                         {"added": [], "outbound_hits": [], "lookups": 0, "errors": []})


class EnteredTest(unittest.TestCase):
    def row(self, comment, name="x", value="198.51.100.1"):
        return f"{name},{value},IP,high,high,AB,{comment}"

    def test_rows_are_counted_by_the_origin_their_comment_names(self):
        rows = [
            self.row("Inbound probe of WAN - Spark syslog 2026-10-29 - VT 11/94 malicious 2026-10-29"),
            self.row("Inbound probe of WAN - Spark syslog 2026-10-29 - VT 9/94 malicious 2026-10-29"),
            self.row("News digest - Qilin 2026-10-29 - VT 9/94 malicious 2026-10-29"),
            self.row("Cousin - sent from Telegram - VT 9/94 malicious 2026-10-29"),
            self.row("sent from Telegram"),
            self.row("added without VirusTotal check 2026-10-29"),
            self.row("INCD alert - VT 9/94 malicious 2026-10-29"),
        ]

        self.assertEqual(spark_brief.entered(rows), {"logs": 2, "news": 1, "hand": 3, "other": 1})

    def test_no_rows_yield_zero_for_every_origin(self):
        self.assertEqual(spark_brief.entered([]), {"logs": 0, "news": 0, "hand": 0, "other": 0})

    def test_the_header_and_malformed_lines_are_not_rows(self):
        rows = [HEADER.strip(), "", "not,a,row", self.row("Spark syslog")]

        self.assertEqual(spark_brief.entered(rows), {"logs": 1, "news": 0, "hand": 0, "other": 0})


class NextRecheckTest(unittest.TestCase):
    TODAY = date.fromisoformat("2026-10-19")

    def test_next_recheck_is_the_earliest_due_date(self):
        feed = (HEADER
                + f"vt-ip-1,203.0.113.7,IP,medium,high,AB,VT 6/86 malicious {aged(50)}\n"
                + f"vt-domain-1,evil.com,Domain,high,high,AB,APT28 - VT 12/93 malicious {aged(100)}\n")

        self.assertEqual(spark_brief.next_recheck(feed, self.TODAY), self.TODAY + timedelta(days=10))

    def test_a_feed_without_dated_rows_has_no_next_recheck(self):
        feed = HEADER + "x,198.51.100.1,IP,high,high,AB,Modat\n" + f"h,{'a' * 64},SHA256,high,high,AV,VT 60/65 malicious {aged(500)}\n"

        self.assertIsNone(spark_brief.next_recheck(feed, self.TODAY))
        self.assertIsNone(spark_brief.next_recheck("", self.TODAY))

    def test_rows_already_overdue_are_due_today(self):
        feed = HEADER + f"vt-ip-1,203.0.113.7,IP,medium,high,AB,VT 6/86 malicious {aged(90)}\n"

        self.assertEqual(spark_brief.next_recheck(feed, self.TODAY), self.TODAY)

    def test_comments_and_short_lines_are_skipped(self):
        feed = HEADER + f"# VT 6/86 malicious {aged(90)}\nshort,line\n" + f"x,1.2.3.4,IP,high,high,AB,VT 6/86 malicious {aged(40)}\n"

        self.assertEqual(spark_brief.next_recheck(feed, self.TODAY), self.TODAY + timedelta(days=20))


def sample_attack(top=(), sources=0, dropped=0, detections=()):
    return {"dropped": dropped, "sources": Counter({f"198.51.{i // 256}.{i % 256}": 1 for i in range(sources)}),
            "detections": list(detections), "top": list(top)}


class RenderTest(unittest.TestCase):
    def sample(self):
        a = spark_brief.attacks(entries(*CAPTURE), spark_logs.feed_members(FEED))
        return a, spark_brief.parse_run_log(RUN_LOG)

    def test_render_matches_the_approved_layout(self):
        a, run = self.sample()

        text = spark_brief.render(DAY, a, run, {"logs": 1, "news": 0, "hand": 0}, Counter({NEW: 20}), date(2026, 12, 18))

        self.assertEqual(text.splitlines()[0], "Spark brief — Wed 2026-10-28")
        self.assertIn("Probes dropped: 4 from 2 sources · TP detections: 1 · Sent to block: 1 · Outbound hits: 1", text)
        self.assertIn("  47.79.34.208     VT 11/94   probed 20×   →  added", text)
        self.assertIn("10.68.144.121 reached c2.example.net (VT 9/94)", text)
        self.assertIn("INDICATORS ENTERED: 1 from the Spark's logs · 0 from news · 0 by hand", text)
        self.assertIn("Lookups: 2 of 500 · next re-check 2026-12-18 · no errors", text)

    def test_a_full_brief_reads_like_the_approved_example(self):
        detections = entries(INBOUND_PREVENT, INBOUND_PREVENT.replace("Anti Malware", "IPS"))
        attack = sample_attack(top=[(HEAVY, 312, True), (LIGHT, 9, False)], sources=3912, dropped=41207,
                               detections=detections)
        run = {"added": [(NEW, "IP 11/94 malicious")], "lookups": 45, "errors": [],
               "outbound_hits": [("c2.example.net", "Domain 9/94 malicious", ["10.68.144.121"])]}

        text = spark_brief.render(DAY, attack, run, {"logs": 3, "news": 5, "hand": 0, "other": 0},
                                  Counter({NEW: 20}), date(2026, 12, 18))

        self.assertEqual(text, "\n".join([
            "Spark brief — Wed 2026-10-28",
            "Probes dropped: 41,207 from 3,912 sources · TP detections: 2 · Sent to block: 1 · Outbound hits: 1",
            "",
            "SENT TO BLOCK (passed the firewall, VirusTotal flags them)",
            "  47.79.34.208     VT 11/94   probed 20×   →  added",
            "OUTBOUND HIT — look at this device",
            "  10.68.144.121 reached c2.example.net (VT 9/94)",
            "THREAT PREVENTION",
            "  Anti-Malware: 1 ·  IPS: 1",
            "TOP PROBING SOURCES (all dropped)",
            "  93.152.221.36   312×  (in feed)",
            "  109.205.211.205   9×",
            "  … 3,910 more",
            "INDICATORS ENTERED: 3 from the Spark's logs · 5 from news · 0 by hand",
            "Lookups: 45 of 500 · next re-check 2026-12-18 · no errors",
        ]))

    def test_system_log_lines_get_one_line_above_the_footer(self):
        a, run = self.sample()

        text = spark_brief.render(DAY, dict(a, system=6), run, {"logs": 1, "news": 0, "hand": 0}, Counter(), None)

        self.assertEqual(text.splitlines()[-2:], ["System log: 6 lines", "Lookups: 2 of 500 · no errors"])
        self.assertNotIn("System log", spark_brief.render(DAY, a, run, {}, Counter(), None))

    def test_empty_sections_are_left_out_but_the_brief_is_still_sent(self):
        attack = spark_brief.attacks([], spark_logs.feed_members(FEED))
        run = spark_brief.parse_run_log("")

        text = spark_brief.render(DAY, attack, run, spark_brief.entered([]), Counter(), None)

        self.assertEqual(text, "\n".join([
            "Spark brief — Wed 2026-10-28",
            "Probes dropped: 0 from 0 sources · TP detections: 0 · Sent to block: 0 · Outbound hits: 0",
            "",
            "Lookups: 0 of 500 · no errors",
        ]))
        for header in ("SENT TO BLOCK", "OUTBOUND HIT", "THREAT PREVENTION", "TOP PROBING SOURCES", "INDICATORS ENTERED"):
            self.assertNotIn(header, text)

    def test_each_section_appears_only_when_it_has_something(self):
        a, run = self.sample()
        quiet_run = dict(run, added=[], outbound_hits=[])

        text = spark_brief.render(DAY, a, quiet_run, {"logs": 0, "news": 0, "hand": 0}, Counter(), None)

        self.assertNotIn("SENT TO BLOCK", text)
        self.assertNotIn("OUTBOUND HIT —", text)
        self.assertIn("THREAT PREVENTION\n  Anti-Malware: 1\n", text)
        self.assertIn("TOP PROBING SOURCES (all dropped)\n  93.152.221.36   3×  (in feed)\n  109.205.211.205 1×\n", text)
        self.assertNotIn("more", text)
        self.assertNotIn("INDICATORS ENTERED", text)

    def test_every_device_that_reached_a_hit_gets_a_line(self):
        run = dict(spark_brief.parse_run_log(""), outbound_hits=[("198.51.100.9", "IP 7/94 malicious", ["10.0.0.1", "10.0.0.2"])])

        text = spark_brief.render(DAY, sample_attack(), run, {}, Counter(), None)

        self.assertIn("OUTBOUND HIT — look at this device\n  10.0.0.1 reached 198.51.100.9 (VT 7/94)\n"
                      "  10.0.0.2 reached 198.51.100.9 (VT 7/94)\n", text)
        self.assertIn("Outbound hits: 1", text)

    def test_a_source_that_was_only_accepted_has_no_probe_count(self):
        run = dict(spark_brief.parse_run_log(RUN_LOG))

        text = spark_brief.render(DAY, sample_attack(), run, {}, Counter(), None)

        self.assertIn("\n  47.79.34.208     VT 11/94   →  added\n", text)

    def test_one_source_is_not_plural(self):
        text = spark_brief.render(DAY, sample_attack(sources=1, dropped=7), spark_brief.parse_run_log(""), {}, Counter(), None)

        self.assertIn("Probes dropped: 7 from 1 source · ", text)

    def test_errors_are_listed_and_counted_in_the_footer(self):
        run = spark_brief.parse_run_log("2026-10-29 07:31:00 ERROR: git push failed\nERROR: VT refused the key\n")

        text = spark_brief.render(DAY, sample_attack(), run, {}, Counter(), date(2026, 12, 18))

        self.assertIn("ERRORS\n  2026-10-29 07:31:00 ERROR: git push failed\n  ERROR: VT refused the key\n", text)
        self.assertTrue(text.endswith("Lookups: 0 of 500 · next re-check 2026-12-18 · 2 errors"), text)

    def errors_section(self, lines):
        text = spark_brief.render(DAY, sample_attack(), spark_brief.parse_run_log("\n".join(lines)), {}, Counter(), None)
        return text.split("ERRORS\n")[1].rsplit("\n", 1)[0].splitlines(), text

    def test_a_virustotal_outage_stays_one_message(self):
        lines = lookup_errors(400)
        self.assertEqual(lines[0], "host0.example.net: error (HTTP 503 ServiceUnavailable)")

        section, text = self.errors_section(lines)

        self.assertEqual(section, ["  400 lookups: error (HTTP 503 ServiceUnavailable)"])
        self.assertTrue(text.endswith("· 400 errors"), "the footer still counts every failure")
        self.assertLess(len(text), telegram_api.MESSAGE_LIMIT)

    def test_a_single_lookup_error_keeps_its_original_line(self):
        section, _ = self.errors_section(lookup_errors(1))

        self.assertEqual(section, ["  host0.example.net: error (HTTP 503 ServiceUnavailable)"])

    def test_lookup_errors_merge_by_status_and_detail_at_the_place_of_the_first(self):
        mixed = ["ERROR: git push failed", *lookup_errors(2), "other.example.net: error (HTTP 400 BadRequestError)",
                 "198.51.100.5: quota (QuotaExceededError - stopping)", "VirusTotal quota reached; rerun tomorrow for the rest."]

        section, _ = self.errors_section(mixed)

        self.assertEqual(section, [
            "  ERROR: git push failed",
            "  2 lookups: error (HTTP 503 ServiceUnavailable)",
            "  other.example.net: error (HTTP 400 BadRequestError)",
            "  198.51.100.5: quota (QuotaExceededError - stopping)",
            "  VirusTotal quota reached; rerun tomorrow for the rest.",
        ])

    def test_at_most_five_error_lines_are_shown_and_the_rest_are_counted(self):
        seven = [f"ERROR: failure {n}" for n in range(1, 8)]

        section, text = self.errors_section(seven)

        self.assertEqual(section, [f"  ERROR: failure {n}" for n in range(1, 6)] + ["  … 2 more"])
        self.assertTrue(text.endswith("· 7 errors"), text)

    def test_five_error_lines_are_all_shown(self):
        section, _ = self.errors_section([f"ERROR: failure {n}" for n in range(1, 6)])

        self.assertEqual(section, [f"  ERROR: failure {n}" for n in range(1, 6)])

    def test_rows_from_no_known_origin_are_counted_when_there_are_any(self):
        text = spark_brief.render(DAY, sample_attack(), spark_brief.parse_run_log(""),
                                  {"logs": 0, "news": 0, "hand": 0, "other": 4}, Counter(), None)

        self.assertIn("INDICATORS ENTERED: 0 from the Spark's logs · 0 from news · 0 by hand · 4 other", text)

    def test_the_lookup_quota_is_a_parameter(self):
        text = spark_brief.render(DAY, sample_attack(), spark_brief.parse_run_log(RUN_LOG), {}, Counter(), None, lookups_quota=1000)

        self.assertIn("Lookups: 2 of 1,000", text)


class ComposeTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.feed = self.dir / "spark-ioc-feed.csv"
        self.feed.write_text(FEED)

    def compose(self, rows=(), run_log=RUN_LOG):
        return spark_brief.compose(DAY, self.dir, self.feed, run_log, list(rows), TODAY)

    def test_the_brief_is_built_from_the_capture_the_run_log_and_the_feed(self):
        write_capture(self.dir, DAY, CAPTURE)
        row = f"vt-ip-1,{NEW},IP,medium,high,AB,Inbound probe of WAN - Spark syslog 2026-10-29 - VT 11/94 malicious 2026-10-29"

        text = self.compose([row])

        self.assertEqual(text.splitlines()[0], "Spark brief — Wed 2026-10-28")
        self.assertIn("Probes dropped: 4 from 2 sources · TP detections: 1 · Sent to block: 1 · Outbound hits: 1", text)
        self.assertIn("  93.152.221.36   3×  (in feed)\n", text)
        self.assertIn("INDICATORS ENTERED: 1 from the Spark's logs · 0 from news · 0 by hand\n", text)
        self.assertIn("Lookups: 2 of 500 · next re-check 2026-10-31 · no errors", text)  # the feed's IP: 2026-09-01 + 60 days

    def test_probe_counts_span_the_day_and_the_morning_of_the_run(self):
        write_capture(self.dir, DAY, [drop(NEW), drop(NEW, "reject")])
        write_capture(self.dir, TODAY, [drop(NEW), drop(HEAVY)], gz=True)

        text = self.compose()

        self.assertIn("  47.79.34.208     VT 11/94   probed 3×   →  added", text)
        self.assertIn("Probes dropped: 2 from 1 source", text, "the totals are the day's alone")

    def test_a_missing_capture_still_gives_a_brief(self):
        text = self.compose()

        self.assertIn("Probes dropped: 0 from 0 sources · TP detections: 0 · Sent to block: 1 · Outbound hits: 1", text)
        self.assertNotIn("TOP PROBING SOURCES", text)
        self.assertIn("  47.79.34.208     VT 11/94   →  added", text)

    def test_a_day_without_a_capture_says_so_among_the_errors(self):
        text = self.compose()

        self.assertIn("ERRORS\n  no syslog capture for 2026-10-28\n", text)
        self.assertTrue(text.endswith("· 1 error"), text)

    def test_a_day_with_a_capture_is_not_an_error(self):
        write_capture(self.dir, DAY, CAPTURE, gz=True)

        self.assertNotIn("no syslog capture", self.compose())

    def test_a_quota_morning_shows_its_errors_and_counts_them(self):
        write_capture(self.dir, DAY, CAPTURE)
        run_log = check_output({"/domains/evil.example": vt_error(500, "InternalError"),
                                "/ip_addresses/109.205.211.205": vt_error(429, "QuotaExceededError")})

        text = self.compose(run_log=run_log)

        self.assertIn("ERRORS\n  evil.example: error (HTTP 500 InternalError)\n"
                      "  109.205.211.205: quota (QuotaExceededError - stopping)\n"
                      "  VirusTotal quota reached; rerun tomorrow for the rest.\n", text)
        self.assertTrue(text.endswith("· 3 errors"), text)

    def test_system_log_lines_in_the_capture_change_no_count_and_raise_nothing(self):
        write_capture(self.dir, DAY, SYSTEM_LINES + CAPTURE)

        text = self.compose()

        self.assertIn("Probes dropped: 4 from 2 sources · TP detections: 1 · Sent to block: 1", text)
        self.assertIn("\nSystem log: 6 lines\n", text)
        self.assertTrue(text.endswith("· no errors"), text)

    def test_yesterdays_gzipped_capture_is_read(self):
        write_capture(self.dir, DAY, CAPTURE, gz=True)

        self.assertIn("Probes dropped: 4 from 2 sources", self.compose())

    def test_blank_lines_in_the_capture_are_skipped(self):
        write_capture(self.dir, DAY, ["", drop(HEAVY), "  ", ""])

        self.assertIn("Probes dropped: 1 from 1 source", self.compose())

    def test_error_lines_in_the_run_log_show_up(self):
        write_capture(self.dir, DAY, CAPTURE)

        text = self.compose(run_log="ERROR: spark_logs.py crashed\n")

        self.assertIn("ERRORS\n  ERROR: spark_logs.py crashed\n", text)
        self.assertTrue(text.endswith("1 error"), text)


class AddedRowsTest(unittest.TestCase):
    """committed_rows(): the feed rows added since the last brief, or in the last 36 hours, read from git."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name)
        self.feed = self.repo / "spark-ioc-feed.csv"
        git(self.repo, "init", "-q", "-b", "main")

    def commit(self, text, when=None):
        return commit_feed(self.repo, text, when=when)

    def row(self, n, comment="Inbound probe of WAN - Spark syslog 2026-10-29"):
        return f"vt-ip-{n},198.51.100.{n},IP,medium,high,AB,{comment}"

    def test_a_directory_without_a_repository_or_commits_has_no_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            feed = Path(tmp, "spark-ioc-feed.csv")
            feed.write_text(HEADER)

            self.assertEqual(spark_brief.committed_rows(feed), [])
        self.assertEqual(spark_brief.committed_rows(self.feed), [])

    def test_a_root_commit_has_no_parent_and_all_its_rows_count(self):
        self.commit(HEADER + self.row(1) + "\n" + self.row(2) + "\n")

        self.assertEqual(spark_brief.committed_rows(self.feed), [self.row(1), self.row(2)])

    def test_rows_older_than_the_window_do_not_count(self):
        self.commit(HEADER + self.row(1) + "\n", when="2026-01-01T07:30:00")
        self.commit(HEADER + self.row(1) + "\n" + self.row(2) + "\n")

        self.assertEqual(spark_brief.committed_rows(self.feed), [self.row(2)])

    def test_without_a_last_brief_every_commit_in_the_window_counts_and_one_not_touching_the_feed_does_not(self):
        self.commit(HEADER + self.row(1) + "\n", when="2026-01-01T07:30:00")
        self.commit(HEADER + self.row(1) + "\n" + self.row(2) + "\n")
        (self.repo / "other.txt").write_text("x\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "other")
        self.commit(HEADER + self.row(1) + "\n" + self.row(2) + "\n" + self.row(3) + "\n")

        self.assertEqual(spark_brief.committed_rows(self.feed), [self.row(2), self.row(3)])

    def test_after_a_delivered_brief_only_the_commits_since_it_count(self):
        self.commit(HEADER + self.row(1) + "\n")
        covered = self.commit(HEADER + self.row(1) + "\n" + self.row(2) + "\n")
        head = self.commit(HEADER + self.row(1) + "\n" + self.row(2) + "\n" + self.row(3) + "\n")

        self.assertEqual(spark_brief.committed_rows(self.feed, since=covered), [self.row(3)])
        self.assertEqual(spark_brief.committed_rows(self.feed, since=head), [])

    def test_the_last_brief_not_the_window_decides_how_far_back_to_look(self):
        covered = self.commit(HEADER, when="2026-01-01T07:30:00")
        self.commit(HEADER + self.row(1) + "\n", when="2026-01-02T07:30:00")  # a day whose brief was refused

        self.assertEqual(spark_brief.committed_rows(self.feed, since=covered), [self.row(1)])
        self.assertEqual(spark_brief.committed_rows(self.feed), [])

    def test_a_last_brief_the_repository_does_not_know_falls_back_to_the_window(self):
        self.commit(HEADER + self.row(1) + "\n", when="2026-01-01T07:30:00")
        self.commit(HEADER + self.row(1) + "\n" + self.row(2) + "\n")

        for unknown in ("0" * 40, "not a commit", "--output=" + str(self.repo / "oops")):
            with self.subTest(since=unknown):
                self.assertEqual(spark_brief.committed_rows(self.feed, since=unknown), [self.row(2)])
        self.assertFalse((self.repo / "oops").exists(), "the marker is never handed to git as an option")

    def test_a_row_rewritten_in_place_is_not_an_entry(self):
        self.commit(HEADER + self.row(1) + "\n", when="2026-01-01T07:30:00")
        rewritten = self.commit(HEADER + self.row(1, "Spark syslog - seen in Spark logs 2026-10-29") + "\n" + self.row(2) + "\n")

        self.assertEqual(spark_brief.committed_rows(self.feed), [self.row(2)])
        self.assertEqual(spark_brief.committed_rows(self.feed, since=git(self.repo, "rev-parse", rewritten + "^").strip()),
                         [self.row(2)])

    def test_the_users_diff_settings_do_not_change_what_is_read(self):
        git(self.repo, "config", "color.ui", "always")
        git(self.repo, "config", "diff.external", "true")
        self.commit(HEADER + self.row(1) + "\n" + self.row(2) + "\n")

        self.assertEqual(spark_brief.committed_rows(self.feed), [self.row(1), self.row(2)])

    def test_head_commit_is_the_commit_the_feed_is_at_or_none_outside_a_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(spark_brief.head_commit(Path(tmp, "spark-ioc-feed.csv")))
        self.assertIsNone(spark_brief.head_commit(self.feed))
        head = self.commit(HEADER)

        self.assertEqual(spark_brief.head_commit(self.feed), head)


class CommandLineTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.feed = self.dir / "spark-ioc-feed.csv"
        self.feed.write_text(FEED)
        self.run_log = self.dir / "run.log"
        self.run_log.write_text(RUN_LOG)
        write_capture(self.dir, DAY, CAPTURE)
        self.args = ["--dir", str(self.dir), "--feed", str(self.feed), "--date", DAY.isoformat(),
                     "--run-log", str(self.run_log)]

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(REPO / "spark_brief.py"), *self.args, *args],
                              capture_output=True, text=True, env=cli_env(), cwd=REPO)

    def test_cli_prints_the_brief_when_no_telegram_token(self):
        for extra in ((), ("--send",)):
            with self.subTest(extra=extra):
                proc = self.run_cli(*extra)

                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertTrue(proc.stdout.startswith("Spark brief — Wed 2026-10-28\n"), proc.stdout)
                self.assertIn("Probes dropped: 4 from 2 sources", proc.stdout)
                self.assertIn("Sent to block: 1", proc.stdout)

    def test_cli_without_a_run_log_still_prints_a_brief(self):
        self.args = [a for a in self.args if a not in ("--run-log", str(self.run_log))]

        proc = self.run_cli()

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Sent to block: 0", proc.stdout)

    def test_cli_defaults_to_yesterdays_capture(self):
        self.args = [a for a in self.args if a not in ("--date", DAY.isoformat())]
        write_capture(self.dir, date.today() - timedelta(days=1), [drop(HEAVY)])

        proc = self.run_cli()

        self.assertIn(f"Spark brief — {date.today() - timedelta(days=1):%a %Y-%m-%d}\n", proc.stdout)
        self.assertIn("Probes dropped: 1 from 1 source", proc.stdout)


class SendTest(unittest.TestCase):
    """--send: the brief to Telegram, then an attacker-context note per indicator sent to block."""

    MISSING = object()

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        git(self.dir, "init", "-q", "-b", "main")
        self.head = commit_feed(self.dir, FEED)
        (self.dir / "run.log").write_text(RUN_LOG + "198.51.100.9: added (IP 7/94 malicious)\n")
        write_capture(self.dir, DAY, CAPTURE)
        self.marker = self.dir / "last-brief.json"
        self.sent, self.notes = [], []
        self.refuse = lambda text: False

    def http(self, url, data=None, headers=None, timeout=60):
        if self.refuse(data["text"]):
            return 400, {"ok": False, "description": "Bad Request: chat not found"}
        self.sent.append(data["text"])
        return 200, {"ok": True, "result": {"message_id": len(self.sent)}}

    def attacker_context(self):
        module = types.ModuleType("attacker_context")

        def note(indicator, capture_dir, today, **kwargs):
            self.notes.append((indicator, Path(capture_dir), today))
            return f"note on {indicator}"

        module.note = note
        return module

    def main(self, telegram=True, context=None, send=True):
        argv = ["--dir", str(self.dir), "--feed", str(self.dir / "spark-ioc-feed.csv"), "--date", DAY.isoformat(),
                "--run-log", str(self.dir / "run.log")] + (["--send"] if send else [])
        bot = telegram_api.Telegram("T", 1, http=self.http) if telegram else None
        module = None if context is self.MISSING else context or self.attacker_context()
        out, err = io.StringIO(), io.StringIO()
        with patch("telegram_api.from_keychain", return_value=bot), \
                patch.dict(sys.modules, {"attacker_context": module}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = spark_brief.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_the_brief_goes_out_first_then_one_note_per_indicator_sent_to_block(self):
        code, out, err = self.main()

        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.sent), 3)
        self.assertTrue(self.sent[0].startswith("Spark brief — Wed 2026-10-28\n"))
        self.assertEqual(self.sent[1:], ["note on 47.79.34.208", "note on 198.51.100.9"])
        self.assertEqual(self.notes, [(NEW, self.dir, "2026-10-28"), ("198.51.100.9", self.dir, "2026-10-28")])

    def test_a_chat_id_that_is_not_a_number_prints_the_brief_and_never_its_value(self):
        stored = {"TELEGRAM_BOT_TOKEN": "T", "TELEGRAM_CHAT_ID": "abc-123-secret"}
        argv = ["--dir", str(self.dir), "--feed", str(self.dir / "spark-ioc-feed.csv"), "--date", DAY.isoformat(),
                "--run-log", str(self.dir / "run.log"), "--send"]
        out, err = io.StringIO(), io.StringIO()
        with patch("keychain.item", side_effect=lambda account, *a, **k: stored.get(account, "")), \
                patch.dict(sys.modules, {"attacker_context": self.attacker_context()}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = spark_brief.main(argv)

        self.assertEqual(code, 1, "the brief did not go out")
        self.assertIn("TELEGRAM_CHAT_ID is not a number", err.getvalue())
        self.assertNotIn("abc-123-secret", out.getvalue() + err.getvalue())
        self.assertTrue(out.getvalue().startswith("Spark brief — Wed 2026-10-28\n"))
        self.assertEqual((self.sent, self.notes), ([], []))
        self.assertFalse(self.marker.exists())

    def test_a_sent_brief_leaves_one_line_in_the_log_and_is_not_printed(self):
        code, out, err = self.main()

        self.assertEqual(out, "Brief sent to Telegram\n")

    def test_without_a_token_the_brief_is_printed_and_no_note_is_made(self):
        code, out, err = self.main(telegram=False)

        self.assertEqual(code, 0, err)
        self.assertTrue(out.startswith("Spark brief — Wed 2026-10-28\n"))
        self.assertEqual((self.sent, self.notes), ([], []))

    def test_when_telegram_refuses_the_brief_it_is_printed_and_the_exit_status_says_so(self):
        self.refuse = lambda text: text.startswith("Spark brief")

        code, out, err = self.main()

        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("Spark brief — Wed 2026-10-28\n"), "the brief must reach the log")
        self.assertIn("chat not found", err)
        self.assertEqual((self.sent, self.notes), ([], []))

    def test_a_morning_with_nothing_sent_to_block_sends_the_brief_alone(self):
        (self.dir / "run.log").write_text("Added to the feed: 0  clean: 3  unknown to VirusTotal: 0  left for another day: 0\n")

        code, out, err = self.main()

        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.notes, [])

    def test_a_note_that_comes_back_empty_sends_nothing(self):
        context = types.ModuleType("attacker_context")
        context.note = lambda *args, **kwargs: ""

        code, out, err = self.main(context=context)

        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.sent), 1)

    def test_a_note_that_cannot_be_sent_does_not_stop_the_next_and_exits_2_because_the_brief_went_out(self):
        self.refuse = lambda text: text == "note on 47.79.34.208"

        code, out, err = self.main()

        self.assertEqual(code, 2)
        self.assertIn("47.79.34.208", err)
        self.assertEqual(self.sent[-1], "note on 198.51.100.9")
        self.assertTrue(self.sent[0].startswith("Spark brief"))
        self.assertTrue(self.marker.exists(), "the brief was delivered, whatever happened to the notes")

    def test_a_missing_attacker_context_module_exits_2_after_the_brief_went_out(self):
        code, out, err = self.main(context=self.MISSING)

        self.assertEqual(code, 2)
        self.assertIn("attacker_context", err)
        self.assertEqual(len(self.sent), 1)

    # The marker syslog/last-brief.json: the commit the last delivered brief covered, so that the next
    # one counts the rows committed since and no row is counted in two briefs.
    def test_a_delivered_brief_records_the_commit_it_covered(self):
        self.main()

        marker = json.loads(self.marker.read_text())
        self.assertEqual(marker["commit"], self.head)
        self.assertIsInstance(datetime.fromisoformat(marker["delivered"]), datetime)

    def test_the_next_brief_counts_only_the_rows_added_since_the_last(self):
        self.main()
        first = self.sent[0]
        self.sent.clear()
        commit_feed(self.dir, FEED + "x,198.51.100.77,IP,high,high,AB,Cousin - sent from Telegram - VT 9/94 malicious 2026-10-29\n")

        self.main()

        self.assertIn("INDICATORS ENTERED: 1 from the Spark's logs · 0 from news · 0 by hand\n", first)
        self.assertIn("INDICATORS ENTERED: 0 from the Spark's logs · 0 from news · 1 by hand\n", self.sent[0])

    def test_a_brief_printed_for_want_of_a_token_counts_as_delivered(self):
        self.main(telegram=False)

        self.assertEqual(json.loads(self.marker.read_text())["commit"], self.head)

    def test_a_brief_that_was_only_printed_on_request_does_not(self):
        self.main(send=False)

        self.assertFalse(self.marker.exists())

    def test_a_refused_brief_leaves_the_marker_alone_so_the_next_covers_both_days(self):
        self.marker.write_text('{"commit": "' + "a" * 40 + '", "delivered": "2026-10-27T07:31:00"}\n')
        before = self.marker.read_text()
        self.refuse = lambda text: text.startswith("Spark brief")

        self.main()

        self.assertEqual(self.marker.read_text(), before)

    def test_a_marker_that_is_not_json_is_ignored_and_replaced(self):
        self.marker.write_text("not json")

        code, out, err = self.main()

        self.assertEqual(code, 0, err)
        self.assertIn("INDICATORS ENTERED: 1 from the Spark's logs", self.sent[0], "the 36-hour window stood in")
        self.assertEqual(json.loads(self.marker.read_text())["commit"], self.head)

    def test_a_marker_that_cannot_be_written_is_a_warning_and_the_brief_still_went_out(self):
        self.marker.mkdir()

        code, out, err = self.main()

        self.assertEqual(code, 0)
        self.assertEqual(len(self.sent), 3)
        self.assertIn("last-brief.json", err)


if __name__ == "__main__":
    unittest.main()
