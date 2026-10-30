import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import vt_check

REPO = Path(__file__).resolve().parent.parent
STUBS = REPO / "tests" / "stubs"
KEYCHAIN_LOOKUP = ["security", "find-generic-password", "-s", "spark-ioc-feed", "-a", "VT_API_KEY", "-w"]
HEADER = "# UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT\n"
EXISTING = "test-domain-01,example.com,Domain,high,high,AB,TEST ENTRY\n"
RANGE_ROW = "scanner-x,185.1.2.0-185.1.2.255,IP Range,high,high,AB,scanner network\n"
TODAY = "2026-10-19"
SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def cli_env(env_key=None):
    """A subprocess environment with no VT_API_KEY and a `security` that finds no Keychain item."""
    env = {k: v for k, v in os.environ.items() if k not in ("VT_API_KEY", "REPUTATION_API_KEY")}
    env["PATH"] = f"{STUBS}{os.pathsep}{env.get('PATH', '')}"
    if env_key:
        env["VT_API_KEY"] = env_key
    return env


def keychain_with(key):
    """A subprocess.run stand-in whose Keychain holds `key` (None: no item)."""
    def run(cmd, **kwargs):
        run.calls.append(cmd)
        if key is None:
            return subprocess.CompletedProcess(cmd, 44, stdout="", stderr="The specified item could not be found in the keychain.\n")
        return subprocess.CompletedProcess(cmd, 0, stdout=key + "\n", stderr="")
    run.calls = []
    return run


def aged(days):
    """ISO date `days` days before TODAY."""
    return (date.fromisoformat(TODAY) - timedelta(days=days)).isoformat()


# Rows as vt_check.py writes them, dated relative to TODAY. --recheck looks IPs up
# again after 60 days, domains and URLs after 180, hashes never.
OLD = "vt-domain-e3daa29865,evil.com,Domain,high,high,AB,APT28 - confirmed 2026-03-01\n"  # 232 days
OLD_IP = "vt-ip-7b3f0a9c21,203.0.113.7,IP,medium,high,AB,confirmed 2026-07-15\n"  # 96 days
OLD_URL = "vt-url-5a1d6f0c2e,https://bad.example/x,URL,medium,high,AB,confirmed 2026-02-01\n"  # 260 days
OLD_HASH = f"vt-sha256-9634a68018,{SHA256},SHA256,high,high,AV,confirmed 2026-06-30\n"  # 111 days
RECENT = "vt-domain-ec0f4e8e0a,bad.example.net,Domain,high,high,AB,confirmed 2026-10-01\n"  # 18 days


def vt_object(obj_type, obj_id, malicious, suspicious=0, undetected=20, harmless=60):
    """A VirusTotal API v3 object response, shaped like the real thing."""
    return 200, {
        "data": {
            "id": obj_id,
            "type": obj_type,
            "links": {"self": f"https://www.virustotal.com/api/v3/{obj_type}s/{obj_id}"},
            "attributes": {
                "last_analysis_date": 1760860800,
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "undetected": undetected,
                    "harmless": harmless,
                    "timeout": 0,
                },
                "reputation": -10,
                "tags": [],
                "total_votes": {"harmless": 0, "malicious": 0},
            },
        }
    }


def vt_error(status, code):
    return status, {"error": {"code": code, "message": f"{code} message"}}


class FakeVT:
    """Stands in for the VirusTotal HTTP API: maps API paths to responses."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, path):
        self.calls.append(path)
        return self.responses.get(path, vt_error(404, "NotFoundError"))


class ClassifyTest(unittest.TestCase):
    def test_recognises_and_normalises_each_type(self):
        cases = [
            ("1.2.3.4", ("IP", "1.2.3.4")),
            ("2001:4860:4860::8888", ("IP", "2001:4860:4860::8888")),
            ("Evil.COM.", ("Domain", "evil.com")),
            ("bad.example.net", ("Domain", "bad.example.net")),
            ("https://evil.com/a", ("URL", "https://evil.com/a")),
            ("44D88612FEA8A8F36DE82E1278ABB02F", ("MD5", "44d88612fea8a8f36de82e1278abb02f")),
            ("3395856ce81f2b7382dee72602f798b642f14140", ("SHA1", "3395856ce81f2b7382dee72602f798b642f14140")),
            (
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                ("SHA256", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"),
            ),
        ]
        for raw, want in cases:
            with self.subTest(raw=raw):
                self.assertEqual(vt_check.classify(raw), want)

    def test_refangs_defanged_indicators(self):
        cases = [
            ("evil[.]com", ("Domain", "evil.com")),
            ("hxxps://evil[.]com/a", ("URL", "https://evil.com/a")),
            ("1.2.3[.]4", ("IP", "1.2.3.4")),
        ]
        for raw, want in cases:
            with self.subTest(raw=raw):
                self.assertEqual(vt_check.classify(raw), want)

    def test_rejects_what_cannot_be_checked_or_written(self):
        for raw in [
            "10.0.0.1",  # private address
            "127.0.0.1",
            "224.0.0.252",  # multicast (LLMNR), a vendor list artefact
            "255.255.255.255",  # broadcast
            "169.254.1.1",  # link-local
            "1.2.3.4-1.2.3.9",  # range
            "not an indicator",
            "localhost",  # no dot
            "https://evil.com/a,b",  # comma would break the CSV row
            "44d88612fea8a8f36de82e1278abb02",  # 31 hex chars
        ]:
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    vt_check.classify(raw)


class ApiPathTest(unittest.TestCase):
    def test_paths_per_type(self):
        cases = [
            (("IP", "1.2.3.4"), "/ip_addresses/1.2.3.4"),
            (("Domain", "evil.com"), "/domains/evil.com"),
            (("MD5", "44d88612fea8a8f36de82e1278abb02f"), "/files/44d88612fea8a8f36de82e1278abb02f"),
            (("URL", "https://evil.com/a"), "/urls/aHR0cHM6Ly9ldmlsLmNvbS9h"),
        ]
        for args, want in cases:
            with self.subTest(args=args):
                self.assertEqual(vt_check.api_path(*args), want)


class FeedMembersTest(unittest.TestCase):
    def test_values_case_insensitively_addresses_inside_ranges_and_rows_added_later(self):
        members = vt_check.feed_members(HEADER + EXISTING + RANGE_ROW)

        self.assertIn("EXAMPLE.com", members)
        self.assertIn("185.1.2.255", members)
        self.assertNotIn("185.1.3.1", members)
        self.assertNotIn("evil.com", members)
        members.add("Evil.com")
        self.assertIn("evil.com", members)


class RunTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.feed = Path(tmp.name) / "feed.csv"
        self.feed.write_text(HEADER + EXISTING)
        self.sleeps = []

    def run_check(self, indicators, fake, **kwargs):
        return vt_check.run(
            indicators,
            self.feed,
            fake,
            sleep=self.sleeps.append,
            today=TODAY,
            out=lambda *a: None,
            **kwargs,
        )

    def statuses(self, results):
        return {r.indicator: r.status for r in results}

    def test_malicious_indicator_is_appended_as_a_feed_row(self):
        fake = FakeVT({"/domains/evil.com": vt_object("domain", "evil.com", malicious=12, suspicious=1)})

        results = self.run_check(["evil.com"], fake)

        self.assertEqual(self.statuses(results), {"evil.com": "added"})
        self.assertEqual(
            self.feed.read_text(),
            HEADER + EXISTING
            + "vt-domain-e3daa29865,evil.com,Domain,high,high,AB,confirmed 2026-10-19\n",
        )

    def test_an_address_inside_a_feed_ip_range_is_in_feed_and_not_looked_up(self):
        self.feed.write_text(HEADER + EXISTING + RANGE_ROW)
        fake = FakeVT({"/ip_addresses/185.1.2.7": vt_object("ip_address", "185.1.2.7", malicious=9)})

        results = self.run_check(["185.1.2.7", "185.1.3.7"], fake)

        self.assertEqual(self.statuses(results), {"185.1.2.7": "in-feed", "185.1.3.7": "not-found"})
        self.assertEqual(fake.calls, ["/ip_addresses/185.1.3.7"])

    def test_label_goes_into_comment_without_commas(self):
        fake = FakeVT({"/domains/evil.com": vt_object("domain", "evil.com", malicious=12, suspicious=1)})

        self.run_check([("evil.com", "APT28, via CISA AA26-201A")], fake)

        row = self.feed.read_text().splitlines()[2]
        self.assertEqual(
            row,
            "vt-domain-e3daa29865,evil.com,Domain,high,high,AB,"
            "APT28 via CISA AA26-201A - confirmed 2026-10-19",
        )

    def test_hashes_go_to_antivirus_and_ips_to_antibot(self):
        sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        fake = FakeVT({
            f"/files/{sha256}": vt_object("file", sha256, malicious=60, undetected=5, harmless=0),
            "/ip_addresses/8.8.4.4": vt_object("ip_address", "8.8.4.4", malicious=5),
        })

        self.run_check([sha256, "8.8.4.4"], fake)

        added = self.feed.read_text().splitlines()[2:]
        self.assertEqual(added, [
            f"vt-sha256-9634a68018,{sha256},SHA256,high,high,AV,confirmed 2026-10-19",
            "vt-ip-2d2878d281,8.8.4.4,IP,medium,high,AB,confirmed 2026-10-19",
        ])

    def test_ips_need_five_engines_and_other_types_three(self):
        fake = FakeVT({
            "/ip_addresses/8.8.4.4": vt_object("ip_address", "8.8.4.4", malicious=4),
            "/ip_addresses/9.9.9.9": vt_object("ip_address", "9.9.9.9", malicious=5),
            "/domains/evil.com": vt_object("domain", "evil.com", malicious=3),
        })

        results = self.run_check(["8.8.4.4", "9.9.9.9", "evil.com"], fake)

        self.assertEqual(
            self.statuses(results),
            {"8.8.4.4": "clean", "9.9.9.9": "added", "evil.com": "added"},
        )

    def test_min_malicious_overrides_the_per_type_defaults(self):
        fake = FakeVT({"/ip_addresses/8.8.4.4": vt_object("ip_address", "8.8.4.4", malicious=4)})

        results = self.run_check(["8.8.4.4"], fake, min_malicious=4)

        self.assertEqual(self.statuses(results), {"8.8.4.4": "added"})

    def test_confidence_follows_detection_count(self):
        cases = [(3, "low"), (4, "low"), (5, "medium"), (9, "medium"), (10, "high")]
        for malicious, want in cases:
            with self.subTest(malicious=malicious):
                self.feed.write_text(HEADER)
                fake = FakeVT({"/domains/evil.com": vt_object("domain", "evil.com", malicious=malicious)})

                self.run_check(["evil.com"], fake)

                row = self.feed.read_text().splitlines()[1].split(",")
                self.assertEqual(row[3], want)

    def test_indicator_below_threshold_is_not_added(self):
        fake = FakeVT({"/domains/evil.com": vt_object("domain", "evil.com", malicious=2)})

        results = self.run_check(["evil.com"], fake, min_malicious=3)

        self.assertEqual(self.statuses(results), {"evil.com": "clean"})
        self.assertEqual(self.feed.read_text(), HEADER + EXISTING)

    def test_threshold_is_configurable(self):
        fake = FakeVT({"/domains/evil.com": vt_object("domain", "evil.com", malicious=2)})

        results = self.run_check(["evil.com"], fake, min_malicious=1)

        self.assertEqual(self.statuses(results), {"evil.com": "added"})

    def test_unknown_to_virustotal_is_not_added(self):
        results = self.run_check(["evil.com"], FakeVT({}))

        self.assertEqual(self.statuses(results), {"evil.com": "not-found"})
        self.assertEqual(self.feed.read_text(), HEADER + EXISTING)

    def test_indicator_already_in_feed_is_skipped_without_an_api_call(self):
        fake = FakeVT({})

        results = self.run_check(["EXAMPLE.com"], fake)

        self.assertEqual(self.statuses(results), {"EXAMPLE.com": "in-feed"})
        self.assertEqual(fake.calls, [])

    def test_duplicate_input_is_checked_once(self):
        fake = FakeVT({"/domains/evil.com": vt_object("domain", "evil.com", malicious=12)})

        self.run_check(["evil.com", "evil[.]com", "Evil.com"], fake)

        self.assertEqual(fake.calls, ["/domains/evil.com"])
        self.assertEqual(self.feed.read_text().count("evil.com"), 1)

    def test_invalid_indicator_is_reported_and_skipped(self):
        fake = FakeVT({})

        results = self.run_check(["1.2.3.4-1.2.3.9"], fake)

        self.assertEqual(self.statuses(results), {"1.2.3.4-1.2.3.9": "invalid"})
        self.assertEqual(fake.calls, [])

    def test_dry_run_leaves_feed_untouched(self):
        fake = FakeVT({"/domains/evil.com": vt_object("domain", "evil.com", malicious=12)})

        results = self.run_check(["evil.com"], fake, dry_run=True)

        self.assertEqual(self.statuses(results), {"evil.com": "would-add"})
        self.assertEqual(self.feed.read_text(), HEADER + EXISTING)

    def test_waits_between_api_calls_only(self):
        fake = FakeVT({
            "/domains/evil.com": vt_object("domain", "evil.com", malicious=12),
            "/domains/bad.example.net": vt_object("domain", "bad.example.net", malicious=0),
        })

        self.run_check(["evil.com", "example.com", "junk", "bad.example.net", "8.8.4.4"], fake, delay=15)

        # 3 API calls (example.com is in the feed, junk is invalid) -> 2 waits
        self.assertEqual(len(fake.calls), 3)
        self.assertEqual(self.sleeps, [15, 15])

    def test_quota_exceeded_stops_but_keeps_rows_already_added(self):
        fake = FakeVT({
            "/domains/evil.com": vt_object("domain", "evil.com", malicious=12),
            "/domains/bad.example.net": vt_error(429, "QuotaExceededError"),
        })

        results = self.run_check(["evil.com", "bad.example.net", "8.8.4.4"], fake)

        self.assertEqual(
            self.statuses(results),
            {"evil.com": "added", "bad.example.net": "quota", "8.8.4.4": "unchecked"},
        )
        self.assertNotIn("/ip_addresses/8.8.4.4", fake.calls)
        self.assertIn("evil.com", self.feed.read_text())
        self.assertEqual(fake.calls.count("/domains/bad.example.net"), 2, "a second 429 is the quota stop")
        self.assertIn(61, self.sleeps)

    def test_a_429_waits_a_minute_and_tries_once_more(self):
        # One lookup from elsewhere (a note, /who) went over the free key's four a minute.
        replies = {"/domains/evil.com": [vt_error(429, "QuotaExceededError"),
                                         vt_object("domain", "evil.com", malicious=12)]}
        calls = []

        def fetch(path):
            calls.append(path)
            return replies[path].pop(0) if replies.get(path) else vt_error(404, "NotFoundError")

        results = self.run_check(["evil.com", "bad.example.net"], fetch, delay=15)

        self.assertEqual(self.statuses(results), {"evil.com": "added", "bad.example.net": "not-found"})
        self.assertEqual(calls, ["/domains/evil.com", "/domains/evil.com", "/domains/bad.example.net"])
        self.assertEqual(self.sleeps, [61, 15])

    def test_bad_api_key_raises(self):
        fake = FakeVT({"/domains/evil.com": vt_error(401, "WrongCredentialsError")})

        with self.assertRaises(vt_check.VTError):
            self.run_check(["evil.com", "bad.example.net"], fake)

        self.assertEqual(fake.calls, ["/domains/evil.com"])
        self.assertEqual(self.feed.read_text(), HEADER + EXISTING)

    def test_other_api_error_skips_that_indicator_only(self):
        fake = FakeVT({
            "/domains/evil.com": vt_error(400, "BadRequestError"),
            "/domains/bad.example.net": vt_object("domain", "bad.example.net", malicious=12),
        })

        results = self.run_check(["evil.com", "bad.example.net"], fake)

        self.assertEqual(self.statuses(results), {"evil.com": "error", "bad.example.net": "added"})

    def test_appends_on_a_new_line_when_feed_lacks_trailing_newline(self):
        self.feed.write_text(HEADER + EXISTING.rstrip("\n"))
        fake = FakeVT({"/domains/evil.com": vt_object("domain", "evil.com", malicious=12)})

        self.run_check(["evil.com"], fake)

        lines = self.feed.read_text().splitlines()
        self.assertEqual(lines[1], EXISTING.rstrip("\n"))
        self.assertTrue(lines[2].startswith("vt-domain-e3daa29865,evil.com,"))


class RecheckTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.feed = Path(tmp.name) / "feed.csv"
        self.feed.write_text(HEADER + EXISTING + OLD)
        self.sleeps = []

    def recheck(self, fake, **kwargs):
        return vt_check.recheck(
            self.feed,
            fake,
            sleep=self.sleeps.append,
            today=TODAY,
            out=lambda *a: None,
            **kwargs,
        )

    def statuses(self, results):
        return {r.indicator: r.status for r in results}

    def test_old_row_still_malicious_gets_a_fresh_ratio_and_date(self):
        fake = FakeVT({"/domains/evil.com": vt_object("domain", "evil.com", malicious=11)})

        results = self.recheck(fake)

        self.assertEqual(self.statuses(results)["evil.com"], "refreshed")
        self.assertEqual(
            self.feed.read_text(),
            HEADER + EXISTING
            + "vt-domain-e3daa29865,evil.com,Domain,high,high,AB,APT28 - confirmed 2026-10-19\n",
        )

    def test_confidence_follows_the_new_detection_count(self):
        fake = FakeVT({"/domains/evil.com": vt_object("domain", "evil.com", malicious=4)})

        self.recheck(fake)

        row = self.feed.read_text().splitlines()[2].split(",")
        self.assertEqual(row[3], "low")

    def test_old_row_no_longer_malicious_is_removed(self):
        fake = FakeVT({"/domains/evil.com": vt_object("domain", "evil.com", malicious=2)})

        results = self.recheck(fake)

        self.assertEqual(self.statuses(results)["evil.com"], "removed")
        self.assertEqual(self.feed.read_text(), HEADER + EXISTING)

    def test_old_ip_row_below_five_engines_is_removed(self):
        self.feed.write_text(HEADER + OLD_IP)
        fake = FakeVT({"/ip_addresses/203.0.113.7": vt_object("ip_address", "203.0.113.7", malicious=4)})

        results = self.recheck(fake)

        self.assertEqual(self.statuses(results)["203.0.113.7"], "removed")
        self.assertEqual(self.feed.read_text(), HEADER)

    def test_recent_and_hand_written_rows_are_kept_without_a_lookup(self):
        self.feed.write_text(HEADER + EXISTING + RECENT + OLD)
        fake = FakeVT({"/domains/evil.com": vt_object("domain", "evil.com", malicious=11)})

        results = self.recheck(fake)

        self.assertEqual(fake.calls, ["/domains/evil.com"])
        self.assertEqual(
            self.statuses(results),
            {"example.com": "kept", "bad.example.net": "kept", "evil.com": "refreshed"},
        )
        self.assertEqual(self.feed.read_text().splitlines()[:3], (HEADER + EXISTING + RECENT).splitlines())

    def test_each_type_has_its_own_default_age(self):
        def row(name, value, ioc_type, days):
            return f"{name},{value},{ioc_type},high,high,AB,confirmed {aged(days)}\n"

        self.feed.write_text(
            HEADER
            + row("ip-due", "203.0.113.7", "IP", 60)
            + row("ip-fresh", "203.0.113.8", "IP", 59)
            + row("domain-due", "evil.com", "Domain", 180)
            + row("domain-fresh", "bad.example.net", "Domain", 179)
            + row("url-due", "https://bad.example/x", "URL", 180)
            + row("hash-never", SHA256, "SHA256", 400)
        )
        fake = FakeVT({
            "/ip_addresses/203.0.113.7": vt_object("ip_address", "203.0.113.7", malicious=9),
            "/domains/evil.com": vt_object("domain", "evil.com", malicious=9),
            vt_check.api_path("URL", "https://bad.example/x"): vt_object("url", "x", malicious=9),
        })

        results = self.recheck(fake)

        self.assertEqual(fake.calls, [
            "/ip_addresses/203.0.113.7",
            "/domains/evil.com",
            vt_check.api_path("URL", "https://bad.example/x"),
        ])
        self.assertEqual(self.statuses(results), {
            "203.0.113.7": "refreshed",
            "203.0.113.8": "kept",
            "evil.com": "refreshed",
            "bad.example.net": "kept",
            "https://bad.example/x": "refreshed",
            SHA256: "kept",
        })

    def test_hashes_are_never_rechecked_by_default(self):
        self.feed.write_text(HEADER + OLD_HASH)
        fake = FakeVT({f"/files/{SHA256}": vt_object("file", SHA256, malicious=0)})

        self.recheck(fake)

        self.assertEqual(fake.calls, [])
        self.assertEqual(self.feed.read_text(), HEADER + OLD_HASH)

    def test_max_age_overrides_the_per_type_defaults(self):
        self.feed.write_text(HEADER + RECENT + OLD_HASH)
        fake = FakeVT({
            "/domains/bad.example.net": vt_object("domain", "bad.example.net", malicious=11),
            f"/files/{SHA256}": vt_object("file", SHA256, malicious=60, undetected=5, harmless=0),
        })

        self.recheck(fake, max_age=10)

        self.assertEqual(fake.calls, ["/domains/bad.example.net", f"/files/{SHA256}"])

    def test_threshold_is_configurable(self):
        fake = FakeVT({"/domains/evil.com": vt_object("domain", "evil.com", malicious=2)})

        results = self.recheck(fake, min_malicious=1)

        self.assertEqual(self.statuses(results)["evil.com"], "refreshed")

    def test_rows_keep_their_order_and_the_header_its_bytes(self):
        self.feed.write_text(HEADER + OLD_IP + OLD + EXISTING)
        fake = FakeVT({
            "/ip_addresses/203.0.113.7": vt_object("ip_address", "203.0.113.7", malicious=6),
            "/domains/evil.com": vt_object("domain", "evil.com", malicious=0),
        })

        self.recheck(fake)

        self.assertEqual(self.feed.read_bytes().split(b"\n")[0], HEADER.rstrip("\n").encode())
        self.assertEqual(self.feed.read_text().splitlines(), [
            HEADER.rstrip("\n"),
            "vt-ip-7b3f0a9c21,203.0.113.7,IP,medium,high,AB,confirmed 2026-10-19",
            EXISTING.rstrip("\n"),
        ])

    def test_quota_stop_updates_rows_done_so_far_and_leaves_the_rest_untouched(self):
        self.feed.write_text(HEADER + OLD + OLD_IP + OLD_URL)
        fake = FakeVT({
            "/domains/evil.com": vt_object("domain", "evil.com", malicious=11),
            "/ip_addresses/203.0.113.7": vt_error(429, "QuotaExceededError"),
        })

        results = self.recheck(fake)

        self.assertEqual(
            self.statuses(results),
            {"evil.com": "refreshed", "203.0.113.7": "quota", "https://bad.example/x": "unchecked"},
        )
        self.assertEqual(fake.calls.count("/ip_addresses/203.0.113.7"), 2, "tried once more after a minute")
        self.assertNotIn(vt_check.api_path("URL", "https://bad.example/x"), fake.calls)
        self.assertEqual(
            self.feed.read_text(),
            HEADER
            + "vt-domain-e3daa29865,evil.com,Domain,high,high,AB,APT28 - confirmed 2026-10-19\n"
            + OLD_IP + OLD_URL,
        )

    def test_dry_run_reports_changes_without_writing(self):
        self.feed.write_text(HEADER + OLD + OLD_IP)
        fake = FakeVT({
            "/domains/evil.com": vt_object("domain", "evil.com", malicious=11),
            "/ip_addresses/203.0.113.7": vt_object("ip_address", "203.0.113.7", malicious=1),
        })

        results = self.recheck(fake, dry_run=True)

        self.assertEqual(self.statuses(results), {"evil.com": "would-refresh", "203.0.113.7": "would-remove"})
        self.assertEqual(self.feed.read_text(), HEADER + OLD + OLD_IP)

    def test_waits_between_lookups_only(self):
        self.feed.write_text(HEADER + EXISTING + OLD + RECENT + OLD_IP)
        fake = FakeVT({
            "/domains/evil.com": vt_object("domain", "evil.com", malicious=11),
            "/ip_addresses/203.0.113.7": vt_object("ip_address", "203.0.113.7", malicious=6),
        })

        self.recheck(fake, delay=15)

        self.assertEqual(len(fake.calls), 2)
        self.assertEqual(self.sleeps, [15])

    def test_row_virustotal_no_longer_knows_is_left_alone(self):
        results = self.recheck(FakeVT({}))

        self.assertEqual(self.statuses(results)["evil.com"], "not-found")
        self.assertEqual(self.feed.read_text(), HEADER + EXISTING + OLD)

    def test_bad_api_key_raises_and_leaves_feed_untouched(self):
        fake = FakeVT({"/domains/evil.com": vt_error(401, "WrongCredentialsError")})

        with self.assertRaises(vt_check.VTError):
            self.recheck(fake)

        self.assertEqual(self.feed.read_text(), HEADER + EXISTING + OLD)


    # Rows added with --trusted carry no VirusTotal date; they get their first check 90 days
    # after they were added (hashes never) and become ordinary checked rows if it passes.
    def trusted(self, value, ioc_type, days, name="trusted-x"):
        product = "AV" if ioc_type in ("MD5", "SHA1", "SHA256") else "AB"
        return (f"{name},{value},{ioc_type},high,high,{product},"
                f"MuddyWater - Cyberint export - added unchecked {aged(days)}\n")

    def test_trusted_row_verified_after_90_days_becomes_a_checked_row(self):
        self.feed.write_text(HEADER + self.trusted("157.230.234.35", "IP", 90))
        fake = FakeVT({"/ip_addresses/157.230.234.35": vt_object("ip_address", "157.230.234.35", malicious=7)})

        results = self.recheck(fake)

        self.assertEqual(self.statuses(results)["157.230.234.35"], "verified")
        self.assertEqual(
            self.feed.read_text(),
            HEADER + "trusted-x,157.230.234.35,IP,medium,high,AB,MuddyWater - Cyberint export - confirmed 2026-10-19\n",
        )

    def test_trusted_row_not_flagged_after_90_days_is_removed(self):
        self.feed.write_text(HEADER + EXISTING + self.trusted("c2.example.org", "Domain", 90))
        fake = FakeVT({"/domains/c2.example.org": vt_object("domain", "c2.example.org", malicious=1)})

        results = self.recheck(fake)

        self.assertEqual(self.statuses(results)["c2.example.org"], "removed")
        self.assertEqual(self.feed.read_text(), HEADER + EXISTING)

    def test_younger_trusted_rows_and_trusted_hashes_are_kept_without_a_lookup(self):
        self.feed.write_text(HEADER + self.trusted("157.230.234.35", "IP", 89) + self.trusted(SHA256, "SHA256", 400))
        fake = FakeVT({})

        results = self.recheck(fake)

        self.assertEqual(fake.calls, [])
        self.assertEqual(set(self.statuses(results).values()), {"kept"})

    # An IP that probed this network carries "seen in Spark logs <date>" and is re-verified 180
    # days after its last sighting, however old its VirusTotal check is.
    def seen_ip(self, checked_days, seen_days):
        return (f"vt-ip-7b3f0a9c21,203.0.113.7,IP,medium,high,AB,Inbound probe of WAN - Spark syslog - "
                f"seen in Spark logs {aged(seen_days)} - confirmed {aged(checked_days)}\n")

    def test_an_ip_seen_in_the_logs_waits_180_days_from_its_last_sighting(self):
        self.feed.write_text(HEADER + self.seen_ip(checked_days=70, seen_days=100))
        fake = FakeVT({})

        results = self.recheck(fake)

        self.assertEqual(fake.calls, [])
        self.assertEqual(self.statuses(results)["203.0.113.7"], "kept")

    def test_an_ip_not_seen_for_180_days_is_re_verified_and_keeps_its_sighting_note(self):
        self.feed.write_text(HEADER + self.seen_ip(checked_days=70, seen_days=180))
        fake = FakeVT({"/ip_addresses/203.0.113.7": vt_object("ip_address", "203.0.113.7", malicious=8)})

        results = self.recheck(fake)

        self.assertEqual(self.statuses(results)["203.0.113.7"], "refreshed")
        self.assertEqual(
            self.feed.read_text().splitlines()[1],
            f"vt-ip-7b3f0a9c21,203.0.113.7,IP,medium,high,AB,Inbound probe of WAN - Spark syslog - "
            f"seen in Spark logs {aged(180)} - confirmed 2026-10-19",
        )

    def test_max_age_overrides_the_trusted_and_sighting_clocks(self):
        self.feed.write_text(HEADER + self.trusted("157.230.234.35", "IP", 1) + self.seen_ip(checked_days=1, seen_days=1))
        fake = FakeVT({
            "/ip_addresses/157.230.234.35": vt_object("ip_address", "157.230.234.35", malicious=7),
            "/ip_addresses/203.0.113.7": vt_object("ip_address", "203.0.113.7", malicious=8),
        })

        results = self.recheck(fake, max_age=0)

        self.assertEqual(fake.calls, ["/ip_addresses/157.230.234.35", "/ip_addresses/203.0.113.7"])
        self.assertEqual(self.statuses(results), {"157.230.234.35": "verified", "203.0.113.7": "refreshed"})


class RowDueTest(unittest.TestCase):
    """row_due(): the day a feed row's COMMENT says it comes up for re-verification."""

    def due(self, ioc_type, comment, max_age=None):
        return vt_check.row_due(ioc_type, comment, max_age)

    def test_a_checked_row_is_due_when_its_types_clock_has_run(self):
        self.assertEqual(self.due("IP", f"confirmed {aged(50)}"), date.fromisoformat(aged(50 - 60)))
        self.assertEqual(self.due("Domain", f"APT28 - confirmed {aged(100)}"), date.fromisoformat(aged(100 - 180)))
        self.assertEqual(self.due("URL", f"confirmed {aged(10)}"), date.fromisoformat(aged(10 - 180)))

    def test_a_row_added_without_a_check_is_due_after_90_days(self):
        self.assertEqual(self.due("Domain", f"Qilin - Cyberint export - added unchecked {aged(20)}"),
                         date.fromisoformat(aged(20 - 90)))

    def test_an_ip_seen_in_the_logs_is_not_due_before_180_days_from_the_sighting(self):
        comment = f"Inbound probe of WAN - seen in Spark logs {aged(5)} - confirmed {aged(70)}"

        self.assertEqual(self.due("IP", comment), date.fromisoformat(aged(5 - 180)))

    def test_max_age_replaces_the_clocks_and_reaches_hashes(self):
        self.assertEqual(self.due("IP", f"confirmed {aged(50)}", max_age=10), date.fromisoformat(aged(50 - 10)))
        self.assertEqual(self.due("SHA256", f"confirmed {aged(50)}", max_age=10), date.fromisoformat(aged(50 - 10)))

    def test_rows_that_are_never_rechecked_are_not_due(self):
        self.assertIsNone(self.due("SHA256", f"confirmed {aged(500)}"))
        self.assertIsNone(self.due("IP Range", f"Modat - confirmed {aged(500)}"))

    def test_a_word_that_merely_ends_in_a_note_is_not_a_closing_note(self):
        # A hand-written comment like this must not be re-checked, rewritten or removed as a confirmed row.
        self.assertIsNone(self.due("IP", f"hand note unconfirmed {aged(500)}"))
        self.assertIsNone(self.due("Domain", f"readded unchecked {aged(500)}"))
        self.assertEqual(self.due("IP", f"confirmed {aged(500)}"), date.fromisoformat(aged(500 - 60)))

    def test_a_comment_with_no_date_is_not_due(self):
        self.assertIsNone(self.due("IP", "Modat"))
        self.assertIsNone(self.due("IP", "confirmed 2026-13-45"))
        self.assertIsNone(self.due("IP", "", max_age=10))


class StampSeenTest(unittest.TestCase):
    """stamp_seen(): the daily check marks feed IPs that probed the network with the date."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.feed = Path(tmp.name) / "feed.csv"

    def test_stamps_an_ip_row_before_its_closing_note(self):
        trusted = f"trusted-ip-1,198.51.100.9,IP,high,high,AB,Cyberint - added unchecked {aged(5)}\n"
        self.feed.write_text(HEADER + OLD_IP + trusted)

        stamped = vt_check.stamp_seen(self.feed, ["203.0.113.7", "198.51.100.9"], today=TODAY)

        self.assertEqual(stamped, ["203.0.113.7", "198.51.100.9"])
        self.assertEqual(self.feed.read_text(), HEADER
                         + "vt-ip-7b3f0a9c21,203.0.113.7,IP,medium,high,AB,seen in Spark logs 2026-10-19 - confirmed 2026-07-15\n"
                         + f"trusted-ip-1,198.51.100.9,IP,high,high,AB,Cyberint - seen in Spark logs 2026-10-19 - "
                           f"added unchecked {aged(5)}\n")

    def test_refreshes_a_stamp_older_than_30_days_and_leaves_a_fresh_one(self):
        def row(value, days):
            return f"vt-ip-{value[-1]},{value},IP,medium,high,AB,seen in Spark logs {aged(days)} - confirmed 2026-07-15\n"
        self.feed.write_text(HEADER + row("203.0.113.1", 30) + row("203.0.113.2", 29))

        stamped = vt_check.stamp_seen(self.feed, ["203.0.113.1", "203.0.113.2"], today=TODAY)

        self.assertEqual(stamped, ["203.0.113.1"])
        self.assertEqual(self.feed.read_text(), HEADER + row("203.0.113.1", 0) + row("203.0.113.2", 29))

    def test_a_hand_written_ip_row_gets_the_note_appended(self):
        self.feed.write_text(HEADER + "x,1.2.3.4,IP,high,high,AB,Modat\n")

        vt_check.stamp_seen(self.feed, ["1.2.3.4"], today=TODAY)

        self.assertEqual(self.feed.read_text(), HEADER + "x,1.2.3.4,IP,high,high,AB,Modat - seen in Spark logs 2026-10-19\n")

    def test_ignores_addresses_not_in_the_feed_ranges_and_other_types(self):
        text = (HEADER + EXISTING + OLD
                + "scanner-modat-net,212.73.148.0-212.73.148.255,IP Range,high,medium,AB,Modat\n")
        self.feed.write_text(text)

        stamped = vt_check.stamp_seen(self.feed, ["212.73.148.42", "9.9.9.9", "evil.com"], today=TODAY)

        self.assertEqual(stamped, [])
        self.assertEqual(self.feed.read_text(), text)


class ApiKeyTest(unittest.TestCase):
    def test_environment_variable_wins_without_touching_the_keychain(self):
        run = Mock()

        self.assertEqual(vt_check.api_key({"VT_API_KEY": " abc "}, run=run), "abc")
        run.assert_not_called()

    def test_falls_back_to_the_keychain_item(self):
        run = keychain_with("from-keychain")

        self.assertEqual(vt_check.api_key({}, run=run), "from-keychain")
        self.assertEqual(run.calls, [KEYCHAIN_LOOKUP])

    def test_blank_environment_variable_counts_as_unset(self):
        self.assertEqual(vt_check.api_key({"VT_API_KEY": "  "}, run=keychain_with("from-keychain")), "from-keychain")

    def test_the_generic_variable_name_the_workflow_sets_wins(self):
        # The public workflow stores the key as REPUTATION_API_KEY, a name that says nothing of the service.
        run = Mock()

        self.assertEqual(vt_check.api_key({"REPUTATION_API_KEY": " abc "}, run=run), "abc")
        run.assert_not_called()
        self.assertEqual(vt_check.api_key({"REPUTATION_API_KEY": "  ", "VT_API_KEY": "v"}, run=run), "v")
        self.assertEqual(vt_check.api_key({"REPUTATION_API_KEY": "  "}, run=keychain_with("k")), "k")

    def test_missing_keychain_item_yields_nothing(self):
        self.assertEqual(vt_check.api_key({}, run=keychain_with(None)), "")

    def test_missing_security_tool_yields_nothing(self):
        def run(cmd, **kwargs):
            raise FileNotFoundError(cmd[0])

        self.assertEqual(vt_check.api_key({}, run=run), "")


class CommandLineTest(unittest.TestCase):
    def run_cli(self, *args, stdin="", env_key=None):
        return subprocess.run(
            [sys.executable, str(REPO / "vt_check.py"), *args],
            input=stdin, capture_output=True, text=True, env=cli_env(env_key), cwd=REPO,
        )

    def test_missing_api_key_exits_with_error_that_names_both_places_to_put_it(self):
        proc = self.run_cli("evil.com")

        self.assertEqual(proc.returncode, 2)
        self.assertIn("VT_API_KEY", proc.stderr)
        self.assertIn("security add-generic-password -s spark-ioc-feed -a VT_API_KEY", proc.stderr)

    def test_key_comes_from_the_keychain_when_the_environment_has_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            feed = Path(tmp) / "feed.csv"
            feed.write_text(HEADER + EXISTING + OLD)
            fake = FakeVT({"/domains/evil.com": vt_object("domain", "evil.com", malicious=12)})

            with patch.object(vt_check, "make_fetch", return_value=fake) as make_fetch, \
                    patch("keychain.subprocess.run", keychain_with("from-keychain")), \
                    patch.dict(os.environ, cli_env(), clear=True), \
                    contextlib.redirect_stdout(io.StringIO()):
                code = vt_check.main(["--recheck", "--feed", str(feed)])

            self.assertEqual(code, 0)
            make_fetch.assert_called_once_with("from-keychain")

    def test_no_indicators_exits_with_error(self):
        proc = self.run_cli(env_key="dummy")

        self.assertEqual(proc.returncode, 2)

    def test_reads_indicators_file_with_optional_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "iocs.txt"
            path.write_text(
                "# from incident 42\n"
                "\n"
                "evil.com\n"
                "  bad.example.net  \n"
                "1.2.3.4\tAPT28\tCISA AA26-201A\n"
                "9.9.9.9 Lazarus campaign\n"
            )

            self.assertEqual(
                vt_check.read_indicators([str(path)], ["8.8.4.4"], label="manual"),
                [
                    ("8.8.4.4", "manual"),
                    ("evil.com", "manual"),
                    ("bad.example.net", "manual"),
                    ("1.2.3.4", "APT28 - CISA AA26-201A"),
                    ("9.9.9.9", "Lazarus campaign"),
                ],
            )

    def test_recheck_rejects_indicator_arguments(self):
        proc = self.run_cli("--recheck", "evil.com", env_key="dummy")

        self.assertEqual(proc.returncode, 2)
        self.assertIn("do not pass indicators", proc.stderr)

    def test_recheck_from_the_command_line_rewrites_the_feed_and_summarises(self):
        with tempfile.TemporaryDirectory() as tmp:
            feed = Path(tmp) / "feed.csv"
            feed.write_text(HEADER + EXISTING + OLD)
            fake = FakeVT({"/domains/evil.com": vt_object("domain", "evil.com", malicious=1)})
            output = io.StringIO()

            with patch.object(vt_check, "make_fetch", return_value=fake), \
                    patch.dict(os.environ, {"VT_API_KEY": "dummy"}), \
                    contextlib.redirect_stdout(output):
                code = vt_check.main(["--recheck", "--feed", str(feed)])

            self.assertEqual(code, 0)
            self.assertEqual(feed.read_text(), HEADER + EXISTING)
            self.assertIn("1 kept, 1 removed", output.getvalue())


class TrustedTest(unittest.TestCase):
    """--trusted adds indicators the user vouches for, with no VirusTotal lookup."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.feed = Path(tmp.name) / "feed.csv"
        self.feed.write_text(HEADER + EXISTING)

    def test_adds_rows_without_any_lookup(self):
        results = vt_check.add_trusted(
            [("evil.com", "APT29 - Cyberint export 2026-10-22"), (SHA256, "APT29 - Cyberint export 2026-10-22")],
            self.feed, today=TODAY, out=lambda *a: None,
        )

        self.assertEqual([r.status for r in results], ["added", "added"])
        self.assertEqual(
            self.feed.read_text(),
            HEADER + EXISTING
            + "trusted-domain-e3daa29865,evil.com,Domain,high,high,AB,"
              "APT29 - Cyberint export 2026-10-22 - added unchecked 2026-10-19\n"
            + f"trusted-sha256-9634a68018,{SHA256},SHA256,high,high,AV,"
              "APT29 - Cyberint export 2026-10-22 - added unchecked 2026-10-19\n",
        )

    def test_skips_feed_members_duplicates_and_invalid_values(self):
        results = vt_check.add_trusted(
            [("example.com", "x"), ("evil.com", "x"), ("EVIL.com", "x"), ("10.0.0.1", "x")],
            self.feed, today=TODAY, out=lambda *a: None,
        )

        self.assertEqual([r.status for r in results], ["in-feed", "added", "duplicate", "invalid"])
        self.assertEqual(self.feed.read_text().count("evil.com"), 1)

    def test_an_address_inside_a_feed_ip_range_is_in_feed(self):
        self.feed.write_text(HEADER + EXISTING + RANGE_ROW)

        results = vt_check.add_trusted(
            [("185.1.2.7", "x"), ("185.1.3.7", "x")], self.feed, today=TODAY, out=lambda *a: None,
        )

        self.assertEqual([r.status for r in results], ["in-feed", "added"])

    def test_command_line_needs_no_api_key(self):
        env = {k: v for k, v in os.environ.items() if k not in ("VT_API_KEY", "REPUTATION_API_KEY")}
        proc = subprocess.run(
            [sys.executable, str(REPO / "vt_check.py"), "--trusted", "--feed", str(self.feed), "evil.com"],
            capture_output=True, text=True, env=env, cwd=REPO,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("evil.com: added", proc.stdout)
        self.assertIn(",evil.com,Domain,high,high,AB,added unchecked", self.feed.read_text())


if __name__ == "__main__":
    unittest.main()
