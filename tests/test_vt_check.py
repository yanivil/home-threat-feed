import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import vt_check

REPO = Path(__file__).resolve().parent.parent
HEADER = "# UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT\n"
EXISTING = "test-domain-01,example.com,Domain,high,high,AB,TEST ENTRY\n"
TODAY = "2026-10-19"


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
            + "vt-domain-e3daa29865,evil.com,Domain,high,high,AB,VT 12/93 malicious 2026-10-19\n",
        )

    def test_label_goes_into_comment_without_commas(self):
        fake = FakeVT({"/domains/evil.com": vt_object("domain", "evil.com", malicious=12, suspicious=1)})

        self.run_check([("evil.com", "APT28, via CISA AA26-201A")], fake)

        row = self.feed.read_text().splitlines()[2]
        self.assertEqual(
            row,
            "vt-domain-e3daa29865,evil.com,Domain,high,high,AB,"
            "APT28 via CISA AA26-201A - VT 12/93 malicious 2026-10-19",
        )

    def test_hashes_go_to_antivirus_and_ips_to_antibot(self):
        sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        fake = FakeVT({
            f"/files/{sha256}": vt_object("file", sha256, malicious=60, undetected=5, harmless=0),
            "/ip_addresses/8.8.4.4": vt_object("ip_address", "8.8.4.4", malicious=4),
        })

        self.run_check([sha256, "8.8.4.4"], fake)

        added = self.feed.read_text().splitlines()[2:]
        self.assertEqual(added, [
            f"vt-sha256-9634a68018,{sha256},SHA256,high,high,AV,VT 60/65 malicious 2026-10-19",
            "vt-ip-2d2878d281,8.8.4.4,IP,low,high,AB,VT 4/84 malicious 2026-10-19",
        ])

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


class CommandLineTest(unittest.TestCase):
    def run_cli(self, *args, stdin="", env_key=None):
        env = {k: v for k, v in os.environ.items() if k != "VT_API_KEY"}
        if env_key is not None:
            env["VT_API_KEY"] = env_key
        return subprocess.run(
            [sys.executable, str(REPO / "vt_check.py"), *args],
            input=stdin, capture_output=True, text=True, env=env, cwd=REPO,
        )

    def test_missing_api_key_exits_with_error(self):
        proc = self.run_cli("evil.com")

        self.assertEqual(proc.returncode, 2)
        self.assertIn("VT_API_KEY", proc.stderr)

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


if __name__ == "__main__":
    unittest.main()
