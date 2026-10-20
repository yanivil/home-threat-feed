import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import spark_logs
from tests.test_vt_check import HEADER, FakeVT, vt_object

REPO = Path(__file__).resolve().parent.parent
TODAY = "2026-10-20"

# Entries as syslog_receiver.py stores them (receive time, then the Spark's key="value" pairs).
INBOUND_DROP = ('2026-10-20T20:57:09 Action="drop" Uuid="{0x1}" inzone="External" outzone="Local" '
                'src="109.205.211.205" dst="176.230.223.47" proto="6" rule_name="Cleanup_Rule - Incoming/Internal Default Policy" '
                'svc="46411" ProductName="VPN-1 & FireWall-1"')
INBOUND_PREVENT = ('2026-10-20T20:57:09 Action=" " Uuid="{0x2}" src="31.14.32.6" dst="176.230.223.47" proto="6" '
                   'Protection Name="" Confidence Level="0" severity="1" Protection Type="IP reputation" '
                   'scope="31.14.32.6" ProductName="Anti Malware"')
OUTBOUND_DOMAIN = ('2026-10-20T20:59:16 Action="accept" Uuid="{0x3}" resource="ab.chatgpt.com" inzone="Internal" '
                   'outzone="External" service_id="HTTPS" src="10.68.144.121" dst="104.18.32.47" proto="6" '
                   'xlatesrc="176.230.223.47" tls_server_host_name="chatgpt.com" sni="chatgpt.com" '
                   'dst_domain_name="*.chatgpt.com" destination_domain_name="ab.chatgpt.com" ProductName="VPN-1 & FireWall-1"')
OUTBOUND_URL = ('2026-10-20T20:59:20 Action="accept" Uuid="{0x4}" resource="http://evil.example/path/x.exe?a=1" '
                'inzone="Internal" outzone="External" src="10.45.60.101" dst="185.1.2.5" proto="6" ProductName="URL Filtering"')
OUTBOUND_IP_ONLY = ('2026-10-20T20:59:21 Action="accept" Uuid="{0x5}" inzone="Internal" outzone="External" '
                    'src="10.45.60.100" dst="185.1.2.7" proto="6" svc="443" ProductName="VPN-1 & FireWall-1"')
OUTBOUND_WILDCARD_ONLY = ('2026-10-20T20:59:22 Action="accept" Uuid="{0x6}" inzone="Internal" outzone="External" '
                          'src="10.45.60.100" dst="185.1.2.8" dst_domain_name="*.googleapis.com" ProductName="VPN-1 & FireWall-1"')
LOCAL = ('2026-10-20T20:59:23 Action="accept" Uuid="{0x7}" inzone="Internal" outzone="Local" '
         'src="10.45.60.100" dst="10.45.60.1" proto="17" svc="53" ProductName="VPN-1 & FireWall-1"')
BROADCAST = ('2026-10-20T20:59:24 Action="drop" Uuid="{0x8}" inzone="External" outzone="Local" '
             'src="176.230.241.195" dst="255.255.255.255" proto="17" svc="67" ProductName="VPN-1 & FireWall-1"')
STATS = ('2026-10-20T20:59:25 Action=" " Uuid="{0x9}" malware_detected="0" scanned="12" log_id="3" ProductName="Threat Emulation"')


class ParseTest(unittest.TestCase):
    def test_reads_keys_with_spaces_and_blank_values(self):
        entry = spark_logs.parse_entry(INBOUND_PREVENT)

        self.assertEqual(entry["received"], "2026-10-20T20:57:09")
        self.assertEqual(entry["Action"], " ")
        self.assertEqual(entry["Protection Type"], "IP reputation")
        self.assertEqual(entry["Protection Name"], "")
        self.assertEqual(entry["ProductName"], "Anti Malware")


class ClassifyTest(unittest.TestCase):
    def candidate(self, line):
        return spark_logs.candidate(spark_logs.parse_entry(line), wan_ip="176.230.223.47")

    def test_inbound_drop_yields_the_source_address(self):
        self.assertEqual(self.candidate(INBOUND_DROP), ("inbound", "109.205.211.205", "176.230.223.47"))

    def test_inbound_anti_bot_prevent_without_zones_yields_the_source(self):
        self.assertEqual(self.candidate(INBOUND_PREVENT), ("inbound", "31.14.32.6", "176.230.223.47"))

    def test_outbound_prefers_the_specific_destination_domain(self):
        self.assertEqual(self.candidate(OUTBOUND_DOMAIN), ("outbound", "ab.chatgpt.com", "10.68.144.121"))

    def test_outbound_url_resource_is_reduced_to_its_host(self):
        self.assertEqual(self.candidate(OUTBOUND_URL), ("outbound", "evil.example", "10.45.60.101"))

    def test_outbound_without_a_name_yields_the_destination_address(self):
        self.assertEqual(self.candidate(OUTBOUND_IP_ONLY), ("outbound", "185.1.2.7", "10.45.60.100"))

    def test_wildcard_names_are_not_indicators(self):
        self.assertEqual(self.candidate(OUTBOUND_WILDCARD_ONLY), ("outbound", "185.1.2.8", "10.45.60.100"))

    def test_local_broadcast_and_statistics_entries_yield_nothing(self):
        for line in (LOCAL, BROADCAST, STATS):
            with self.subTest(line=line[20:60]):
                self.assertIsNone(self.candidate(line))


class CollectTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        (self.dir / "spark-2026-10-20.log").write_text(
            "\n".join([INBOUND_DROP, INBOUND_DROP, INBOUND_PREVENT, OUTBOUND_DOMAIN, OUTBOUND_DOMAIN,
                       OUTBOUND_IP_ONLY, LOCAL, BROADCAST, STATS]) + "\n"
        )
        (self.dir / "spark-2026-10-19.log").write_text(OUTBOUND_URL + "\n")

    def test_counts_distinct_indicators_per_direction_over_the_requested_days(self):
        found = spark_logs.collect(self.dir, days=1, today=TODAY, wan_ip="176.230.223.47")

        self.assertEqual(found["inbound"], {"109.205.211.205": 2, "31.14.32.6": 1})
        self.assertEqual(
            found["outbound"],
            {"ab.chatgpt.com": {"count": 2, "devices": ["10.68.144.121"]},
             "185.1.2.7": {"count": 1, "devices": ["10.45.60.100"]}},
        )

    def test_days_reaches_back_into_earlier_files(self):
        found = spark_logs.collect(self.dir, days=2, today=TODAY, wan_ip="176.230.223.47")

        self.assertIn("evil.example", found["outbound"])

    def test_wan_ip_is_learned_from_the_entries_when_not_given(self):
        found = spark_logs.collect(self.dir, days=1, today=TODAY)

        self.assertEqual(set(found["inbound"]), {"109.205.211.205", "31.14.32.6"})


class SelectTest(unittest.TestCase):
    def test_skips_feed_members_and_recently_checked_indicators(self):
        found = {"inbound": {"109.205.211.205": 2, "31.14.32.6": 1, "203.0.113.5": 1},
                 "outbound": {"ab.chatgpt.com": {"count": 2, "devices": ["10.68.144.121"]},
                              "evil.example": {"count": 1, "devices": ["10.45.60.101"]}}}
        in_feed = {"109.205.211.205"}
        cache = {"ab.chatgpt.com": {"checked": "2026-10-01", "malicious": 0, "total": 92},
                 "evil.example": {"checked": "2026-07-01", "malicious": 9, "total": 92}}

        inbound, outbound = spark_logs.select(found, in_feed, cache, today=TODAY, recheck_days=30)

        self.assertEqual(inbound, ["31.14.32.6", "203.0.113.5"])
        self.assertEqual(outbound, ["evil.example"])  # checked 111 days ago: due again


class CheckTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.feed = self.dir / "feed.csv"
        self.feed.write_text(HEADER)
        self.cache = self.dir / "checked.json"

    def test_inbound_hits_are_added_and_outbound_hits_only_reported(self):
        fake = FakeVT({
            "/ip_addresses/31.14.32.6": vt_object("ip_address", "31.14.32.6", malicious=10),
            "/ip_addresses/185.1.2.9": vt_object("ip_address", "185.1.2.9", malicious=1),
            "/domains/evil.example": vt_object("domain", "evil.example", malicious=9),
            "/domains/ab.chatgpt.com": vt_object("domain", "ab.chatgpt.com", malicious=0),
        })
        found = {"inbound": {"31.14.32.6": 3, "185.1.2.9": 1},
                 "outbound": {"evil.example": {"count": 1, "devices": ["10.45.60.101"]},
                              "ab.chatgpt.com": {"count": 2, "devices": ["10.68.144.121"]}}}

        report = spark_logs.check(found, self.feed, self.cache, fake, today=TODAY, sleep=lambda s: None,
                                  out=lambda *a: None)

        rows = self.feed.read_text().splitlines()[1:]
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0].startswith("vt-ip-"))
        self.assertIn(",31.14.32.6,IP,high,high,AB,Inbound probe of WAN - Spark syslog 2026-10-20 - VT 10/90", rows[0])
        self.assertEqual(report["added"], ["31.14.32.6"])
        self.assertEqual(report["outbound_hits"], [("evil.example", "Domain 9/89 malicious", ["10.45.60.101"])])
        cache = json.loads(self.cache.read_text())
        self.assertEqual(cache["185.1.2.9"], {"checked": TODAY, "malicious": 1, "total": 81})
        self.assertEqual(cache["evil.example"]["malicious"], 9)
        self.assertNotIn("evil.example", self.feed.read_text())

    def test_lookup_budget_takes_inbound_first_by_count(self):
        fake = FakeVT({})
        found = {"inbound": {"185.1.2.1": 1, "185.1.2.2": 5},
                 "outbound": {"a.example": {"count": 9, "devices": ["10.0.0.1"]}}}

        report = spark_logs.check(found, self.feed, self.cache, fake, today=TODAY, max_lookups=2,
                                  sleep=lambda s: None, out=lambda *a: None)

        self.assertEqual(fake.calls, ["/ip_addresses/185.1.2.2", "/ip_addresses/185.1.2.1"])
        self.assertEqual(report["skipped"], ["a.example"])

    def test_quota_stop_keeps_the_cache_consistent(self):
        fake = FakeVT({"/ip_addresses/185.1.2.1": (429, {"error": {"code": "QuotaExceededError"}})})
        found = {"inbound": {"185.1.2.1": 1, "185.1.2.2": 1}, "outbound": {}}

        spark_logs.check(found, self.feed, self.cache, fake, today=TODAY, sleep=lambda s: None, out=lambda *a: None)

        self.assertEqual(json.loads(self.cache.read_text()), {})


class CommandLineTest(unittest.TestCase):
    def run_cli(self, *args, env_key=None):
        env = {k: v for k, v in os.environ.items() if k != "VT_API_KEY"}
        if env_key:
            env["VT_API_KEY"] = env_key
        return subprocess.run([sys.executable, str(REPO / "spark_logs.py"), *args],
                              capture_output=True, text=True, env=env, cwd=REPO)

    def test_listing_needs_no_key_and_shows_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "spark-2026-10-20.log").write_text(INBOUND_DROP + "\n" + OUTBOUND_DOMAIN + "\n")
            Path(tmp, "feed.csv").write_text(HEADER)

            proc = self.run_cli("--dir", tmp, "--today", TODAY, "--feed", str(Path(tmp, "feed.csv")))

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("109.205.211.205", proc.stdout)
        self.assertIn("ab.chatgpt.com", proc.stdout)

    def test_check_needs_the_api_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_cli("--dir", tmp, "--check")

        self.assertEqual(proc.returncode, 2)
        self.assertIn("VT_API_KEY", proc.stderr)


if __name__ == "__main__":
    unittest.main()
