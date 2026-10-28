import gzip
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import spark_logs
import vt_check
from tests.test_vt_check import HEADER, FakeVT, cli_env, keychain_with, vt_object

REPO = Path(__file__).resolve().parent.parent
TODAY = "2026-10-20"

# Entries as syslog_receiver.py stores them (receive time, then the Spark's key="value" pairs).
INBOUND_DROP = ('2026-10-20T20:57:09 Action="drop" Uuid="{0x1}" inzone="External" outzone="Local" '
                'src="109.205.211.205" dst="185.1.3.47" proto="6" rule_name="Cleanup_Rule - Incoming/Internal Default Policy" '
                'svc="46411" ProductName="VPN-1 & FireWall-1"')
INBOUND_PREVENT = ('2026-10-20T20:57:09 Action=" " Uuid="{0x2}" src="31.14.32.6" dst="185.1.3.47" proto="6" '
                   'Protection Name="" Confidence Level="0" severity="1" Protection Type="IP reputation" '
                   'scope="31.14.32.6" ProductName="Anti Malware"')
OUTBOUND_DOMAIN = ('2026-10-20T20:59:16 Action="accept" Uuid="{0x3}" resource="ab.chatgpt.com" inzone="Internal" '
                   'outzone="External" service_id="HTTPS" src="192.168.2.121" dst="104.18.32.47" proto="6" '
                   'xlatesrc="185.1.3.47" tls_server_host_name="chatgpt.com" sni="chatgpt.com" '
                   'dst_domain_name="*.chatgpt.com" destination_domain_name="ab.chatgpt.com" ProductName="VPN-1 & FireWall-1"')
OUTBOUND_URL = ('2026-10-20T20:59:20 Action="accept" Uuid="{0x4}" resource="http://evil.example/path/x.exe?a=1" '
                'inzone="Internal" outzone="External" src="192.168.1.101" dst="185.1.2.5" proto="6" ProductName="URL Filtering"')
OUTBOUND_IP_ONLY = ('2026-10-20T20:59:21 Action="accept" Uuid="{0x5}" inzone="Internal" outzone="External" '
                    'src="192.168.1.100" dst="185.1.2.7" proto="6" svc="443" ProductName="VPN-1 & FireWall-1"')
OUTBOUND_WILDCARD_ONLY = ('2026-10-20T20:59:22 Action="accept" Uuid="{0x6}" inzone="Internal" outzone="External" '
                          'src="192.168.1.100" dst="185.1.2.8" dst_domain_name="*.googleapis.com" ProductName="VPN-1 & FireWall-1"')
LOCAL = ('2026-10-20T20:59:23 Action="accept" Uuid="{0x7}" inzone="Internal" outzone="Local" '
         'src="192.168.1.100" dst="192.168.1.1" proto="17" svc="53" ProductName="VPN-1 & FireWall-1"')
BROADCAST = ('2026-10-20T20:59:24 Action="drop" Uuid="{0x8}" inzone="External" outzone="Local" '
             'src="185.1.3.195" dst="255.255.255.255" proto="17" svc="67" ProductName="VPN-1 & FireWall-1"')
STATS = ('2026-10-20T20:59:25 Action=" " Uuid="{0x9}" malware_detected="0" scanned="12" log_id="3" ProductName="Threat Emulation"')
# The Spark's system logs, forwarded beside the security logs: a program tag, a colon, a space, text.
SYSTEM_LINES = [
    '2026-10-28T21:08:02 rsyslogd: [origin software="rsyslogd" swVersion="8.1911.0" x-pid="10352" '
    'x-info="https://www.rsyslog.com"] start',
    "2026-10-28T21:08:03 root: [System Logs] Restarting rsyslogd",
    "2026-10-28T21:08:05 lua: [Security Settings] A policy change has been applied",
    "2026-10-28T21:08:14 lua: [AUDIT] [Interface: WEB] 'admin' CheckIfExists",
    "2026-10-28T21:08:14 root: [WebUI] Syslog server trusted CA certificate was CheckIfExists by admin at 21:08 10/28/2026",
    "2026-10-28T21:17:27 lua: [WEBUI] Failed to stop Shell server.",
]


class ParseTest(unittest.TestCase):
    def test_reads_keys_with_spaces_and_blank_values(self):
        entry = spark_logs.parse_entry(INBOUND_PREVENT)

        self.assertEqual(entry["received"], "2026-10-20T20:57:09")
        self.assertEqual(entry["Action"], " ")
        self.assertEqual(entry["Protection Type"], "IP reputation")
        self.assertEqual(entry["Protection Name"], "")
        self.assertEqual(entry["ProductName"], "Anti Malware")

    def test_a_system_log_line_is_its_tag_and_its_text_and_no_pairs(self):
        entries = [spark_logs.parse_entry(line) for line in SYSTEM_LINES]

        self.assertEqual(entries[0], {"received": "2026-10-28T21:08:02", "tag": "rsyslogd",
                                      "system": '[origin software="rsyslogd" swVersion="8.1911.0" x-pid="10352" '
                                                'x-info="https://www.rsyslog.com"] start'})
        self.assertEqual(entries[1], {"received": "2026-10-28T21:08:03", "tag": "root",
                                      "system": "[System Logs] Restarting rsyslogd"})
        self.assertEqual([e["tag"] for e in entries], ["rsyslogd", "root", "lua", "lua", "root", "lua"])
        self.assertEqual(entries[5]["system"], "[WEBUI] Failed to stop Shell server.")
        for entry in entries:
            self.assertEqual(set(entry), {"received", "tag", "system"})

    def test_security_rows_are_not_system_lines(self):
        for line in (INBOUND_DROP, INBOUND_PREVENT, STATS, '2026-10-28T21:08:02 "ctl"Uuid="{0x1}" src="192.0.2.1"'):
            with self.subTest(line=line[:40]):
                self.assertNotIn("system", spark_logs.parse_entry(line))

    def test_system_lines_are_no_candidate_detection_or_indicator(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "spark-2026-10-28.log").write_text("\n".join(SYSTEM_LINES + [INBOUND_DROP]) + "\n")

            found = spark_logs.collect(tmp, days=1, today="2026-10-28")

        self.assertEqual(found, {"inbound": {"109.205.211.205": 1}, "outbound": {}})
        for line in SYSTEM_LINES:
            entry = spark_logs.parse_entry(line)
            self.assertIsNone(spark_logs.candidate(entry, wan_ip="203.0.113.47"))
            self.assertFalse(spark_logs.is_tp_detection(entry))


class DetectionTest(unittest.TestCase):
    def test_a_threat_prevention_row_with_a_protection_and_addresses_is_a_detection(self):
        self.assertTrue(spark_logs.is_tp_detection(spark_logs.parse_entry(INBOUND_PREVENT)))

    def test_statistics_rows_are_not_detections(self):
        self.assertFalse(spark_logs.is_tp_detection(spark_logs.parse_entry(STATS)))

    def test_a_blade_row_without_addresses_or_a_protection_is_not_a_detection(self):
        no_addresses = STATS.replace("malware_detected", 'Protection Name="Bad" malware_detected')
        no_protection = INBOUND_PREVENT.replace('Protection Type="IP reputation"', 'Protection Type=" "')

        for line in (no_addresses, no_protection):
            with self.subTest(line=line[20:70]):
                self.assertFalse(spark_logs.is_tp_detection(spark_logs.parse_entry(line)))

    def test_other_products_are_not_detections_even_with_a_protection(self):
        firewall = INBOUND_PREVENT.replace('ProductName="Anti Malware"', 'ProductName="VPN-1 & FireWall-1"')

        self.assertFalse(spark_logs.is_tp_detection(spark_logs.parse_entry(firewall)))

    def test_every_threat_prevention_blade_counts(self):
        for blade in spark_logs.TP_BLADES:
            with self.subTest(blade=blade):
                line = INBOUND_PREVENT.replace('ProductName="Anti Malware"', f'ProductName="{blade}"')
                self.assertTrue(spark_logs.is_tp_detection(spark_logs.parse_entry(line)))


class ClassifyTest(unittest.TestCase):
    def candidate(self, line):
        return spark_logs.candidate(spark_logs.parse_entry(line), wan_ip="185.1.3.47")

    def test_inbound_drop_yields_the_source_address(self):
        self.assertEqual(self.candidate(INBOUND_DROP), ("inbound", "109.205.211.205", "185.1.3.47"))

    def test_inbound_anti_bot_prevent_without_zones_yields_the_source(self):
        self.assertEqual(self.candidate(INBOUND_PREVENT), ("inbound", "31.14.32.6", "185.1.3.47"))

    def test_outbound_prefers_the_specific_destination_domain(self):
        self.assertEqual(self.candidate(OUTBOUND_DOMAIN), ("outbound", "ab.chatgpt.com", "192.168.2.121"))

    def test_outbound_url_resource_is_reduced_to_its_host(self):
        self.assertEqual(self.candidate(OUTBOUND_URL), ("outbound", "evil.example", "192.168.1.101"))

    def test_outbound_without_a_name_yields_the_destination_address(self):
        self.assertEqual(self.candidate(OUTBOUND_IP_ONLY), ("outbound", "185.1.2.7", "192.168.1.100"))

    def test_wildcard_names_are_not_indicators(self):
        self.assertEqual(self.candidate(OUTBOUND_WILDCARD_ONLY), ("outbound", "185.1.2.8", "192.168.1.100"))

    def test_a_malformed_url_costs_only_its_name(self):
        # urlsplit raises on "http://[::1": one such line must not stop the daily check, two days running.
        broken = OUTBOUND_URL.replace('resource="http://evil.example/path/x.exe?a=1"', 'resource="http://[::1"')

        self.assertEqual(self.candidate(broken), ("outbound", "185.1.2.5", spark_logs.parse_entry(broken)["src"]))
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, f"spark-{TODAY}.log").write_text(broken + "\n")
            self.assertEqual(list(spark_logs.collect(tmp, today=TODAY)["outbound"]), ["185.1.2.5"])

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
        found = spark_logs.collect(self.dir, days=1, today=TODAY, wan_ip="185.1.3.47")

        self.assertEqual(found["inbound"], {"109.205.211.205": 2, "31.14.32.6": 1})
        self.assertEqual(
            found["outbound"],
            {"ab.chatgpt.com": {"count": 2, "devices": ["192.168.2.121"]},
             "185.1.2.7": {"count": 1, "devices": ["192.168.1.100"]}},
        )

    def test_days_reaches_back_into_earlier_files(self):
        found = spark_logs.collect(self.dir, days=2, today=TODAY, wan_ip="185.1.3.47")

        self.assertIn("evil.example", found["outbound"])

    def test_days_reads_earlier_files_that_retention_has_compressed(self):
        (self.dir / "spark-2026-10-19.log").unlink()
        with gzip.open(self.dir / "spark-2026-10-19.log.gz", "wt") as f:
            f.write(OUTBOUND_URL + "\n")

        found = spark_logs.collect(self.dir, days=2, today=TODAY, wan_ip="185.1.3.47")

        self.assertIn("evil.example", found["outbound"])

    def test_wan_ip_is_learned_from_the_entries_when_not_given(self):
        found = spark_logs.collect(self.dir, days=1, today=TODAY)

        self.assertEqual(set(found["inbound"]), {"109.205.211.205", "31.14.32.6"})


class AllowlistTest(unittest.TestCase):
    def test_the_built_in_list_holds_the_vendor_apex_domains(self):
        self.assertLessEqual(
            {"apple.com", "icloud.com", "apple-dns.net", "aaplimg.com", "google.com", "googleapis.com", "gstatic.com",
             "youtube.com", "microsoft.com", "office.com", "office.net", "live.com", "windows.com", "msidentity.com",
             "akamai.net", "akamaiedge.net", "amazonaws.com", "cloudfront.net", "amazon.com", "whatsapp.net",
             "facebook.com", "fbcdn.net", "cloudflare.com", "digicert.com", "ntp.org", "quad9.net", "one.one.one.one",
             "samsungcloudsolution.net", "anthropic.com", "openai.com", "chatgpt.com"},
            spark_logs.ALLOWED_SUFFIXES,
        )

    def test_allowed_matches_an_apex_domain_and_every_host_under_it(self):
        for name in ("apple.com", "gsp-ssl.ls.apple.com", "ab.chatgpt.com", "one.one.one.one", "0.pool.ntp.org", "Time.Apple.COM."):
            with self.subTest(name=name):
                self.assertTrue(spark_logs.allowed(name))

    def test_allowed_rejects_look_alikes_other_names_and_addresses(self):
        for name in ("notapple.com", "apple.com.evil.example", "evil.example", "185.1.2.7"):
            with self.subTest(name=name):
                self.assertFalse(spark_logs.allowed(name))

    def test_allow_file_extends_the_built_in_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "allow.txt")
            path.write_text("# my own vendors\n\n.Example.ORG\nvendor.example.net   # the TV\n")

            suffixes = spark_logs.load_allow(path)

        self.assertEqual(suffixes, spark_logs.ALLOWED_SUFFIXES | {"example.org", "vendor.example.net"})
        self.assertTrue(spark_logs.allowed("cdn.example.org", suffixes))
        self.assertFalse(spark_logs.allowed("cdn.example.org"))

    def test_a_missing_allow_file_leaves_the_built_in_list(self):
        self.assertEqual(spark_logs.load_allow(Path("/nonexistent/allow.txt")), spark_logs.ALLOWED_SUFFIXES)


class SelectTest(unittest.TestCase):
    FOUND = {
        "inbound": {"109.205.211.205": 9, "31.14.32.6": 5, "203.0.113.5": 4, "198.51.100.9": 1},
        "outbound": {
            "evil.example": {"count": 1, "devices": ["192.168.1.101"]},
            "c2.example.net": {"count": 7, "devices": ["192.168.1.100"]},
            "ab.chatgpt.com": {"count": 40, "devices": ["192.168.2.121"]},  # under an allowed vendor domain
            "185.1.2.7": {"count": 3, "devices": ["192.168.1.100"]},
            "185.1.2.8": {"count": 2, "devices": ["192.168.1.100"]},  # a CDN edge, seen twice
            "185.1.2.9": {"count": 12, "devices": ["192.168.1.100"]},
        },
    }

    def test_groups_candidates_in_check_order_busiest_first(self):
        groups = spark_logs.select(self.FOUND, set(), {}, today=TODAY)

        self.assertEqual(list(groups), ["names", "ips", "inbound"])
        self.assertEqual(groups["names"], ["c2.example.net", "evil.example"])  # every name, vendor ones excepted
        self.assertEqual(groups["ips"], ["185.1.2.9", "185.1.2.7"])  # addresses seen 3+ times
        self.assertEqual(groups["inbound"], ["109.205.211.205", "31.14.32.6"])  # sources seen 5+ times

    def test_allow_decides_which_names_are_skipped(self):
        groups = spark_logs.select(self.FOUND, set(), {}, today=TODAY, allow={"example.net"})

        self.assertEqual(groups["names"], ["ab.chatgpt.com", "evil.example"])

    def test_hit_thresholds_and_the_inbound_cap_are_adjustable(self):
        groups = spark_logs.select(self.FOUND, set(), {}, today=TODAY, min_ip_hits=1, min_inbound_hits=1, max_inbound=3)

        self.assertEqual(groups["ips"], ["185.1.2.9", "185.1.2.7", "185.1.2.8"])
        self.assertEqual(groups["inbound"], ["109.205.211.205", "31.14.32.6", "203.0.113.5"])

    def test_the_inbound_cap_applies_after_feed_members_and_recent_checks_are_dropped(self):
        groups = spark_logs.select(self.FOUND, {"109.205.211.205"}, {}, today=TODAY, min_inbound_hits=1, max_inbound=2)

        self.assertEqual(groups["inbound"], ["31.14.32.6", "203.0.113.5"])

    def test_skips_feed_members_and_recently_checked_indicators(self):
        in_feed = {"109.205.211.205"}
        cache = {"c2.example.net": {"checked": "2026-10-01", "malicious": 0, "total": 92},
                 "evil.example": {"checked": "2026-07-01", "malicious": 9, "total": 92}}

        groups = spark_logs.select(self.FOUND, in_feed, cache, today=TODAY, recheck_days=30)

        self.assertEqual(groups["names"], ["evil.example"])  # checked 111 days ago: due again
        self.assertEqual(groups["inbound"], ["31.14.32.6"])

    def test_skips_addresses_inside_a_feed_ip_range(self):
        found = {"inbound": {"212.73.148.42": 6, "212.73.149.1": 5}, "outbound": {}}
        feed_text = (HEADER + "scanner-modat-net,212.73.148.0-212.73.148.255,IP Range,high,medium,AB,Modat\n"
                     + "x,1.2.3.4,IP,high,high,AB,c\n")

        groups = spark_logs.select(found, spark_logs.feed_members(feed_text), {}, today=TODAY)

        self.assertEqual(groups["inbound"], ["212.73.149.1"])


class CheckTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.feed = self.dir / "feed.csv"
        self.feed.write_text(HEADER)
        self.cache = self.dir / "checked.json"

    def check(self, found, **kwargs):
        return spark_logs.check(found, self.feed, self.cache, kwargs.pop("fake"), today=TODAY,
                                sleep=lambda s: None, out=lambda *a: None, **kwargs)

    def test_inbound_hits_are_added_and_outbound_hits_only_reported(self):
        fake = FakeVT({
            "/ip_addresses/31.14.32.6": vt_object("ip_address", "31.14.32.6", malicious=10),
            "/ip_addresses/185.1.2.9": vt_object("ip_address", "185.1.2.9", malicious=1),
            "/domains/evil.example": vt_object("domain", "evil.example", malicious=9),
            "/domains/c2.example.net": vt_object("domain", "c2.example.net", malicious=0),
        })
        found = {"inbound": {"31.14.32.6": 6, "185.1.2.9": 5},
                 "outbound": {"evil.example": {"count": 1, "devices": ["192.168.1.101"]},
                              "c2.example.net": {"count": 2, "devices": ["192.168.2.121"]}}}

        report = self.check(found, fake=fake)

        rows = self.feed.read_text().splitlines()[1:]
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0].startswith("vt-ip-"))
        self.assertIn(",31.14.32.6,IP,high,high,AB,Inbound probe of WAN - Spark syslog 2026-10-20 - "
                      "seen in Spark logs 2026-10-20 - VT 10/90", rows[0])
        self.assertEqual(report["added"], ["31.14.32.6"])
        self.assertEqual(report["outbound_hits"], [("evil.example", "Domain 9/89 malicious", ["192.168.1.101"])])
        cache = json.loads(self.cache.read_text())
        self.assertEqual(cache["185.1.2.9"], {"checked": TODAY, "malicious": 1, "total": 81})
        self.assertEqual(cache["evil.example"]["malicious"], 9)
        self.assertNotIn("evil.example", self.feed.read_text())

    def test_inbound_sources_already_in_the_feed_are_stamped_as_seen_without_a_lookup(self):
        self.feed.write_text(HEADER + "vt-ip-1,31.14.32.6,IP,high,high,AB,VT 10/90 malicious 2026-09-01\n")
        fake = FakeVT({})
        found = {"inbound": {"31.14.32.6": 2}, "outbound": {}}

        report = self.check(found, fake=fake)

        self.assertEqual(fake.calls, [])
        self.assertEqual(report["stamped"], ["31.14.32.6"])
        self.assertEqual(self.feed.read_text().splitlines()[1],
                         "vt-ip-1,31.14.32.6,IP,high,high,AB,seen in Spark logs 2026-10-20 - VT 10/90 malicious 2026-09-01")

    def test_lookups_go_to_outbound_names_then_recurring_addresses_then_inbound(self):
        fake = FakeVT({})
        found = {"inbound": {"185.1.2.1": 5, "185.1.2.2": 50},
                 "outbound": {"a.example": {"count": 1, "devices": ["10.0.0.1"]},
                              "185.1.2.3": {"count": 3, "devices": ["10.0.0.1"]},
                              "185.1.2.4": {"count": 1, "devices": ["10.0.0.1"]}}}

        report = self.check(found, fake=fake, max_lookups=3)

        self.assertEqual(fake.calls, ["/domains/a.example", "/ip_addresses/185.1.2.3", "/ip_addresses/185.1.2.2"])
        self.assertEqual(report["skipped"], ["185.1.2.1"])

    def test_one_off_inbound_sources_and_single_contact_addresses_are_never_looked_up(self):
        fake = FakeVT({})
        found = {"inbound": {"185.1.2.1": 4}, "outbound": {"185.1.2.4": {"count": 2, "devices": ["10.0.0.1"]}}}

        report = self.check(found, fake=fake)

        self.assertEqual(fake.calls, [])
        self.assertEqual(report["skipped"], [])

    def test_at_most_max_inbound_sources_are_added_per_run(self):
        fake = FakeVT({f"/ip_addresses/185.1.2.{i}": vt_object("ip_address", f"185.1.2.{i}", malicious=10) for i in range(9)})
        found = {"inbound": {f"185.1.2.{i}": 5 + i for i in range(9)}, "outbound": {}}

        report = self.check(found, fake=fake, max_inbound=2)

        self.assertEqual(report["added"], ["185.1.2.8", "185.1.2.7"])
        self.assertEqual(len(self.feed.read_text().splitlines()), 3)

    def test_quota_stop_keeps_the_cache_consistent(self):
        fake = FakeVT({"/ip_addresses/185.1.2.1": (429, {"error": {"code": "QuotaExceededError"}})})
        found = {"inbound": {"185.1.2.1": 5, "185.1.2.2": 5}, "outbound": {}}

        self.check(found, fake=fake)

        self.assertEqual(json.loads(self.cache.read_text()), {})

    def test_quota_stop_during_outbound_leaves_inbound_for_another_day(self):
        fake = FakeVT({"/domains/a.example": (429, {"error": {"code": "QuotaExceededError"}})})
        found = {"inbound": {"185.1.2.1": 5}, "outbound": {"a.example": {"count": 1, "devices": ["10.0.0.1"]}}}

        report = self.check(found, fake=fake)

        self.assertEqual(fake.calls, ["/domains/a.example"] * 2, "a 429 is tried once more")
        self.assertTrue(report["quota"])
        self.assertEqual(report["added"], [])


class CommandLineTest(unittest.TestCase):
    # One day's capture: a name seen once, a vendor host, an address reached three times and one reached
    # once, a source that probed five times and one that probed once.
    CAPTURE = "\n".join([OUTBOUND_URL, OUTBOUND_DOMAIN, *[OUTBOUND_IP_ONLY] * 3, OUTBOUND_WILDCARD_ONLY,
                         *[INBOUND_DROP] * 5, INBOUND_PREVENT]) + "\n"

    def run_cli(self, *args, env_key=None):
        return subprocess.run([sys.executable, str(REPO / "spark_logs.py"), *args],
                              capture_output=True, text=True, env=cli_env(env_key), cwd=REPO)

    def listing(self, *args, allow=None):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "spark-2026-10-20.log").write_text(self.CAPTURE)
            Path(tmp, "feed.csv").write_text(HEADER)
            if allow is not None:
                Path(tmp, "allow.txt").write_text(allow)
            proc = self.run_cli("--dir", tmp, "--today", TODAY, "--feed", str(Path(tmp, "feed.csv")), *args)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout

    def test_listing_needs_no_key_and_shows_the_groups_in_check_order_with_counts(self):
        out = self.listing()

        self.assertIn("2 inbound sources and 4 outbound destinations in the last 1 day(s); "
                      "to check: 1 outbound names, 1 outbound addresses, 1 inbound sources", out)
        names, ips, inbound = (out.index(h) for h in ("outbound names:", "outbound addresses:", "inbound sources:"))
        self.assertLess(names, ips)
        self.assertLess(ips, inbound)
        self.assertLess(names, out.index("evil.example"))
        self.assertLess(out.index("evil.example"), ips)
        self.assertLess(ips, out.index("185.1.2.7"))
        self.assertLess(out.index("185.1.2.7"), inbound)
        self.assertLess(inbound, out.index("109.205.211.205"))
        self.assertIn("1 under allowed vendor domains", out)
        self.assertIn("seen 3+ times", out)
        self.assertIn("seen 5+ times", out)
        self.assertIn("at most 20 a run", out)
        for skipped in ("ab.chatgpt.com", "185.1.2.8", "31.14.32.6"):
            self.assertNotIn(skipped, out)

    def test_allow_file_in_the_capture_directory_extends_the_vendor_list(self):
        out = self.listing(allow="evil.example\n")

        self.assertIn("to check: 0 outbound names", out)
        self.assertIn("2 under allowed vendor domains", out)
        self.assertNotIn("evil.example", out)

    def test_thresholds_and_the_inbound_cap_are_flags(self):
        out = self.listing("--min-ip-hits", "1", "--min-inbound-hits", "1", "--max-inbound", "1")

        self.assertIn("to check: 1 outbound names, 2 outbound addresses, 1 inbound sources", out)
        self.assertIn("185.1.2.8", out)
        self.assertIn("109.205.211.205", out)
        self.assertNotIn("31.14.32.6", out)
        self.assertIn("at most 1 a run", out)

    def test_check_passes_the_defaults_on(self):
        done = {"added": [], "outbound_hits": [], "clean": 0, "not_found": 0, "skipped": [], "quota": False}
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(spark_logs, "check", return_value=done) as check, \
                patch.dict(os.environ, cli_env("k"), clear=True), patch("builtins.print"):
            Path(tmp, "allow.txt").write_text("mine.example\n")
            Path(tmp, "feed.csv").write_text(HEADER)
            code = spark_logs.main(["--dir", tmp, "--check", "--today", TODAY, "--feed", str(Path(tmp, "feed.csv"))])

        self.assertEqual(code, 0)
        kwargs = check.call_args.kwargs
        self.assertEqual(kwargs["max_lookups"], 400)
        self.assertEqual((kwargs["min_ip_hits"], kwargs["min_inbound_hits"], kwargs["max_inbound"]), (3, 5, 20))
        self.assertEqual(kwargs["allow"], spark_logs.ALLOWED_SUFFIXES | {"mine.example"})

    def test_check_needs_the_api_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_cli("--dir", tmp, "--check")

        self.assertEqual(proc.returncode, 2)
        self.assertIn("VT_API_KEY", proc.stderr)
        self.assertIn("security add-generic-password -s spark-ioc-feed -a VT_API_KEY", proc.stderr)

    def test_check_takes_the_key_from_the_keychain_when_the_environment_has_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "spark-2026-10-20.log").write_text(self.CAPTURE)
            feed = Path(tmp, "feed.csv")
            feed.write_text(HEADER)
            fake = FakeVT({"/ip_addresses/109.205.211.205": vt_object("ip_address", "109.205.211.205", malicious=0)})

            with patch.object(vt_check, "make_fetch", return_value=fake) as make_fetch, \
                    patch("keychain.subprocess.run", keychain_with("from-keychain")), \
                    patch.dict(os.environ, cli_env(), clear=True), \
                    patch("builtins.print"):
                code = spark_logs.main(["--dir", tmp, "--check", "--today", TODAY, "--feed", str(feed), "--delay", "0"])

        self.assertEqual(code, 0)
        make_fetch.assert_called_once_with("from-keychain")
        self.assertEqual(fake.calls, ["/domains/evil.example", "/ip_addresses/185.1.2.7", "/ip_addresses/109.205.211.205"])


if __name__ == "__main__":
    unittest.main()
