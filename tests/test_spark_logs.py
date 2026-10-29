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

    # Three hosts under one apex (a family), one lone host, and two hosts under another apex (not a family).
    FAMILY = {
        "inbound": {},
        "outbound": {
            "a.cdn.example": {"count": 5, "devices": ["192.168.1.100"]},
            "b.cdn.example": {"count": 4, "devices": ["192.168.1.101"]},
            "c.cdn.example": {"count": 1, "devices": ["192.168.1.100"]},
            "lone.example.net": {"count": 2, "devices": ["192.168.1.100"]},
            "x.pair.example": {"count": 1, "devices": ["192.168.1.100"]},
            "y.pair.example": {"count": 1, "devices": ["192.168.1.100"]},
        },
    }

    def test_groups_candidates_in_check_order_busiest_first(self):
        groups = spark_logs.select(self.FOUND, set(), {}, today=TODAY)

        self.assertEqual(list(groups), ["inbound", "ips", "names"])
        self.assertEqual(groups["inbound"], ["109.205.211.205", "31.14.32.6"])  # sources seen 5+ times
        self.assertEqual(groups["ips"], ["185.1.2.9", "185.1.2.7"])  # addresses seen 3+ times
        self.assertEqual(groups["names"], ["c2.example.net", "evil.example"])  # every name, vendor ones excepted

    def test_apex_is_the_registrable_domain_near_enough(self):
        for name, expected in [
            ("rr2---sn-nhpax-ua8e7.googlevideo.com", "googlevideo.com"),
            ("Host.Example.COM.", "example.com"),
            ("example.com", "example.com"),
            ("a.b.example.co.jp", "example.co.jp"),
            ("www.foo.co.uk", "foo.co.uk"),
            ("shop.example.com.au", "example.com.au"),
            ("www.city.lg.jp", "city.lg.jp"),  # a public-body registry under a country code
            ("mail.ac.example", "ac.example"),  # "ac" before a long TLD is an ordinary label
            ("single", "single"),
        ]:
            with self.subTest(name=name):
                self.assertEqual(spark_logs.apex(name), expected)

    def test_three_or_more_hosts_under_one_apex_are_one_lookup_of_the_apex(self):
        groups = spark_logs.select(self.FAMILY, set(), {}, today=TODAY)

        # the family counts as the sum of its hosts (10), ahead of the lone host (2) and the pair (1 each)
        self.assertEqual(groups["names"], ["cdn.example", "lone.example.net", "x.pair.example", "y.pair.example"])

    def test_a_family_apex_is_cached_and_skipped_as_itself(self):
        cache = {"cdn.example": {"checked": "2026-10-19", "malicious": 0, "total": 92}}

        groups = spark_logs.select(self.FAMILY, set(), cache, today=TODAY)

        self.assertEqual(groups["names"], ["lone.example.net", "x.pair.example", "y.pair.example"])

    def test_a_lone_host_is_looked_up_even_under_an_apex_checked_clean(self):
        cache = {"pair.example": {"checked": "2026-10-19", "malicious": 0, "total": 92}}

        groups = spark_logs.select(self.FAMILY, set(), cache, today=TODAY)

        self.assertIn("x.pair.example", groups["names"])
        self.assertIn("y.pair.example", groups["names"])

    def test_members_are_the_hosts_a_family_apex_stands_for_and_a_lone_host_itself(self):
        names = spark_logs.candidate_names(self.FAMILY["outbound"])

        self.assertEqual(spark_logs.members(names, "cdn.example"), ["a.cdn.example", "b.cdn.example", "c.cdn.example"])
        self.assertEqual(spark_logs.members(names, "lone.example.net"), ["lone.example.net"])
        self.assertEqual(spark_logs.members(names, "x.pair.example"), ["x.pair.example"])

    def test_hosts_under_a_shared_platform_never_make_a_family(self):
        # Three tenants' pages on a hosting platform are three indicators, not one clean apex.
        found = {"inbound": {}, "outbound": {f"{h}.netlify.app": {"count": 1, "devices": ["192.168.1.100"]} for h in "abc"}}

        groups = spark_logs.select(found, set(), {}, today=TODAY)

        self.assertEqual(groups["names"], ["a.netlify.app", "b.netlify.app", "c.netlify.app"])
        names = spark_logs.candidate_names(found["outbound"])
        self.assertEqual(spark_logs.members(names, "a.netlify.app"), ["a.netlify.app"])
        self.assertEqual(spark_logs.members(names, "netlify.app"), ["netlify.app"])

    def test_a_host_checked_alone_before_is_looked_up_with_its_family_today(self):
        cache = {"a.cdn.example": {"checked": "2026-10-19", "malicious": 0, "total": 92}}

        groups = spark_logs.select(self.FAMILY, set(), cache, today=TODAY)

        self.assertEqual(groups["names"][0], "cdn.example")
        self.assertNotIn("a.cdn.example", groups["names"])

    def test_at_most_max_ips_addresses_are_checked_busiest_first(self):
        found = {"inbound": {}, "outbound": {f"185.1.2.{i}": {"count": 2 + i, "devices": ["192.168.1.100"]}
                                             for i in range(1, 42)}}

        groups = spark_logs.select(found, set(), {}, today=TODAY)

        self.assertEqual(len(groups["ips"]), 40)
        self.assertEqual(groups["ips"][0], "185.1.2.41")
        self.assertNotIn("185.1.2.1", groups["ips"])
        self.assertEqual(spark_logs.select(found, set(), {}, today=TODAY, max_ips=2)["ips"], ["185.1.2.41", "185.1.2.40"])

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
        self.assertEqual(report["outbound_hits"], [("evil.example", "Domain 9/89 malicious", ["192.168.1.101"], ["evil.example"])])
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

    def test_lookups_go_to_inbound_then_recurring_addresses_then_outbound_names(self):
        fake = FakeVT({})
        found = {"inbound": {"185.1.2.1": 5, "185.1.2.2": 50},
                 "outbound": {"a.example": {"count": 1, "devices": ["10.0.0.1"]},
                              "185.1.2.3": {"count": 3, "devices": ["10.0.0.1"]},
                              "185.1.2.4": {"count": 1, "devices": ["10.0.0.1"]}}}

        report = self.check(found, fake=fake, max_lookups=3)

        self.assertEqual(fake.calls, ["/ip_addresses/185.1.2.2", "/ip_addresses/185.1.2.1", "/ip_addresses/185.1.2.3"])
        self.assertEqual(report["skipped"], ["a.example"])

    def test_a_share_a_group_does_not_use_passes_down_to_the_names(self):
        fake = FakeVT({})
        found = {"inbound": {"185.1.2.1": 5, "185.1.2.2": 50},
                 "outbound": {"a.example": {"count": 1, "devices": ["10.0.0.1"]},
                              "b.example": {"count": 1, "devices": ["10.0.0.1"]}}}

        report = self.check(found, fake=fake, max_lookups=3, max_inbound=1)

        self.assertEqual(fake.calls, ["/ip_addresses/185.1.2.2", "/domains/a.example", "/domains/b.example"])
        self.assertEqual(report["skipped"], [])

    def test_an_outbound_hit_on_a_family_apex_names_every_device_that_reached_it(self):
        fake = FakeVT({"/domains/cdn.example": vt_object("domain", "cdn.example", malicious=9)})
        found = {"inbound": {},
                 "outbound": {"a.cdn.example": {"count": 3, "devices": ["10.0.0.1"]},
                              "b.cdn.example": {"count": 2, "devices": ["10.0.0.2"]},
                              "c.cdn.example": {"count": 1, "devices": ["10.0.0.1"]}}}

        report = self.check(found, fake=fake)

        self.assertEqual(fake.calls, ["/domains/cdn.example"], "one lookup for the family")
        self.assertEqual(report["outbound_hits"], [("cdn.example", "Domain 9/89 malicious", ["10.0.0.1", "10.0.0.2"],
                                                    ["a.cdn.example", "b.cdn.example", "c.cdn.example"])])
        self.assertEqual(json.loads(self.cache.read_text())["cdn.example"]["malicious"], 9)

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

    def test_quota_stop_during_inbound_leaves_outbound_for_another_day(self):
        fake = FakeVT({"/ip_addresses/185.1.2.1": (429, {"error": {"code": "QuotaExceededError"}})})
        found = {"inbound": {"185.1.2.1": 5}, "outbound": {"a.example": {"count": 1, "devices": ["10.0.0.1"]}}}

        report = self.check(found, fake=fake)

        self.assertEqual(fake.calls, ["/ip_addresses/185.1.2.1"] * 2, "a 429 is tried once more")
        self.assertTrue(report["quota"])
        self.assertEqual(report["added"], [])
        self.assertEqual(report["outbound_hits"], [])


class CommandLineTest(unittest.TestCase):
    # One day's capture: a name seen once, a vendor host, an address reached three times and one reached
    # once, a source that probed five times and one that probed once.
    CAPTURE = "\n".join([OUTBOUND_URL, OUTBOUND_DOMAIN, *[OUTBOUND_IP_ONLY] * 3, OUTBOUND_WILDCARD_ONLY,
                         *[INBOUND_DROP] * 5, INBOUND_PREVENT]) + "\n"

    def run_cli(self, *args, env_key=None):
        return subprocess.run([sys.executable, str(REPO / "spark_logs.py"), *args],
                              capture_output=True, text=True, env=cli_env(env_key), cwd=REPO)

    def listing(self, *args, allow=None, capture=None):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "spark-2026-10-20.log").write_text(capture or self.CAPTURE)
            Path(tmp, "feed.csv").write_text(HEADER)
            if allow is not None:
                Path(tmp, "allow.txt").write_text(allow)
            proc = self.run_cli("--dir", tmp, "--today", TODAY, "--feed", str(Path(tmp, "feed.csv")), *args)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout

    def test_listing_needs_no_key_and_shows_the_groups_in_check_order_with_counts(self):
        out = self.listing()

        self.assertIn("2 inbound sources and 4 outbound destinations in the last 1 day(s); "
                      "to check: 1 inbound sources, 1 outbound addresses, 1 outbound names (0 family apexes)", out)
        inbound, ips, names = (out.index(h) for h in ("inbound sources:", "outbound addresses:", "outbound names:"))
        self.assertLess(inbound, ips)
        self.assertLess(ips, names)
        self.assertLess(inbound, out.index("109.205.211.205"))
        self.assertLess(out.index("109.205.211.205"), ips)
        self.assertLess(ips, out.index("185.1.2.7"))
        self.assertLess(out.index("185.1.2.7"), names)
        self.assertLess(names, out.index("evil.example"))
        self.assertIn("1 under allowed vendor domains", out)
        self.assertIn("seen 3+ times, at most 40 a run", out)
        self.assertIn("seen 5+ times, at most 20 a run", out)
        self.assertIn("0 family apexes of 3+ hosts", out)
        for skipped in ("ab.chatgpt.com", "185.1.2.8", "31.14.32.6"):
            self.assertNotIn(skipped, out)

    def test_listing_shows_a_family_as_its_apex_with_its_hosts_counted(self):
        family = "".join(OUTBOUND_DOMAIN.replace("ab.chatgpt.com", f"{h}.cdn.example") + "\n" for h in "abc")

        out = self.listing(capture=self.CAPTURE + family)

        self.assertIn("to check: 1 inbound sources, 1 outbound addresses, 2 outbound names (1 family apexes)", out)
        self.assertIn("1 family apexes of 3+ hosts", out)
        self.assertRegex(out, r"cdn\.example\s+x3\s+3 hosts, from 192\.168\.2\.121")
        self.assertNotIn("a.cdn.example", out)

    def test_allow_file_in_the_capture_directory_extends_the_vendor_list(self):
        out = self.listing(allow="evil.example\n")

        self.assertIn("0 outbound names", out)
        self.assertIn("2 under allowed vendor domains", out)
        self.assertNotIn("evil.example", out)

    def test_thresholds_and_the_inbound_cap_are_flags(self):
        out = self.listing("--min-ip-hits", "1", "--min-inbound-hits", "1", "--max-inbound", "1")

        self.assertIn("to check: 1 inbound sources, 2 outbound addresses, 1 outbound names", out)
        self.assertIn("185.1.2.8", out)
        self.assertIn("109.205.211.205", out)
        self.assertNotIn("31.14.32.6", out)
        self.assertIn("seen 1+ times, at most 1 a run", out)

    def test_the_address_cap_is_a_flag(self):
        out = self.listing("--min-ip-hits", "1", "--max-ips", "1")

        self.assertIn("to check: 1 inbound sources, 1 outbound addresses, 1 outbound names", out)
        self.assertIn("185.1.2.7", out)
        self.assertNotIn("185.1.2.8", out)
        self.assertIn("seen 1+ times, at most 1 a run", out)

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

    def test_a_family_hit_lists_the_hosts_behind_the_apex(self):
        done = {"added": [], "clean": 0, "not_found": 0, "skipped": [], "quota": False,
                "outbound_hits": [("cdn.example", "Domain 9/89 malicious", ["192.168.1.100"], ["a.cdn.example", "b.cdn.example", "c.cdn.example"]),
                                  ("evil.example", "Domain 9/89 malicious", ["192.168.1.101"], ["evil.example"])]}
        with tempfile.TemporaryDirectory() as tmp, patch.object(spark_logs, "check", return_value=done), \
                patch.dict(os.environ, cli_env("k"), clear=True), patch("builtins.print") as printed:
            Path(tmp, "feed.csv").write_text(HEADER)
            spark_logs.main(["--dir", tmp, "--check", "--today", TODAY, "--feed", str(Path(tmp, "feed.csv"))])

        lines = [c.args[0] for c in printed.call_args_list if c.args]
        hit = lines.index("OUTBOUND HIT  cdn.example  (Domain 9/89 malicious)  reached by 192.168.1.100  <- check these devices")
        self.assertEqual(lines[hit + 1], "  the family's hosts: a.cdn.example, b.cdn.example, c.cdn.example")
        self.assertTrue(lines[hit + 2].startswith("OUTBOUND HIT  evil.example"), "a lone host gets no hosts line")

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
        self.assertEqual(fake.calls, ["/ip_addresses/109.205.211.205", "/ip_addresses/185.1.2.7", "/domains/evil.example"])


if __name__ == "__main__":
    unittest.main()
