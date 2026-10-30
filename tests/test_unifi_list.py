"""unifi_list.py: the bare IPv4 list for UniFi gateways, rendered from the feed and kept in step with
it by GitHub Actions (.github/workflows/unifi-list.yml), so the Mac's jobs never touch it."""

import io
import ipaddress
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import unifi_list

HEADER = "# UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT\n"
IP = "vt-ip-0011223344,185.1.2.7,IP,medium,high,AB,Inbound probe of WAN - confirmed 2026-10-02\n"
IP2 = "vt-ip-5566778899,185.1.3.47,IP,high,high,AB,Inbound probe of WAN - confirmed 2026-10-03\n"
RANGE = "scanner-example-net,185.1.4.0-185.1.4.255,IP Range,high,medium,AB,Example scanner - port sweeps\n"
DOMAIN = "vt-domain-1a2b3c4d5e,evil.example,Domain,high,high,AB,MuddyWater - confirmed 2026-10-01\n"
URL = "trusted-url-5566778899,https://evil.example/login.php?id=1,URL,high,high,AB,Phishing kit\n"
MD5 = "trusted-md5-aabbccddee,44d88612fea8a8f36de82e1278abb02f,MD5,high,high,AV,EICAR test file MD5\n"


class RenderTest(unittest.TestCase):
    def test_ip_rows_become_one_address_per_line_in_feed_order(self):
        self.assertEqual(unifi_list.render(HEADER + IP2 + IP), "185.1.3.47\n185.1.2.7\n")

    def test_an_ip_range_row_becomes_cidr(self):
        self.assertEqual(unifi_list.render(HEADER + RANGE), "185.1.4.0/24\n")

    def test_a_range_that_is_not_one_block_becomes_the_blocks_that_cover_it(self):
        row = "scanner-x,185.1.4.1-185.1.4.4,IP Range,high,medium,AB,odd range\n"
        self.assertEqual(unifi_list.render(HEADER + row), "185.1.4.1/32\n185.1.4.2/31\n185.1.4.4/32\n")

    def test_domains_urls_and_hashes_are_left_out(self):
        self.assertEqual(unifi_list.render(HEADER + DOMAIN + IP + URL + MD5), "185.1.2.7\n")

    def test_the_header_and_comment_lines_are_left_out(self):
        self.assertEqual(unifi_list.render(HEADER + "# a note\n" + IP), "185.1.2.7\n")

    def test_an_address_inside_a_range_row_is_not_repeated(self):
        inside = "vt-ip-9988776655,185.1.4.9,IP,medium,high,AB,seen in the sweep\n"
        self.assertEqual(unifi_list.render(HEADER + inside + IP + RANGE), "185.1.2.7\n185.1.4.0/24\n")

    def test_the_same_value_twice_is_listed_once(self):
        self.assertEqual(unifi_list.render(HEADER + IP + IP), "185.1.2.7\n")

    def test_ipv6_rows_are_left_out(self):
        v6 = "vt-ip-aabbccddee,2001:db8::7,IP,medium,high,AB,probe\n"
        v6_range = "scanner-v6,2001:db8::-2001:db8::ff,IP Range,high,medium,AB,sweep\n"
        self.assertEqual(unifi_list.render(HEADER + v6 + IP + v6_range), "185.1.2.7\n")

    def test_a_row_the_lint_would_refuse_is_skipped_rather_than_breaking_the_list(self):
        bad = "x,not-an-address,IP,high,high,AB,typo\n"
        short = "x,185.1.2.8\n"
        bad_range = "y,185.1.4.9-banana,IP Range,high,high,AB,typo\n"
        self.assertEqual(unifi_list.render(HEADER + bad + short + bad_range + IP), "185.1.2.7\n")

    def test_a_feed_with_no_addresses_renders_empty(self):
        self.assertEqual(unifi_list.render(HEADER + DOMAIN), "")
        self.assertEqual(unifi_list.render(""), "")


class MainTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.feed = Path(self.dir.name) / "spark-ioc-feed.csv"
        self.out = Path(self.dir.name) / "unifi-blocklist.txt"
        self.feed.write_text(HEADER + IP + RANGE + DOMAIN)

    def run_main(self, *args):
        with redirect_stdout(io.StringIO()) as out:
            status = unifi_list.main([str(self.feed), str(self.out), *args])
        return status, out.getvalue()

    def test_writes_the_list_next_to_the_feed_and_says_how_many_entries(self):
        status, said = self.run_main()
        self.assertEqual(status, 0)
        self.assertEqual(self.out.read_text(), "185.1.2.7\n185.1.4.0/24\n")
        self.assertIn("2 entries", said)
        self.assertIn("written", said)

    def test_a_list_already_in_step_is_left_alone(self):
        self.out.write_text("185.1.2.7\n185.1.4.0/24\n")
        before = self.out.stat().st_mtime_ns
        status, said = self.run_main()
        self.assertEqual(status, 0)
        self.assertEqual(self.out.stat().st_mtime_ns, before)
        self.assertIn("unchanged", said)

    def test_the_default_paths_are_the_repository_files(self):
        root = Path(unifi_list.__file__).resolve().parent
        self.assertEqual(unifi_list.FEED, root / "spark-ioc-feed.csv")
        self.assertEqual(unifi_list.OUT, root / "unifi-blocklist.txt")


class CommittedFilesTest(unittest.TestCase):
    """The list in the repository is what the feed renders to, entry for entry."""

    def setUp(self):
        root = Path(__file__).resolve().parent.parent
        self.feed = root / "spark-ioc-feed.csv"
        self.out = root / "unifi-blocklist.txt"

    def test_the_committed_list_is_in_step_with_the_committed_feed(self):
        self.assertEqual(self.out.read_text(), unifi_list.render(self.feed.read_text()))

    def test_the_committed_list_holds_nothing_but_ipv4_addresses_and_networks(self):
        lines = self.out.read_text().splitlines()
        self.assertGreater(len(lines), 100)
        for line in lines:
            parsed = ipaddress.ip_network(line, strict=True)  # raises on anything else
            self.assertEqual(parsed.version, 4, line)
        self.assertEqual(len(lines), len(set(lines)))


if __name__ == "__main__":
    unittest.main()
