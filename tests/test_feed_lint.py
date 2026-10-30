"""feed_lint.py: the checks the feed passes before every commit (the daily check, the Telegram bot,
the monthly re-check on Actions), so that a row the gateway cannot read, a host this system needs
or a duplicate never reaches it."""

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import feed_lint

HEADER = "# UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT\n"
HEADER_PROBLEM = ("line 1: the header must be exactly "
                  "`# UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT`")
# One row of every TYPE, as the tools write them.
ROWS = (
    "vt-domain-1a2b3c4d5e,evil.example,Domain,high,high,AB,MuddyWater - confirmed 2026-10-01\n"
    "vt-ip-0011223344,185.1.2.7,IP,medium,high,AB,Inbound probe of WAN - confirmed 2026-10-02\n"
    "scanner-example-net,185.1.2.0-185.1.2.255,IP Range,high,medium,AB,Example scanner - port sweeps 2026-10-03\n"
    "trusted-url-5566778899,https://evil.example/login.php?id=1,URL,high,high,AB,"
    "Phishing kit - added unchecked 2026-10-04\n"
    "trusted-md5-aabbccddee,44d88612fea8a8f36de82e1278abb02f,MD5,high,high,AV,EICAR test file MD5 - safe to keep\n"
    "trusted-sha1-ffeeddccbb,3395856ce81f2b7382dee72602f798b642f14140,SHA1,high,high,AV,EICAR test file SHA1\n"
    "vt-sha256-1234567890,275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f,SHA256,low,high,AV,"
    "EICAR - confirmed 2026-10-05\n"
)
GOOD = HEADER + ROWS  # 8 lines: a new row is line 9


def problems(text):
    return feed_lint.problems(text)


class FeedLintTest(unittest.TestCase):
    def test_a_well_formed_feed_has_no_problems(self):
        self.assertEqual(problems(GOOD), [])

    def test_the_committed_feed_passes(self):
        feed = Path(__file__).resolve().parent.parent / "spark-ioc-feed.csv"
        self.assertEqual(problems(feed.read_text()), [])

    def test_the_header_must_be_exact_and_the_message_shows_what_was_found(self):
        self.assertEqual(problems(GOOD.replace("# UNIQ-NAME", "#UNIQ-NAME", 1)),
                         [HEADER_PROBLEM + ", not '#UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT'"])
        self.assertEqual(problems(ROWS), [HEADER_PROBLEM + ", not " + repr(ROWS.split("\n")[0])])
        self.assertEqual(problems(""), [HEADER_PROBLEM + ", not ''"])
        # A byte-order mark or a trailing space looks exactly like the header; the repr shows it.
        self.assertEqual(problems("\ufeff" + GOOD),
                         [HEADER_PROBLEM + ", not '\\ufeff# UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT'"])
        self.assertEqual(problems(GOOD.replace("COMMENT\n", "COMMENT \n", 1)),
                         [HEADER_PROBLEM + ", not '# UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT '"])
        # A giant first line is cut short (a whole row, above, is not): the message goes into a Telegram
        # notice and an osascript string.
        [message] = problems("x" * 300 + "\n")
        self.assertEqual(message, HEADER_PROBLEM + ", not '" + "x" * 157 + "...'")

    def test_every_row_has_seven_fields(self):
        text = GOOD + "x-1,bad.example,Domain,high,high,AB,a comment, with a comma\n"
        self.assertEqual(problems(text), ["line 9: 8 fields, expected 7 (a comma in the COMMENT?)"])
        self.assertEqual(problems(GOOD + "x-1,bad.example,Domain,high,high,AB\n"), ["line 9: 6 fields, expected 7"])
        self.assertEqual(problems(GOOD + "justonefield\n"), ["line 9: 1 field, expected 7"])

    def test_an_empty_field_is_named(self):
        self.assertEqual(problems(GOOD + "x-1,other.example,Domain,,,,c\n"), [
            "line 9: CONFIDENCE is empty: use low, medium, high or critical",
            "line 9: SEVERITY is empty: use low, medium, high or critical",
            "line 9: PRODUCT is empty: use AB for an IP, IP Range, Domain or URL, AV for a hash",
        ])
        self.assertEqual(problems(GOOD + "x-1,,,high,high,AB,c\n"), [
            "line 9: VALUE is empty",
            "line 9: TYPE is empty: use one of IP, IP Range, Domain, URL, MD5, SHA1, SHA256",
        ])
        self.assertEqual(problems(GOOD + "x-1,,Domain,high,high,AB,c\n" + "x-2,,Domain,high,high,AB,c\n"),
                         ["line 9: VALUE is empty", "line 10: VALUE is empty"])

    def test_the_value_must_be_of_its_type_and_normalised(self):
        cases = [
            ("x-1,185.1.2.9,Domain,high,high,AB,c", "line 9: VALUE 185.1.2.9 is an IP, not a Domain"),
            ("x-1,other.example,IP,high,high,AB,c", "line 9: VALUE other.example is a Domain, not an IP"),
            ("x-1,192.168.1.5,IP,high,high,AB,c", "line 9: VALUE 192.168.1.5: not a public IP address"),
            ("x-1,Other.Example,Domain,high,high,AB,c",
             "line 9: VALUE Other.Example is not normalised (expected other.example)"),
            ("x-1,other[.]example,Domain,high,high,AB,c",
             "line 9: VALUE other[.]example is not normalised (expected other.example)"),
            ("x-1,44d88612fea8a8f36de82e1278abb02e,SHA1,high,high,AV,c",
             "line 9: VALUE 44d88612fea8a8f36de82e1278abb02e is an MD5, not a SHA1"),
            ("x-1,not an indicator!,Domain,high,high,AB,c",
             "line 9: VALUE not an indicator!: not an IP, domain, URL, MD5, SHA1 or SHA256"),
        ]
        for row, expected in cases:
            with self.subTest(row=row):
                self.assertEqual(problems(GOOD + row + "\n"), [expected])

    def test_an_ip_range_is_two_public_addresses_in_order(self):
        cases = [
            ("x-1,185.1.2.0/24,IP Range,high,medium,AB,c",
             "line 9: VALUE 185.1.2.0/24 is not an IP Range (expected a.b.c.d-a.b.c.e)"),
            ("x-1,185.1.2.1-other.example,IP Range,high,medium,AB,c",
             "line 9: VALUE 185.1.2.1-other.example is not an IP Range (expected a.b.c.d-a.b.c.e)"),
            ("x-1,185.1.2.9-185.1.2.1,IP Range,high,medium,AB,c",
             "line 9: VALUE 185.1.2.9-185.1.2.1: the range ends before it starts"),
            ("x-1,10.0.0.1-10.0.0.9,IP Range,high,medium,AB,c",
             "line 9: VALUE 10.0.0.1-10.0.0.9: not a public IP address"),
            ("x-1,185.1.2.9-2606:4700::1111,IP Range,high,medium,AB,c",
             "line 9: VALUE 185.1.2.9-2606:4700::1111: an IPv4 and an IPv6 address do not make a range"),
        ]
        for row, expected in cases:
            with self.subTest(row=row):
                self.assertEqual(problems(GOOD + row + "\n"), [expected])

    def test_hosts_this_system_needs_are_refused(self):
        for value, kind in [("github.com", "Domain"), ("raw.githubusercontent.com", "Domain"),
                            ("api.telegram.org", "Domain"), ("https://api.anthropic.com/v1/messages", "URL"),
                            ("files.www.virustotal.com", "Domain")]:
            with self.subTest(value=value):
                row = f"x-1,{value},{kind},high,high,AB,c\n"
                self.assertEqual(problems(GOOD + row),
                                 [f"line 9: VALUE {value} is a host this system needs (never block)"])

    def test_a_domain_that_covers_a_needed_host_is_refused(self):
        # If the gateway matches a Domain row against subdomains too, the parent blocks the host.
        for value, needed in [("githubusercontent.com", "raw.githubusercontent.com"),
                              ("telegram.org", "api.telegram.org"), ("anthropic.com", "api.anthropic.com"),
                              ("virustotal.com", "www.virustotal.com")]:
            with self.subTest(value=value):
                self.assertEqual(problems(GOOD + f"x-1,{value},Domain,high,high,AB,c\n"),
                                 [f"line 9: VALUE {value} would block {needed}, a host this system needs (never block)"])
        # A URL on such a parent blocks one page, not the host.
        self.assertEqual(problems(GOOD + "x-1,https://telegram.org/malware.exe,URL,high,high,AB,c\n"), [])

    def test_the_comment_names_no_lookup_service(self):
        # The rows say what was done (`confirmed <date>`, `added unchecked <date>`), not where.
        cases = [
            ("x-1,other.example,Domain,high,high,AB,APT28 - VT 12/93 malicious 2026-10-01", "VT"),
            ("x-1,other.example,Domain,high,high,AB,checked on VirusTotal 2026-10-01", "VirusTotal"),
            ("x-1,other.example,Domain,high,high,AB,Phishing kit - added without virustotal check 2026-10-04",
             "virustotal"),
            ("x-1,other.example,Domain,high,high,AB,vt said so", "vt"),
        ]
        for row, word in cases:
            with self.subTest(row=row):
                self.assertEqual(problems(GOOD + row + "\n"),
                                 [f"line 9: COMMENT mentions {word}: the feed names no lookup service"])
        # Only the word itself: VTX, a name with the letters inside, is not it.
        self.assertEqual(problems(GOOD + "x-1,other.example,Domain,high,high,AB,VTX report - confirmed 2026-10-01\n"), [])

    def test_a_value_appears_once_whatever_its_case(self):
        self.assertEqual(problems(GOOD + "x-1,evil.example,Domain,high,high,AB,c\n"),
                         ["line 9: VALUE evil.example repeats line 2"])
        self.assertEqual(problems(GOOD + "x-1,https://EVIL.example/login.php?id=1,URL,high,high,AB,c\n"),
                         ["line 9: VALUE https://EVIL.example/login.php?id=1 repeats line 5"])

    def test_a_uniq_name_is_unique_and_present(self):
        self.assertEqual(problems(GOOD + "vt-domain-1a2b3c4d5e,other.example,Domain,high,high,AB,c\n"),
                         ["line 9: UNIQ-NAME vt-domain-1a2b3c4d5e repeats line 2"])
        self.assertEqual(problems(GOOD + ",other.example,Domain,high,high,AB,c\n"), ["line 9: UNIQ-NAME is empty"])

    def test_hidden_characters_are_refused_and_named_with_their_column(self):
        row = "x-1,other.example,Domain,high,high,AB,a label"
        column = len(row) + 1
        cases = [
            ("\x1b[2K", "U+001B (escape)"),
            ("\u200bwide", "U+200B (ZERO WIDTH SPACE)"),
            ("\ttab", "U+0009 (tab)"),
            ("\r", "U+000D (carriage return: a Windows line ending)"),
            ("\u2028more", "U+2028 (LINE SEPARATOR)"),  # not category C, but splitlines() breaks on it
            (chr(0xE000) + "x", "U+E000 (private-use character)"),
        ]
        for tail, named in cases:
            with self.subTest(named=named):
                self.assertEqual(problems(GOOD + row + tail + "\n"),
                                 [f"line 9: hidden character {named} at column {column}"])

    def test_confidence_severity_product_and_type_take_the_gateways_values(self):
        cases = [
            ("x-1,other.example,Domain,High,high,AB,c",
             "line 9: CONFIDENCE High is not one of low, medium, high, critical"),
            ("x-1,other.example,Domain,high,urgent,AB,c",
             "line 9: SEVERITY urgent is not one of low, medium, high, critical"),
            ("x-1,other.example,Domain,high,high,av,c", "line 9: PRODUCT av is not AB or AV"),
            ("x-1,other.example,Domain,high,high,AV,c", "line 9: PRODUCT AV for a Domain, expected AB"),
            ("x-1,44d88612fea8a8f36de82e1278abb02e,MD5,high,high,AB,c", "line 9: PRODUCT AB for an MD5, expected AV"),
            ("x-1,other.example,Hostname,high,high,AB,c",
             "line 9: TYPE Hostname is not one of IP, IP Range, Domain, URL, MD5, SHA1, SHA256"),
        ]
        for row, expected in cases:
            with self.subTest(row=row):
                self.assertEqual(problems(GOOD + row + "\n"), [expected])

    def test_blank_lines_comments_and_the_final_newline(self):
        self.assertEqual(problems(GOOD + "\n" + "x-1,other.example,Domain,high,high,AB,c\n"), ["line 9: empty line"])
        self.assertEqual(problems(GOOD + "# a note between the rows\n"), [])
        self.assertEqual(problems(GOOD.rstrip("\n")), ["line 8: no newline at the end of the file"])

    def test_every_problem_of_a_row_is_reported_but_a_broken_line_only_once(self):
        row = "x-1,other.example,Domain,High,Urgent,AV,c\n"
        self.assertEqual(problems(GOOD + row), [
            "line 9: CONFIDENCE High is not one of low, medium, high, critical",
            "line 9: SEVERITY Urgent is not one of low, medium, high, critical",
            "line 9: PRODUCT AV for a Domain, expected AB",
        ])
        self.assertEqual(problems(GOOD + "x-1,other.example,Hostname,High,high\x1b,AB\n"),
                         ["line 9: hidden character U+001B (escape) at column 37"])
        self.assertEqual(problems(GOOD + "x-1,other.example,Hostname,High,high\n"), ["line 9: 5 fields, expected 7"])


class MainTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "spark-ioc-feed.csv"

    def run_main(self):
        out = io.StringIO()
        with redirect_stdout(out):
            status = feed_lint.main([str(self.path)])
        return status, out.getvalue()

    def test_a_clean_feed_is_reported_with_its_row_count_and_exits_zero(self):
        self.path.write_text(GOOD)
        self.assertEqual(self.run_main(), (0, f"{self.path}: 7 rows, no problems\n"))

    def test_problems_are_listed_and_the_exit_status_is_one(self):
        self.path.write_text(GOOD + "x-1,github.com,Domain,high,high,AB,c\n" + "x-2,evil.example,Domain,high,high,AB,c\n")
        self.assertEqual(self.run_main(), (1, "line 9: VALUE github.com is a host this system needs (never block)\n"
                                              "line 10: VALUE evil.example repeats line 2\n"
                                              f"{self.path}: 2 problems in 9 rows\n"))

    def test_the_file_is_read_as_it_is_on_disk(self):
        # Universal newlines would hide a Windows line ending; a byte that is not UTF-8 is named too.
        row = "x-1,other.example,Domain,high,high,AB,c"
        self.path.write_bytes((GOOD + row).encode() + b"\r\n")
        self.assertEqual(self.run_main(), (1, "line 9: hidden character U+000D (carriage return: a Windows line "
                                              f"ending) at column {len(row) + 1}\n{self.path}: 1 problem in 8 rows\n"))
        self.path.write_bytes((GOOD + row[:-1]).encode() + b"caf\xe9\n")
        self.assertEqual(feed_lint.problems_in(self.path),
                         [f"line 9: hidden character U+DCE9 (a byte that is not UTF-8) at column {len(row) + 3}"])

    def test_the_repository_feed_is_the_default(self):
        out = io.StringIO()
        with redirect_stdout(out):
            status = feed_lint.main([])
        self.assertEqual(status, 0)
        self.assertRegex(out.getvalue(), r"spark-ioc-feed\.csv: \d+ rows, no problems\n$")


if __name__ == "__main__":
    unittest.main()
