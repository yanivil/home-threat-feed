import tempfile
import unittest
from datetime import datetime
from pathlib import Path

import syslog_receiver

T1 = datetime(2026, 10, 20, 20, 57, 5)
T2 = datetime(2026, 10, 20, 20, 57, 9)

# A Spark security log exactly as it arrives: BSD-style envelope with no tag, then key="value" pairs.
SPARK = (b'<85>Oct 20 20:57:05 Bernhard-Hod Action="accept" Uuid="{0x6ad7ab6f,0x1,0x2a32bd3e,0xf4cba862}" '
         b'resource="dns.quad9.net" src="10.45.60.100" dst="9.9.9.9" proto="17"')
# Long entries are split over several datagrams; the continuations carry no envelope.
PART1 = b'<85>Oct 20 20:57:09 Bernhard-Hod Action="drop" src="109.205.211.205" dst="176.230.223.47" rule_name="Block'
PART2 = b' QUIC" ROW_END="0" UP_match_table="TABLE_END" svc="443"'


class CollectorTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.collector = syslog_receiver.Collector(self.dir)

    def lines(self, day="2026-10-20"):
        return (self.dir / f"spark-{day}.log").read_text().splitlines()

    def test_strips_the_envelope_and_prefixes_the_receive_time(self):
        self.collector.feed(SPARK, now=T1)
        self.collector.flush()

        self.assertEqual(self.lines(), [
            '2026-10-20T20:57:05 Action="accept" Uuid="{0x6ad7ab6f,0x1,0x2a32bd3e,0xf4cba862}" '
            'resource="dns.quad9.net" src="10.45.60.100" dst="9.9.9.9" proto="17"',
        ])

    def test_continuation_datagrams_are_joined_to_their_entry(self):
        self.collector.feed(PART1, now=T2)
        self.collector.feed(PART2, now=T2)
        self.collector.feed(SPARK, now=T2)  # a new entry completes the previous one
        self.collector.flush()

        self.assertEqual(self.lines(), [
            '2026-10-20T20:57:09 Action="drop" src="109.205.211.205" dst="176.230.223.47" '
            'rule_name="Block QUIC" ROW_END="0" UP_match_table="TABLE_END" svc="443"',
            '2026-10-20T20:57:09 Action="accept" Uuid="{0x6ad7ab6f,0x1,0x2a32bd3e,0xf4cba862}" '
            'resource="dns.quad9.net" src="10.45.60.100" dst="9.9.9.9" proto="17"',
        ])

    def test_entry_is_written_only_once_complete_or_flushed(self):
        self.collector.feed(PART1, now=T2)

        self.assertFalse((self.dir / "spark-2026-10-20.log").exists())
        self.collector.flush()
        self.assertEqual(len(self.lines()), 1)

    def test_rfc5424_envelope_is_stripped_too(self):
        self.collector.feed(b'<134>1 2026-10-20T20:57:05+03:00 host app - - - Action="accept" src="1.2.3.4"', now=T1)
        self.collector.flush()

        self.assertEqual(self.lines(), ['2026-10-20T20:57:05 Action="accept" src="1.2.3.4"'])

    def test_undecodable_bytes_do_not_lose_the_entry(self):
        self.collector.feed(b'<85>Oct 20 20:57:05 Bernhard-Hod Action="accept" x="\xff"', now=T1)
        self.collector.flush()

        self.assertEqual(self.lines(), ['2026-10-20T20:57:05 Action="accept" x="�"'])

    def test_entries_go_to_the_file_of_their_day(self):
        self.collector.feed(SPARK, now=datetime(2026, 10, 20, 23, 59, 59))
        self.collector.feed(SPARK, now=datetime(2026, 10, 21, 0, 0, 1))
        self.collector.flush()

        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["spark-2026-10-20.log", "spark-2026-10-21.log"])
        self.assertEqual(len(self.lines("2026-10-20")), 1)
        self.assertEqual(len(self.lines("2026-10-21")), 1)


if __name__ == "__main__":
    unittest.main()
