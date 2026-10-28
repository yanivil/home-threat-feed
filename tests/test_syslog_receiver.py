import argparse
import socket
import subprocess
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

import syslog_receiver

T1 = datetime(2026, 10, 20, 20, 57, 5)
T2 = datetime(2026, 10, 20, 20, 57, 9)

# A Spark security log exactly as it arrives: BSD-style envelope with no tag, then key="value" pairs.
SPARK = (b'<85>Oct 20 20:57:05 Home-Spark Action="accept" Uuid="{0x6ad7ab6f,0x1,0x2a32bd3e,0xf4cba862}" '
         b'resource="dns.quad9.net" src="192.168.1.100" dst="9.9.9.9" proto="17"')
# Long entries are split over several datagrams; the continuations carry no envelope.
PART1 = b'<85>Oct 20 20:57:09 Home-Spark Action="drop" src="109.205.211.205" dst="185.1.3.47" rule_name="Block'
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
            'resource="dns.quad9.net" src="192.168.1.100" dst="9.9.9.9" proto="17"',
        ])

    def test_continuation_datagrams_are_joined_to_their_entry(self):
        self.collector.feed(PART1, now=T2)
        self.collector.feed(PART2, now=T2)
        self.collector.feed(SPARK, now=T2)  # a new entry completes the previous one
        self.collector.flush()

        self.assertEqual(self.lines(), [
            '2026-10-20T20:57:09 Action="drop" src="109.205.211.205" dst="185.1.3.47" '
            'rule_name="Block QUIC" ROW_END="0" UP_match_table="TABLE_END" svc="443"',
            '2026-10-20T20:57:09 Action="accept" Uuid="{0x6ad7ab6f,0x1,0x2a32bd3e,0xf4cba862}" '
            'resource="dns.quad9.net" src="192.168.1.100" dst="9.9.9.9" proto="17"',
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
        self.collector.feed(b'<85>Oct 20 20:57:05 Home-Spark Action="accept" x="\xff"', now=T1)
        self.collector.flush()

        self.assertEqual(self.lines(), ['2026-10-20T20:57:05 Action="accept" x="�"'])

    def test_entries_go_to_the_file_of_their_day(self):
        self.collector.feed(SPARK, now=datetime(2026, 10, 20, 23, 59, 59))
        self.collector.feed(SPARK, now=datetime(2026, 10, 21, 0, 0, 1))
        self.collector.flush()

        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["spark-2026-10-20.log", "spark-2026-10-21.log"])
        self.assertEqual(len(self.lines("2026-10-20")), 1)
        self.assertEqual(len(self.lines("2026-10-21")), 1)

    def test_one_datagram_is_one_capture_line_whatever_it_holds(self):
        # A forged datagram must not become a second, made-up entry in the capture.
        self.collector.feed(b'<85>Oct 20 20:57:05 Home-Spark Action="accept" src="192.0.2.5"\r\n'
                            b'2026-10-20T20:57:05 Action="drop" Protection Name="forged"\rx="1"\r\n', now=T1)
        self.collector.feed(b'\nAction="drop"\n', now=T1)  # a continuation, joined to its entry
        self.collector.flush()

        self.assertEqual(self.lines(), ['2026-10-20T20:57:05 Action="accept" src="192.0.2.5"  2026-10-20T20:57:05 '
                                        'Action="drop" Protection Name="forged" x="1" Action="drop"'])


ROUTE_OUTPUT = """\
   route to: default
destination: default
       mask: default
    gateway: 192.0.2.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
"""


def route(stdout=ROUTE_OUTPUT, returncode=0, raises=None):
    """A subprocess.run stand-in for `route -n get default`; records each call."""
    def run(argv, **kwargs):
        run.calls.append((argv, kwargs))
        if raises:
            raise raises
        return subprocess.CompletedProcess(argv, returncode, stdout, "")
    run.calls = []
    return run


class SourceTest(unittest.TestCase):
    def setUp(self):
        self.logged = []

    def test_a_datagram_is_kept_only_from_an_allowed_source(self):
        self.assertTrue(syslog_receiver.accepts({"192.0.2.1"}, "192.0.2.1"))
        self.assertFalse(syslog_receiver.accepts({"192.0.2.1"}, "192.0.2.7"))
        self.assertFalse(syslog_receiver.accepts(set(), "192.0.2.1"))
        self.assertTrue(syslog_receiver.accepts(None, "198.51.100.9"), "None: any source")

    def test_the_default_source_is_the_default_routes_gateway(self):
        run = route()

        self.assertEqual(syslog_receiver.default_gateway(run), "192.0.2.1")
        [(argv, kwargs)] = run.calls
        self.assertEqual(argv, ["/sbin/route", "-n", "get", "default"])
        self.assertEqual(kwargs["timeout"], 5)
        self.assertNotIn("shell", kwargs)

    def test_a_default_route_that_cannot_be_read_gives_none(self):
        for run in (route(raises=OSError("no route")), route(raises=subprocess.TimeoutExpired("route", 5)),
                    route(returncode=1), route(stdout="route: writing to routing socket: not in table\n"),
                    route(stdout=ROUTE_OUTPUT.replace("192.0.2.1", "link#14"))):
            with self.subTest(run=run):
                self.assertIsNone(syslog_receiver.default_gateway(run))

    def sources(self, given, gateway="192.0.2.1"):
        return syslog_receiver.resolve_sources(given, lambda: gateway, self.logged.append)

    def test_sources_given_on_the_command_line_win_and_any_turns_the_filter_off(self):
        self.assertEqual(self.sources(["192.0.2.9", "198.51.100.2"]), {"192.0.2.9", "198.51.100.2"})
        self.assertIsNone(self.sources(["any"]))
        self.assertIsNone(self.sources(["192.0.2.9", "any"]))

    def test_without_a_source_the_gateway_is_the_one(self):
        self.assertEqual(self.sources(None), {"192.0.2.1"})
        self.assertEqual(self.logged, ["accepting datagrams from 192.0.2.1 only (the default route's gateway)"])

    def test_an_unreadable_default_route_accepts_any_source_and_says_so(self):
        self.assertIsNone(self.sources(None, gateway=None))
        self.assertEqual(len(self.logged), 1)
        self.assertTrue(self.logged[0].startswith("WARNING: the default route could not be read"), self.logged)
        self.assertIn("accepting datagrams from any source", self.logged[0])

    def test_a_source_must_be_an_address_or_any(self):
        self.assertEqual(syslog_receiver.source_arg(" 192.0.2.1 "), "192.0.2.1")
        self.assertEqual(syslog_receiver.source_arg("ANY"), "any")
        with self.assertRaises(argparse.ArgumentTypeError):
            syslog_receiver.source_arg("spark.lan")

    def test_rejections_are_logged_once_per_source_and_their_total_at_most_hourly(self):
        clock = [1000.0]
        keep = syslog_receiver.SourceFilter({"192.0.2.1"}, clock=lambda: clock[0], log=self.logged.append)

        self.assertEqual([keep(a) for a in ("192.0.2.7", "192.0.2.7", "192.0.2.1", "198.51.100.3", "192.0.2.1")],
                         [False, False, True, False, True])
        clock[0] += 3600
        keep("192.0.2.7")
        clock[0] += 60
        keep("192.0.2.7")

        self.assertEqual(self.logged, [
            "dropping datagrams from 192.0.2.7: not an allowed source",
            "receiving from 192.0.2.1",
            "dropping datagrams from 198.51.100.3: not an allowed source",
            "4 datagrams from other sources dropped so far",
        ])


class ServeTest(unittest.TestCase):
    """serve() over a real UDP socket bound to the loopback address, stopped after a few receives."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(self.server.close)
        self.server.bind(("127.0.0.1", 0))
        self.server.settimeout(0.2)
        self.logged = []

    def serve(self, sources, *datagrams):
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with client:
            for datagram in datagrams:
                client.sendto(datagram, self.server.getsockname())
        receives = []
        stop = lambda: len(receives) > len(datagrams) or receives.append(None)  # one receive more: a timeout
        keep = syslog_receiver.SourceFilter(sources, log=self.logged.append)
        syslog_receiver.serve(self.server, syslog_receiver.Collector(self.dir), keep, stop=stop,
                              log=self.logged.append)
        return sorted(self.dir.iterdir())

    def test_a_datagram_from_a_source_not_allowed_is_dropped(self):
        files = self.serve({"192.0.2.1"}, SPARK)

        self.assertEqual(files, [])
        self.assertEqual(self.logged, ["dropping datagrams from 127.0.0.1: not an allowed source"])

    def test_a_datagram_from_an_allowed_source_is_written(self):
        [path] = self.serve({"127.0.0.1"}, SPARK, PART1, PART2)

        lines = [line.partition(" ")[2] for line in path.read_text().splitlines()]
        self.assertEqual(lines, [syslog_receiver.envelope(SPARK)[1],
                                 syslog_receiver.envelope(PART1)[1] + syslog_receiver.envelope(PART2)[1]])
        self.assertEqual(self.logged, ["receiving from 127.0.0.1"])


if __name__ == "__main__":
    unittest.main()
