#!/usr/bin/env python3
"""Receive the Spark's syslog stream and store it as one plain-text file per day.

    python3 syslog_receiver.py [--port 5514] [--dir syslog] [--source ADDR ...]

The gateway sends each security log as a UDP syslog datagram (Logs & Monitoring →
External Log Servers → Syslog Servers), splitting long entries over several
datagrams. This strips the syslog envelope, joins the pieces, and appends
`<received time> <entry>` to syslog/spark-YYYY-MM-DD.log, one entry per line.
spark_logs.py reads those files, and the Telegram bot alerts from them, so only
the gateway may write them: a datagram from any other address is dropped. The
gateway is --source (repeatable; "any" turns the filter off), by default the
Mac's default route as `route -n get default` names it when the receiver starts.
When that cannot be read the receiver says so and keeps every datagram: the
capture never stops silently. Standard library only; keep it running (see the
README for a LaunchAgent).
"""

import argparse
import ipaddress
import re
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

DEFAULT_PORT = 5514
DEFAULT_DIR = Path(__file__).resolve().parent / "syslog"
IDLE_FLUSH_SECONDS = 2
ANY = "any"
ROUTE = ["/sbin/route", "-n", "get", "default"]
ROUTE_TIMEOUT = 5
REPORT_EVERY = 3600  # seconds between two logged totals of the datagrams dropped
LOGGED_SOURCES = 1000  # distinct dropped sources named in the log; past them, only the totals

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
RFC5424_RE = re.compile(r"^<\d{1,3}>\d+ \S+ \S+ \S+ \S+ \S+ (?:-|\[.*?\]) ?(?P<msg>.*)$", re.DOTALL)
# What the Spark sends: <PRI>Mmm dd hh:mm:ss HOSTNAME MSG (no tag)
BSD_RE = re.compile(r"^<\d{1,3}>[A-Z][a-z]{2} {1,2}\d{1,2} \d\d:\d\d:\d\d \S+ (?P<msg>.*)$", re.DOTALL)


def log(text):
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S} {text}", flush=True)


def envelope(raw):
    """Return (starts_an_entry, text): the message without its syslog envelope,
    or the datagram itself when it has none (a continuation of the previous entry).
    A CR or LF inside the datagram becomes a space: one datagram never makes two lines."""
    text = raw.decode("utf-8", errors="replace").rstrip("\r\n").replace("\r", " ").replace("\n", " ")
    for pattern in (RFC5424_RE, BSD_RE):
        m = pattern.match(text)
        if m:
            return True, m.group("msg")
    return False, text


class Collector:
    """Joins split datagrams into entries and appends each to its day's file."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.pending = None  # (received datetime, text) of the entry still being assembled

    def feed(self, raw, now=None):
        now = now or datetime.now()
        starts, text = envelope(raw)
        if starts or self.pending is None:
            self.flush()
            self.pending = (now, text)
        else:
            self.pending = (self.pending[0], self.pending[1] + text)

    def flush(self):
        if self.pending is None:
            return
        received, text = self.pending
        self.pending = None
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / f"spark-{received:%Y-%m-%d}.log"
        with path.open("a", encoding="utf-8") as f:
            f.write(f"{received:%Y-%m-%dT%H:%M:%S} {text}\n")


def accepts(sources, address):
    """Whether a datagram from `address` is kept: `sources` holds the allowed addresses, None any."""
    return sources is None or address in sources


def default_gateway(run=subprocess.run):
    """The address of the default route's gateway, from `route -n get default`; None when the
    command fails or names no address (a route through an interface: "gateway: link#14")."""
    try:
        proc = run(ROUTE, capture_output=True, text=True, timeout=ROUTE_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    for line in proc.stdout.splitlines():
        key, _, value = line.strip().partition(":")
        if key == "gateway":
            try:
                return str(ipaddress.ip_address(value.strip()))
            except ValueError:
                return None
    return None


def source_arg(text):
    """argparse type of --source: an IP address, or "any"."""
    text = text.strip()
    if text.lower() == ANY:
        return ANY
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an IP address or {ANY!r}: {text!r}") from None


def resolve_sources(given, gateway=default_gateway, log=log):
    """The allowed source addresses, None for any: the --source values `given` ("any" among them
    turns the filter off), else the default route's gateway, else (it cannot be read) any, said so."""
    if given:
        return None if ANY in given else set(given)
    address = gateway()
    if address is None:
        log("WARNING: the default route could not be read (route -n get default); "
            "accepting datagrams from any source")
        return None
    log(f"accepting datagrams from {address} only (the default route's gateway)")
    return {address}


class SourceFilter:
    """`keep(address)`: whether to keep a datagram from `address`. Logs the first source kept, the
    first datagram dropped from each other source (its address, never its content) and, at most
    once every REPORT_EVERY seconds of `clock`, the running total dropped."""

    def __init__(self, sources, clock=time.time, log=log):
        self.sources = sources
        self.clock = clock
        self.log = log
        self.receiving = False
        self.named = set()  # dropped sources already named in the log
        self.dropped = 0
        self.reported = clock()

    def __call__(self, address):
        if accepts(self.sources, address):
            if not self.receiving:
                self.receiving = True
                self.log(f"receiving from {address}")
            return True
        self.dropped += 1
        if address not in self.named and len(self.named) < LOGGED_SOURCES:
            self.named.add(address)
            self.log(f"dropping datagrams from {address}: not an allowed source")
        now = self.clock()
        if now - self.reported >= REPORT_EVERY:
            self.reported = now
            self.log(f"{self.dropped:,} datagrams from other sources dropped so far")
        return False


def serve(sock, collector, keep, stop=lambda: False, log=log):
    """Receive datagrams on the bound `sock` (its timeout is the idle flush) into `collector`, those
    `keep(address)` accepts, until `stop()` is true; the entry in progress is written on the way out."""
    count = 0
    try:
        while not stop():
            try:
                raw, sender = sock.recvfrom(65535)
            except socket.timeout:
                collector.flush()  # nothing more is coming for the entry in progress
                continue
            if not keep(sender[0]):
                continue
            collector.feed(raw)
            count += 1
            if count % 1000 == 0:
                log(f"{count} datagrams received")
    finally:
        collector.flush()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Store the Spark's syslog stream as daily text files.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"UDP port to listen on (default {DEFAULT_PORT})")
    parser.add_argument("--dir", type=Path, default=DEFAULT_DIR, help=f"directory for the daily files (default {DEFAULT_DIR})")
    parser.add_argument("--source", action="append", type=source_arg, metavar="ADDR",
                        help="keep datagrams from this address only (repeatable; 'any' keeps every one); "
                             "default: the default route's gateway, read at start")
    args = parser.parse_args(argv)

    sources = resolve_sources(args.source)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.port))
    sock.settimeout(IDLE_FLUSH_SECONDS)
    log(f"listening on UDP {args.port}, writing to {args.dir}")
    try:
        serve(sock, Collector(args.dir), SourceFilter(sources))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
