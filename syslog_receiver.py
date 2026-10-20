#!/usr/bin/env python3
"""Receive the Spark's syslog stream and store it as one plain-text file per day.

    python3 syslog_receiver.py [--port 5514] [--dir syslog]

The gateway sends each security log as a UDP syslog datagram (Logs & Monitoring →
External Log Servers → Syslog Servers), splitting long entries over several
datagrams. This strips the syslog envelope, joins the pieces, and appends
`<received time> <entry>` to syslog/spark-YYYY-MM-DD.log, one entry per line.
spark_logs.py reads those files. Standard library only; keep it running (see the
README for a LaunchAgent).
"""

import argparse
import re
import socket
import sys
from datetime import datetime
from pathlib import Path

DEFAULT_PORT = 5514
DEFAULT_DIR = Path(__file__).resolve().parent / "syslog"
IDLE_FLUSH_SECONDS = 2

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
RFC5424_RE = re.compile(r"^<\d{1,3}>\d+ \S+ \S+ \S+ \S+ \S+ (?:-|\[.*?\]) ?(?P<msg>.*)$", re.DOTALL)
# What the Spark sends: <PRI>Mmm dd hh:mm:ss HOSTNAME MSG (no tag)
BSD_RE = re.compile(r"^<\d{1,3}>[A-Z][a-z]{2} {1,2}\d{1,2} \d\d:\d\d:\d\d \S+ (?P<msg>.*)$", re.DOTALL)


def envelope(raw):
    """Return (starts_an_entry, text): the message without its syslog envelope,
    or the datagram itself when it has none (a continuation of the previous entry)."""
    text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
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


def main(argv=None):
    parser = argparse.ArgumentParser(description="Store the Spark's syslog stream as daily text files.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"UDP port to listen on (default {DEFAULT_PORT})")
    parser.add_argument("--dir", type=Path, default=DEFAULT_DIR, help=f"directory for the daily files (default {DEFAULT_DIR})")
    args = parser.parse_args(argv)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.port))
    sock.settimeout(IDLE_FLUSH_SECONDS)
    collector = Collector(args.dir)
    print(f"listening on UDP {args.port}, writing to {args.dir}", flush=True)
    count = 0
    try:
        while True:
            try:
                raw, _ = sock.recvfrom(65535)
            except socket.timeout:
                collector.flush()  # nothing more is coming for the entry in progress
                continue
            collector.feed(raw)
            count += 1
            if count % 1000 == 0:
                print(f"{count} datagrams received", flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        collector.flush()


if __name__ == "__main__":
    sys.exit(main())
