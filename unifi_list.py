"""Render unifi-blocklist.txt, the feed's addresses as a bare IPv4 list for UniFi gateways.

UniFi Network 11 refreshes a "Network List" from a URL, but the URL must return nothing but
addresses, one per line, IPv4 or IPv6 but not both: the CSV the Spark reads is of no use to it.
This list is every `IP` row and every `IP Range` row (as CIDR) of the feed, in the feed's order,
an address already inside a range left out, IPv6 rows left out (none today; they would need a
second list). The rows themselves, the CSV and its lint are untouched: the list is derived.

It is kept in step by GitHub, not by the Mac's jobs: .github/workflows/unifi-list.yml renders
and commits it after every push that changes the feed, and the monthly re-check renders it
before its own commit (see docs/system-design.md, D10).

    python3 unifi_list.py [spark-ioc-feed.csv [unifi-blocklist.txt]]    # writes the list when it differs
"""

import ipaddress
import sys
from pathlib import Path

FEED = Path(__file__).resolve().parent / "spark-ioc-feed.csv"
OUT = Path(__file__).resolve().parent / "unifi-blocklist.txt"


def _rows(text):
    """(VALUE, TYPE) of every row of the feed `text`, in order; the header, comments and lines
    too short to be rows are skipped."""
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        fields = line.split(",")
        if len(fields) < 3:
            continue
        yield fields[1].strip(), fields[2].strip()


def _networks(value):
    """The IPv4 networks that cover the IP Range `value` (`a.b.c.d-a.b.c.e`); [] for anything else."""
    start, sep, end = value.partition("-")
    if not sep:
        return []
    try:
        first, last = ipaddress.ip_address(start.strip()), ipaddress.ip_address(end.strip())
        if first.version != 4 or last.version != 4 or first > last:
            return []
        return list(ipaddress.summarize_address_range(first, last))
    except ValueError:
        return []


def render(text):
    """The list for the feed `text`: one entry per line, each an IPv4 address or an IPv4 network in
    CIDR notation, in the feed's order, nothing else; '' when the feed holds no IPv4 row. An address
    inside one of the feed's ranges is left out (the range covers it), a value listed twice is listed
    once, and a value the lint would refuse is skipped rather than breaking the list."""
    ranges = [net for value, kind in _rows(text) if kind == "IP Range" for net in _networks(value)]
    lines, seen = [], set()
    for value, kind in _rows(text):
        if kind == "IP":
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                continue
            if ip.version != 4 or any(ip in net for net in ranges):
                continue
            entries = [str(ip)]
        elif kind == "IP Range":
            entries = [str(net) for net in _networks(value)]
        else:
            continue
        for entry in entries:
            if entry not in seen:
                seen.add(entry)
                lines.append(entry)
    return "".join(line + "\n" for line in lines)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    feed = Path(args[0]) if args else FEED
    out = Path(args[1]) if len(args) > 1 else OUT
    text = render(feed.read_text())
    entries = text.count("\n")
    plural = "entries" if entries != 1 else "entry"
    if out.exists() and out.read_text() == text:
        print(f"{out.name}: {entries} {plural}, unchanged")
    else:
        out.write_text(text)
        print(f"{out.name}: {entries} {plural}, written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
