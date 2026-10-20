#!/usr/bin/env python3
"""Mine the Spark's syslog capture for indicators and check them on VirusTotal.

    python3 spark_logs.py                 # list what the last day's logs would check
    python3 spark_logs.py --check         # look them up (needs VT_API_KEY)
    python3 spark_logs.py --days 3 --check --max-lookups 300

Reads syslog/spark-YYYY-MM-DD.log (written by syslog_receiver.py) and pulls out:
  inbound  - public addresses that probed the WAN; the ones VirusTotal flags are
             ADDED to the feed (they are attacker-side, blocking them costs nothing)
  outbound - names or addresses LAN devices connected to; hits are only REPORTED,
             with the devices that talked to them, because an outbound hit means
             "look at that device", not just "block the address"
Indicators already in the feed, or checked within --recheck-days (syslog/checked.json),
are skipped, and --max-lookups caps a run so it fits the free API's daily quota.
"""

import argparse
import ipaddress
import json
import os
import re
import sys
import time
from collections import Counter
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import vt_check

DEFAULT_DIR = Path(__file__).resolve().parent / "syslog"
CACHE_NAME = "checked.json"
PAIR_RE = re.compile(r'(?:^|\s)(?P<key>[A-Za-z][A-Za-z0-9_ .-]*?)="(?P<value>[^"]*)"')
NAME_KEYS = ("resource", "destination_domain_name", "tls_server_host_name", "sni")
RATIO_RE = re.compile(r"(\d+)/(\d+) malicious")


class FeedMembers:
    """What the feed already blocks: its values, plus any address inside its IP Range rows."""

    def __init__(self, text):
        self.values = vt_check.feed_values(text)
        self.ranges = []
        for line in text.splitlines():
            fields = line.split(",")
            if len(fields) == 7 and fields[2].strip() == "IP Range" and "-" in fields[1]:
                start, _, end = fields[1].partition("-")
                try:
                    self.ranges.append((ipaddress.ip_address(start.strip()), ipaddress.ip_address(end.strip())))
                except ValueError:
                    continue

    def __contains__(self, indicator):
        if indicator.lower() in self.values:
            return True
        ip = _ip(indicator)
        return ip is not None and any(start <= ip <= end for start, end in self.ranges if ip.version == start.version)


def feed_members(text):
    return FeedMembers(text)


def parse_entry(line):
    """The entry's key="value" pairs, plus "received" from the receiver's prefix."""
    received, _, rest = line.partition(" ")
    entry = {"received": received}
    for m in PAIR_RE.finditer(rest):
        entry[m.group("key").strip()] = m.group("value")
    return entry


def _ip(text):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _host_name(entry):
    """The most specific real host name the entry carries, if any."""
    for key in NAME_KEYS:
        value = entry.get(key, "").strip()
        if not value or value.startswith("*"):
            continue
        if "://" in value:
            value = urlsplit(value).hostname or ""
        else:
            value = value.split("/")[0].split(":")[0]
        try:
            ioc_type, value = vt_check.classify(value)
        except ValueError:
            continue
        if ioc_type == "Domain":
            return value
    return None


def candidate(entry, wan_ip=None):
    """(direction, indicator, peer) for an entry worth checking, else None.

    inbound: a public source reaching our WAN address; indicator = that source.
    outbound: a LAN device reaching a public destination; indicator = the
    destination's host name when the entry names one, else its address.
    """
    src, dst = _ip(entry.get("src", "")), _ip(entry.get("dst", ""))
    if src is None or dst is None:
        return None
    if src.is_global and (str(dst) == wan_ip or dst.is_global):
        return "inbound", str(src), str(dst)
    if src.is_private and dst.is_global and entry.get("outzone") != "Local" and str(dst) != wan_ip:
        return "outbound", _host_name(entry) or str(dst), str(src)
    return None


def _learn_wan_ip(entries):
    nats = Counter(e["xlatesrc"] for e in entries if _ip(e.get("xlatesrc", "")) and _ip(e["xlatesrc"]).is_global)
    return nats.most_common(1)[0][0] if nats else None


def collect(directory, days=1, today=None, wan_ip=None):
    """Distinct indicators seen in the last `days` daily files, with counts (and devices for outbound)."""
    today = date.fromisoformat(today) if today else date.today()
    entries = []
    for back in range(days):
        path = Path(directory) / f"spark-{today - timedelta(days=back):%Y-%m-%d}.log"
        if path.exists():
            with path.open(encoding="utf-8") as f:
                entries.extend(parse_entry(line.rstrip("\n")) for line in f if line.strip())
    wan_ip = wan_ip or _learn_wan_ip(entries)
    inbound, outbound = Counter(), {}
    for entry in entries:
        found = candidate(entry, wan_ip)
        if not found:
            continue
        direction, indicator, peer = found
        if direction == "inbound":
            inbound[indicator] += 1
        else:
            item = outbound.setdefault(indicator, {"count": 0, "devices": []})
            item["count"] += 1
            if peer not in item["devices"]:
                item["devices"].append(peer)
    for item in outbound.values():
        item["devices"].sort()
    return {"inbound": dict(inbound), "outbound": outbound}


def select(found, in_feed, cache, today, recheck_days=30):
    """Indicators still worth a lookup, busiest first: not in the feed, not checked recently."""
    today = date.fromisoformat(today)

    def fresh(indicator):
        if indicator.lower() in in_feed:
            return False
        checked = cache.get(indicator, {}).get("checked")
        return not checked or date.fromisoformat(checked) <= today - timedelta(days=recheck_days)

    inbound = sorted((i for i in found["inbound"] if fresh(i)), key=lambda i: -found["inbound"][i])
    outbound = sorted((i for i in found["outbound"] if fresh(i)), key=lambda i: -found["outbound"][i]["count"])
    return inbound, outbound


def load_cache(path):
    path = Path(path)
    return json.loads(path.read_text()) if path.exists() else {}


def check(found, feed_path, cache_path, fetch, *, today=None, max_lookups=None, min_malicious=None,
          recheck_days=30, delay=vt_check.FREE_API_DELAY, sleep=time.sleep, out=print):
    """Look the selected indicators up: add flagged inbound sources, report flagged outbound ones."""
    today = today or date.today().isoformat()
    cache = load_cache(cache_path)
    in_feed = feed_members(Path(feed_path).read_text())
    inbound, outbound = select(found, in_feed, cache, today, recheck_days)
    if max_lookups is not None:
        budget = max(0, max_lookups)
        inbound, outbound, skipped = inbound[:budget], outbound[:max(0, budget - len(inbound))], \
            inbound[budget:] + outbound[max(0, budget - len(inbound)):]
    else:
        skipped = []
    report = {"added": [], "outbound_hits": [], "clean": 0, "not_found": 0, "skipped": skipped, "quota": False}

    def run(items, label, dry_run):
        if not items:
            return []
        return vt_check.run([(i, label) for i in items], feed_path, fetch, min_malicious=min_malicious,
                            dry_run=dry_run, delay=delay, sleep=sleep, today=today, out=out)

    results = run(inbound, f"Inbound probe of WAN - Spark syslog {today}", dry_run=False)
    if inbound and outbound and not any(r.status == "quota" for r in results):
        sleep(delay)
    if not any(r.status == "quota" for r in results):
        results += run(outbound, f"Outbound destination - Spark syslog {today}", dry_run=True)

    for r in results:
        ratio = RATIO_RE.search(r.detail)
        if r.status in ("added", "clean", "would-add") and ratio:
            cache[r.indicator] = {"checked": today, "malicious": int(ratio.group(1)), "total": int(ratio.group(2))}
        elif r.status == "not-found":
            cache[r.indicator] = {"checked": today, "malicious": 0, "total": 0}
            report["not_found"] += 1
        if r.status == "added":
            report["added"].append(r.indicator)
        elif r.status == "would-add":
            report["outbound_hits"].append((r.indicator, r.detail.split(" -> ")[0], found["outbound"][r.indicator]["devices"]))
        elif r.status == "clean":
            report["clean"] += 1
        elif r.status == "quota":
            report["quota"] = True
    Path(cache_path).write_text(json.dumps(cache, indent=1, sort_keys=True))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Mine the Spark's syslog capture for indicators to check.")
    parser.add_argument("--dir", type=Path, default=DEFAULT_DIR, help="syslog capture directory")
    parser.add_argument("--days", type=int, default=1, help="how many daily files to read, ending today (default 1)")
    parser.add_argument("--check", action="store_true", help="look the candidates up on VirusTotal (needs VT_API_KEY)")
    parser.add_argument("--max-lookups", type=int, default=200, help="lookups per run, inbound first (default 200)")
    parser.add_argument("--recheck-days", type=int, default=30, help="days before an indicator is looked up again")
    parser.add_argument("--feed", type=Path, default=vt_check.FEED, help="feed CSV to append confirmed inbound sources to")
    parser.add_argument("--wan-ip", help="the gateway's public address (learned from the logs when omitted)")
    parser.add_argument("--delay", type=float, default=vt_check.FREE_API_DELAY, help="seconds between lookups")
    parser.add_argument("--today", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    today = args.today or date.today().isoformat()
    found = collect(args.dir, days=args.days, today=today, wan_ip=args.wan_ip)
    cache = load_cache(args.dir / CACHE_NAME)
    in_feed = feed_members(args.feed.read_text()) if args.feed.exists() else set()
    inbound, outbound = select(found, in_feed, cache, today, args.recheck_days)
    say = lambda *a: print(*a, flush=True)
    say(f"{len(found['inbound'])} inbound sources and {len(found['outbound'])} outbound destinations in the last "
        f"{args.days} day(s); {len(inbound)} and {len(outbound)} still to check")

    if not args.check:
        for i in inbound:
            say(f"  inbound   {i:40} x{found['inbound'][i]}")
        for i in outbound:
            item = found["outbound"][i]
            say(f"  outbound  {i:40} x{item['count']}  from {', '.join(item['devices'])}")
        return 0

    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key:
        parser.error("set the VT_API_KEY environment variable to your VirusTotal API key")
    report = check(found, args.feed, args.dir / CACHE_NAME, vt_check.make_fetch(api_key), today=today,
                   max_lookups=args.max_lookups, recheck_days=args.recheck_days, delay=args.delay, out=say)
    say(f"Added to the feed: {len(report['added'])}  clean: {report['clean']}  unknown to VirusTotal: {report['not_found']}"
        f"  left for another day: {len(report['skipped'])}")
    for indicator, ratio, devices in report["outbound_hits"]:
        say(f"OUTBOUND HIT  {indicator}  ({ratio})  reached by {', '.join(devices)}  <- check these devices")
    if report["quota"]:
        say("VirusTotal quota reached; rerun tomorrow for the rest.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
