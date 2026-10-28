#!/usr/bin/env python3
"""Mine the Spark's syslog capture for indicators and check them on VirusTotal.

    python3 spark_logs.py                 # list what the last day's logs would check
    python3 spark_logs.py --check         # look them up (VT_API_KEY, or the Keychain item)
    python3 spark_logs.py --days 3 --check --max-lookups 300

Reads syslog/spark-YYYY-MM-DD.log (written by syslog_receiver.py) and pulls out:
  outbound - names or addresses LAN devices connected to; hits are only REPORTED,
             with the devices that talked to them, because an outbound hit means
             "look at that device", not just "block the address"
  inbound  - public addresses that probed the WAN; the ones VirusTotal flags are
             ADDED to the feed (they are attacker-side, blocking them costs nothing)
Lookups go to outbound names first (the hunting signal; hosts under ALLOWED_SUFFIXES
and syslog/allow.txt are skipped), then outbound addresses reached --min-ip-hits times,
then at most --max-inbound sources that probed --min-inbound-hits times. Indicators
already in the feed, or checked within --recheck-days (syslog/checked.json), are
skipped, and --max-lookups caps a run so it fits the free API's daily quota.
"""

import argparse
import gzip
import ipaddress
import json
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
# A system log line: a program tag, a colon, a space ("rsyslogd: ...", "lua: [AUDIT] ..."). A security
# row starts with a pair (Action="...") or a quote ("ctl"Uuid="..."), never so.
SYSTEM_RE = re.compile(r'(?P<tag>[^\s:="]+): (?P<text>.*)', re.DOTALL)
NAME_KEYS = ("resource", "destination_domain_name", "tls_server_host_name", "sni")
RATIO_RE = re.compile(r"(\d+)/(\d+) malicious")
ALLOW_NAME = "allow.txt"
# The Spark's Threat Prevention blades, as they name themselves in ProductName.
TP_BLADES = ("Anti Malware", "Anti-Bot", "IPS", "SmartDefense", "Threat Emulation", "Anti Virus")
# Vendor apex domains whose hosts LAN devices reach all day; looking them up would only burn quota.
# syslog/allow.txt (one suffix per line, git-ignored) extends this list.
ALLOWED_SUFFIXES = frozenset({
    "apple.com", "icloud.com", "apple-dns.net", "aaplimg.com",
    "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "microsoft.com", "office.com", "office.net", "live.com", "windows.com", "msidentity.com",
    "akamai.net", "akamaiedge.net", "amazonaws.com", "cloudfront.net", "amazon.com",
    "whatsapp.net", "facebook.com", "fbcdn.net", "cloudflare.com", "digicert.com",
    "ntp.org", "quad9.net", "one.one.one.one", "samsungcloudsolution.net",
    "anthropic.com", "openai.com", "chatgpt.com",
})


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


def allowed(name, suffixes=ALLOWED_SUFFIXES):
    """True when `name` is one of the allowed vendor domains or a host under one of them."""
    labels = name.lower().rstrip(".").split(".")
    return any(".".join(labels[i:]) in suffixes for i in range(len(labels)))


def load_allow(path):
    """ALLOWED_SUFFIXES plus the suffixes in `path` (one per line, # comments), when the file exists."""
    path = Path(path)
    extra = set()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            suffix = line.split("#")[0].strip().lower().strip(".")
            if suffix:
                extra.add(suffix)
    return ALLOWED_SUFFIXES | extra


def parse_entry(line):
    """The entry's key="value" pairs, plus "received" from the receiver's prefix. A system log line
    ("<stamp> <tag>: <text>", the Spark's own programs) is {"received", "tag", "system": <text>}
    and none of its pairs: it is never an indicator, a probe or a detection."""
    received, _, rest = line.partition(" ")
    system = SYSTEM_RE.match(rest)
    if system:
        return {"received": received, "tag": system.group("tag"), "system": system.group("text")}
    entry = {"received": received}
    for m in PAIR_RE.finditer(rest):
        entry[m.group("key").strip()] = m.group("value")
    return entry


def is_tp_detection(entry):
    """True for a Threat Prevention row that names a protection or an attack between a source and a
    destination. The statistics rows the blades emit every minute (counters, no addresses) are not."""
    return ("system" not in entry and entry.get("ProductName") in TP_BLADES
            and bool(entry.get("src", "").strip()) and bool(entry.get("dst", "").strip())
            and any(entry.get(key, "").strip() for key in ("Protection Name", "attack", "malware_action", "Protection Type")))


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
    if "system" in entry:
        return None
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


def _open_capture(path):
    """The day's file as text, plain or as the .gz that syslog_retention.py leaves after a
    week; None when the day has no file."""
    if path.exists():
        return path.open(encoding="utf-8")
    compressed = path.with_name(path.name + ".gz")
    if compressed.exists():
        return gzip.open(compressed, "rt", encoding="utf-8")
    return None


def collect(directory, days=1, today=None, wan_ip=None):
    """Distinct indicators seen in the last `days` daily files, with counts (and devices for outbound)."""
    today = date.fromisoformat(today) if today else date.today()
    entries = []
    for back in range(days):
        f = _open_capture(Path(directory) / f"spark-{today - timedelta(days=back):%Y-%m-%d}.log")
        if f:
            with f:
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


def select(found, in_feed, cache, today, recheck_days=30, *, allow=ALLOWED_SUFFIXES,
           min_ip_hits=3, min_inbound_hits=5, max_inbound=20):
    """Indicators still worth a lookup, grouped in the order they are checked, busiest first.

    "names": every outbound host name not under an allowed vendor domain (the hunting
    signal); "ips": outbound addresses reached at least min_ip_hits times (a C2 reached
    by address recurs, a CDN edge does not); "inbound": sources that probed at least
    min_inbound_hits times, at most max_inbound of them a run (persistent probing, not
    one-off background noise). Feed members and recent cache entries are left out.
    """
    today = date.fromisoformat(today)
    outbound = found["outbound"]

    def fresh(indicator):
        if indicator.lower() in in_feed:
            return False
        checked = cache.get(indicator, {}).get("checked")
        return not checked or date.fromisoformat(checked) <= today - timedelta(days=recheck_days)

    def busiest(indicators, count):
        return sorted((i for i in indicators if fresh(i)), key=lambda i: -count(i))

    names = [i for i in outbound if _ip(i) is None and not allowed(i, allow)]
    ips = [i for i in outbound if _ip(i) is not None and outbound[i]["count"] >= min_ip_hits]
    inbound = [i for i in found["inbound"] if found["inbound"][i] >= min_inbound_hits]
    return {
        "names": busiest(names, lambda i: outbound[i]["count"]),
        "ips": busiest(ips, lambda i: outbound[i]["count"]),
        "inbound": busiest(inbound, lambda i: found["inbound"][i])[:max_inbound],
    }


def budget(groups, max_lookups):
    """The groups cut to max_lookups in order, and the indicators left for another day."""
    if max_lookups is None:
        return groups, []
    left, picked, skipped = max(0, max_lookups), {}, []
    for group, items in groups.items():
        picked[group], skipped = items[:left], skipped + items[left:]
        left -= len(picked[group])
    return picked, skipped


def load_cache(path):
    path = Path(path)
    return json.loads(path.read_text()) if path.exists() else {}


def check(found, feed_path, cache_path, fetch, *, today=None, max_lookups=None, min_malicious=None,
          recheck_days=30, allow=ALLOWED_SUFFIXES, min_ip_hits=3, min_inbound_hits=5, max_inbound=20,
          delay=vt_check.FREE_API_DELAY, sleep=time.sleep, out=print):
    """Look the selected indicators up, outbound first: report flagged destinations, add flagged inbound sources."""
    today = today or date.today().isoformat()
    cache = load_cache(cache_path)
    in_feed = feed_members(Path(feed_path).read_text())
    groups = select(found, in_feed, cache, today, recheck_days, allow=allow, min_ip_hits=min_ip_hits,
                    min_inbound_hits=min_inbound_hits, max_inbound=max_inbound)
    picked, skipped = budget(groups, max_lookups)
    outbound, inbound = picked["names"] + picked["ips"], picked["inbound"]
    report = {"added": [], "outbound_hits": [], "clean": 0, "not_found": 0, "skipped": skipped, "quota": False,
              "stamped": []}

    def run(items, label, dry_run):
        if not items:
            return []
        return vt_check.run([(i, label) for i in items], feed_path, fetch, min_malicious=min_malicious,
                            dry_run=dry_run, delay=delay, sleep=sleep, today=today, out=out)

    results = run(outbound, f"Outbound destination - Spark syslog {today}", dry_run=True)
    if outbound and inbound and not any(r.status == "quota" for r in results):
        sleep(delay)
    if not any(r.status == "quota" for r in results):
        results += run(inbound, f"Inbound probe of WAN - Spark syslog {today}", dry_run=False)

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
    # Every inbound source that is a feed IP, the ones just added included, probed us today:
    # note it, so --recheck runs its longer clock from the last sighting (vt_check.SEEN_MAX_AGE).
    report["stamped"] = vt_check.stamp_seen(feed_path, list(found["inbound"]), today=today)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Mine the Spark's syslog capture for indicators to check.")
    parser.add_argument("--dir", type=Path, default=DEFAULT_DIR, help="syslog capture directory")
    parser.add_argument("--days", type=int, default=1, help="how many daily files to read, ending today (default 1)")
    parser.add_argument("--check", action="store_true",
                        help="look the candidates up on VirusTotal (key from VT_API_KEY or the Keychain)")
    parser.add_argument("--max-lookups", type=int, default=400,
                        help="lookups per run: outbound names, then outbound addresses, then inbound sources (default 400)")
    parser.add_argument("--min-ip-hits", type=int, default=3,
                        help="outbound addresses (no name) are looked up once reached this often (default 3)")
    parser.add_argument("--min-inbound-hits", type=int, default=5,
                        help="inbound sources are looked up once they probed this often (default 5)")
    parser.add_argument("--max-inbound", type=int, default=20, help="inbound sources looked up per run (default 20)")
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
    allow = load_allow(args.dir / ALLOW_NAME)
    thresholds = dict(min_ip_hits=args.min_ip_hits, min_inbound_hits=args.min_inbound_hits, max_inbound=args.max_inbound)
    groups = select(found, in_feed, cache, today, args.recheck_days, allow=allow, **thresholds)
    say = lambda *a: print(*a, flush=True)
    say(f"{len(found['inbound'])} inbound sources and {len(found['outbound'])} outbound destinations in the last "
        f"{args.days} day(s); to check: {len(groups['names'])} outbound names, {len(groups['ips'])} outbound addresses, "
        f"{len(groups['inbound'])} inbound sources")

    if not args.check:
        vendor = sum(1 for i in found["outbound"] if _ip(i) is None and allowed(i, allow))
        headers = {
            "names": f"outbound names: {len(groups['names'])} to check ({vendor} under allowed vendor domains skipped)",
            "ips": f"outbound addresses: {len(groups['ips'])} to check (seen {args.min_ip_hits}+ times)",
            "inbound": f"inbound sources: {len(groups['inbound'])} to check (seen {args.min_inbound_hits}+ times, "
                       f"at most {args.max_inbound} a run)",
        }
        for group, indicators in groups.items():
            say(headers[group])
            for i in indicators:
                if group == "inbound":
                    say(f"  {i:40} x{found['inbound'][i]}")
                else:
                    say(f"  {i:40} x{found['outbound'][i]['count']}  from {', '.join(found['outbound'][i]['devices'])}")
        return 0

    key = vt_check.api_key()
    if not key:
        parser.error(vt_check.NO_KEY_HELP)
    report = check(found, args.feed, args.dir / CACHE_NAME, vt_check.make_fetch(key), today=today,
                   max_lookups=args.max_lookups, recheck_days=args.recheck_days, allow=allow, **thresholds,
                   delay=args.delay, out=say)
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
