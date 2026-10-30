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
Lookups go first to at most --max-inbound sources that probed --min-inbound-hits times,
then to the --max-ips busiest outbound addresses reached --min-ip-hits times, then to
outbound names (the hunting signal; hosts under ALLOWED_SUFFIXES and syslog/allow.txt are
skipped), where FAMILY_HOSTS or more hosts under one apex are looked up once, as the apex.
Indicators already in the feed, or checked within --recheck-days (syslog/checked.json),
are skipped, and --max-lookups caps a run so it fits the free API's daily quota.
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
# Hosts under one apex that make a family: a CDN's tail of hostnames (rr2---sn-….googlevideo.com,
# ….cdn.example) is one service, looked up once as the apex. Fewer hosts stay separate lookups, so
# an infected device's one host under a dynamic-DNS or hosting apex keeps its own verdict. Hosts
# under a shared platform (x.netlify.app: one tenant among millions, vt_check.SHARED_PLATFORMS)
# never make a family however many there are: the platform's apex is always clean.
FAMILY_HOSTS = 3
# Second-level labels under a two-letter country code that are registries, not registrants
# (co.uk, com.au, ac.jp, go.jp): the apex of a host under them has three labels.
SECOND_LEVEL = frozenset({"co", "com", "net", "org", "ac", "gov", "edu", "or", "ne", "go", "lg", "gob", "nhs", "sch",
                          "k12", "muni"})


# The duplicate check lives in vt_check (one implementation for every insert path); these names stay
# for the callers and tests that reach it through spark_logs.
FeedMembers = vt_check.FeedMembers
feed_members = vt_check.feed_members


def allowed(name, suffixes=ALLOWED_SUFFIXES):
    """True when `name` is one of the allowed vendor domains or a host under one of them."""
    labels = name.lower().rstrip(".").split(".")
    return any(".".join(labels[i:]) in suffixes for i in range(len(labels)))


def apex(name):
    """The registrable domain of `name`, near enough: its last two labels, or three under a
    second-level registry of a country code (SECOND_LEVEL)."""
    labels = name.lower().rstrip(".").split(".")
    if len(labels) >= 3 and labels[-2] in SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def candidate_names(outbound, allow=ALLOWED_SUFFIXES):
    """The outbound host names worth a lookup: not addresses, not under an allowed vendor domain."""
    return [i for i in outbound if _ip(i) is None and not allowed(i, allow)]


def families(names):
    """The apexes that FAMILY_HOSTS or more of `names` share, each with its hosts; a shared
    platform's apex never makes one, so its hosts stay lone."""
    by_apex = {}
    for name in names:
        by_apex.setdefault(apex(name), []).append(name)
    return {a: sorted(hosts) for a, hosts in by_apex.items()
            if len(hosts) >= FAMILY_HOSTS and a not in vt_check.SHARED_PLATFORMS}


def members(names, indicator):
    """The names `indicator` stands for: the hosts under it when it is a family apex, else itself."""
    return families(names).get(indicator, [indicator])


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
            try:
                value = urlsplit(value).hostname or ""
            except ValueError:  # "http://[::1": a malformed URL costs only its own name
                continue
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
           min_ip_hits=3, min_inbound_hits=5, max_inbound=20, max_ips=40):
    """Indicators still worth a lookup, grouped in the order they are checked, busiest first.

    "inbound": sources that probed at least min_inbound_hits times, at most max_inbound of
    them a run (persistent probing, not one-off background noise); "ips": the max_ips busiest
    outbound addresses reached at least min_ip_hits times (a C2 reached by address recurs,
    a CDN edge does not); "names": every outbound host name not under an allowed vendor
    domain (the hunting signal), where FAMILY_HOSTS or more hosts under one apex are one
    entry, the apex, counted as their sum. The caps give the first two groups a share of
    --max-lookups that the names cannot take. Feed members and recent cache entries are
    left out.
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

    candidates = candidate_names(outbound, allow)
    grouped = families(candidates)
    in_family = {h for hosts in grouped.values() for h in hosts}
    # entry (a family apex or a lone host) -> how often it was reached
    names = {family: sum(outbound[h]["count"] for h in hosts) for family, hosts in grouped.items()}
    names.update((h, outbound[h]["count"]) for h in candidates if h not in in_family)
    ips = [i for i in outbound if _ip(i) is not None and outbound[i]["count"] >= min_ip_hits]
    inbound = [i for i in found["inbound"] if found["inbound"][i] >= min_inbound_hits]
    return {
        "inbound": busiest(inbound, lambda i: found["inbound"][i])[:max_inbound],
        "ips": busiest(ips, lambda i: outbound[i]["count"])[:max_ips],
        "names": busiest(names, names.__getitem__),
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
          recheck_days=30, allow=ALLOWED_SUFFIXES, min_ip_hits=3, min_inbound_hits=5, max_inbound=20, max_ips=40,
          delay=vt_check.FREE_API_DELAY, sleep=time.sleep, out=print):
    """Look the selected indicators up, inbound first: add flagged inbound sources, report flagged destinations."""
    today = today or date.today().isoformat()
    cache = load_cache(cache_path)
    in_feed = feed_members(Path(feed_path).read_text())
    groups = select(found, in_feed, cache, today, recheck_days, allow=allow, min_ip_hits=min_ip_hits,
                    min_inbound_hits=min_inbound_hits, max_inbound=max_inbound, max_ips=max_ips)
    picked, skipped = budget(groups, max_lookups)
    inbound, outbound = picked["inbound"], picked["ips"] + picked["names"]
    names = candidate_names(found["outbound"], allow)
    report = {"added": [], "outbound_hits": [], "clean": 0, "not_found": 0, "skipped": skipped, "quota": False,
              "stamped": []}

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
            hosts = members(names, r.indicator)
            devices = sorted({d for h in hosts for d in found["outbound"][h]["devices"]})
            report["outbound_hits"].append((r.indicator, r.detail.split(" -> ")[0], devices, hosts))
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
                        help="look the candidates up (key from REPUTATION_API_KEY, VT_API_KEY or the Keychain)")
    parser.add_argument("--max-lookups", type=int, default=400,
                        help="lookups per run: inbound sources, then outbound addresses, then outbound names (default 400)")
    parser.add_argument("--min-ip-hits", type=int, default=3,
                        help="outbound addresses (no name) are looked up once reached this often (default 3)")
    parser.add_argument("--min-inbound-hits", type=int, default=5,
                        help="inbound sources are looked up once they probed this often (default 5)")
    parser.add_argument("--max-inbound", type=int, default=20,
                        help="inbound sources looked up per run, busiest first (default 20)")
    parser.add_argument("--max-ips", type=int, default=40,
                        help="outbound addresses looked up per run, busiest first (default 40)")
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
    thresholds = dict(min_ip_hits=args.min_ip_hits, min_inbound_hits=args.min_inbound_hits, max_inbound=args.max_inbound,
                      max_ips=args.max_ips)
    groups = select(found, in_feed, cache, today, args.recheck_days, allow=allow, **thresholds)
    grouped = families(candidate_names(found["outbound"], allow))
    hosts = {entry: grouped.get(entry, [entry]) for entry in groups["names"]}
    apexes = sum(1 for h in hosts.values() if len(h) > 1)
    say = lambda *a: print(*a, flush=True)
    say(f"{len(found['inbound'])} inbound sources and {len(found['outbound'])} outbound destinations in the last "
        f"{args.days} day(s); to check: {len(groups['inbound'])} inbound sources, {len(groups['ips'])} outbound addresses, "
        f"{len(groups['names'])} outbound names ({apexes} family apexes)")

    if not args.check:
        outbound = found["outbound"]
        vendor = sum(1 for i in outbound if _ip(i) is None and allowed(i, allow))
        headers = {
            "inbound": f"inbound sources: {len(groups['inbound'])} to check (seen {args.min_inbound_hits}+ times, "
                       f"at most {args.max_inbound} a run)",
            "ips": f"outbound addresses: {len(groups['ips'])} to check (seen {args.min_ip_hits}+ times, "
                   f"at most {args.max_ips} a run)",
            "names": f"outbound names: {len(groups['names'])} to check ({apexes} family apexes of {FAMILY_HOSTS}+ hosts; "
                     f"{vendor} under allowed vendor domains skipped)",
        }
        for group, indicators in groups.items():
            say(headers[group])
            for i in indicators:
                if group == "inbound":
                    say(f"  {i:40} x{found['inbound'][i]}")
                elif group == "names" and len(hosts[i]) > 1:
                    count = sum(outbound[h]["count"] for h in hosts[i])
                    devices = sorted({d for h in hosts[i] for d in outbound[h]["devices"]})
                    say(f"  {i:40} x{count}  {len(hosts[i])} hosts, from {', '.join(devices)}")
                else:
                    say(f"  {i:40} x{outbound[i]['count']}  from {', '.join(outbound[i]['devices'])}")
        return 0

    key = vt_check.api_key()
    if not key:
        parser.error(vt_check.NO_KEY_HELP)
    report = check(found, args.feed, args.dir / CACHE_NAME, vt_check.make_fetch(key), today=today,
                   max_lookups=args.max_lookups, recheck_days=args.recheck_days, allow=allow, **thresholds,
                   delay=args.delay, out=say)
    say(f"Added to the feed: {len(report['added'])}  clean: {report['clean']}  unknown to the service: {report['not_found']}"
        f"  left for another day: {len(report['skipped'])}")
    for indicator, ratio, devices, family in report["outbound_hits"]:
        say(f"OUTBOUND HIT  {indicator}  ({ratio})  reached by {', '.join(devices)}  <- check these devices")
        if len(family) > 1:
            say(f"  the family's hosts: {', '.join(family)}")
    if report["quota"]:
        say("Lookup quota reached; rerun tomorrow for the rest.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
