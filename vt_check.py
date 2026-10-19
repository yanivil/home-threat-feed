#!/usr/bin/env python3
"""Check indicators against VirusTotal and add the malicious ones to the Spark IoC feed.

    export VT_API_KEY=...        # your VirusTotal API key (never commit it)
    python3 vt_check.py evil.com 203.0.113.7 https://bad.example/x <sha256>
    python3 vt_check.py -f iocs.txt --dry-run

An indicators file has one indicator per line, optionally followed by whitespace
and a label (group, source...) that goes into the COMMENT column. Tab-separated
label fields are joined with " - ". Blank lines and lines starting with # are skipped.
Defanged input (evil[.]com, hxxps://...) is accepted.
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, namedtuple
from datetime import date
from pathlib import Path

API_BASE = "https://www.virustotal.com/api/v3"
FEED = Path(__file__).resolve().parent / "spark-ioc-feed.csv"
FREE_API_DELAY = 15  # free key allows 4 lookups per minute

HASH_TYPES = {32: "MD5", 40: "SHA1", 64: "SHA256"}
HEX_RE = re.compile(r"[0-9a-f]+")
DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)"
    r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})"
)

Result = namedtuple("Result", "indicator status detail")


class VTError(Exception):
    """VirusTotal refused the request in a way that makes continuing pointless."""


def refang(text):
    text = text.strip()
    for defanged, plain in (("[.]", "."), ("(.)", "."), ("[:]", ":")):
        text = text.replace(defanged, plain)
    return re.sub(r"^hxxp", "http", text, flags=re.IGNORECASE)


def classify(raw):
    """Return (feed TYPE, normalised value), or raise ValueError."""
    value = refang(raw)
    if re.match(r"https?://", value, re.IGNORECASE):
        if "," in value or any(c.isspace() for c in value):
            raise ValueError("URL contains a comma or whitespace")
        return "URL", value
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        if not ip.is_global:
            raise ValueError("not a public IP address")
        return "IP", str(ip)
    lowered = value.lower().rstrip(".")
    if HEX_RE.fullmatch(lowered) and len(lowered) in HASH_TYPES:
        return HASH_TYPES[len(lowered)], lowered
    if DOMAIN_RE.fullmatch(lowered):
        return "Domain", lowered
    raise ValueError("not an IP, domain, URL, MD5, SHA1 or SHA256")


def api_path(ioc_type, value):
    if ioc_type == "IP":
        return f"/ip_addresses/{value}"
    if ioc_type == "Domain":
        return f"/domains/{value}"
    if ioc_type == "URL":
        return "/urls/" + base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    return f"/files/{value}"


def confidence(malicious):
    if malicious >= 10:
        return "high"
    if malicious >= 5:
        return "medium"
    return "low"


def feed_row(ioc_type, value, stats, label, today):
    malicious = stats.get("malicious", 0)
    name = f"vt-{ioc_type.lower()}-{hashlib.sha1(value.encode()).hexdigest()[:10]}"
    product = "AV" if ioc_type in HASH_TYPES.values() else "AB"
    comment = f"VT {malicious}/{sum(stats.values())} malicious {today}"
    label = " ".join(label.replace(",", " ").split())
    if label:
        comment = f"{label} - {comment}"
    return ",".join([name, value, ioc_type, confidence(malicious), "high", product, comment])


def feed_values(text):
    values = set()
    for line in text.splitlines():
        fields = line.split(",")
        if not line.startswith("#") and len(fields) > 1:
            values.add(fields[1].strip().lower())
    return values


def run(indicators, feed_path, fetch, *, min_malicious=3, dry_run=False,
        delay=FREE_API_DELAY, sleep=time.sleep, today=None, out=print):
    """Look up each indicator and append rows for the malicious ones to the feed.

    `indicators` holds strings or (indicator, label) pairs. `fetch(path)` returns
    (HTTP status, parsed JSON) for a VirusTotal API v3 path.
    """
    today = today or date.today().isoformat()
    feed_path = Path(feed_path)
    text = feed_path.read_text()
    in_feed = feed_values(text)
    needs_newline = bool(text) and not text.endswith("\n")
    checked = set()
    results = []
    stopped = False

    def record(raw, status, detail=""):
        results.append(Result(raw, status, detail))
        out(f"{raw}: {status}" + (f" ({detail})" if detail else ""))

    for item in indicators:
        raw, label = (item, "") if isinstance(item, str) else item
        if stopped:
            record(raw, "unchecked")
            continue
        try:
            ioc_type, value = classify(raw)
        except ValueError as e:
            record(raw, "invalid", str(e))
            continue
        if value.lower() in in_feed:
            record(raw, "in-feed")
            continue
        if value.lower() in checked:
            record(raw, "duplicate")
            continue
        if checked:
            sleep(delay)
        checked.add(value.lower())

        status, body = fetch(api_path(ioc_type, value))
        error = (body.get("error") or {}).get("code", "") if isinstance(body, dict) else ""
        if status in (401, 403):
            raise VTError(f"VirusTotal refused the API key: HTTP {status} {error}")
        if status == 429:
            stopped = True
            record(raw, "quota", f"{error} - stopping")
            continue
        if status == 404:
            record(raw, "not-found", "VirusTotal has no record")
            continue
        if status != 200:
            record(raw, "error", f"HTTP {status} {error}")
            continue

        stats = body["data"]["attributes"].get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        ratio = f"{ioc_type} {malicious}/{sum(stats.values())} malicious"
        if malicious < min_malicious:
            record(raw, "clean", ratio)
            continue
        row = feed_row(ioc_type, value, stats, label, today)
        if dry_run:
            record(raw, "would-add", f"{ratio} -> {row}")
            continue
        with feed_path.open("a", newline="\n") as f:
            f.write(("\n" if needs_newline else "") + row + "\n")
        needs_newline = False
        in_feed.add(value.lower())
        record(raw, "added", ratio)

    return results


def make_fetch(api_key):
    def fetch(path):
        request = urllib.request.Request(
            API_BASE + path, headers={"x-apikey": api_key, "Accept": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.load(e)
            except ValueError:
                return e.code, {}

    return fetch


def read_indicators(files, args, label=""):
    """Return (indicator, label) pairs from command-line args, then files."""
    entries = [(a.strip(), label) for a in args if a.strip()]
    for name in files:
        text = sys.stdin.read() if name == "-" else Path(name).read_text()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            own = ""
            if len(parts) > 1:
                own = " - ".join(p.strip() for p in parts[1].split("\t") if p.strip())
            entries.append((parts[0], own or label))
    return entries


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check indicators on VirusTotal and add the malicious ones to the Spark IoC feed."
    )
    parser.add_argument("indicators", nargs="*", help="IPs, domains, URLs or MD5/SHA1/SHA256 hashes")
    parser.add_argument("-f", "--file", action="append", default=[],
                        help="file with one indicator per line, optionally followed by a label (- for stdin)")
    parser.add_argument("-l", "--label", default="",
                        help="COMMENT text for indicators without a label of their own")
    parser.add_argument("--min-malicious", type=int, default=3,
                        help="engines that must flag an indicator before it is added (default 3)")
    parser.add_argument("--feed", type=Path, default=FEED, help="feed CSV to append to")
    parser.add_argument("--delay", type=float, default=FREE_API_DELAY,
                        help=f"seconds between lookups (default {FREE_API_DELAY}, the free-key rate)")
    parser.add_argument("--dry-run", action="store_true", help="show what would be added, change nothing")
    args = parser.parse_args(argv)

    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key:
        parser.error("set the VT_API_KEY environment variable to your VirusTotal API key")
    entries = read_indicators(args.file, args.indicators, args.label)
    if not entries:
        parser.error("no indicators given")

    say = lambda *a: print(*a, flush=True)
    say(f"Checking {len(entries)} indicators against VirusTotal "
        f"(min {args.min_malicious} malicious detections{', dry run' if args.dry_run else ''})")
    try:
        results = run(entries, args.feed, make_fetch(api_key), min_malicious=args.min_malicious,
                      dry_run=args.dry_run, delay=args.delay, out=say)
    except VTError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    counts = Counter(r.status for r in results)
    say("Summary: " + ", ".join(f"{n} {status}" for status, n in counts.most_common()))
    if counts["quota"]:
        say(f"VirusTotal quota reached; {counts['unchecked'] + 1} indicators still need checking.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
