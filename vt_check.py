#!/usr/bin/env python3
"""Check indicators against VirusTotal and add the malicious ones to the Spark IoC feed.

    export VT_API_KEY=...        # your VirusTotal API key (never commit it)
    python3 vt_check.py evil.com 203.0.113.7 https://bad.example/x <sha256>
    python3 vt_check.py -f iocs.txt --dry-run
    python3 vt_check.py --recheck [--max-age 60] [--dry-run]   # re-verify old feed rows

An indicators file has one indicator per line, optionally followed by whitespace
and a label (group, source...) that goes into the COMMENT column. Tab-separated
label fields are joined with " - ". Blank lines and lines starting with # are skipped.
Defanged input (evil[.]com, hxxps://...) is accepted.

--recheck looks up again every feed row whose COMMENT ends in "VT n/m malicious
YYYY-MM-DD" once that date is old enough for the row's TYPE (IPs 60 days, domains
and URLs 180, hashes never; --max-age DAYS applies DAYS to every type): rows still
flagged by enough engines get a fresh ratio, date and confidence, rows that fell
below are removed. Rows without such a note (hand-written ones) are never touched.
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
from datetime import date, timedelta
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

# The note feed_row() puts at the end of COMMENT; --recheck finds rows by it.
VT_NOTE_RE = re.compile(r"VT (\d+)/(\d+) malicious (\d{4}-\d{2}-\d{2})$")
# Days after which --recheck looks a row up again, per TYPE. Attacker IPs are
# re-leased within weeks and domains re-registered after a year or so, while a
# malicious file stays malicious: hashes are rechecked only when --max-age says so.
MAX_AGE = {"IP": 60, "Domain": 180, "URL": 180}
RECHECK_TYPES = ("IP", "Domain", "URL", "MD5", "SHA1", "SHA256")

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


def lookup(fetch, ioc_type, value):
    """Fetch an indicator's VirusTotal object.

    Return (None, "", last_analysis_stats) on success, or (status, detail, None)
    with status "quota", "not-found" or "error". Raise VTError on a refused key.
    """
    status, body = fetch(api_path(ioc_type, value))
    error = (body.get("error") or {}).get("code", "") if isinstance(body, dict) else ""
    if status in (401, 403):
        raise VTError(f"VirusTotal refused the API key: HTTP {status} {error}")
    if status == 429:
        return "quota", f"{error} - stopping", None
    if status == 404:
        return "not-found", "VirusTotal has no record", None
    if status != 200:
        return "error", f"HTTP {status} {error}", None
    return None, "", body["data"]["attributes"].get("last_analysis_stats", {})


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

        problem, detail, stats = lookup(fetch, ioc_type, value)
        if problem:
            stopped = problem == "quota"
            record(raw, problem, detail)
            continue
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


def recheck(feed_path, fetch, *, max_age=None, min_malicious=3, dry_run=False,
            delay=FREE_API_DELAY, sleep=time.sleep, today=None, out=print):
    """Look up again the feed rows whose VirusTotal check is old enough for their type.

    "Old enough" is MAX_AGE days for the row's TYPE (never for hashes), or
    `max_age` days for every type when given. Rows that `min_malicious` engines
    still flag get a fresh ratio, date and confidence; rows that fell below are
    removed. Every other row, the header and the row order stay exactly as they
    were. The file is rewritten after each change, so a run that stops early
    (quota, Ctrl-C) leaves it consistent.
    """
    today = today or date.today().isoformat()
    today_date = date.fromisoformat(today)
    feed_path = Path(feed_path)
    with feed_path.open(newline="") as f:
        lines = f.read().split("\n")
    results = []
    looked_up = False
    stopped = False

    def record(value, status, detail="", quiet=False):
        results.append(Result(value, status, detail))
        if not quiet:
            out(f"{value}: {status}" + (f" ({detail})" if detail else ""))

    def save():
        with feed_path.open("w", newline="") as f:
            f.write("\n".join(line for line in lines if line is not None))

    for i, line in enumerate(lines):
        fields = line.split(",")
        if line.startswith("#") or len(fields) != 7:
            continue
        value, ioc_type, comment = fields[1], fields[2], fields[6]
        note = VT_NOTE_RE.search(comment)
        try:
            checked = date.fromisoformat(note.group(3)) if note else None
        except ValueError:
            checked = None
        if checked is None or ioc_type not in RECHECK_TYPES:
            record(value, "kept", "no VirusTotal date", quiet=True)
            continue
        age_limit = MAX_AGE.get(ioc_type) if max_age is None else max_age
        if age_limit is None:
            record(value, "kept", f"{ioc_type} rows are not rechecked", quiet=True)
            continue
        if checked > today_date - timedelta(days=age_limit):
            record(value, "kept", f"checked {checked}", quiet=True)
            continue
        if stopped:
            record(value, "unchecked")
            continue
        if looked_up:
            sleep(delay)
        looked_up = True

        problem, detail, stats = lookup(fetch, ioc_type, value)
        if problem:
            stopped = problem == "quota"
            record(value, problem, detail)
            continue
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        change = f"{ioc_type} {note.group(1)}/{note.group(2)} -> {malicious}/{total} malicious"
        if malicious < min_malicious:
            record(value, "would-remove" if dry_run else "removed", change)
            if not dry_run:
                lines[i] = None
                save()
            continue
        fields[3] = confidence(malicious)
        fields[6] = comment[:note.start()] + f"VT {malicious}/{total} malicious {today}"
        record(value, "would-refresh" if dry_run else "refreshed", change)
        if not dry_run:
            lines[i] = ",".join(fields)
            save()

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
    parser.add_argument("--feed", type=Path, default=FEED, help="feed CSV to append to (with --recheck: to rewrite)")
    parser.add_argument("--delay", type=float, default=FREE_API_DELAY,
                        help=f"seconds between lookups (default {FREE_API_DELAY}, the free-key rate)")
    parser.add_argument("--dry-run", action="store_true", help="show what would change, change nothing")
    parser.add_argument("--recheck", action="store_true",
                        help="instead of adding indicators, re-verify the feed's own rows: rows whose "
                             "VirusTotal check is old get a fresh ratio and date, or are removed")
    parser.add_argument("--max-age", type=int, default=None, metavar="DAYS",
                        help="with --recheck, re-verify rows of every type checked DAYS or more days ago "
                             "(0 = every row); default per type: IPs 60, domains and URLs 180, hashes never")
    args = parser.parse_args(argv)

    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key:
        parser.error("set the VT_API_KEY environment variable to your VirusTotal API key")
    entries = read_indicators(args.file, args.indicators, args.label)
    if args.recheck and entries:
        parser.error("--recheck re-verifies the rows already in the feed; do not pass indicators")
    if not args.recheck and not entries:
        parser.error("no indicators given")

    say = lambda *a: print(*a, flush=True)
    mode = f"min {args.min_malicious} malicious detections{', dry run' if args.dry_run else ''}"
    try:
        if args.recheck:
            ages = (f"{args.max_age}+ days ago, every type" if args.max_age is not None
                    else ", ".join(f"{t} {d}+" for t, d in MAX_AGE.items()) + " days ago, hashes never")
            say(f"Re-checking {args.feed.name} rows last verified {ages} on VirusTotal ({mode})")
            results = recheck(args.feed, make_fetch(api_key), max_age=args.max_age,
                              min_malicious=args.min_malicious, dry_run=args.dry_run,
                              delay=args.delay, out=say)
        else:
            say(f"Checking {len(entries)} indicators against VirusTotal ({mode})")
            results = run(entries, args.feed, make_fetch(api_key), min_malicious=args.min_malicious,
                          dry_run=args.dry_run, delay=args.delay, out=say)
    except VTError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    counts = Counter(r.status for r in results)
    say("Summary: " + ", ".join(f"{n} {status}" for status, n in counts.most_common()))
    if counts["quota"]:
        what = "rows" if args.recheck else "indicators"
        say(f"VirusTotal quota reached; {counts['unchecked'] + 1} {what} still need checking.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
