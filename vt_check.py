#!/usr/bin/env python3
"""Check indicators against VirusTotal and add the malicious ones to the Spark IoC feed.

    export VT_API_KEY=...        # your VirusTotal API key (never commit it), or store it
                                 # once in the macOS Keychain (see api_key) and skip this
    python3 vt_check.py evil.com 203.0.113.7 https://bad.example/x <sha256>
    python3 vt_check.py -f iocs.txt --dry-run
    python3 vt_check.py --recheck [--max-age 60] [--dry-run]   # re-verify old feed rows

An indicators file has one indicator per line, optionally followed by whitespace
and a label (group, source...) that goes into the COMMENT column. Tab-separated
label fields are joined with " - ". Blank lines and lines starting with # are skipped.
Defanged input (evil[.]com, hxxps://...) is accepted.

--recheck looks up again every feed row that is due by the dates in its COMMENT: IPs
60 days after their "VT n/m malicious YYYY-MM-DD" note, domains and URLs 180, rows
"added without VirusTotal check YYYY-MM-DD" 90 days after that, hashes never; an IP
"seen in Spark logs YYYY-MM-DD" (the daily check's note for feed IPs that probed the
WAN) is besides never due before 180 days after that sighting. --max-age DAYS applies
DAYS to every row's own date. Rows still flagged by enough engines get a fresh ratio,
date and confidence (an unchecked row becomes a checked one), rows that fell below are
removed. Rows without any date (hand-written ones) are never touched.
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, namedtuple
from datetime import date, timedelta
from pathlib import Path

import keychain

API_BASE = "https://www.virustotal.com/api/v3"
FEED = Path(__file__).resolve().parent / "spark-ioc-feed.csv"
FREE_API_DELAY = 15  # free key allows 4 lookups per minute
QUOTA_WAIT = 61  # after a 429, seconds before the one more try: the minute's four lookups are spent

HASH_TYPES = {32: "MD5", 40: "SHA1", 64: "SHA256"}
HEX_RE = re.compile(r"[0-9a-f]+")
DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)"
    r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})"
)

# Where the VirusTotal key lives when VT_API_KEY is not in the environment:
#   security add-generic-password -s spark-ioc-feed -a VT_API_KEY -w '<key>' -U
KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT = keychain.SERVICE, "VT_API_KEY"
NO_KEY_HELP = (f"set the VT_API_KEY environment variable to your VirusTotal API key, or store it in the "
               f"Keychain: security add-generic-password -s {KEYCHAIN_SERVICE} -a {KEYCHAIN_ACCOUNT} -w '<key>' -U")

# The notes that close a COMMENT: feed_row() ends it with the VirusTotal ratio and date,
# add_trusted() with the day the row was added unchecked. --recheck reads its clock from
# them. "seen in Spark logs <date>" sits before the closing note (stamp_seen) and says when
# the IP last probed this network.
VT_NOTE_RE = re.compile(r"VT (\d+)/(\d+) malicious (\d{4}-\d{2}-\d{2})$")
TRUSTED_NOTE_RE = re.compile(r"added without VirusTotal check (\d{4}-\d{2}-\d{2})$")
SEEN_NOTE_RE = re.compile(r"seen in Spark logs (\d{4}-\d{2}-\d{2})")
# Days after which --recheck looks a row up again, per TYPE. Attacker IPs are
# re-leased within weeks and domains re-registered after a year or so, while a
# malicious file stays malicious: hashes are rechecked only when --max-age says so.
MAX_AGE = {"IP": 60, "Domain": 180, "URL": 180}
# A row added without a check gets its first VirusTotal look 90 days in (hashes never); an
# IP that probed this network is first-hand evidence and waits 180 days after its last
# sighting, whatever its check date, since VirusTotal's count for a scanner decays while
# the scanning goes on. The daily check refreshes a sighting at most every 30 days.
TRUSTED_MAX_AGE = 90
SEEN_MAX_AGE = 180
SEEN_REFRESH_DAYS = 30
RECHECK_TYPES = ("IP", "Domain", "URL", "MD5", "SHA1", "SHA256")
# Hosts whose apex is a shared platform: an attacker's page there is one tenant among millions, so a
# bare entry would block the platform and the platform's own verdict says nothing about a tenant. A
# specific sub-host (x.netlify.app) is the indicator. cyberint_xlsx.py drops the bare apexes with
# this list; spark_logs.py never collapses hosts under one of them into a family.
SHARED_PLATFORMS = {
    "github.com", "githubusercontent.com", "gitlab.com", "google.com", "googleapis.com", "drive.google.com",
    "docs.google.com", "dropbox.com", "microsoft.com", "live.com", "onedrive.live.com", "sharepoint.com",
    "amazonaws.com", "cloudfront.net", "azurewebsites.net", "workers.dev", "pages.dev", "netlify.app",
    "vercel.app", "herokuapp.com", "telegram.org", "t.me", "discord.com", "discordapp.com", "ngrok.io",
    "ngrok-free.app", "pastebin.com", "mega.nz", "anydesk.com", "teamviewer.com", "cloudflare.com",
    "bit.ly", "tinyurl.com", "wetransfer.com", "box.com", "icloud.com", "apple.com", "facebook.com",
    "twitter.com", "x.com", "youtube.com", "linkedin.com", "reddit.com", "medium.com", "wordpress.com",
    "blogspot.com", "weebly.com", "wixsite.com", "simplex.im", "proton.me", "protonmail.com", "gmail.com",
    "somee.com", "sendit.sh", "firebaseio.com", "storyblok.com", "onehub.com",
    "transfer.sh", "fex.net", "sendspace.com", "premiumize.com", "gofile.io", "file.io", "anonfiles.com",
    "mediafire.com", "pixeldrain.com", "catbox.moe", "ufile.io", "filetransfer.io", "temp.sh",
    # e-mail providers that ransomware notes name as contact channels
    "cyberfear.com", "tutanota.com", "tuta.io", "tuta.com", "onionmail.org", "mailfence.com", "cock.li",
    "skiff.com", "outlook.com", "yahoo.com", "mail.ru", "yandex.ru", "zoho.com",
}
# Engines that must flag an indicator before it is added or kept, per TYPE. IPs
# get a higher bar: hosting addresses collect a few blocklist hits just for being
# on a busy provider, and a wrongly blocked IP breaks more than a wrong domain.
MIN_MALICIOUS = {"IP": 5}
DEFAULT_MIN_MALICIOUS = 3

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
        if not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_link_local:
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


def min_for(ioc_type, override=None):
    """Engines needed for `ioc_type`: `override` for every type when given."""
    if override is not None:
        return override
    return MIN_MALICIOUS.get(ioc_type, DEFAULT_MIN_MALICIOUS)


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


def lookup_retrying(fetch, ioc_type, value, sleep=time.sleep):
    """lookup(), with a 429 waited out once (QUOTA_WAIT seconds of `sleep`): a lookup made elsewhere
    (a note, /who) can spend the minute's share of the free key. A second 429 is the quota stop."""
    found = lookup(fetch, ioc_type, value)
    if found[0] == "quota":
        sleep(QUOTA_WAIT)
        found = lookup(fetch, ioc_type, value)
    return found


def run(indicators, feed_path, fetch, *, min_malicious=None, dry_run=False,
        delay=FREE_API_DELAY, sleep=time.sleep, today=None, out=print):
    """Look up each indicator and append rows for the malicious ones to the feed.

    `indicators` holds strings or (indicator, label) pairs. `fetch(path)` returns
    (HTTP status, parsed JSON) for a VirusTotal API v3 path. An indicator is added
    when MIN_MALICIOUS engines for its type flag it (DEFAULT_MIN_MALICIOUS
    otherwise), or `min_malicious` engines for every type when given.
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

        problem, detail, stats = lookup_retrying(fetch, ioc_type, value, sleep)
        if problem:
            stopped = problem == "quota"
            record(raw, problem, detail)
            continue
        malicious = stats.get("malicious", 0)
        ratio = f"{ioc_type} {malicious}/{sum(stats.values())} malicious"
        if malicious < min_for(ioc_type, min_malicious):
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


def add_trusted(indicators, feed_path, *, today=None, out=print):
    """Append rows for indicators the user vouches for, with no VirusTotal lookup.

    Same input as run(); rows get CONFIDENCE high and a COMMENT that says the
    indicator was added without a check, so --recheck never touches them.
    """
    today = today or date.today().isoformat()
    feed_path = Path(feed_path)
    text = feed_path.read_text()
    in_feed = feed_values(text)
    needs_newline = bool(text) and not text.endswith("\n")
    added_now = set()
    results = []
    for item in indicators:
        raw, label = (item, "") if isinstance(item, str) else item
        try:
            ioc_type, value = classify(raw)
        except ValueError as e:
            status, detail = "invalid", str(e)
        else:
            key = value.lower()
            if key in added_now:
                status, detail = "duplicate", ""
            elif key in in_feed:
                status, detail = "in-feed", ""
            else:
                name = f"trusted-{ioc_type.lower()}-{hashlib.sha1(value.encode()).hexdigest()[:10]}"
                product = "AV" if ioc_type in HASH_TYPES.values() else "AB"
                comment = f"added without VirusTotal check {today}"
                label = " ".join(label.replace(",", " ").split())
                if label:
                    comment = f"{label} - {comment}"
                row = ",".join([name, value, ioc_type, "high", "high", product, comment])
                with feed_path.open("a", newline="\n") as f:
                    f.write(("\n" if needs_newline else "") + row + "\n")
                needs_newline = False
                added_now.add(key)
                status, detail = "added", ioc_type
        results.append(Result(raw, status, detail))
        out(f"{raw}: {status}" + (f" ({detail})" if detail else ""))
    return results


def _note_date(match, group=1):
    """The date a note's regex match carries, or None without a match or with a bad date."""
    if not match:
        return None
    try:
        return date.fromisoformat(match.group(group))
    except ValueError:
        return None


def recheck_due(ioc_type, checked, trusted, last_seen, max_age=None):
    """The day a row comes up for re-verification, or None for never.

    `checked` is the date of the row's last VirusTotal check, or the day it was added
    without one when `trusted`; `last_seen` the day the IP last probed this network. A row
    is due once every clock it carries has run: TRUSTED_MAX_AGE or MAX_AGE for its type
    from `checked`, SEEN_MAX_AGE from `last_seen`. Hashes are never due. With `max_age`,
    every row is due that many days after its own date, hashes included.
    """
    if max_age is not None:
        return (checked or last_seen) + timedelta(days=max_age)
    if ioc_type in HASH_TYPES.values():
        return None
    dues = []
    if checked is not None:
        dues.append(checked + timedelta(days=TRUSTED_MAX_AGE if trusted else MAX_AGE[ioc_type]))
    if last_seen is not None:
        dues.append(last_seen + timedelta(days=SEEN_MAX_AGE))
    return max(dues)


def _closing_note(comment):
    """(VirusTotal note, unchecked note) matches of the note that closes `comment`; the one it
    does not end with is None."""
    note = VT_NOTE_RE.search(comment)
    return note, None if note else TRUSTED_NOTE_RE.search(comment)


def row_due(ioc_type, comment, max_age=None):
    """The day the feed row with this TYPE and COMMENT comes up for re-verification (see
    recheck_due), or None when it never does: a TYPE --recheck skips, or a COMMENT with no
    VirusTotal, unchecked or sighting date."""
    note, trusted = _closing_note(comment)
    checked = _note_date(note, 3) if note else _note_date(trusted)
    last_seen = _note_date(SEEN_NOTE_RE.search(comment))
    if ioc_type not in RECHECK_TYPES or (checked is None and last_seen is None):
        return None
    return recheck_due(ioc_type, checked, trusted is not None, last_seen, max_age)


def recheck(feed_path, fetch, *, max_age=None, min_malicious=None, dry_run=False,
            delay=FREE_API_DELAY, sleep=time.sleep, today=None, out=print):
    """Look up again the feed rows that are due for their type (see recheck_due).

    Rows that enough engines flag (MIN_MALICIOUS for the type, or `min_malicious`
    for every type) get a fresh ratio, date and confidence; a row added without a
    check becomes an ordinary checked row that way ("verified"); rows that fell
    below are removed. Every other row, the header and the row order stay exactly
    as they were. The file is rewritten after each change, so a run that stops
    early (quota, Ctrl-C) leaves it consistent.
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
        due = row_due(ioc_type, comment, max_age)
        if due is None:
            record(value, "kept", "no due date", quiet=True)
            continue
        if due > today_date:
            record(value, "kept", f"due {due}", quiet=True)
            continue
        if stopped:
            record(value, "unchecked")
            continue
        if looked_up:
            sleep(delay)
        looked_up = True

        problem, detail, stats = lookup_retrying(fetch, ioc_type, value, sleep)
        if problem:
            stopped = problem == "quota"
            record(value, problem, detail)
            continue
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        note, trusted = _closing_note(comment)
        before = f"{note.group(1)}/{note.group(2)}" if note else "unchecked"
        change = f"{ioc_type} {before} -> {malicious}/{total} malicious"
        if malicious < min_for(ioc_type, min_malicious):
            record(value, "would-remove" if dry_run else "removed", change)
            if not dry_run:
                lines[i] = None
                save()
            continue
        closing = note or trusted  # a hand-written row carrying only a sighting has neither
        fresh = f"VT {malicious}/{total} malicious {today}"
        fields[3] = confidence(malicious)
        fields[6] = comment[:closing.start()] + fresh if closing else f"{comment} - {fresh}"
        done, would = ("verified", "would-verify") if trusted else ("refreshed", "would-refresh")
        record(value, would if dry_run else done, change)
        if not dry_run:
            lines[i] = ",".join(fields)
            save()

    return results


def stamp_seen(feed_path, addresses, *, today=None, refresh_after=SEEN_REFRESH_DAYS):
    """Note on the feed's IP rows for `addresses` that they probed this network today.

    The note goes before the row's closing VirusTotal or trusted note (at the end of a
    hand-written COMMENT) and is refreshed only once it is `refresh_after` days old, so a
    scanner that knocks every day does not rewrite the feed every day. Rows of other types,
    IP ranges and addresses not in the feed are ignored. Returns the values stamped, in
    feed order; the file is untouched when there are none.
    """
    today = today or date.today().isoformat()
    today_date = date.fromisoformat(today)
    wanted = set(addresses)
    feed_path = Path(feed_path)
    with feed_path.open(newline="") as f:
        lines = f.read().split("\n")
    stamped = []
    for i, line in enumerate(lines):
        fields = line.split(",")
        if line.startswith("#") or len(fields) != 7 or fields[2] != "IP" or fields[1] not in wanted:
            continue
        comment = fields[6]
        seen = SEEN_NOTE_RE.search(comment)
        if seen:
            last = _note_date(seen)
            if last is not None and last > today_date - timedelta(days=refresh_after):
                continue
            comment = comment[:seen.start(1)] + today + comment[seen.end(1):]
        else:
            closing = VT_NOTE_RE.search(comment) or TRUSTED_NOTE_RE.search(comment)
            sighting = f"seen in Spark logs {today}"
            comment = (comment[:closing.start()] + sighting + " - " + comment[closing.start():] if closing
                       else f"{comment} - {sighting}")
        fields[6] = comment
        lines[i] = ",".join(fields)
        stamped.append(fields[1])
    if stamped:
        with feed_path.open("w", newline="") as f:
            f.write("\n".join(lines))
    return stamped


def api_key(environ=None, run=None):
    """The VirusTotal key: VT_API_KEY from `environ` (default os.environ), else the Keychain
    item KEYCHAIN_ACCOUNT (keychain.item); "" when neither has one."""
    return keychain.item(KEYCHAIN_ACCOUNT, "VT_API_KEY", environ, run)


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
    parser.add_argument("--min-malicious", type=int, default=None, metavar="N",
                        help="engines that must flag an indicator before it is added or kept, for every "
                             f"type (default per type: IPs {MIN_MALICIOUS['IP']}, others {DEFAULT_MIN_MALICIOUS})")
    parser.add_argument("--feed", type=Path, default=FEED, help="feed CSV to append to (with --recheck: to rewrite)")
    parser.add_argument("--delay", type=float, default=FREE_API_DELAY,
                        help=f"seconds between lookups (default {FREE_API_DELAY}, the free-key rate)")
    parser.add_argument("--dry-run", action="store_true", help="show what would change, change nothing")
    parser.add_argument("--recheck", action="store_true",
                        help="instead of adding indicators, re-verify the feed's own rows: rows whose "
                             "VirusTotal check is old get a fresh ratio and date, or are removed")
    parser.add_argument("--max-age", type=int, default=None, metavar="DAYS",
                        help="with --recheck, re-verify rows of every type checked DAYS or more days ago "
                             "(0 = every row); default per type: IPs 60, domains and URLs 180, rows added "
                             f"without a check {TRUSTED_MAX_AGE}, IPs seen in the Spark's logs {SEEN_MAX_AGE} "
                             "after their last sighting, hashes never")
    parser.add_argument("--trusted", action="store_true",
                        help="add the indicators without looking them up (a source you vouch for); "
                             "needs no API key, rows are never re-checked")
    args = parser.parse_args(argv)

    entries = read_indicators(args.file, args.indicators, args.label)
    if args.recheck and entries:
        parser.error("--recheck re-verifies the rows already in the feed; do not pass indicators")
    if not args.recheck and not entries:
        parser.error("no indicators given")
    say = lambda *a: print(*a, flush=True)

    if args.trusted:
        if args.recheck or args.dry_run:
            parser.error("--trusted cannot be combined with --recheck or --dry-run")
        say(f"Adding {len(entries)} indicators without a VirusTotal check")
        results = add_trusted(entries, args.feed, out=say)
        counts = Counter(r.status for r in results)
        say("Summary: " + ", ".join(f"{n} {status}" for status, n in counts.most_common()))
        return 0

    key = api_key()
    if not key:
        parser.error(NO_KEY_HELP)
    threshold = (f"min {args.min_malicious} malicious detections" if args.min_malicious is not None
                 else f"min {DEFAULT_MIN_MALICIOUS} malicious detections, IPs {MIN_MALICIOUS['IP']}")
    mode = threshold + (", dry run" if args.dry_run else "")
    try:
        if args.recheck:
            ages = (f"{args.max_age}+ days ago, every type" if args.max_age is not None
                    else ", ".join(f"{t} {d}+" for t, d in MAX_AGE.items())
                    + f" days ago, unchecked rows {TRUSTED_MAX_AGE}+, IPs seen in the logs {SEEN_MAX_AGE}+ "
                    "after their last sighting, hashes never")
            say(f"Re-checking {args.feed.name} rows last verified {ages} on VirusTotal ({mode})")
            results = recheck(args.feed, make_fetch(key), max_age=args.max_age,
                              min_malicious=args.min_malicious, dry_run=args.dry_run,
                              delay=args.delay, out=say)
        else:
            say(f"Checking {len(entries)} indicators against VirusTotal ({mode})")
            results = run(entries, args.feed, make_fetch(key), min_malicious=args.min_malicious,
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
