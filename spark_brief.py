#!/usr/bin/env python3
"""Compose the morning brief: one plain-text message on the previous day's attack attempts, on
what the daily check just added to the feed, and on the system's health.

    python3 spark_brief.py                        # print yesterday's brief
    python3 spark_brief.py --date 2026-10-28      # print the brief for that day
    python3 spark_brief.py --send --run-log LOG   # what daily_check.sh runs: post it to Telegram
    python3 spark_brief.py --send --notice TEXT   # daily_check.sh's one-line notice when it fails early

Reads the day's capture (syslog/spark-YYYY-MM-DD.log, plain or gzipped), the daily check's output
(--run-log: the rows it added, its outbound hits, the lookups it used, the lines that say something
went wrong and the exception of each traceback), the feed
and the feed's git history. --send posts the brief with the bot in the Keychain (telegram_api),
then one attacker-context note per source the check sent to block; without --send, or without a
bot token, the brief is printed. The layout is the one approved in docs/system-design.md, D6.

A delivered brief (sent, or printed for want of a token, with --send) records the feed's commit in
syslog/last-brief.json, so the next brief counts the rows committed since and none twice. Exit
status: 0 the brief went out (or was printed), 1 it did not, 2 it went out but a note did not.
"""

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import date, datetime, timedelta
from pathlib import Path

import spark_logs
import telegram_api
import vt_check

LOOKUPS_QUOTA = 500  # the free VirusTotal key's lookups a day
TOP = 10
MARKER_NAME = "last-brief.json"  # in the capture directory, beside checked.json
ADDED_WINDOW = "36 hours ago"  # how far back the feed's commits count when no earlier brief is on record
BLADE_NAMES = {"Anti Malware": "Anti-Malware", "Anti Virus": "Anti-Virus"}
SHA_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
ADDED_RE = re.compile(r"(\S+): added \(([^)]*)\)$")
HIT_RE = re.compile(r"OUTBOUND HIT  (\S+)  \((.*?)\)  reached by (.*?)  <- check these devices")
LOOKUPS_RE = re.compile(r"Added to the feed: (\d+)  clean: (\d+)  unknown to VirusTotal: (\d+)")
# What the run log says when something went wrong: vt_check.run prints "<x>: error (HTTP ...)" and
# "<x>: quota (... - stopping)", spark_logs.py "VirusTotal quota reached; ..." on a quota stop and,
# through argparse, "spark_logs.py: error: ..." when it could not start (no VirusTotal key).
PROBLEMS = ("ERROR", ": error (", ": quota ", "VirusTotal quota reached", ": error: ")
TRACEBACK = "Traceback (most recent call last):"
LOOKUP_ERROR_RE = re.compile(r"\S+: (error|quota) \((.*)\)$")  # one failed lookup, as vt_check.run prints it
ERROR_LINES = 5  # the brief lists this many error lines, then counts the rest


def read_entries(path):
    """The parsed entries of the capture at `path`, plain or gzipped; None when the day has no file."""
    f = spark_logs._open_capture(Path(path))
    return None if f is None else _parse_lines(f)


def _parse_lines(f):
    with f:
        for line in f:
            if line.strip():
                yield spark_logs.parse_entry(line.rstrip("\n"))


def capture_path(directory, day):
    return Path(directory) / f"spark-{day:%Y-%m-%d}.log"


def attacks(entries, feed):
    """What the firewall turned away: `dropped` counts the entries it dropped or rejected from the
    External zone, `sources` those entries per source address, `detections` lists the Threat
    Prevention rows, `top` the ten busiest sources as (address, count, whether the feed has it).
    `system` counts the system log lines, which are none of these."""
    dropped, sources, detections, system = 0, Counter(), [], 0
    for entry in entries:
        if "system" in entry:
            system += 1
            continue
        if entry.get("Action") in ("drop", "reject") and entry.get("inzone") == "External":
            dropped += 1
            if entry.get("src"):
                sources[entry["src"]] += 1
        if spark_logs.is_tp_detection(entry):
            detections.append(entry)
    return {"dropped": dropped, "sources": sources, "detections": detections, "system": system,
            "top": [(ip, count, ip in feed) for ip, count in sources.most_common(TOP)]}


def parse_run_log(text):
    """What the daily check's output says: `added` as (indicator, ratio), `outbound_hits` as
    (indicator, ratio, devices), `lookups` used (added, clean and unknown to VirusTotal) and the
    `errors`: the lines that say something went wrong (PROBLEMS) and the last line, the exception,
    of each traceback."""
    run = {"added": [], "outbound_hits": [], "lookups": 0, "errors": []}
    in_traceback = False
    for line in text.splitlines():
        if in_traceback:
            if line.strip() and not line[0].isspace():  # the frames are indented; the exception is not
                run["errors"].append(line)
                in_traceback = False
            continue
        if line.startswith(TRACEBACK):
            in_traceback = True
            continue
        added, hit, totals = ADDED_RE.match(line), HIT_RE.match(line), LOOKUPS_RE.match(line)
        if added:
            run["added"].append(added.groups())
        elif hit:
            run["outbound_hits"].append((hit.group(1), hit.group(2), hit.group(3).split(", ")))
        elif totals:
            run["lookups"] = sum(int(n) for n in totals.groups())
        if any(problem in line for problem in PROBLEMS):
            run["errors"].append(line)
    return run


def _fields(line):
    """The seven fields of a feed row; None for the header, comments and malformed lines."""
    fields = line.split(",")
    return None if line.startswith("#") or len(fields) != 7 else fields


def origin(comment):
    if "Spark syslog" in comment:
        return "logs"
    if comment.startswith("News"):
        return "news"
    if "sent from Telegram" in comment or "added unchecked" in comment:
        return "hand"
    return "other"


def entered(rows):
    """How many of the feed `rows` came from the Spark's logs, news, hand, or somewhere else,
    by the origin their COMMENT names."""
    counts = Counter(origin(fields[6]) for fields in map(_fields, rows) if fields)
    return {key: counts[key] for key in ("logs", "news", "hand", "other")}


def next_recheck(feed_text, today):
    """The earliest day a row of the feed comes up for re-verification (vt_check.row_due), or
    `today` when one is already overdue; None when no row has a due date."""
    dues = [vt_check.row_due(fields[2], fields[6]) for fields in map(_fields, feed_text.splitlines()) if fields]
    dues = [due for due in dues if due]
    return max(min(dues), today) if dues else None


def _vt(ratio):
    """'VT 11/94' from the check's 'IP 11/94 malicious'."""
    found = spark_logs.RATIO_RE.search(ratio)
    return f"VT {found.group(1)}/{found.group(2)}" if found else ratio


def _count(n, noun):
    return f"{n:,} {noun}" + ("" if n == 1 else "s")


def _error_lines(errors):
    """The error lines as the brief lists them: lookups that failed with the same status and detail
    become one line, at the place of the first (a VirusTotal outage fails every lookup of a run);
    every other line stays as it is."""
    groups = {}  # (status, detail) of a failed lookup, else the line's position -> [first line, count]
    for position, line in enumerate(errors):
        failed = LOOKUP_ERROR_RE.match(line)
        key = failed.groups() if failed else position
        if key in groups:
            groups[key][1] += 1
        else:
            groups[key] = [line, 1]
    return [line if count == 1 else f"{count:,} lookups: {key[0]} ({key[1]})" for key, (line, count) in groups.items()]


def render(day, attack, run, entered, probes, next_due, lookups_quota=LOOKUPS_QUOTA):
    """The brief for `day` as plain text; a section with nothing to say is left out. `probes`
    counts per source the drops the daily check saw, for the 'probed N×' beside each added one."""
    lines = [f"Spark brief — {day:%a} {day.isoformat()}",
             f"Probes dropped: {attack['dropped']:,} from {_count(len(attack['sources']), 'source')} · "
             f"TP detections: {len(attack['detections'])} · Sent to block: {len(run['added'])} · "
             f"Outbound hits: {len(run['outbound_hits'])}",
             ""]
    if run["added"]:
        lines.append("SENT TO BLOCK (passed the firewall, VirusTotal flags them)")
        for indicator, ratio in run["added"]:
            probed = f"   probed {probes[indicator]:,}×" if probes.get(indicator) else ""
            lines.append(f"  {indicator:<15}  {_vt(ratio)}{probed}   →  added")
    if run["outbound_hits"]:
        lines.append("OUTBOUND HIT — look at this device")
        for indicator, ratio, devices in run["outbound_hits"]:
            lines += [f"  {device} reached {indicator} ({_vt(ratio)})" for device in devices]
    if attack["detections"]:
        blades = Counter(BLADE_NAMES.get(e["ProductName"], e["ProductName"]) for e in attack["detections"])
        lines += ["THREAT PREVENTION", "  " + " ·  ".join(f"{blade}: {n}" for blade, n in blades.most_common())]
    if attack["top"]:
        width = len(f"{attack['top'][0][1]:,}")
        lines.append("TOP PROBING SOURCES (all dropped)")
        for ip, count, in_feed in attack["top"]:
            lines.append(f"  {ip:<15} {count:>{width},}×" + ("  (in feed)" if in_feed else ""))
        if len(attack["sources"]) > len(attack["top"]):
            lines.append(f"  … {len(attack['sources']) - len(attack['top']):,} more")
    counts = {key: entered.get(key, 0) for key in ("logs", "news", "hand", "other")}
    if any(counts.values()):
        lines.append(f"INDICATORS ENTERED: {counts['logs']} from the Spark's logs · {counts['news']} from news · "
                     f"{counts['hand']} by hand" + (f" · {counts['other']} other" if counts["other"] else ""))
    if run["errors"]:
        shown = _error_lines(run["errors"])
        lines += ["ERRORS"] + [f"  {line}" for line in shown[:ERROR_LINES]]
        if len(shown) > ERROR_LINES:
            lines.append(f"  … {len(shown) - ERROR_LINES:,} more")
    if attack.get("system"):
        lines.append(f"System log: {_count(attack['system'], 'line')}")
    footer = [f"Lookups: {run['lookups']} of {lookups_quota:,}"]
    if next_due:
        footer.append(f"next re-check {next_due.isoformat()}")
    footer.append(_count(len(run["errors"]), "error") if run["errors"] else "no errors")
    return "\n".join(lines + [" · ".join(footer)])


def compose(day, capture_dir, feed_path, run_log_text, added_rows, today):
    """The brief for `day`, written on the morning of `today`, from the capture in `capture_dir`,
    the feed, the daily check's output and the feed rows added since the last brief. A day with
    no capture gives a brief without attack sections, and an error that says so: all quiet and a
    receiver that was down must not look alike."""
    feed_text = Path(feed_path).read_text()
    feed = spark_logs.feed_members(feed_text)
    run = parse_run_log(run_log_text)
    entries = read_entries(capture_path(capture_dir, day))
    if entries is None:  # first: a receiver that was down is the brief's key health signal
        run["errors"].insert(0, f"no syslog capture for {day.isoformat()}")
    attack = attacks(entries or (), feed)
    # The check read the day and the morning of the run, so the probes it saw span both.
    probes = attack["sources"] + attacks(read_entries(capture_path(capture_dir, today)) or (), feed)["sources"]
    return render(day, attack, run, entered(added_rows), probes, next_recheck(feed_text, today))


def _git(directory, *args):
    """git's output in `directory`; None when git fails or is not there."""
    try:
        proc = subprocess.run(["git", *args], cwd=directory, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout if proc.returncode == 0 else None


def head_commit(feed_path):
    """The commit the feed's repository is at; None outside a repository."""
    return (_git(Path(feed_path).parent, "rev-parse", "HEAD") or "").strip() or None


def committed_rows(feed_path, since=None):
    """The rows the feed gained since the commit `since`, the one the last brief covered. Without it,
    or when the repository does not know it (first run, rewritten history), the rows of the commits
    within ADDED_WINDOW. A row that was only rewritten in place (a re-check, a sighting note) is not
    an addition; outside a repository, or with no new commit, there are none."""
    feed_path = Path(feed_path)
    directory, name = feed_path.parent, feed_path.name
    known = (isinstance(since, str) and SHA_RE.fullmatch(since)
             and _git(directory, "cat-file", "-e", f"{since}^{{commit}}") is not None)
    if known:
        base = since
    else:
        commits = (_git(directory, "log", f"--since={ADDED_WINDOW}", "--format=%H", "--", name) or "").split()
        if not commits:
            return []
        # The oldest commit's parent; the empty tree when it is the root commit.
        base = (_git(directory, "rev-parse", "--verify", "--quiet", commits[-1] + "^")
                or _git(directory, "hash-object", "-t", "tree", "/dev/null") or "").strip()
    diff = _git(directory, "diff", "--no-color", "--no-ext-diff", base, "HEAD", "--", name) if base else None
    added, removed = [], set()
    for line in (diff or "").splitlines():
        fields = _fields(line[1:])
        if not fields or line.startswith(("+++", "---")):
            continue
        if line[0] == "+":
            added.append(line[1:])
        elif line[0] == "-":
            removed.add(fields[1])
    return [row for row in added if row.split(",")[1] not in removed]


def read_marker(path):
    """The commit the last delivered brief covered; None without a readable marker."""
    try:
        marker = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None
    commit = marker.get("commit") if isinstance(marker, dict) else None
    return commit if isinstance(commit, str) else None


def record_delivery(path, commit):
    """Note in the marker that a brief covering the feed up to `commit` was delivered."""
    if commit is None:
        return
    marker = {"commit": commit, "delivered": datetime.now().isoformat(timespec="seconds")}
    try:
        Path(path).write_text(json.dumps(marker, indent=1) + "\n")
    except OSError as e:
        print(f"warning: could not record the brief in {path}: {e}", file=sys.stderr)


def send_notes(telegram, indicators, capture_dir, day):
    """Send the attacker-context note of each indicator as a message of its own. Returns 0, or 2 when
    a note (or the module that writes them) failed: the brief itself is out by then. A note that
    fails does not stop the next."""
    if not indicators:
        return 0
    try:
        import attacker_context  # only a sent brief needs it, and it brings the network clients with it
    except ImportError as e:
        print(f"error: no attacker notes: {e}", file=sys.stderr)
        return 2
    status = 0
    for indicator in indicators:
        try:
            note = attacker_context.note(indicator, capture_dir, day.isoformat())
            if note:
                telegram.send_message(note)
        except (telegram_api.TelegramError, OSError) as e:
            print(f"error: the note on {indicator} was not sent: {e}", file=sys.stderr)
            status = 2
    return status


def send_notice(text, send):
    """--notice: `text` alone, posted with the bot in the Keychain under --send, else (or without a bot)
    printed. 0 when it went out or was printed, 1 when Telegram did not take it."""
    try:
        telegram = telegram_api.from_keychain() if send else None
    except telegram_api.TelegramError as e:  # a chat id that is not a number; the message never carries it
        telegram, problem = None, e
    else:
        problem = None
    if telegram is not None:
        try:
            telegram.send_message(text)
        except (telegram_api.TelegramError, OSError) as e:
            problem = e
        else:
            print("Notice sent to Telegram")
            return 0
    print(text)
    if problem:
        print(f"error: the notice was not sent: {problem}", file=sys.stderr)
        return 1
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compose the morning brief on the Spark's attack attempts and the feed.")
    parser.add_argument("--date", type=date.fromisoformat, metavar="YYYY-MM-DD",
                        help="the day to report (default yesterday); the brief is taken to be written the morning after")
    parser.add_argument("--run-log", type=Path, help="the daily check's output: rows added, outbound hits, lookups, errors")
    parser.add_argument("--send", action="store_true",
                        help="post the brief to Telegram, then a note per source sent to block, instead of printing it; "
                             f"the delivery is recorded in {MARKER_NAME}")
    parser.add_argument("--dir", type=Path, default=spark_logs.DEFAULT_DIR, help="syslog capture directory")
    parser.add_argument("--feed", type=Path, default=vt_check.FEED, help="the feed CSV")
    parser.add_argument("--notice", metavar="TEXT",
                        help="send (with --send) or print TEXT alone instead of a brief: the daily check's "
                             "word when it failed before it had a run to brief on")
    args = parser.parse_args(argv)
    if args.notice is not None:
        return send_notice(args.notice, args.send)

    day = args.date or date.today() - timedelta(days=1)
    run_log = args.run_log.read_text() if args.run_log else ""
    marker, head = args.dir / MARKER_NAME, head_commit(args.feed)
    rows = committed_rows(args.feed, read_marker(marker))
    brief = compose(day, args.dir, args.feed, run_log, rows, day + timedelta(days=1))
    try:
        telegram = telegram_api.from_keychain() if args.send else None
    except telegram_api.TelegramError as e:  # a chat id that is not a number; the message never carries it
        print(brief)
        print(f"error: the brief was not sent: {e}", file=sys.stderr)
        return 1
    if telegram is None:
        if args.send:
            print("no Telegram bot token and chat id in the Keychain; printing the brief instead", file=sys.stderr)
        print(brief)
        if args.send:
            record_delivery(marker, head)
        return 0

    try:
        telegram.send_message(brief)
    except (telegram_api.TelegramError, OSError) as e:
        print(brief)
        print(f"error: the brief was not sent: {e}", file=sys.stderr)
        return 1
    print("Brief sent to Telegram")
    record_delivery(marker, head)
    return send_notes(telegram, [indicator for indicator, _ in parse_run_log(run_log)["added"]], args.dir, day)


if __name__ == "__main__":
    sys.exit(main())
