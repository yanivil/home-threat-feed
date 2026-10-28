#!/usr/bin/env python3
"""Compose the morning brief: one plain-text message on the previous day's attack attempts, on
what the daily check just added to the feed, and on the system's health.

    python3 spark_brief.py                        # print yesterday's brief
    python3 spark_brief.py --date 2026-10-28      # print the brief for that day
    python3 spark_brief.py --send --run-log LOG   # what daily_check.sh runs: post it to Telegram

Reads the day's capture (syslog/spark-YYYY-MM-DD.log, plain or gzipped), the daily check's output
(--run-log: the rows it added, its outbound hits, the lookups it used, its ERROR lines), the feed
and the feed's git history. --send posts the brief with the bot in the Keychain (telegram_api),
then one attacker-context note per source the check sent to block; without --send, or without a
bot token, the brief is printed. The layout is the one approved in docs/system-design.md, D6.
"""

import argparse
import re
import subprocess
import sys
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

import spark_logs
import telegram_api
import vt_check

LOOKUPS_QUOTA = 500  # the free VirusTotal key's lookups a day
TOP = 10
ADDED_WINDOW = "36 hours ago"  # how far back the feed's commits count as this brief's additions
BLADE_NAMES = {"Anti Malware": "Anti-Malware", "Anti Virus": "Anti-Virus"}
ADDED_RE = re.compile(r"(\S+): added \(([^)]*)\)$")
HIT_RE = re.compile(r"OUTBOUND HIT  (\S+)  \((.*?)\)  reached by (.*?)  <- check these devices")
LOOKUPS_RE = re.compile(r"Added to the feed: (\d+)  clean: (\d+)  unknown to VirusTotal: (\d+)")


def read_entries(path):
    """The parsed entries of the capture at `path`, plain or gzipped; none when the day has no file."""
    f = spark_logs._open_capture(Path(path))
    if f is None:
        return
    with f:
        for line in f:
            if line.strip():
                yield spark_logs.parse_entry(line.rstrip("\n"))


def capture_path(directory, day):
    return Path(directory) / f"spark-{day:%Y-%m-%d}.log"


def attacks(entries, feed):
    """What the firewall turned away: `dropped` counts the entries it dropped or rejected from the
    External zone, `sources` those entries per source address, `detections` lists the Threat
    Prevention rows, `top` the ten busiest sources as (address, count, whether the feed has it)."""
    dropped, sources, detections = 0, Counter(), []
    for entry in entries:
        if entry.get("Action") in ("drop", "reject") and entry.get("inzone") == "External":
            dropped += 1
            if entry.get("src"):
                sources[entry["src"]] += 1
        if spark_logs.is_tp_detection(entry):
            detections.append(entry)
    return {"dropped": dropped, "sources": sources, "detections": detections,
            "top": [(ip, count, ip in feed) for ip, count in sources.most_common(TOP)]}


def parse_run_log(text):
    """What the daily check's output says: `added` as (indicator, ratio), `outbound_hits` as
    (indicator, ratio, devices), `lookups` used (added, clean and unknown to VirusTotal) and the
    `errors`, the lines that contain ERROR."""
    run = {"added": [], "outbound_hits": [], "lookups": 0, "errors": []}
    for line in text.splitlines():
        added, hit, totals = ADDED_RE.match(line), HIT_RE.match(line), LOOKUPS_RE.match(line)
        if added:
            run["added"].append(added.groups())
        elif hit:
            run["outbound_hits"].append((hit.group(1), hit.group(2), hit.group(3).split(", ")))
        elif totals:
            run["lookups"] = sum(int(n) for n in totals.groups())
        if "ERROR" in line:
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
    if "sent from Telegram" in comment or "added without VirusTotal check" in comment:
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
        lines += ["ERRORS"] + [f"  {line}" for line in run["errors"]]
    footer = [f"Lookups: {run['lookups']} of {lookups_quota:,}"]
    if next_due:
        footer.append(f"next re-check {next_due.isoformat()}")
    footer.append(_count(len(run["errors"]), "error") if run["errors"] else "no errors")
    return "\n".join(lines + [" · ".join(footer)])


def compose(day, capture_dir, feed_path, run_log_text, added_rows, today):
    """The brief for `day`, written on the morning of `today`, from the capture in `capture_dir`,
    the feed, the daily check's output and the feed rows added since the last brief. A day with
    no capture gives a brief without attack sections."""
    feed_text = Path(feed_path).read_text()
    feed = spark_logs.feed_members(feed_text)
    attack = attacks(read_entries(capture_path(capture_dir, day)), feed)
    # The check read the day and the morning of the run, so the probes it saw span both.
    probes = attack["sources"] + attacks(read_entries(capture_path(capture_dir, today)), feed)["sources"]
    return render(day, attack, parse_run_log(run_log_text), entered(added_rows), probes,
                  next_recheck(feed_text, today))


def committed_rows(feed_path):
    """The rows the feed's commits of the last 36 hours added, as written. A row that was only
    rewritten in place (a re-check, a sighting note) is not an addition; outside a repository,
    or with no such commit, there are none."""
    feed_path = Path(feed_path)

    def git(*args):
        try:
            proc = subprocess.run(["git", *args], cwd=feed_path.parent, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            return None
        return proc.stdout if proc.returncode == 0 else None

    commits = (git("log", f"--since={ADDED_WINDOW}", "--format=%H", "--", feed_path.name) or "").split()
    if not commits:
        return []
    # The oldest commit's parent; the empty tree when it is the root commit.
    parent = git("rev-parse", "--verify", "--quiet", commits[-1] + "^") or git("hash-object", "-t", "tree", "/dev/null")
    diff = git("diff", parent.strip(), "HEAD", "--", feed_path.name) if parent else None
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


def send_notes(telegram, indicators, capture_dir, day):
    """Send the attacker-context note of each indicator as a message of its own; 1 if any could
    not be sent, else 0. A note that fails does not stop the next."""
    if not indicators:
        return 0
    import attacker_context  # only a sent brief needs it, and it brings the network clients with it
    status = 0
    for indicator in indicators:
        try:
            note = attacker_context.note(indicator, capture_dir, day.isoformat())
            if note:
                telegram.send_message(note)
        except (telegram_api.TelegramError, OSError) as e:
            print(f"error: the note on {indicator} was not sent: {e}", file=sys.stderr)
            status = 1
    return status


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compose the morning brief on the Spark's attack attempts and the feed.")
    parser.add_argument("--date", type=date.fromisoformat, metavar="YYYY-MM-DD",
                        help="the day to report (default yesterday); the brief is taken to be written the morning after")
    parser.add_argument("--run-log", type=Path, help="the daily check's output: rows added, outbound hits, lookups, errors")
    parser.add_argument("--send", action="store_true",
                        help="post the brief to Telegram, then a note per source sent to block, instead of printing it")
    parser.add_argument("--dir", type=Path, default=spark_logs.DEFAULT_DIR, help="syslog capture directory")
    parser.add_argument("--feed", type=Path, default=vt_check.FEED, help="the feed CSV")
    args = parser.parse_args(argv)

    day = args.date or date.today() - timedelta(days=1)
    run_log = args.run_log.read_text() if args.run_log else ""
    brief = compose(day, args.dir, args.feed, run_log, committed_rows(args.feed), day + timedelta(days=1))
    telegram = telegram_api.from_keychain() if args.send else None
    if telegram is None:
        if args.send:
            print("no Telegram bot token and chat id in the Keychain; printing the brief instead", file=sys.stderr)
        print(brief)
        return 0

    try:
        telegram.send_message(brief)
    except (telegram_api.TelegramError, OSError) as e:
        print(brief)
        print(f"error: the brief was not sent: {e}", file=sys.stderr)
        return 1
    return send_notes(telegram, [indicator for indicator, _ in parse_run_log(run_log)["added"]], args.dir, day)


if __name__ == "__main__":
    sys.exit(main())
