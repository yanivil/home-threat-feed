"""Lint spark-ioc-feed.csv before it is committed.

The gateway pulls the feed as it is, so a row it cannot read, a host this system itself needs, a
duplicate or a hidden character must never reach main. Every writer runs this first and refuses
to commit while it fails: daily_check.sh (after its pull and again before its commit), the
Telegram bot (telegram_bot.Bot._commit) and the monthly re-check on GitHub Actions
(.github/workflows/recheck.yml). A row typed in the GitHub web editor goes to main unchecked;
the next daily run then fails its lint and says so in the morning brief.

    python3 feed_lint.py [spark-ioc-feed.csv]    # exit 0: no problems; 1: the problems, one per line
"""

import ipaddress
import sys
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit

import spark_logs
import vt_check

HEADER = "# UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT"
TYPES = ("IP", "IP Range", "Domain", "URL", "MD5", "SHA1", "SHA256")
HASH_TYPES = ("MD5", "SHA1", "SHA256")
LEVELS = ("low", "medium", "high", "critical")
PRODUCTS = ("AB", "AV")
# Hosts the feed must never hold. The gateway enforces the feed on every device, this Mac included,
# and these are what the system itself talks to: the feed's own source, Telegram, the attacker
# notes and VirusTotal. The bot refuses them at intake (Bot.never_block); the lint, in the file.
NEVER_BLOCK = frozenset({"github.com", "raw.githubusercontent.com", "api.telegram.org", "api.anthropic.com",
                         "www.virustotal.com"})
_AN = {"IP", "IP Range", "MD5"}


def _a(kind):
    return f"an {kind}" if kind in _AN else f"a {kind}"


def _never_block(value):
    try:
        host = urlsplit(value).hostname if "://" in value else value
    except ValueError:  # "https://[::1": no host to compare
        return False
    return bool(host) and spark_logs.allowed(host, NEVER_BLOCK)


def _value_problems(value, kind):
    """What is wrong with `value` as a row of TYPE `kind`: [] or one message."""
    if kind == "IP Range":
        ends = value.split("-")
        try:
            classified = [vt_check.classify(end) for end in ends] if len(ends) == 2 else []
        except ValueError as e:
            return [f"VALUE {value}: {e}"]
        if [found for found, _ in classified] != ["IP", "IP"] or [norm for _, norm in classified] != ends:
            return [f"VALUE {value} is not an IP Range (expected a.b.c.d-a.b.c.e)"]
        if ipaddress.ip_address(ends[0]) > ipaddress.ip_address(ends[1]):
            return [f"VALUE {value}: the range ends before it starts"]
        return []
    try:
        found, normalised = vt_check.classify(value)
    except ValueError as e:
        return [f"VALUE {value}: {e}"]
    if found != kind:
        return [f"VALUE {value} is {_a(found)}, not {_a(kind)}"]
    if normalised != value:
        return [f"VALUE {value} is not normalised (expected {normalised})"]
    if kind in ("Domain", "URL") and _never_block(value):
        return [f"VALUE {value} is a host this system needs (never block)"]
    return []


def problems(text):
    """The problems in the feed `text`, one per entry as `line N: what`; [] when it is clean. A line
    with a hidden character or the wrong number of fields is reported once; a readable row, for each
    of its faults."""
    found = []
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()  # the newline that ends the last line
    elif text:
        found.append(f"line {len(lines)}: no newline at the end of the file")
    if not lines or lines[0] != HEADER:
        found.append(f"line 1: the header must be exactly `{HEADER}`")
    names, values = {}, {}
    for number, line in enumerate(lines[1:], start=2):
        hidden = next((c for c in line if unicodedata.category(c).startswith("C")), None)
        if hidden is not None:
            found.append(f"line {number}: hidden character U+{ord(hidden):04X}")
            continue
        if not line:
            found.append(f"line {number}: empty line")
            continue
        if line.startswith("#"):
            continue
        fields = line.split(",")
        if len(fields) != 7:
            hint = " (a comma in the COMMENT?)" if len(fields) > 7 else ""
            found.append(f"line {number}: {len(fields)} fields, expected 7{hint}")
            continue
        name, value, kind, confidence, severity, product, _ = fields
        if not name:
            found.append(f"line {number}: UNIQ-NAME is empty")
        elif name in names:
            found.append(f"line {number}: UNIQ-NAME {name} repeats line {names[name]}")
        else:
            names[name] = number
        if kind not in TYPES:
            found.append(f"line {number}: TYPE {kind} is not one of {', '.join(TYPES)}")
        else:
            found.extend(f"line {number}: {problem}" for problem in _value_problems(value, kind))
        if confidence not in LEVELS:
            found.append(f"line {number}: CONFIDENCE {confidence} is not one of {', '.join(LEVELS)}")
        if severity not in LEVELS:
            found.append(f"line {number}: SEVERITY {severity} is not one of {', '.join(LEVELS)}")
        if product not in PRODUCTS:
            found.append(f"line {number}: PRODUCT {product} is not AB or AV")
        elif kind in TYPES and product != ("AV" if kind in HASH_TYPES else "AB"):
            found.append(f"line {number}: PRODUCT {product} for {_a(kind)}, "
                         f"expected {'AV' if kind in HASH_TYPES else 'AB'}")
        if value.lower() in values:
            found.append(f"line {number}: VALUE {value} repeats line {values[value.lower()]}")
        else:
            values[value.lower()] = number
    return found


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    path = Path(args[0]) if args else vt_check.FEED
    text = path.read_text()
    found = problems(text)
    rows = sum(1 for line in text.split("\n")[1:] if line and not line.startswith("#"))
    for problem in found:
        print(problem)
    if found:
        print(f"{path}: {len(found)} problem{'s' if len(found) != 1 else ''} in {rows} rows")
        return 1
    print(f"{path}: {rows} rows, no problems")
    return 0


if __name__ == "__main__":
    sys.exit(main())
