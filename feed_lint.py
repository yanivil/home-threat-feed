"""Lint spark-ioc-feed.csv before it is committed.

The gateway pulls the feed as it is, so a row it cannot read, a host this system itself needs, a
duplicate or a hidden character must never reach main. Every writer runs this first and refuses
to commit while it fails: daily_check.sh (after its pull and again before its commit), the
Telegram bot (telegram_bot.Bot._commit) and the monthly re-check on GitHub Actions
(.github/workflows/recheck.yml). A row typed in the GitHub web editor goes to main unchecked;
the next daily run then fails its lint and its morning notice names the line to fix.

    python3 feed_lint.py [spark-ioc-feed.csv]    # exit 0: no problems; 1: the problems, one per line
"""

import ipaddress
import re
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
# The public rows say what was done (`confirmed <date>`, `added unchecked <date>`), never where: the
# lookup service's terms keep its results private, so its name and its counts stay out of the file.
SERVICE_RE = re.compile(r"virustotal|\bvt\b", re.IGNORECASE)
_AN = {"IP", "IP Range", "MD5"}
# The hidden characters most often typed or pasted, named for the owner; the rest get their Unicode
# name, or their category's when they have none (a lone surrogate is how read() keeps a byte that is
# not UTF-8).
_HIDDEN_NAMES = {"\t": "tab", "\r": "carriage return: a Windows line ending", "\x1b": "escape"}
_CATEGORY_NAMES = {"Cs": "a byte that is not UTF-8", "Co": "private-use character", "Cn": "unassigned character"}


def _a(kind):
    return f"an {kind}" if kind in _AN else f"a {kind}"


def _or(options):
    return ", ".join(options[:-1]) + " or " + options[-1]


def _hidden(line):
    """(column, 'U+XXXX (name)') of the first character of `line` that does not show: the control,
    format, unassigned and private-use characters (Unicode category C) and the line and paragraph
    separators, which str.splitlines() breaks on; None when every character shows."""
    for index, char in enumerate(line):
        category = unicodedata.category(char)
        if category.startswith("C") or category in ("Zl", "Zp"):
            name = (_HIDDEN_NAMES.get(char)
                    or unicodedata.name(char, _CATEGORY_NAMES.get(category, "control character")))
            return index + 1, f"U+{ord(char):04X} ({name})"
    return None


def never_block_problem(value, kind):
    """Why a Domain or URL row of `value` must not be in the feed, or None: its host is one the
    system needs (or under one) or, for a Domain, the parent of one, since a gateway that matches a
    Domain row against subdomains would block the host with it. A URL blocks one page, not a host."""
    try:
        host = urlsplit(value).hostname if "://" in value else value
    except ValueError:  # "https://[::1": no host to compare
        return None
    if not host:
        return None
    if spark_logs.allowed(host, NEVER_BLOCK):
        return f"VALUE {value} is a host this system needs (never block)"
    if kind == "Domain":
        covered = [needed for needed in sorted(NEVER_BLOCK) if needed.endswith("." + host)]
        if covered:
            return f"VALUE {value} would block {covered[0]}, a host this system needs (never block)"
    return None


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
        first, last = ipaddress.ip_address(ends[0]), ipaddress.ip_address(ends[1])
        if first.version != last.version:
            return [f"VALUE {value}: an IPv4 and an IPv6 address do not make a range"]
        if first > last:
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
    if kind in ("Domain", "URL"):
        problem = never_block_problem(value, kind)
        if problem:
            return [problem]
    return []


def problems(text):
    """The problems in the feed `text`, one per entry as `line N: what`; [] when it is clean. A line
    with a hidden character or the wrong number of fields is reported once; a readable row, for each
    of its faults. Each message names the field and what to use, since the owner reads it in a
    Telegram notice or reply, not next to the file."""
    found = []
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()  # the newline that ends the last line
    elif text:
        found.append(f"line {len(lines)}: no newline at the end of the file")
    first = lines[0] if lines else ""
    if first != HEADER:  # the repr shows a byte-order mark or a trailing space; a huge line is cut
        shown = first if len(first) <= 160 else first[:157] + "..."  # a whole row still shows
        found.append(f"line 1: the header must be exactly `{HEADER}`, not {shown!r}")
    names, values = {}, {}
    for number, line in enumerate(lines[1:], start=2):
        hidden = _hidden(line)
        if hidden:
            column, what = hidden
            found.append(f"line {number}: hidden character {what} at column {column}")
            continue
        if not line:
            found.append(f"line {number}: empty line")
            continue
        if line.startswith("#"):
            continue
        fields = line.split(",")
        if len(fields) != 7:
            hint = " (a comma in the COMMENT?)" if len(fields) > 7 else ""
            found.append(f"line {number}: {len(fields)} field{'s' if len(fields) != 1 else ''}, expected 7{hint}")
            continue
        name, value, kind, confidence, severity, product, comment = fields
        if not name:
            found.append(f"line {number}: UNIQ-NAME is empty")
        elif name in names:
            found.append(f"line {number}: UNIQ-NAME {name} repeats line {names[name]}")
        else:
            names[name] = number
        if not value:
            found.append(f"line {number}: VALUE is empty")
        if not kind:
            found.append(f"line {number}: TYPE is empty: use one of {', '.join(TYPES)}")
        elif kind not in TYPES:
            found.append(f"line {number}: TYPE {kind} is not one of {', '.join(TYPES)}")
        elif value:
            found.extend(f"line {number}: {problem}" for problem in _value_problems(value, kind))
        for field, level in (("CONFIDENCE", confidence), ("SEVERITY", severity)):
            if not level:
                found.append(f"line {number}: {field} is empty: use {_or(LEVELS)}")
            elif level not in LEVELS:
                found.append(f"line {number}: {field} {level} is not one of {', '.join(LEVELS)}")
        if not product:
            found.append(f"line {number}: PRODUCT is empty: use AB for an IP, IP Range, Domain or URL, AV for a hash")
        elif product not in PRODUCTS:
            found.append(f"line {number}: PRODUCT {product} is not AB or AV")
        elif kind in TYPES and product != ("AV" if kind in HASH_TYPES else "AB"):
            found.append(f"line {number}: PRODUCT {product} for {_a(kind)}, "
                         f"expected {'AV' if kind in HASH_TYPES else 'AB'}")
        if value:
            if value.lower() in values:
                found.append(f"line {number}: VALUE {value} repeats line {values[value.lower()]}")
            else:
                values[value.lower()] = number
        named = SERVICE_RE.search(comment)
        if named:
            found.append(f"line {number}: COMMENT mentions {named.group()}: the feed names no lookup service")
    return found


def read(path):
    """The feed file as it is on disk: Path.read_text() would turn a Windows line ending into a plain
    newline and refuse a byte that is not UTF-8; here the first is reported as a hidden character and
    the second is kept as a lone surrogate, which _hidden names."""
    return Path(path).read_bytes().decode("utf-8", errors="surrogateescape")


def problems_in(path):
    """problems() of the file at `path`, read with read()."""
    return problems(read(path))


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    path = Path(args[0]) if args else vt_check.FEED
    text = read(path)
    found = problems(text)
    rows = sum(1 for line in text.split("\n")[1:] if line and not line.startswith("#"))
    rows_text = f"{rows} row{'s' if rows != 1 else ''}"
    for problem in found:
        print(problem)
    if found:
        print(f"{path}: {len(found)} problem{'s' if len(found) != 1 else ''} in {rows_text}")
        return 1
    print(f"{path}: {rows_text}, no problems")
    return 0


if __name__ == "__main__":
    sys.exit(main())
