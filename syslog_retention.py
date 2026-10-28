#!/usr/bin/env python3
"""Compress the Spark's daily captures after a week and delete them after 180 days.

    python3 syslog_retention.py [--dir syslog] [--compress-after 7] [--keep-days 180]

syslog_receiver.py writes one file a day, syslog/spark-YYYY-MM-DD.log, hundreds of MB
each. A day that is COMPRESS_AFTER_DAYS or more days old becomes spark-YYYY-MM-DD.log.gz
(spark_logs.py reads those as it reads the plain ones); a day that is KEEP_DAYS or more
days old is removed, compressed or not. Ages come from the date in the file name, never
from the file's modification time, so today's file, still being written, is never touched.
daily_check.sh runs this before anything else every morning. Standard library only.
"""

import argparse
import gzip
import re
import shutil
import sys
from datetime import date
from pathlib import Path

DEFAULT_DIR = Path(__file__).resolve().parent / "syslog"
COMPRESS_AFTER_DAYS = 7
KEEP_DAYS = 180
CAPTURE_RE = re.compile(r"^spark-(\d{4}-\d{2}-\d{2})\.log(\.gz)?$")


def captures(directory):
    """(path, day) for every daily capture in `directory`, oldest first.

    A name that looks like a capture but holds no real date is left alone.
    """
    found = []
    for path in Path(directory).iterdir():
        match = CAPTURE_RE.match(path.name)
        if not match or not path.is_file():
            continue
        try:
            day = date.fromisoformat(match.group(1))
        except ValueError:
            continue
        found.append((path, day))
    return sorted(found, key=lambda item: (item[1], item[0].name))


def compress(path):
    """Replace `path` with `path`.gz holding the same bytes; the original goes only once the
    compressed copy is complete, so an interrupted run leaves the plain file in place."""
    target = path.with_name(path.name + ".gz")
    partial = path.with_name(path.name + ".gz.part")
    with path.open("rb") as src, gzip.open(partial, "wb") as dst:
        shutil.copyfileobj(src, dst)
    partial.replace(target)
    path.unlink()
    return target


def prune(directory, today=None, compress_after=COMPRESS_AFTER_DAYS, keep_days=KEEP_DAYS):
    """Compress captures `compress_after` or more days old, remove those `keep_days` or more.

    Returns {"compressed": [file names], "removed": [file names]}, oldest first. A missing
    directory means there is nothing to do.
    """
    today = today or date.today()
    result = {"compressed": [], "removed": []}
    directory = Path(directory)
    if not directory.is_dir():
        return result
    for path, day in captures(directory):
        age = (today - day).days
        if age >= keep_days:
            path.unlink()
            result["removed"].append(path.name)
        elif age >= compress_after and path.suffix == ".log":
            compress(path)
            result["compressed"].append(path.name)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Compress the Spark's daily captures after a week and delete them after 180 days."
    )
    parser.add_argument("--dir", type=Path, default=DEFAULT_DIR, help="the capture directory (default syslog/)")
    parser.add_argument("--compress-after", type=int, default=COMPRESS_AFTER_DAYS, metavar="DAYS",
                        help=f"gzip a day's file once it is this old (default {COMPRESS_AFTER_DAYS})")
    parser.add_argument("--keep-days", type=int, default=KEEP_DAYS, metavar="DAYS",
                        help=f"remove a day's file once it is this old (default {KEEP_DAYS})")
    parser.add_argument("--today", type=date.fromisoformat, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    result = prune(args.dir, today=args.today, compress_after=args.compress_after, keep_days=args.keep_days)
    for name in result["compressed"]:
        print(f"compressed {name}")
    for name in result["removed"]:
        print(f"removed {name}")
    print(f"Capture retention: {len(result['compressed'])} compressed, {len(result['removed'])} removed "
          f"(gzip after {args.compress_after} days, keep {args.keep_days})", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
