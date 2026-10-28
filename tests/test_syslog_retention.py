"""syslog_retention.py: compresses the daily captures after a week and drops them after 180 days."""

import gzip
import subprocess
import sys
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

import syslog_retention

REPO = Path(__file__).resolve().parent.parent
TODAY = date(2026, 10, 28)


def day(back):
    return f"{TODAY - timedelta(days=back):%Y-%m-%d}"


class PruneTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def capture(self, back, compressed=False):
        text = f"{day(back)}T08:00:00 Action=\"drop\" src=\"203.0.113.{back % 250}\"\n"
        path = self.dir / f"spark-{day(back)}.log"
        if compressed:
            path = path.with_suffix(".log.gz")
            path.write_bytes(gzip.compress(text.encode()))
        else:
            path.write_text(text)
        return text

    def names(self):
        return sorted(p.name for p in self.dir.iterdir())

    def test_compresses_a_day_once_it_is_seven_days_old(self):
        self.capture(0)
        self.capture(6)
        text7 = self.capture(7)
        self.capture(8)

        result = syslog_retention.prune(self.dir, today=TODAY)

        self.assertEqual(self.names(), sorted([f"spark-{day(0)}.log", f"spark-{day(6)}.log",
                                               f"spark-{day(7)}.log.gz", f"spark-{day(8)}.log.gz"]))
        with gzip.open(self.dir / f"spark-{day(7)}.log.gz", "rt") as f:
            self.assertEqual(f.read(), text7)
        self.assertEqual(result["compressed"], [f"spark-{day(8)}.log", f"spark-{day(7)}.log"])
        self.assertEqual(result["removed"], [])

    def test_removes_days_older_than_the_retention_window_compressed_or_not(self):
        self.capture(179, compressed=True)
        self.capture(180, compressed=True)
        self.capture(181)

        result = syslog_retention.prune(self.dir, today=TODAY)

        self.assertEqual(self.names(), [f"spark-{day(179)}.log.gz"])
        self.assertEqual(result["removed"], [f"spark-{day(181)}.log", f"spark-{day(180)}.log.gz"])
        self.assertEqual(result["compressed"], [])

    def test_a_second_run_changes_nothing(self):
        self.capture(10)
        self.capture(200)
        syslog_retention.prune(self.dir, today=TODAY)
        before = {p.name: p.read_bytes() for p in self.dir.iterdir()}

        result = syslog_retention.prune(self.dir, today=TODAY)

        self.assertEqual({p.name: p.read_bytes() for p in self.dir.iterdir()}, before)
        self.assertEqual(result, {"compressed": [], "removed": []})

    def test_the_ages_are_adjustable(self):
        self.capture(2)
        self.capture(3)
        self.capture(30)

        syslog_retention.prune(self.dir, today=TODAY, compress_after=3, keep_days=30)

        self.assertEqual(self.names(), sorted([f"spark-{day(2)}.log", f"spark-{day(3)}.log.gz"]))

    def test_leaves_everything_that_is_not_a_daily_capture_alone(self):
        for name in ("allow.txt", "checked.json", "spark-notes.log", "spark-2026-13-45.log", "other-2020-01-01.log"):
            (self.dir / name).write_text("keep me\n")
        (self.dir / "nested").mkdir()

        result = syslog_retention.prune(self.dir, today=TODAY)

        self.assertEqual(self.names(), ["allow.txt", "checked.json", "nested", "other-2020-01-01.log",
                                        "spark-2026-13-45.log", "spark-notes.log"])
        self.assertEqual(result, {"compressed": [], "removed": []})

    def test_a_missing_directory_is_not_an_error(self):
        result = syslog_retention.prune(self.dir / "absent", today=TODAY)

        self.assertEqual(result, {"compressed": [], "removed": []})


class CommandLineTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(REPO / "syslog_retention.py"), *args],
                              capture_output=True, text=True)

    def test_reports_what_it_compressed_and_removed(self):
        (self.dir / f"spark-{day(9)}.log").write_text("old\n")
        (self.dir / f"spark-{day(400)}.log").write_text("ancient\n")

        proc = self.run_cli("--dir", str(self.dir), "--today", TODAY.isoformat())

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(f"compressed spark-{day(9)}.log", proc.stdout)
        self.assertIn(f"removed spark-{day(400)}.log", proc.stdout)
        self.assertIn("1 compressed, 1 removed", proc.stdout)

    def test_says_so_when_there_is_nothing_to_do(self):
        (self.dir / f"spark-{day(0)}.log").write_text("today\n")

        proc = self.run_cli("--dir", str(self.dir), "--today", TODAY.isoformat())

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("0 compressed, 0 removed", proc.stdout)


if __name__ == "__main__":
    unittest.main()
