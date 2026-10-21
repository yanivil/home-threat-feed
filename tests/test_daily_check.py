"""daily_check.sh and its LaunchAgent: the once-a-day run that mines the syslog capture,
commits the feed when rows were added and pushes to main."""

import os
import plistlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "daily_check.sh"
PLIST = REPO / "launchd" / "com.spark-ioc-feed.daily.plist"
HEADER = "# UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT\n"
SEED_ROW = "vt-ip-7b3f0a9c21,203.0.113.7,IP,medium,high,AB,VT 6/86 malicious 2026-07-15\n"

# Stands in for spark_logs.py: records its arguments, appends STUB_ADD rows to the feed
# beside it, prints STUB_OUTBOUND outbound hits the way the real script does, exits STUB_EXIT.
STUB_SPARK_LOGS = """\
import os, sys
from pathlib import Path
here = Path(__file__).resolve().parent
(here / "argv.txt").write_text(" ".join(sys.argv[1:]))
with (here / "spark-ioc-feed.csv").open("a") as f:
    for i in range(int(os.environ.get("STUB_ADD", "0"))):
        f.write(f"vt-ip-{i:010},198.51.100.{i},IP,medium,high,AB,Inbound probe of WAN - VT 7/95 malicious 2026-10-21\\n")
print("3 inbound sources and 2 outbound destinations in the last 2 day(s); 3 and 2 still to check")
for i in range(int(os.environ.get("STUB_OUTBOUND", "0"))):
    print(f"OUTBOUND HIT  bad{i}.example  (Domain 7/94 malicious)  reached by 10.0.0.{i}  <- check these devices")
print("Added to the feed: 0  clean: 1  unknown to VirusTotal: 0  left for another day: 0")
sys.exit(int(os.environ.get("STUB_EXIT", "0")))
"""

# Stands in for osascript: appends its arguments to the file STUB_NOTIFICATIONS names.
STUB_OSASCRIPT = '#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$STUB_NOTIFICATIONS"\n'


class DailyCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.repo, self.origin, self.bin = root / "repo", root / "origin.git", root / "bin"
        self.notifications = root / "notifications.txt"
        self.bin.mkdir()
        (self.bin / "osascript").write_text(STUB_OSASCRIPT)
        (self.bin / "osascript").chmod(0o755)
        self.env = {k: v for k, v in os.environ.items() if k != "VT_API_KEY"}
        self.env.update({
            "PATH": f"{self.bin}{os.pathsep}{self.env.get('PATH', '')}",
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.com",
            "STUB_NOTIFICATIONS": str(self.notifications),
        })

        self.repo.mkdir()
        (self.repo / "spark-ioc-feed.csv").write_text(HEADER + SEED_ROW)
        (self.repo / "other.txt").write_text("unrelated\n")
        (self.repo / "spark_logs.py").write_text(STUB_SPARK_LOGS)
        shutil.copy(SCRIPT, self.repo / "daily_check.sh")
        self.git("init", "-q", "-b", "main", cwd=self.repo)
        self.git("add", "-A", cwd=self.repo)
        self.git("commit", "-q", "-m", "seed", cwd=self.repo)
        self.git("init", "-q", "--bare", "-b", "main", str(self.origin), cwd=root)
        self.git("remote", "add", "origin", str(self.origin), cwd=self.repo)
        self.git("push", "-q", "-u", "origin", "main", cwd=self.repo)

    def git(self, *args, cwd):
        return subprocess.run(["git", *args], cwd=cwd, env=self.env, check=True,
                              capture_output=True, text=True).stdout.strip()

    def run_script(self, **stub):
        env = {**self.env, **{k: str(v) for k, v in stub.items()}}
        # From another directory: the script must find the repo it lives in by itself.
        return subprocess.run(["bash", str(self.repo / "daily_check.sh")], cwd=self.tmp.name,
                              env=env, capture_output=True, text=True)

    def head(self, where=None):
        return self.git("rev-parse", "HEAD" if where is None else "main", cwd=where or self.repo)

    def head_files(self):
        return set(self.git("show", "--name-only", "--format=", "HEAD", cwd=self.repo).splitlines())

    def subject(self):
        return self.git("log", "-1", "--format=%s", cwd=self.repo)

    def refuse_pushes(self):
        hook = self.origin / "hooks" / "pre-receive"
        hook.write_text("#!/bin/sh\necho 'origin refuses this push' >&2\nexit 1\n")
        hook.chmod(0o755)
        return hook

    def test_runs_the_check_over_two_days_with_the_daily_lookup_budget(self):
        proc = self.run_script()

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual((self.repo / "argv.txt").read_text(), "--days 2 --check --max-lookups 150")

    def test_added_rows_are_committed_alone_and_pushed(self):
        (self.repo / "other.txt").write_text("edited but not mine to commit\n")
        self.git("add", "other.txt", cwd=self.repo)
        (self.repo / "untracked.txt").write_text("nor this\n")
        before = self.head()

        proc = self.run_script(STUB_ADD=2)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotEqual(self.head(), before)
        self.assertEqual(self.subject(), "Add 2 WAN-probe sources mined from the Spark's syslog, "
                                         "each flagged by 5+ VirusTotal engines")
        self.assertEqual(self.head_files(), {"spark-ioc-feed.csv"})
        self.assertEqual(self.head(self.origin), self.head())
        self.assertIn("other.txt", self.git("diff", "--cached", "--name-only", cwd=self.repo))
        self.assertTrue((self.repo / "untracked.txt").exists())
        self.assertIn("Pushed", proc.stdout)

    def test_one_added_row_gets_a_singular_message(self):
        proc = self.run_script(STUB_ADD=1)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.subject(), "Add 1 WAN-probe source mined from the Spark's syslog, "
                                         "each flagged by 5+ VirusTotal engines")

    def test_unchanged_feed_makes_no_commit(self):
        before = self.head()

        proc = self.run_script()

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.head(), before)
        self.assertIn("unchanged", proc.stdout)

    def test_log_lines_carry_a_timestamp_and_the_check_output(self):
        proc = self.run_script()

        self.assertRegex(proc.stdout, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} .*[Ss]tart")
        self.assertIn("3 inbound sources and 2 outbound destinations", proc.stdout)
        self.assertRegex(proc.stdout, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} .*done")

    def test_failed_push_exits_non_zero_and_the_next_run_pushes_the_pending_commit(self):
        hook = self.refuse_pushes()
        before = self.head()

        proc = self.run_script(STUB_ADD=1)

        self.assertEqual(proc.returncode, 1)
        self.assertIn("ERROR", proc.stdout + proc.stderr)
        self.assertIn("push", proc.stdout + proc.stderr)
        self.assertNotEqual(self.head(), before, "the commit must stay local for the next run")
        self.assertEqual(self.head(self.origin), before)
        self.assertEqual(self.notifications.read_text().count("\n"), 1)

        hook.unlink()
        proc = self.run_script()

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.head(self.origin), self.head())

    def test_commits_made_elsewhere_are_pulled_in_before_the_check(self):
        other = Path(self.tmp.name) / "other-clone"
        self.git("clone", "-q", str(self.origin), str(other), cwd=self.tmp.name)
        (other / "other.txt").write_text("edited on GitHub\n")
        self.git("commit", "-q", "-am", "Edit other.txt elsewhere", cwd=other)
        self.git("push", "-q", cwd=other)

        proc = self.run_script(STUB_ADD=1)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.head(self.origin), self.head())
        self.assertEqual((self.repo / "other.txt").read_text(), "edited on GitHub\n")
        self.assertEqual(self.git("log", "--format=%s", cwd=self.repo).splitlines()[1], "Edit other.txt elsewhere")

    def test_outbound_hits_raise_a_notification_that_points_at_the_log(self):
        proc = self.run_script(STUB_OUTBOUND=2)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("OUTBOUND HIT  bad0.example", proc.stdout)
        notified = self.notifications.read_text()
        self.assertIn("display notification", notified)
        self.assertIn("2 outbound", notified)
        self.assertIn("/tmp/spark-daily-check.log", notified)

    def test_a_clean_run_sends_no_notification(self):
        self.run_script(STUB_ADD=1)

        self.assertFalse(self.notifications.exists())

    def test_quota_stop_still_commits_what_was_added_but_exits_non_zero(self):
        proc = self.run_script(STUB_ADD=1, STUB_EXIT=1)

        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.head_files(), {"spark-ioc-feed.csv"})
        self.assertEqual(self.head(self.origin), self.head())
        self.assertIn("exited 1", proc.stdout + proc.stderr)
        self.assertIn("quota", proc.stdout + proc.stderr)


class DailyPlistTest(unittest.TestCase):
    def test_runs_the_script_every_morning_at_0730_and_logs_to_tmp(self):
        plist = plistlib.loads(PLIST.read_bytes())

        self.assertEqual(plist["Label"], "com.spark-ioc-feed.daily")
        self.assertEqual(plist["ProgramArguments"][0], "/bin/bash")
        self.assertEqual(Path(plist["ProgramArguments"][1]).name, "daily_check.sh")
        self.assertEqual(plist["WorkingDirectory"], str(Path(plist["ProgramArguments"][1]).parent))
        self.assertEqual(plist["StartCalendarInterval"], {"Hour": 7, "Minute": 30})
        self.assertEqual(plist["StandardOutPath"], "/tmp/spark-daily-check.log")
        self.assertEqual(plist["StandardErrorPath"], "/tmp/spark-daily-check.log")
        self.assertNotIn("RunAtLoad", plist, "a daily job must not fire on every login")


if __name__ == "__main__":
    unittest.main()
