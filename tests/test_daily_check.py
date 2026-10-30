"""daily_check.sh and its LaunchAgent: the once-a-day run that mines the syslog capture,
commits the feed when rows were added and pushes to main."""

import json
import os
import plistlib
import shutil
import subprocess
import tempfile
import time
import unittest
from datetime import date, timedelta
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "daily_check.sh"
PLIST = REPO / "launchd" / "com.spark-ioc-feed.daily.plist"
HEADER = "# UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT\n"
SEED_ROW = "vt-ip-7b3f0a9c21,185.1.5.7,IP,medium,high,AB,confirmed 2026-07-15\n"  # feed_lint wants a public IP

# Stands in for spark_logs.py: records its arguments and whether the feed lock is held while it
# runs, appends STUB_ADD rows to the feed beside it, prints STUB_OUTBOUND outbound hits the way
# the real script does, exits STUB_EXIT. Only its command line is stubbed: it re-exports the real
# module (copied beside it as spark_logs_real.py) so spark_brief.py, which imports spark_logs,
# gets the real functions.
STUB_SPARK_LOGS = """\
import importlib.util, os, sys
from pathlib import Path
here = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("spark_logs_real", here / "spark_logs_real.py")
_real = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_real)
globals().update({k: v for k, v in vars(_real).items() if not k.startswith("__")})


def main():
    (here / "argv.txt").write_text(" ".join(sys.argv[1:]))
    (here / "lock_held.txt").write_text(str((here / "syslog" / ".feed-lock").is_dir()))
    feed = here / "spark-ioc-feed.csv"
    # Rows numbered after those already there: a second run must not repeat one (feed_lint refuses it).
    start = sum(1 for line in feed.read_text().splitlines() if line and not line.startswith("#"))
    with feed.open("a") as f:
        for i in range(start, start + int(os.environ.get("STUB_ADD", "0"))):
            f.write(f"vt-ip-{i:010},185.1.4.{i},IP,medium,high,AB,"
                    "Inbound probe of WAN - Spark syslog 2026-10-21 - confirmed 2026-10-21\\n")
        if os.environ.get("STUB_BAD_ROW"):
            f.write("stub-bad,github.com,Domain,high,high,AB,a row the gateway must never see\\n")
    print("3 inbound sources and 2 outbound destinations in the last 2 day(s); 3 and 2 still to check")
    for i in range(int(os.environ.get("STUB_OUTBOUND", "0"))):
        print(f"OUTBOUND HIT  bad{i}.example  (Domain 7/94 malicious)  reached by 10.0.0.{i}  <- check these devices")
    print("Added to the feed: 0  clean: 1  unknown to the service: 0  left for another day: 0")
    sys.exit(int(os.environ.get("STUB_EXIT", "0")))


if __name__ == "__main__":
    main()
"""

# Stands in for spark_brief.py: records each call (its arguments, the run log it was given, whether the
# feed lock was held) in brief_calls.jsonl beside it; a brief (--run-log) exits STUB_BRIEF_EXIT, and with
# STUB_BRIEF_LOCK it takes the feed lock the way the bot would while it runs.
STUB_BRIEF = """\
import json, os, sys
from pathlib import Path
here = Path(__file__).resolve().parent
args = sys.argv[1:]
call = {"args": args, "locked": (here / "syslog" / ".feed-lock").is_dir()}
if "--run-log" in args:
    call["run_log"] = Path(args[args.index("--run-log") + 1]).read_text()
with (here / "brief_calls.jsonl").open("a") as f:
    f.write(json.dumps(call) + "\\n")
print("stub brief:", " ".join(args))
if "--run-log" in args and os.environ.get("STUB_BRIEF_LOCK"):
    (here / "syslog" / ".feed-lock").mkdir()
sys.exit(int(os.environ.get("STUB_BRIEF_EXIT", "0")) if "--run-log" in args else 0)
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
        self.sleeps = root / "sleeps.txt"
        self.lock = self.repo / "syslog" / ".feed-lock"
        self.bin.mkdir()
        (self.bin / "osascript").write_text(STUB_OSASCRIPT)
        (self.bin / "osascript").chmod(0o755)
        self.env = {k: v for k, v in os.environ.items() if k not in ("VT_API_KEY", "REPUTATION_API_KEY")}
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
        shutil.copy(REPO / "syslog_retention.py", self.repo / "syslog_retention.py")  # the real one: no network, no key
        # The brief is the real one, over the real spark_logs functions; no Keychain item exists, so it prints.
        for module in ("spark_brief.py", "telegram_api.py", "keychain.py", "vt_check.py", "feed_lint.py"):
            shutil.copy(REPO / module, self.repo / module)
        shutil.copy(REPO / "spark_logs.py", self.repo / "spark_logs_real.py")
        (self.repo / "attacker_context.py").write_text('note = lambda *a, **k: ""\n')
        shutil.copy(REPO / "tests" / "stubs" / "security", self.bin / "security")
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
                              env=env, capture_output=True, text=True, timeout=120)

    def stub_brief(self):
        (self.repo / "spark_brief.py").write_text(STUB_BRIEF)

    def brief_calls(self):
        path = self.repo / "brief_calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def head(self, where=None):
        return self.git("rev-parse", "HEAD" if where is None else "main", cwd=where or self.repo)

    def head_files(self):
        return set(self.git("show", "--name-only", "--format=", "HEAD", cwd=self.repo).splitlines())

    def subject(self):
        return self.git("log", "-1", "--format=%s", cwd=self.repo)

    def hold_lock(self, hours_ago=0):
        """The lock the Telegram bot takes, made `hours_ago` hours back."""
        self.lock.parent.mkdir(exist_ok=True)
        self.lock.mkdir()
        taken = time.time() - hours_ago * 3600
        os.utime(self.lock, (taken, taken))

    def stub_sleep(self, then=""):
        """Replace sleep with a script that records its argument, then runs the shell line `then`."""
        stub = self.bin / "sleep"
        stub.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{self.sleeps}'\n{then}\n")
        stub.chmod(0o755)

    def refuse_pushes(self):
        hook = self.origin / "hooks" / "pre-receive"
        hook.write_text("#!/bin/sh\necho 'origin refuses this push' >&2\nexit 1\n")
        hook.chmod(0o755)
        return hook

    def test_runs_the_check_over_two_days_with_the_scripts_own_lookup_budget(self):
        proc = self.run_script()

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual((self.repo / "argv.txt").read_text(), "--days 2 --check")
        self.assertNotIn("lookups", proc.stdout)

    def test_days_and_max_lookups_in_the_environment_override_the_defaults(self):
        proc = self.run_script(DAYS=3, MAX_LOOKUPS=50)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual((self.repo / "argv.txt").read_text(), "--days 3 --check --max-lookups 50")
        self.assertIn("last 3 day(s), up to 50 lookups", proc.stdout)

    def test_added_rows_are_committed_alone_and_pushed(self):
        (self.repo / "other.txt").write_text("edited but not mine to commit\n")
        self.git("add", "other.txt", cwd=self.repo)
        (self.repo / "untracked.txt").write_text("nor this\n")
        before = self.head()

        proc = self.run_script(STUB_ADD=2)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotEqual(self.head(), before)
        self.assertEqual(self.subject(), "Add 2 WAN-probe sources mined from the Spark's syslog, "
                                         "each flagged by 5+ engines")
        self.assertEqual(self.head_files(), {"spark-ioc-feed.csv"})
        self.assertEqual(self.head(self.origin), self.head())
        self.assertIn("other.txt", self.git("diff", "--cached", "--name-only", cwd=self.repo))
        self.assertTrue((self.repo / "untracked.txt").exists())
        self.assertIn("Pushed", proc.stdout)

    def test_one_added_row_gets_a_singular_message(self):
        proc = self.run_script(STUB_ADD=1)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.subject(), "Add 1 WAN-probe source mined from the Spark's syslog, "
                                         "each flagged by 5+ engines")

    def test_unchanged_feed_makes_no_commit(self):
        before = self.head()

        proc = self.run_script()

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.head(), before)
        self.assertIn("unchanged", proc.stdout)

    def test_a_bad_row_on_main_fails_the_run_before_the_check(self):
        # Typed in the GitHub web editor: it reached main unchecked, and the next run says so.
        self.stub_brief()
        with (self.repo / "spark-ioc-feed.csv").open("a") as f:
            f.write("web-edit,github.com,Domain,high,high,AB,typed in the GitHub web editor\n")
            f.write("web-edit-2,api.telegram.org,Domain,high,high,AB,and another\n")
        self.git("commit", "-q", "-am", "web edit", cwd=self.repo)
        self.git("push", "-q", cwd=self.repo)
        before = self.head()

        proc = self.run_script(STUB_ADD=1)

        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("line 4: VALUE api.telegram.org is a host this system needs (never block)", proc.stdout)
        # The notice shows no log, so it carries the first problem itself.
        reason = ("the feed on main fails its lint, nothing was checked: line 3: VALUE github.com is a host "
                  "this system needs (never block) and 1 more; fix spark-ioc-feed.csv")
        self.assertIn(f"ERROR: {reason}", proc.stdout)
        self.assertFalse((self.repo / "argv.txt").exists())  # the check did not run
        self.assertEqual(self.head(), before)
        calls = self.brief_calls()
        self.assertEqual([c["args"][:2] for c in calls], [["--send", "--notice"]])
        self.assertEqual(calls[0]["args"][2], f"Daily check failed: {reason}")
        self.assertFalse(self.lock.exists())

    def test_a_bad_row_left_on_this_mac_is_told_apart_from_main(self):
        # The bot refused to commit a hand edit: the file here differs from main, and main is fine.
        self.stub_brief()
        with (self.repo / "spark-ioc-feed.csv").open("a") as f:
            f.write("hand-edit,github.com,Domain,high,high,AB,typed into the file\n")

        proc = self.run_script()

        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("ERROR: the feed on this Mac (uncommitted changes) fails its lint, nothing was checked: "
                      "line 3: VALUE github.com is a host this system needs (never block); fix spark-ioc-feed.csv",
                      proc.stdout)
        self.assertIn("github.com", (self.repo / "spark-ioc-feed.csv").read_text())  # left for the fix
        self.assertFalse(self.lock.exists())

    def test_rows_the_check_wrote_that_fail_the_lint_are_not_committed(self):
        self.stub_brief()
        before = self.head()

        proc = self.run_script(STUB_ADD=1, STUB_BAD_ROW=1)

        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        reason = ("the rows the check added fail the lint and stay uncommitted in spark-ioc-feed.csv: "
                  "line 4: VALUE github.com is a host this system needs (never block)")
        self.assertIn(f"ERROR: {reason}", proc.stdout)
        self.assertEqual(self.head(), before)
        self.assertIn("github.com", (self.repo / "spark-ioc-feed.csv").read_text())  # left for the fix
        self.assertIn(f"ERROR: {reason}", self.brief_calls()[-1]["run_log"])  # the brief's ERRORS line
        self.assertFalse(self.lock.exists())

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
        self.assertIn(os.path.expanduser("~/Library/Logs/spark-ioc-feed/daily-check.log"), notified)

    def test_the_brief_is_composed_after_the_run(self):
        proc = self.run_script(STUB_ADD=1, STUB_OUTBOUND=1)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Spark brief —", proc.stdout)
        self.assertLess(proc.stdout.index("Pushed to"), proc.stdout.index("Spark brief —"))
        self.assertLess(proc.stdout.index("Spark brief —"), proc.stdout.index("Daily check done"))
        self.assertIn("Outbound hits: 1", proc.stdout, "the brief reads the run's own output")
        self.assertIn("10.0.0.0 reached bad0.example (7/94)", proc.stdout)
        self.assertIn("INDICATORS ENTERED: 1 from the Spark's logs", proc.stdout, "and the rows git says were added")

    def test_the_brief_is_sent_even_when_the_check_stopped_at_the_quota(self):
        proc = self.run_script(STUB_ADD=1, STUB_EXIT=1)

        self.assertEqual(proc.returncode, 1)
        self.assertIn("Spark brief —", proc.stdout)
        self.assertLess(proc.stdout.index("Spark brief —"), proc.stdout.index("exited 1"))

    def test_a_brief_or_a_note_that_cannot_be_sent_is_a_warning_not_a_failed_run(self):
        # 1: the brief was not sent; 2: it was, an attacker note was not.
        for status in (1, 2):
            with self.subTest(status=status):
                (self.repo / "spark_brief.py").write_text(f"import sys\nprint('brief broke', file=sys.stderr)\nsys.exit({status})\n")

                proc = self.run_script()

                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertIn("brief broke", proc.stdout)
                self.assertIn(f"WARNING: spark_brief.py exited {status}: the brief or an attacker note was not sent (see above)",
                              proc.stdout)
                self.assertIn("Daily check done", proc.stdout)

    def test_consecutive_briefs_do_not_count_a_row_twice(self):
        first = self.run_script(STUB_ADD=1)
        second = self.run_script(STUB_ADD=1)

        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn("INDICATORS ENTERED: 1 from the Spark's logs · 0 from news · 0 by hand\n", second.stdout)
        self.assertIn("INDICATORS ENTERED: 1 from the Spark's logs", first.stdout)
        self.assertTrue((self.repo / "syslog" / "last-brief.json").exists())

    def test_old_captures_are_compressed_before_anything_else(self):
        old = self.repo / "syslog" / f"spark-{date.today() - timedelta(days=10):%Y-%m-%d}.log"
        old.parent.mkdir()
        old.write_text("an entry from ten days ago\n")
        self.git("remote", "set-url", "origin", str(Path(self.tmp.name) / "gone.git"), cwd=self.repo)

        proc = self.run_script()

        self.assertEqual(proc.returncode, 1, "a failed pull still fails the run")
        self.assertFalse(old.exists())
        self.assertTrue(old.with_suffix(".log.gz").exists())
        self.assertIn(f"compressed {old.name}", proc.stdout)

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

    def test_the_run_holds_the_feed_lock_and_releases_it(self):
        proc = self.run_script()

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual((self.repo / "lock_held.txt").read_text(), "True")
        self.assertFalse(self.lock.exists())

    def test_a_stale_lock_does_not_block_the_run(self):
        self.hold_lock(hours_ago=4)
        self.stub_sleep()

        proc = self.run_script()

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertFalse(self.sleeps.exists(), "a stale lock is taken over, not waited for")
        self.assertEqual((self.repo / "lock_held.txt").read_text(), "True")
        self.assertFalse(self.lock.exists())

    def test_a_lock_the_bot_releases_while_the_run_waits_lets_the_run_go_on(self):
        self.hold_lock(hours_ago=1)
        self.stub_sleep(then=f"rmdir '{self.lock}'")

        proc = self.run_script()

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout.count("waiting"), 1)
        self.assertEqual(self.sleeps.read_text(), "5\n")
        self.assertEqual((self.repo / "lock_held.txt").read_text(), "True")
        self.assertFalse(self.lock.exists())

    def test_a_lock_held_for_twenty_minutes_fails_the_run_and_is_left_for_its_owner(self):
        # Twenty, not ten: a 50-indicator check from the bot holds the lock about 13 minutes.
        self.hold_lock(hours_ago=1)
        self.stub_sleep()

        proc = self.run_script()

        self.assertEqual(proc.returncode, 1)
        self.assertIn("ERROR: the feed is locked by the Telegram bot for over twenty minutes", proc.stdout)
        self.assertEqual(self.sleeps.read_text(), "5\n" * 240)
        self.assertEqual(proc.stdout.count("waiting up to twenty minutes"), 1)
        self.assertFalse((self.repo / "argv.txt").exists(), "the check must not run without the lock")
        self.assertTrue(self.lock.is_dir(), "the lock is not ours to remove")
        self.assertEqual(self.notifications.read_text().count("\n"), 1)

    def test_a_failed_pull_sends_a_one_line_notice(self):
        self.stub_brief()
        self.git("remote", "set-url", "origin", str(Path(self.tmp.name) / "gone.git"), cwd=self.repo)

        proc = self.run_script()

        self.assertEqual(proc.returncode, 1)
        [call] = self.brief_calls()
        self.assertEqual(call["args"][:2], ["--send", "--notice"])
        self.assertTrue(call["args"][2].startswith("Daily check failed: git pull failed; the feed was not checked"),
                        call["args"])
        self.assertFalse(call["locked"], "the lock is given back before the notice")
        self.assertEqual(self.notifications.read_text().count("\n"), 1, "the macOS notification stays")

    def test_a_lock_that_stays_held_sends_the_notice_and_leaves_the_lock(self):
        self.hold_lock(hours_ago=1)
        self.stub_sleep()
        self.stub_brief()

        proc = self.run_script()

        self.assertEqual(proc.returncode, 1)
        [call] = self.brief_calls()
        self.assertEqual(call["args"], ["--send", "--notice", "Daily check failed: the feed is locked by the Telegram "
                                                             "bot for over twenty minutes"])
        self.assertTrue(self.lock.is_dir(), "the bot's lock")

    def test_a_failed_push_sends_the_brief_with_the_failure_among_its_errors(self):
        self.refuse_pushes()

        proc = self.run_script(STUB_ADD=1)

        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout.count("Spark brief —"), 1, proc.stdout)
        self.assertIn("\nERRORS\n", proc.stdout)
        self.assertIn("  ERROR: git push failed; the commit stays local and the next run will push it\n", proc.stdout)
        self.assertNotIn("Daily check failed:", proc.stdout, "the brief is the one message")

    def test_a_brief_that_cannot_be_sent_is_followed_by_the_notice(self):
        self.stub_brief()

        proc = self.run_script(STUB_BRIEF_EXIT=1)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        calls = self.brief_calls()
        self.assertEqual([call["args"][1] for call in calls], ["--run-log", "--notice"])
        self.assertEqual(calls[1]["args"][2],
                         "Daily check failed: the morning brief was not sent (spark_brief.py exited 1)")

    def test_a_brief_whose_note_failed_needs_no_notice(self):
        self.stub_brief()

        self.run_script(STUB_BRIEF_EXIT=2)

        self.assertEqual([call["args"][1] for call in self.brief_calls()], ["--run-log"])

    def test_a_quota_stop_sends_the_brief_alone(self):
        self.stub_brief()

        proc = self.run_script(STUB_ADD=1, STUB_EXIT=1)

        self.assertEqual(proc.returncode, 1)
        [call] = self.brief_calls()
        self.assertEqual(call["args"][:2], ["--send", "--run-log"])
        self.assertIn("Added to the feed:", call["run_log"])

    def test_the_lock_is_given_back_before_the_brief_and_one_taken_since_is_left_alone(self):
        # The brief's attacker notes skip VirusTotal while the lock exists; the bot may take it meanwhile.
        self.stub_brief()

        proc = self.run_script(STUB_ADD=1, STUB_BRIEF_LOCK=1)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual((self.repo / "lock_held.txt").read_text(), "True", "held through the check")
        self.assertFalse(self.brief_calls()[0]["locked"])
        self.assertTrue(self.lock.is_dir(), "the lock the bot took during the brief is not the script's to remove")

    def test_a_stale_lock_that_cannot_be_removed_is_waited_for_not_spun_on(self):
        self.hold_lock(hours_ago=4)
        (self.lock / "left-behind").write_text("rmdir cannot remove a directory that is not empty\n")
        taken = time.time() - 4 * 3600  # writing in it made it new again
        os.utime(self.lock, (taken, taken))
        self.stub_sleep()
        self.stub_brief()

        proc = self.run_script()

        self.assertEqual(proc.returncode, 1)
        self.assertIn("ERROR: the feed is locked by the Telegram bot for over twenty minutes", proc.stdout)
        self.assertEqual(self.sleeps.read_text(), "5\n" * 240)

    def test_a_capture_directory_that_cannot_be_made_fails_the_run_at_once(self):
        (self.repo / "syslog").write_text("a file where the directory should be\n")
        self.stub_sleep()
        self.stub_brief()

        proc = self.run_script()

        self.assertEqual(proc.returncode, 1)
        self.assertIn("ERROR: cannot create syslog/", proc.stdout)
        self.assertFalse(self.sleeps.exists(), "no wait for a lock that can never be taken")
        self.assertEqual(self.brief_calls()[0]["args"], ["--send", "--notice", "Daily check failed: cannot create syslog/"])

    def test_a_run_that_fails_before_the_check_still_releases_the_lock(self):
        # fail runs while the lock is still held: the osascript stub notes whether it was.
        (self.bin / "osascript").write_text("#!/bin/sh\n[ -d syslog/.feed-lock ] && touch lock_held_at_failure.txt\n")
        self.git("remote", "set-url", "origin", str(Path(self.tmp.name) / "gone.git"), cwd=self.repo)

        proc = self.run_script()

        self.assertEqual(proc.returncode, 1, "a failed pull fails the run")
        self.assertTrue((self.repo / "lock_held_at_failure.txt").exists())
        self.assertFalse(self.lock.exists())


class DailyPlistTest(unittest.TestCase):
    def test_runs_the_script_every_morning_at_0730_under_python_app_and_logs_under_library(self):
        plist = plistlib.loads(PLIST.read_bytes())
        program, flag, command = plist["ProgramArguments"]

        self.assertEqual(plist["Label"], "com.spark-ioc-feed.daily")
        # Python.app is the one program macOS lets read the external disk from launchd; bash
        # runs under it and inherits the grant (docs/system-design.md, D1).
        self.assertTrue(program.endswith("/Python.app/Contents/MacOS/Python"), program)
        self.assertEqual(flag, "-c")
        self.assertIn("'/bin/bash'", command)
        self.assertIn(plist["WorkingDirectory"] + "/daily_check.sh", command)
        self.assertEqual(plist["StartCalendarInterval"], {"Hour": 7, "Minute": 30})
        log = plist["StandardOutPath"]
        self.assertTrue(log.endswith("/Library/Logs/spark-ioc-feed/daily-check.log"), log)
        self.assertEqual(plist["StandardErrorPath"], log)
        self.assertNotIn("RunAtLoad", plist, "a daily job must not fire on every login")


if __name__ == "__main__":
    unittest.main()
