"""news_check.sh and its LaunchAgent: the once-a-day run that asks the news agent for candidates outside the
feed lock, looks them up inside it, commits the feed when rows were added and pushes to main (design D7)."""

import json
import os
import plistlib
import shutil
import subprocess
import tempfile
import time
import unittest
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "news_check.sh"
PLIST = REPO / "launchd" / "com.spark-ioc-feed.news.plist"
HEADER = "# UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT\n"
SEED_ROW = "vt-ip-7b3f0a9c21,185.1.5.7,IP,medium,high,AB,confirmed 2026-07-15\n"
TODAY = date.today().isoformat()

# Stands in for news_agent.py: records each call (its arguments, whether the feed lock was held) in
# agent_calls.jsonl beside it. Without --check it writes STUB_CANDIDATES candidates to the --out file (or
# exits STUB_AGENT_EXIT the way the real one does for a missing key, 3, or an unreachable model, 2). With
# --check it appends STUB_ADD rows to the feed beside it unless --dry-run (and a bad row with STUB_BAD_ROW),
# prints what the real one prints and exits STUB_CHECK_EXIT.
STUB_NEWS_AGENT = """\
import json, os, sys
from pathlib import Path
here = Path(__file__).resolve().parent
args = sys.argv[1:]
with (here / "agent_calls.jsonl").open("a") as f:
    f.write(json.dumps({"args": args, "locked": (here / "syslog" / ".feed-lock").is_dir()}) + "\\n")
if "--check" in args:
    path = Path(args[args.index("--check") + 1])
    entries = [l for l in path.read_text().splitlines() if l and not l.startswith("#")]
    if not entries:
        print("Nothing to check")
        sys.exit(0)
    dry = "--dry-run" in args
    print(f"Checking {len(entries)} indicators against the reputation service (min 3 malicious detections, IPs 5"
          + (", dry run)" if dry else ")"))
    feed = here / "spark-ioc-feed.csv"
    start = sum(1 for line in feed.read_text().splitlines() if line and not line.startswith("#"))
    if not dry:
        with feed.open("a") as f:
            for i in range(start, start + int(os.environ.get("STUB_ADD", "0"))):
                f.write(f"vt-domain-{i:010},bad{i}.example,Domain,medium,high,AB,"
                        "News 2026-10-28 Fake parcel SMS - confirmed 2026-10-29\\n")
            if os.environ.get("STUB_BAD_ROW"):
                f.write("stub-bad,github.com,Domain,high,high,AB,a row the gateway must never see\\n")
    print("News check: 1 added, 1 clean")
    sys.exit(int(os.environ.get("STUB_CHECK_EXIT", "0")))
status = int(os.environ.get("STUB_AGENT_EXIT", "0"))
if status == 3:
    print("news agent: no ANTHROPIC_API_KEY in the Keychain (service spark-ioc-feed)")
    sys.exit(3)
if status:
    print("news agent: Overloaded")
    sys.exit(status)
out = Path(args[args.index("--out") + 1])
n = int(os.environ.get("STUB_CANDIDATES", "2"))
out.write_text("# News candidates\\n" + "".join(f"bad{i}.example\\tNews 2026-10-28 Fake parcel SMS\\n" for i in range(n)))
print("news usage: input=50000 output=3000 searches=8 fetches=4 seconds=120")
print(f"{n} candidates for lookup from {n} named")
"""

# Stands in for spark_brief.py: records each call (its arguments, whether the feed lock was held) in
# brief_calls.jsonl beside it. The news job only ever sends the one-line notice through it.
STUB_BRIEF = """\
import json, sys
from pathlib import Path
here = Path(__file__).resolve().parent
with (here / "brief_calls.jsonl").open("a") as f:
    f.write(json.dumps({"args": sys.argv[1:], "locked": (here / "syslog" / ".feed-lock").is_dir()}) + "\\n")
print("stub brief:", " ".join(sys.argv[1:]))
"""

STUB_OSASCRIPT = '#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$STUB_NOTIFICATIONS"\n'


class NewsCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.repo, self.origin, self.bin = root / "repo", root / "origin.git", root / "bin"
        self.notifications = root / "notifications.txt"
        self.sleeps = root / "sleeps.txt"
        self.lock = self.repo / "syslog" / ".feed-lock"
        self.candidates = self.repo / "syslog" / f"news-{TODAY}.txt"
        self.bin.mkdir()
        (self.bin / "osascript").write_text(STUB_OSASCRIPT)
        (self.bin / "osascript").chmod(0o755)
        self.env = {k: v for k, v in os.environ.items() if k not in ("VT_API_KEY", "DRY_RUN", "MAX_CANDIDATES")}
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
        (self.repo / "news_agent.py").write_text(STUB_NEWS_AGENT)
        (self.repo / "spark_brief.py").write_text(STUB_BRIEF)
        shutil.copy(SCRIPT, self.repo / "news_check.sh")
        for module in ("feed_lint.py", "spark_logs.py", "vt_check.py", "keychain.py"):  # the real lint
            shutil.copy(REPO / module, self.repo / module)
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
        return subprocess.run(["bash", str(self.repo / "news_check.sh")], cwd=self.tmp.name,
                              env=env, capture_output=True, text=True, timeout=120)

    def calls(self, name):
        path = self.repo / f"{name}_calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def notices(self):
        return [call["args"][2] for call in self.calls("brief") if call["args"][:2] == ["--send", "--notice"]]

    def head(self, where=None):
        return self.git("rev-parse", "HEAD" if where is None else "main", cwd=where or self.repo)

    def head_files(self):
        return set(self.git("show", "--name-only", "--format=", "HEAD", cwd=self.repo).splitlines())

    def subject(self):
        return self.git("log", "-1", "--format=%s", cwd=self.repo)

    def hold_lock(self, hours_ago=0):
        self.lock.parent.mkdir(exist_ok=True)
        self.lock.mkdir()
        taken = time.time() - hours_ago * 3600
        os.utime(self.lock, (taken, taken))

    def stub_sleep(self, then=""):
        stub = self.bin / "sleep"
        stub.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{self.sleeps}'\n{then}\n")
        stub.chmod(0o755)

    def refuse_pushes(self):
        hook = self.origin / "hooks" / "pre-receive"
        hook.write_text("#!/bin/sh\necho 'origin refuses this push' >&2\nexit 1\n")
        hook.chmod(0o755)
        return hook

    def test_asks_outside_the_lock_checks_inside_it_commits_and_pushes(self):
        (self.repo / "other.txt").write_text("edited but not mine to commit\n")
        before = self.head()

        proc = self.run_script(STUB_ADD=2)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        find, check = self.calls("agent")
        self.assertEqual(find["args"], ["--out", f"syslog/news-{TODAY}.txt"])
        self.assertFalse(find["locked"], "the model call must not hold the feed lock")
        self.assertEqual(check["args"], ["--check", f"syslog/news-{TODAY}.txt"])
        self.assertTrue(check["locked"], "the lookups must hold the feed lock")
        self.assertTrue(self.candidates.exists())
        self.assertNotEqual(self.head(), before)
        self.assertEqual(self.subject(), f"Add 2 indicators from news {TODAY}")
        self.assertEqual(self.head_files(), {"spark-ioc-feed.csv"})
        self.assertEqual(self.head(self.origin), self.head())
        self.assertIn("Pushed", proc.stdout)
        self.assertIn("News check done", proc.stdout)
        self.assertIn("news usage: input=50000", proc.stdout, "the agent's output is in the log")
        self.assertFalse(self.lock.exists())
        self.assertEqual(self.calls("brief"), [], "no brief and no notice on a good run")
        self.assertFalse(self.notifications.exists())

    def test_one_row_gets_a_singular_subject(self):
        proc = self.run_script(STUB_ADD=1)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.subject(), f"Add 1 indicator from news {TODAY}")

    def test_nothing_flagged_makes_no_commit(self):
        before = self.head()

        proc = self.run_script()

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.head(), before)
        self.assertIn("Feed unchanged", proc.stdout)

    def test_a_quiet_day_takes_no_lock_and_looks_nothing_up(self):
        self.stub_sleep()

        proc = self.run_script(STUB_CANDIDATES=0)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(len(self.calls("agent")), 1, "no --check without candidates")
        self.assertIn("No candidates today", proc.stdout)
        self.assertIn("News check done", proc.stdout)
        self.assertFalse(self.sleeps.exists())

    def test_dry_run_looks_up_and_commits_nothing(self):
        before = self.head()

        proc = self.run_script(DRY_RUN=1, STUB_ADD=2)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        _, check = self.calls("agent")
        self.assertEqual(check["args"], ["--check", f"syslog/news-{TODAY}.txt", "--dry-run"])
        self.assertEqual(self.head(), before)
        self.assertIn("dry run", proc.stdout)
        self.assertIn("Dry run: nothing committed or pushed", proc.stdout)
        self.assertIn("News check done", proc.stdout)

    def test_a_dry_run_leaves_commits_already_ahead_for_the_next_run(self):
        (self.repo / "other.txt").write_text("edited by hand\n")
        self.git("commit", "-q", "-am", "Edit other.txt by hand", cwd=self.repo)
        before = self.head()

        proc = self.run_script(DRY_RUN=1)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.head(), before)
        self.assertNotEqual(self.head(self.origin), before, "a dry run pushes nothing")

    def test_dry_run_zero_is_not_a_dry_run(self):
        proc = self.run_script(DRY_RUN=0, STUB_ADD=1)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.calls("agent")[1]["args"], ["--check", f"syslog/news-{TODAY}.txt"])
        self.assertEqual(self.subject(), f"Add 1 indicator from news {TODAY}")

    def test_a_max_candidates_that_is_not_a_number_fails_before_the_model_call(self):
        proc = self.run_script(MAX_CANDIDATES="ten")

        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.calls("agent"), [])
        self.assertEqual(self.notices(), ["News check failed: MAX_CANDIDATES must be a number, not 'ten'"])

    def test_max_candidates_in_the_environment_is_passed_on(self):
        proc = self.run_script(MAX_CANDIDATES=10)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.calls("agent")[0]["args"], ["--out", f"syslog/news-{TODAY}.txt", "--max-candidates", "10"])
        self.assertIn("up to 10 candidates", proc.stdout)

    def test_a_missing_anthropic_key_fails_before_the_lock_with_a_notice(self):
        self.stub_sleep()

        proc = self.run_script(STUB_AGENT_EXIT=3)

        self.assertEqual(proc.returncode, 1)
        self.assertEqual(len(self.calls("agent")), 1)
        self.assertEqual(self.notices(), ["News check failed: no ANTHROPIC_API_KEY in the Keychain, the news agent "
                                          "cannot run (README, \"News agent\")"])
        self.assertIn("ERROR: no ANTHROPIC_API_KEY", proc.stdout)
        self.assertFalse(self.sleeps.exists())
        self.assertFalse(self.lock.exists())
        self.assertEqual(self.notifications.read_text().count("\n"), 1)

    def test_an_unreachable_model_fails_with_a_notice(self):
        proc = self.run_script(STUB_AGENT_EXIT=2)

        self.assertEqual(proc.returncode, 1)
        self.assertEqual(len(self.calls("agent")), 1)
        self.assertEqual(self.notices(), ["News check failed: the model call failed, nothing was looked up "
                                          "(see " + os.path.expanduser("~/Library/Logs/spark-ioc-feed/news-check.log") + ")"])
        self.assertIn("news agent: Overloaded", proc.stdout, "the agent's reason is in the log")

    def test_a_quota_stop_still_commits_what_was_added_but_fails(self):
        proc = self.run_script(STUB_ADD=1, STUB_CHECK_EXIT=4)

        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.subject(), f"Add 1 indicator from news {TODAY}")
        self.assertEqual(self.head(self.origin), self.head())
        [notice] = self.notices()
        self.assertIn("exited 4", notice)
        self.assertIn("quota", notice)
        self.assertFalse(self.lock.exists())

    def test_a_quota_stop_in_a_dry_run_says_nothing_was_committed(self):
        before = self.head()

        proc = self.run_script(DRY_RUN=1, STUB_ADD=1, STUB_CHECK_EXIT=4)

        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.head(), before)
        [notice] = self.notices()
        self.assertIn("exited 4", notice)
        self.assertIn("a dry run, nothing was committed", notice)
        self.assertNotIn("rows done so far", notice)

    def test_a_failed_push_after_a_failed_check_names_both(self):
        self.refuse_pushes()

        proc = self.run_script(STUB_ADD=1, STUB_CHECK_EXIT=2)

        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.subject(), f"Add 1 indicator from news {TODAY}")  # the rows are committed all the same
        [notice] = self.notices()
        self.assertIn("git push failed", notice)
        self.assertIn("news_agent.py --check itself exited 2", notice)

    def test_failed_lookups_still_commit_what_was_added_but_fail(self):
        proc = self.run_script(STUB_ADD=1, STUB_CHECK_EXIT=2)

        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.subject(), f"Add 1 indicator from news {TODAY}")
        self.assertEqual(self.head(self.origin), self.head())
        [notice] = self.notices()
        self.assertIn("exited 2", notice)
        self.assertIn("the reputation service refused the key or lookups failed; the rows done so far are in", notice)
        self.assertFalse(self.calls("brief")[0]["locked"], "the lock is given back before the notice")

    def test_a_missing_vt_key_fails_the_check_with_a_notice(self):
        proc = self.run_script(STUB_CHECK_EXIT=3)

        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.notices(), ["News check failed: no VT_API_KEY in the Keychain, nothing was looked up "
                                          "(README, \"Daily check on this Mac\")"])
        self.assertFalse(self.lock.exists())

    def test_a_lock_held_for_twenty_minutes_fails_the_run_and_is_left_for_its_owner(self):
        self.hold_lock(hours_ago=1)
        self.stub_sleep()

        proc = self.run_script(STUB_ADD=1)

        self.assertEqual(proc.returncode, 1)
        self.assertTrue(self.candidates.exists(), "the model call ran before the lock")
        self.assertEqual(len(self.calls("agent")), 1, "the lookups must not run without the lock")
        self.assertEqual(self.sleeps.read_text(), "5\n" * 240)
        self.assertEqual(proc.stdout.count("waiting up to twenty minutes"), 1)
        self.assertEqual(self.notices(), ["News check failed: the feed is locked for over twenty minutes"])
        self.assertTrue(self.lock.is_dir(), "the lock is not ours to remove")

    def test_a_stale_lock_is_taken_over(self):
        self.hold_lock(hours_ago=4)
        self.stub_sleep()

        proc = self.run_script(STUB_ADD=1)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertFalse(self.sleeps.exists())
        self.assertTrue(self.calls("agent")[1]["locked"])
        self.assertFalse(self.lock.exists())

    def test_a_lock_released_while_waiting_lets_the_run_go_on(self):
        self.hold_lock(hours_ago=1)
        self.stub_sleep(then=f"rmdir '{self.lock}'")

        proc = self.run_script(STUB_ADD=1)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.sleeps.read_text(), "5\n")
        self.assertEqual(self.subject(), f"Add 1 indicator from news {TODAY}")

    def test_a_bad_row_on_main_fails_before_the_lookups(self):
        with (self.repo / "spark-ioc-feed.csv").open("a") as f:
            f.write("web-edit,github.com,Domain,high,high,AB,typed in the GitHub web editor\n")
        self.git("commit", "-q", "-am", "web edit", cwd=self.repo)
        self.git("push", "-q", cwd=self.repo)
        before = self.head()

        proc = self.run_script(STUB_ADD=1)

        self.assertEqual(proc.returncode, 1)
        self.assertEqual(len(self.calls("agent")), 1)
        self.assertEqual(self.head(), before)
        self.assertEqual(self.notices(), ["News check failed: the feed on main fails its lint, nothing was looked up: "
                                          "line 3: VALUE github.com is a host this system needs (never block); "
                                          "fix spark-ioc-feed.csv"])
        self.assertFalse(self.lock.exists())

    def test_rows_the_check_wrote_that_fail_the_lint_are_not_committed(self):
        before = self.head()

        proc = self.run_script(STUB_ADD=1, STUB_BAD_ROW=1)

        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.head(), before)
        self.assertIn("github.com", (self.repo / "spark-ioc-feed.csv").read_text(), "left for the fix")
        self.assertEqual(self.notices(), ["News check failed: the rows the check added fail the lint and stay "
                                          "uncommitted in spark-ioc-feed.csv: line 4: VALUE github.com is a host "
                                          "this system needs (never block)"])
        self.assertFalse(self.lock.exists())

    def test_a_failed_pull_sends_a_notice_and_releases_the_lock(self):
        self.git("remote", "set-url", "origin", str(Path(self.tmp.name) / "gone.git"), cwd=self.repo)

        proc = self.run_script(STUB_ADD=1)

        self.assertEqual(proc.returncode, 1)
        [notice] = self.notices()
        self.assertTrue(notice.startswith("News check failed: git pull failed; nothing was looked up"), notice)
        self.assertFalse(self.calls("brief")[0]["locked"], "the lock is given back before the notice")
        self.assertFalse(self.lock.exists())

    def test_a_failed_push_keeps_the_commit_for_the_next_run(self):
        hook = self.refuse_pushes()
        before = self.head()

        proc = self.run_script(STUB_ADD=1)

        self.assertEqual(proc.returncode, 1)
        self.assertNotEqual(self.head(), before)
        self.assertEqual(self.head(self.origin), before)
        [notice] = self.notices()
        self.assertTrue(notice.startswith("News check failed: git push failed; the commit stays local"), notice)

        hook.unlink()
        proc = self.run_script()

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.head(self.origin), self.head())

    def test_commits_made_elsewhere_are_pulled_in_first(self):
        other = Path(self.tmp.name) / "other-clone"
        self.git("clone", "-q", str(self.origin), str(other), cwd=self.tmp.name)
        (other / "other.txt").write_text("edited on GitHub\n")
        self.git("commit", "-q", "-am", "Edit other.txt elsewhere", cwd=other)
        self.git("push", "-q", cwd=other)

        proc = self.run_script(STUB_ADD=1)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.head(self.origin), self.head())
        self.assertEqual(self.git("log", "--format=%s", cwd=self.repo).splitlines()[1], "Edit other.txt elsewhere")

    def test_log_lines_carry_a_timestamp(self):
        proc = self.run_script()

        self.assertRegex(proc.stdout, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} News check starting")
        self.assertRegex(proc.stdout, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} News check done")


class NewsPlistTest(unittest.TestCase):
    def test_runs_the_script_every_morning_at_0630_under_python_app_and_logs_under_library(self):
        plist = plistlib.loads(PLIST.read_bytes())
        program, flag, command = plist["ProgramArguments"]

        self.assertEqual(plist["Label"], "com.spark-ioc-feed.news")
        self.assertTrue(program.endswith("/Python.app/Contents/MacOS/Python"), program)
        self.assertEqual(flag, "-c")
        self.assertIn("'/bin/bash'", command)
        self.assertIn(plist["WorkingDirectory"] + "/news_check.sh", command)
        self.assertEqual(plist["StartCalendarInterval"], {"Hour": 6, "Minute": 30})
        log = plist["StandardOutPath"]
        self.assertTrue(log.endswith("/Library/Logs/spark-ioc-feed/news-check.log"), log)
        self.assertEqual(plist["StandardErrorPath"], log)
        self.assertNotIn("RunAtLoad", plist, "a daily job must not fire on every login")


if __name__ == "__main__":
    unittest.main()
