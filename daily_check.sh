#!/bin/bash
# The once-a-day syslog check for the Spark IoC feed, run by launchd/com.spark-ioc-feed.daily.plist:
#   0. syslog_retention.py gzip captures older than a week, drop those older than 180 days; runs
#                          first so that a failed pull never skips it, and never fails the run
#   1. feed lock           take syslog/.feed-lock, the directory the Telegram bot also holds while it
#                          adds rows (feed_lock.py); wait up to twenty minutes for the bot, take over a
#                          lock older than three hours, give it back right after the push
#   2. git pull            bring in rows committed elsewhere (GitHub web edits, the monthly re-check)
#   3. spark_logs.py       mine the last two daily captures, look new indicators up on VirusTotal
#                          (outbound names first, then recurring outbound addresses, then persistent
#                          inbound sources; see its --help for the thresholds)
#   4. git commit + push   spark-ioc-feed.csv only, when the check added rows
#   5. spark_brief.py      send the morning brief to Telegram: yesterday's attack attempts, the rows
#                          this run added, the system's health (it is printed here when there is no
#                          bot token); sent even when the check stopped early, never fails the run
# Every run ends with one Telegram message: the brief, or, when the run fails before it, the brief
# with the failure among its errors (once the check has run) or a one-line "Daily check failed:
# <reason>" (before it); a brief that cannot be sent is followed by that notice too.
# The VirusTotal key comes from VT_API_KEY or the login Keychain (see vt_check.api_key). Everything
# is printed with a timestamp; the LaunchAgent sends it to ~/Library/Logs/spark-ioc-feed/daily-check.log.
# Outbound hits are only reported there (plus a macOS notification), never added to the feed.
# Exit status: 0 all good, otherwise something failed and the log says what. A commit that could
# not be pushed stays local and is pushed by the next run.
#
#   bash daily_check.sh                 # from anywhere: works on the repository it lives in
#   DAYS=3 MAX_LOOKUPS=50 bash daily_check.sh

set -u
cd "$(dirname "$0")" || exit 1
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"   # launchd's PATH has no Homebrew (python3, gh)

FEED=spark-ioc-feed.csv
LOG_FILE=$HOME/Library/Logs/spark-ioc-feed/daily-check.log
# At 07:30 today's capture holds a few hours; yesterday's completes the day. syslog/checked.json
# keeps indicators seen in both from being looked up twice. The lookup budget is the script's
# default (400, outbound names first: under two hours at 15 s each, inside the free key's 500 a
# day) unless MAX_LOOKUPS says otherwise.
DAYS=${DAYS:-2}
MAX_LOOKUPS=${MAX_LOOKUPS:-}

lock=syslog/.feed-lock
locked=    # set while the lock is this run's
run_log=   # the check's output, once there is one
briefed=   # set once a Telegram message for this run was attempted: a later failure sends no other

log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
notify() { osascript -e "display notification \"$1\" with title \"Spark IoC feed\"" >/dev/null 2>&1 || true; }
remove_run_log() { [ -z "$run_log" ] || rm -f "$run_log"; }
# Give the feed lock back (only when it is ours, and once) and leave the EXIT trap only the run log
# to remove: once given back, the lock may be the bot's.
release_lock() {
    if [ -n "$locked" ]; then
        rmdir "$lock" 2>/dev/null
        locked=
    fi
    trap remove_run_log EXIT
}
# The one-line notice; spark_brief.py prints it when there is no bot token.
notice() {
    python3 spark_brief.py --send --notice "Daily check failed: $1" 2>&1 \
        || log "WARNING: the failure notice was not sent either (see above)"
}
# The morning brief from the run's own output; its exit status is spark_brief.py's: 0 sent (or printed
# for want of a token), 1 not sent, 2 sent but an attacker note was not.
brief() { python3 spark_brief.py --send --run-log "$run_log" 2>&1; }
fail() {
    log "ERROR: $1"
    notify "$1"
    if [ -z "$briefed" ]; then
        briefed=1
        release_lock
        if [ -n "$run_log" ]; then
            printf 'ERROR: %s\n' "$1" >> "$run_log"   # the brief lists it among its errors
            brief
            status=$?
            [ "$status" -eq 0 ] || [ "$status" -eq 2 ] || notice "$1"
        else
            notice "$1"
        fi
    fi
    exit 1
}

log "Daily check starting: last $DAYS day(s)${MAX_LOOKUPS:+, up to $MAX_LOOKUPS lookups}"
python3 syslog_retention.py 2>&1 || log "WARNING: capture retention failed (see above); carrying on with the check"

# mkdir is atomic, so it is the lock (feed_lock.py takes the same directory). The directory must
# exist first: without it mkdir fails the way a held lock does. The lock is marked ours only once
# mkdir made it, so a run that gives up never removes the bot's. A stale lock that rmdir cannot
# remove (not empty, not a directory) is waited for like a held one. Two waiters that find the same
# stale lock can both remove it and one of them then waits again: inherent to mkdir locks, and the
# wait is bounded.
mkdir -p syslog || fail "cannot create syslog/"
waited=0
while ! mkdir "$lock" 2>/dev/null; do
    if [ -n "$(find "$lock" -maxdepth 0 -mmin +180 2>/dev/null)" ] && rmdir "$lock" 2>/dev/null; then
        continue   # its holder is long gone
    fi
    [ "$waited" -eq 0 ] && log "The feed is locked, probably by the Telegram bot adding a row; waiting up to twenty minutes"
    sleep 5
    waited=$((waited + 5))
    [ "$waited" -ge 1200 ] && fail "the feed is locked by the Telegram bot for over twenty minutes"
done
locked=1
trap 'remove_run_log; release_lock' EXIT

git pull --rebase --autostash --quiet || fail "git pull failed; the feed was not checked (see $LOG_FILE)"

run_log=$(mktemp -t spark-daily-check) || { run_log=; fail "cannot create the run log"; }
python3 spark_logs.py --days "$DAYS" --check ${MAX_LOOKUPS:+--max-lookups "$MAX_LOOKUPS"} 2>&1 | tee "$run_log"
check_status=${PIPESTATUS[0]}
hits=$(grep -c '^OUTBOUND HIT' "$run_log")

if git diff --quiet -- "$FEED"; then
    log "Feed unchanged"
else
    read -r added removed _ < <(git diff --numstat -- "$FEED")
    if [ "$removed" -eq 0 ]; then
        plural=s; [ "$added" -eq 1 ] && plural=
        message="Add $added WAN-probe source$plural mined from the Spark's syslog, each flagged by 5+ VirusTotal engines"
    else
        message="Update the feed from the Spark's syslog check (+$added/-$removed lines)"
    fi
    git commit --quiet -m "$message" -- "$FEED" || fail "git commit of $FEED failed"
    log "Committed: $message"
fi

if [ "$(git rev-list --count '@{upstream}..HEAD')" -gt 0 ]; then
    git push --quiet || fail "git push failed; the commit stays local and the next run will push it"
    log "Pushed to $(git rev-parse --abbrev-ref '@{upstream}')"
fi
# The feed is written: the bot may add rows again, and the brief's attacker notes may use
# VirusTotal (they skip it while the lock exists).
release_lock

if [ "$hits" -gt 0 ]; then
    log "$hits outbound hit(s) above: a LAN device reached a flagged destination"
    notify "$hits outbound hit(s): a LAN device reached a flagged destination. See $LOG_FILE"
fi

# The brief reports what this run did, so it is composed from the run's own output ($run_log) and
# the feed as pushed. It goes out before the check's status is judged: a morning that stopped at the
# VirusTotal quota still reports what it added (and lists the quota stop among its errors), and a
# quiet morning still shows the system ran. With no bot token the brief is printed here and the
# step succeeds; it logs "Brief sent to Telegram" when it was sent. A non-zero exit (1: the brief was
# not sent, 2: it went out but an attacker note did not) is a warning, never the run's failure; when
# the brief did not go out, the one-line notice says so.
briefed=1
brief
brief_status=$?
if [ "$brief_status" -ne 0 ]; then
    log "WARNING: spark_brief.py exited $brief_status: the brief or an attacker note was not sent (see above)"
    [ "$brief_status" -eq 2 ] || notice "the morning brief was not sent (spark_brief.py exited $brief_status)"
fi

if [ "$check_status" -ne 0 ]; then
    fail "spark_logs.py exited $check_status (1 = VirusTotal quota reached, rows done so far are in; else see above)"
fi
log "Daily check done"
