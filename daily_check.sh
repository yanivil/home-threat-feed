#!/bin/bash
# The once-a-day syslog check for the Spark IoC feed, run by launchd/com.spark-ioc-feed.daily.plist:
#   0. syslog_retention.py gzip captures older than a week, drop those older than 180 days; runs
#                          first so that a failed pull never skips it, and never fails the run
#   1. feed lock           take syslog/.feed-lock, the directory the Telegram bot also holds while it
#                          adds rows (feed_lock.py); wait up to ten minutes for the bot, take over a
#                          lock older than three hours, release it when the script exits
#   2. git pull            bring in rows committed elsewhere (GitHub web edits, the monthly re-check)
#   3. spark_logs.py       mine the last two daily captures, look new indicators up on VirusTotal
#                          (outbound names first, then recurring outbound addresses, then persistent
#                          inbound sources; see its --help for the thresholds)
#   4. git commit + push   spark-ioc-feed.csv only, when the check added rows
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

log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
notify() { osascript -e "display notification \"$1\" with title \"Spark IoC feed\"" >/dev/null 2>&1 || true; }
fail() { log "ERROR: $1"; notify "$1"; exit 1; }

log "Daily check starting: last $DAYS day(s)${MAX_LOOKUPS:+, up to $MAX_LOOKUPS lookups}"
python3 syslog_retention.py 2>&1 || log "WARNING: capture retention failed (see above); carrying on with the check"

# mkdir is atomic, so it is the lock (feed_lock.py takes the same directory). The directory must
# exist first: without it mkdir fails the way a held lock does. The trap is set only once the
# lock is ours, so a run that gives up never removes the bot's.
mkdir -p syslog
lock=syslog/.feed-lock
waited=0
while ! mkdir "$lock" 2>/dev/null; do
    if [ -n "$(find "$lock" -maxdepth 0 -mmin +180 2>/dev/null)" ]; then   # its holder is long gone
        rmdir "$lock" 2>/dev/null
        continue
    fi
    [ "$waited" -eq 0 ] && log "The feed is locked, probably by the Telegram bot adding a row; waiting up to ten minutes"
    sleep 5
    waited=$((waited + 5))
    [ "$waited" -ge 600 ] && fail "the feed is locked by the Telegram bot for over ten minutes"
done
trap 'rmdir "$lock" 2>/dev/null' EXIT

git pull --rebase --autostash --quiet || fail "git pull failed; the feed was not checked (see $LOG_FILE)"

run_log=$(mktemp -t spark-daily-check) || exit 1
trap 'rm -f "$run_log"; rmdir "$lock" 2>/dev/null' EXIT
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

if [ "$hits" -gt 0 ]; then
    log "$hits outbound hit(s) above: a LAN device reached a flagged destination"
    notify "$hits outbound hit(s): a LAN device reached a flagged destination. See $LOG_FILE"
fi
if [ "$check_status" -ne 0 ]; then
    fail "spark_logs.py exited $check_status (1 = VirusTotal quota reached, rows done so far are in; else see above)"
fi
log "Daily check done"
