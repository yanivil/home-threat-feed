#!/bin/bash
# The once-a-day syslog check for the Spark IoC feed, run by launchd/com.spark-ioc-feed.daily.plist:
#   1. git pull            bring in rows committed elsewhere (GitHub web edits, the monthly re-check)
#   2. spark_logs.py       mine the last two daily captures, look new indicators up on VirusTotal
#   3. git commit + push   spark-ioc-feed.csv only, when the check added rows
# The VirusTotal key comes from VT_API_KEY or the login Keychain (see vt_check.api_key). Everything
# is printed with a timestamp; the LaunchAgent sends it to /tmp/spark-daily-check.log. Outbound hits
# are only reported there (plus a macOS notification), never added to the feed.
# Exit status: 0 all good, otherwise something failed and the log says what. A commit that could
# not be pushed stays local and is pushed by the next run.
#
#   bash daily_check.sh                 # from anywhere: works on the repository it lives in
#   DAYS=3 MAX_LOOKUPS=50 bash daily_check.sh

set -u
cd "$(dirname "$0")" || exit 1
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"   # launchd's PATH has no Homebrew (python3, gh)

FEED=spark-ioc-feed.csv
LOG_FILE=/tmp/spark-daily-check.log
# At 07:30 today's capture holds a few hours; yesterday's completes the day. syslog/checked.json
# keeps indicators seen in both from being looked up twice.
DAYS=${DAYS:-2}
MAX_LOOKUPS=${MAX_LOOKUPS:-150}   # 15 s each: under 40 minutes, well inside the free key's 500 a day

log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
notify() { osascript -e "display notification \"$1\" with title \"Spark IoC feed\"" >/dev/null 2>&1 || true; }
fail() { log "ERROR: $1"; notify "$1"; exit 1; }

log "Daily check starting: last $DAYS day(s), up to $MAX_LOOKUPS lookups"
git pull --rebase --autostash --quiet || fail "git pull failed; the feed was not checked (see $LOG_FILE)"

run_log=$(mktemp -t spark-daily-check) || exit 1
trap 'rm -f "$run_log"' EXIT
python3 spark_logs.py --days "$DAYS" --check --max-lookups "$MAX_LOOKUPS" 2>&1 | tee "$run_log"
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
