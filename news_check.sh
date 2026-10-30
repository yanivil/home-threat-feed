#!/bin/bash
# The once-a-day news check for the Spark IoC feed, run by launchd/com.spark-ioc-feed.news.plist
# at 06:30 (design D7, docs/system-design.md):
#   1. news_agent.py       ask Claude (Opus 5.5 with web search and web fetch) for the network indicators
#                          the week's public security reporting names; our code keeps the home-relevant
#                          ones (IPs, domains, URLs; no vendor domains, no shared-platform apexes, no
#                          stale reports, nothing in the feed or looked up in the last three days), at
#                          most 40, written to syslog/news-<today>.txt. Runs OUTSIDE the feed lock, so
#                          the Telegram bot is not held up while the model reads.
#   2. feed lock           take syslog/.feed-lock the way daily_check.sh does: wait up to twenty minutes
#                          for the bot, take over a lock older than three hours, give it back right after
#                          the push
#   3. git pull            bring in rows committed elsewhere, then feed_lint.py: a feed that fails it
#                          stops the run here, and the notice says what to fix
#   4. news_agent.py --check  look the candidates up on VirusTotal (the same lookups as vt_check.py -f,
#                          default thresholds: 5 engines for an IP, 3 otherwise), add the flagged ones,
#                          record every verdict in syslog/news-checked.json so the next days skip them
#   5. git commit + push   spark-ioc-feed.csv only, when the check added rows, after feed_lint.py
#                          passed it again; a feed that fails stays uncommitted. A check that stopped
#                          early (the quota, a refused key, lookups that failed) still gets its rows
#                          committed and pushed, then the run fails and says why.
# A run that fails sends one line to Telegram, "News check failed: <reason>" (spark_brief.py --send
# --notice; printed here when there is no bot token). The job sends no brief: the 07:30 daily check's
# brief counts the rows it added ("from news"). A quiet day (no candidates) takes no lock and ends.
# The Anthropic key (ANTHROPIC_API_KEY) and the VirusTotal key (VT_API_KEY) come from the login
# Keychain, service spark-ioc-feed (README, "News agent"). Everything is printed with a timestamp;
# the LaunchAgent sends it to ~/Library/Logs/spark-ioc-feed/news-check.log, where the agent's one
# "news usage:" line says what the model call cost.
# Exit status: 0 all good, otherwise something failed and the log says what. A commit that could
# not be pushed stays local and is pushed by the next run (this one's or the daily check's).
#
#   bash news_check.sh                  # from anywhere: works on the repository it lives in
#   DRY_RUN=1 bash news_check.sh        # look the candidates up; commit and push nothing (the first run to make)
#   MAX_CANDIDATES=10 bash news_check.sh

set -u
cd "$(dirname "$0")" || exit 1
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"   # launchd's PATH has no Homebrew (python3)

FEED=spark-ioc-feed.csv
LOG_FILE=$HOME/Library/Logs/spark-ioc-feed/news-check.log
TODAY=$(date '+%Y-%m-%d')
CANDIDATES=syslog/news-$TODAY.txt
DRY_RUN=${DRY_RUN:-}
case $DRY_RUN in 0) DRY_RUN= ;; esac   # DRY_RUN=0 means no dry run
MAX_CANDIDATES=${MAX_CANDIDATES:-}

lock=syslog/.feed-lock
locked=    # set while the lock is this run's

log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
notify() { osascript -e "display notification \"$1\" with title \"Spark IoC feed\"" >/dev/null 2>&1 || true; }
# Give the feed lock back (only when it is ours, and once): once given back, the lock may be the bot's.
release_lock() {
    if [ -n "$locked" ]; then
        rmdir "$lock" 2>/dev/null
        locked=
    fi
    trap - EXIT
}
# The one-line notice; spark_brief.py prints it when there is no bot token.
notice() {
    python3 spark_brief.py --send --notice "News check failed: $1" 2>&1 \
        || log "WARNING: the failure notice was not sent either (see above)"
}
# feed_lint.py on the feed, its output printed. When it fails, lint_problem holds the first problem
# (and how many more) for the failure message: the Telegram notice shows no log.
lint_problem=
lint() {
    local out status more
    out=$(python3 feed_lint.py "$FEED" 2>&1); status=$?
    printf '%s\n' "$out"
    lint_problem=$(printf '%s\n' "$out" | grep '^line ' | head -n 1 | tr '"' "'")
    more=$(printf '%s\n' "$out" | grep -c '^line ')
    [ "$more" -le 1 ] || lint_problem="$lint_problem and $((more - 1)) more"
    [ "$status" -eq 0 ] || [ -n "$lint_problem" ] || lint_problem="feed_lint.py itself failed (see $LOG_FILE)"
    return "$status"
}
fail() {
    log "ERROR: $1"
    notify "$1"
    release_lock
    notice "$1"
    exit 1
}

log "News check starting${DRY_RUN:+ (dry run)}${MAX_CANDIDATES:+, up to $MAX_CANDIDATES candidates}"
case $MAX_CANDIDATES in
    ''|*[!0-9]*) [ -z "$MAX_CANDIDATES" ] || fail "MAX_CANDIDATES must be a number, not '$MAX_CANDIDATES'" ;;
esac
mkdir -p syslog || fail "cannot create syslog/"

# 1. The model call, outside the lock. The agent prints its usage line, what it kept and why it
#    dropped the rest; a quiet day leaves a file with no candidates.
python3 news_agent.py --out "$CANDIDATES" ${MAX_CANDIDATES:+--max-candidates "$MAX_CANDIDATES"} 2>&1
agent_status=$?
case $agent_status in
    0) ;;
    3) fail "no ANTHROPIC_API_KEY in the Keychain, the news agent cannot run (README, \"News agent\")" ;;
    2) fail "the model call failed, nothing was looked up (see $LOG_FILE)" ;;
    *) fail "news_agent.py exited $agent_status, nothing was looked up (see $LOG_FILE)" ;;
esac
count=$(grep -v '^#' "$CANDIDATES" | grep -c .)
if [ "$count" -eq 0 ]; then
    log "No candidates today; nothing to look up"
    log "News check done"
    exit 0
fi

# 2. The lock: mkdir is atomic (feed_lock.py takes the same directory). The lock is marked ours only
#    once mkdir made it, so a run that gives up never removes the bot's. A stale lock that rmdir
#    cannot remove is waited for like a held one.
waited=0
while ! mkdir "$lock" 2>/dev/null; do
    if [ -n "$(find "$lock" -maxdepth 0 -mmin +180 2>/dev/null)" ] && rmdir "$lock" 2>/dev/null; then
        continue   # its holder is long gone
    fi
    [ "$waited" -eq 0 ] && log "The feed is locked, probably by the Telegram bot adding a row; waiting up to twenty minutes"
    sleep 5
    waited=$((waited + 5))
    [ "$waited" -ge 1200 ] && fail "the feed is locked for over twenty minutes"
done
locked=1
trap release_lock EXIT

# 3. Pull, then lint: a row typed into GitHub's web editor reached main unchecked, or a hand edit the
#    bot refused to commit is still here; either way nothing runs until the file is fixed.
git pull --rebase --autostash --quiet || fail "git pull failed; nothing was looked up (see $LOG_FILE)"
if ! lint; then
    where="on main"
    git diff --quiet HEAD -- "$FEED" || where="on this Mac (uncommitted changes)"
    fail "the feed $where fails its lint, nothing was looked up: $lint_problem; fix $FEED"
fi

# 4. The lookups. Exit 3 means nothing was looked up; 4 (the quota), 2 (a refused key, lookups that
#    failed) and anything else happen after some rows may have been added, which are committed below
#    before the run is judged.
python3 news_agent.py --check "$CANDIDATES" ${DRY_RUN:+--dry-run} 2>&1
check_status=$?
[ "$check_status" -ne 3 ] || fail "no VT_API_KEY in the Keychain, nothing was looked up (README, \"Daily check on this Mac\")"

# 5. Commit and push what the check added. A dry run added nothing and leaves the pushing to the next run.
#    A failure here names the check's own failure too, so a refused key is not hidden behind a refused push.
check_note=
[ "$check_status" -eq 0 ] || check_note="; news_agent.py --check itself exited $check_status (see $LOG_FILE)"
if [ -n "$DRY_RUN" ]; then
    log "Dry run: nothing committed or pushed"
else
    if git diff --quiet -- "$FEED"; then
        log "Feed unchanged"
    else
        lint || fail "the rows the check added fail the lint and stay uncommitted in $FEED: $lint_problem$check_note"
        read -r added removed _ < <(git diff --numstat -- "$FEED")
        if [ "$removed" -eq 0 ]; then
            plural=s; [ "$added" -eq 1 ] && plural=
            message="Add $added indicator$plural from news $TODAY"
        else
            message="Update the feed from the news check (+$added/-$removed lines)"
        fi
        git commit --quiet -m "$message" -- "$FEED" || fail "git commit of $FEED failed$check_note"
        log "Committed: $message"
    fi
    if [ "$(git rev-list --count '@{upstream}..HEAD')" -gt 0 ]; then
        git push --quiet || fail "git push failed; the commit stays local and the next run will push it$check_note"
        log "Pushed to $(git rev-parse --abbrev-ref '@{upstream}')"
    fi
fi
release_lock

rows="the rows done so far are in"
[ -z "$DRY_RUN" ] || rows="a dry run, nothing was committed"
case $check_status in
    0) ;;
    4) fail "news_agent.py --check exited 4: the lookup quota is reached; $rows, the rest are candidates again tomorrow" ;;
    2) fail "news_agent.py --check exited 2: the reputation service refused the key or lookups failed; $rows (see $LOG_FILE)" ;;
    *) fail "news_agent.py --check exited $check_status; $rows (see $LOG_FILE)" ;;
esac
log "News check done"
