# Spark IoC feed: how the system fits together, and why

The README says how to run each script. This document says what the whole thing is for,
how the pieces connect, which rules they enforce, and the decisions behind them with what
each one produced. Dates are when a decision was taken or an outcome observed.

## 1. Purpose

A Check Point Spark 1595 gateway protects a home network. The gateway blocks whatever is in a
custom IoC feed it pulls from GitHub (`spark-ioc-feed.csv`). This system keeps that feed
worth pulling: it grows it from what the gateway itself sees, from vendor reporting, and from
indicators added by hand; it checks every candidate against VirusTotal before adding it; it
re-verifies rows as they age and drops the ones that stopped being malicious; and it tells
the owner when something on the LAN reached a known-bad destination.

## 2. Components and data flow (as built on 2026-10-28)

```
Spark 1595 (the LAN gateway)                    GitHub: yanivil/spark-ioc-feed
   | security logs, syslog over UDP 5514              ^            |
   v                                                  | push       | the Spark pulls
iMac "home-server" (on the LAN), user home-server     |            v  spark-ioc-feed.csv
   |                                                  |
   +-- syslog_receiver.py  (LaunchAgent com.spark-ioc-feed.syslog, always on)
   |      -> syslog/spark-YYYY-MM-DD.log   one entry per line, one file per day
   |
   +-- daily_check.sh      (LaunchAgent com.spark-ioc-feed.daily, 07:30)
   |      feed lock -> git pull -> feed_lint.py -> spark_logs.py --days 2 --check -> vt_check.run() -> CSV
   |      -> feed_lint.py -> commit, push
   |      -> spark_brief.py --send (the morning brief to Telegram)
   |      macOS notification on outbound hits and on errors; a Telegram notice when a run fails
   |
   +-- telegram_bot.py     (LaunchAgent com.spark-ioc-feed.telegram, always on)
   |      Telegram <-> commands (add indicators: feed lock -> git pull -> vt_check.run() -> CSV -> commit, push)
   |      live watcher (capture_watcher.py): syslog/spark-<today>.log -> alerts (capped)
   |      note thread: attacker notes (attacker_context.py), capped
   |
   +-- by hand: vt_check.py <indicators> | --trusted | cyberint_xlsx.py -> TSV -> vt_check.py --trusted

GitHub Actions, 1st of the month: .github/workflows/recheck.yml -> vt_check.py --recheck -> CSV
```

| Piece | Runs | Reads | Writes |
|---|---|---|---|
| `syslog_receiver.py` | always, restarted by launchd if it dies | UDP 5514, the gateway's datagrams only (`--source`, by default the default route's gateway) | `syslog/spark-<day>.log`, one line per entry; its log names the source it receives from and the ones it drops |
| `daily_check.sh` | 07:30 daily (a run missed while asleep happens on wake) | capture of the last 2 days, `syslog/checked.json`, `syslog/allow.txt`, VT key from the Keychain | the feed, `syslog/checked.json`, `syslog/.feed-lock` (taken after the retention step, given back right after the push), `~/Library/Logs/spark-ioc-feed/daily-check.log`, a notification, and as its last step the morning brief |
| `syslog_retention.py` | first step of the daily job | capture file names (the date in them) | `.log` → `.log.gz` after 7 days; removes both after 180 |
| `spark_logs.py` | from the daily job or by hand | capture files, plain or `.gz` | feed rows (through `vt_check.run`) |
| `vt_check.py` | by hand, from the daily job, from Actions | VirusTotal API v3 | feed rows; with `--recheck`, rewrites rows in place |
| `cyberint_xlsx.py` | by hand | Cyberint `.xlsx` exports | a TSV for `vt_check.py --trusted` |
| `recheck.yml` | monthly on GitHub | the feed, `VT_API_KEY` secret | the feed |
| `keychain.py` | imported by the scripts that need a secret | an environment variable, else the login Keychain (service `spark-ioc-feed`) | nothing |
| `telegram_api.py` | imported by the bot and the brief | Telegram Bot API (`getUpdates`); bot token and chat id from the Keychain | messages and documents to the owner's chat |
| `feed_lock.py` | by the bot around each addition | `syslog/.feed-lock` | the lock directory (`daily_check.sh` takes the same one) |
| `spark_brief.py` | last step of the daily job, or by hand | the day's capture, the daily check's output, the feed and its git history, `syslog/last-brief.json` | the brief on Telegram (printed in the log when there is no token), `syslog/last-brief.json` |
| `attacker_context.py` | for each alert's note, `/who` and the brief's sent-to-block notes | yesterday's and today's capture; VirusTotal, RDAP, Shodan InternetDB, GreyNoise (optional); the Anthropic API | nothing: it returns the text |
| `telegram_bot.py` | always, restarted by launchd | Telegram updates, today's capture, the feed, the Keychain | the feed (rows and one commit per addition), `syslog/telegram-offset.json`, `~/Library/Logs/spark-ioc-feed/telegram-bot.log`, messages |
| `capture_watcher.py` | a thread of the bot | today's capture, the feed | alerts (handed to the bot), `syslog/watcher-offset.json` (its place in the capture) |
| `launchd/com.spark-ioc-feed.telegram.plist` | installed in `~/Library/LaunchAgents/`; `RunAtLoad` and `KeepAlive` | nothing | the bot's log |

All three LaunchAgents run the Command Line Tools `Python.app` binary as their program (see
decision D1), with logs in `~/Library/Logs/spark-ioc-feed/`. `daily_check.sh` takes the feed
lock before its `git pull` (waiting up to twenty minutes for the bot, taking over a lock older
than three hours), gives it back right after its push and ends by sending the brief; see D6.

## 3. Rules the system enforces

**Feed format.** The Check Point custom-feed CSV: `UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT`.
`UNIQ-NAME` is `vt-<type>-<sha1 prefix>` for VirusTotal-checked rows and `trusted-<type>-<...>`
for rows added without a check; the prefix is derived from the value, so a value maps to one
name. `COMMENT` carries the provenance and the dates the rules below read.

**Admission.** A candidate is added when VirusTotal engines flag it: 5 or more for an IP
(hosting addresses collect a few hits just for sitting on a busy provider, and a wrongly
blocked IP breaks more than a wrong domain), 3 or more for anything else. `CONFIDENCE` is
`high` at 10+ engines, `medium` at 5+, else `low`. Private, reserved, multicast and link-local
addresses, and URLs with commas, are rejected before any lookup.

**No duplicates.** Every insert path reads the feed first and skips values already there
(case-insensitively, and for IPs also addresses inside the feed's `IP Range` rows), plus
duplicates inside the same batch. Syslog candidates looked up within the last 30 days are not
looked up again (`syslog/checked.json`). The checks live in two places today,
`vt_check.feed_values` and `spark_logs.feed_members`; they agree, and merging them is pending.

**What the gateway's logs contribute.** Outbound destinations are *reported, never added*: a
LAN device reaching a flagged destination is a device to look at, not a feed row. Inbound
sources that probed the WAN 5+ times are added when VirusTotal flags them (5+ engines, being
IPs), at most 20 a run. The free VirusTotal key allows 500 lookups a day, so a run spends them
in this order: inbound sources (at most 20), the 40 busiest outbound addresses seen 3+ times,
then outbound names (minus well-known vendor domains; three or more hosts under one apex are
looked up once, as the apex), capped at 400 a day; the rest waits for another day (D9).

**Expiration.** Rows are not expired by age; they are *re-verified* by age and removed only
when VirusTotal no longer flags them above the admission bar:

| TYPE | Re-verified after | Removed when | Notes |
|---|---|---|---|
| IP | 60 days | fewer than 5 engines flag it | addresses change hands fastest |
| Domain, URL | 180 days | fewer than 3 engines flag it | see D4 |
| MD5, SHA1, SHA256 | never | - | a malicious file stays malicious |
| rows added without a check (`--trusted`) | 90 days after they were added | fewer engines than the type's bar flag it | hashes never; a row that passes becomes a checked row (D5) |
| IPs seen probing this network | 180 days after the last sighting, never before the row's own clock | fewer than 5 engines flag it | the daily check stamps `seen in Spark logs <date>`, refreshed at most monthly (D5) |

The dates read are the closing note of `COMMENT` (`VT a/b malicious YYYY-MM-DD`, or `added
without VirusTotal check YYYY-MM-DD`) and the sighting note before it (`seen in Spark logs
YYYY-MM-DD`); `vt_check.recheck_due` turns them into the day a row is due. The monthly Action
rewrites the feed in place and commits, so an expiration reaches the gateway at its next pull.

**Raw-log retention.** See D3.

## 4. Decisions

Each entry: the situation, what was decided, and what it produced.

### D1. The repository stays on the external disk; launchd jobs run as Python.app (2026-10-28)

The repository lives on `/Volumes/eDisk_2TB`, a USB disk. The first install of the syslog
LaunchAgent failed 88 times in a row with `Operation not permitted` reading
`syslog_receiver.py`: macOS lets a background job read an external volume only if the job's
own program holds Full Disk Access, and it judges every file access by the job's *top*
process. `/usr/bin/python3`, `/bin/bash`, `cat` and `git` are Apple platform binaries, which
macOS denies without ever prompting, and a grant given to `python3.9` never matched because
that file only re-executes `Python.app`.

Decided: keep the repository where it is (the owner's preference over moving it to the
internal disk) and make `Python.app` the program of every LaunchAgent, with Full Disk Access
granted to it once in System Settings. The daily job starts `bash` *under* Python.app
(`subprocess.call`), so bash, git and python3 inherit the grant and need none of their own.

Outcome: receiver up within seconds of the grant, 4,824 log entries in its first two minutes;
launchd respawned it instantly when killed; the daily job's first run under launchd pulled,
checked 45 destinations and finished (all clean, nothing added). The plists document the
reason in their comments.

### D2. Restart behaviour: FileVault stays on (2026-10-28)

Both agents start at login and survive reboots. FileVault is on and auto-login is off, so after
a power cut the iMac restarts (`autorestart 1`) and waits at the unlock screen; once unlocked,
this user is logged in automatically and both agents start. The Mac never sleeps on AC
(`sleep 0`). Decided: keep FileVault on and accept that a restart needs the password once;
unattended recovery would require turning it off.

### D3. Raw-log retention: keep 180 days, compress after 7 (requested and built 2026-10-28)

The receiver writes about 650 MB a day uncompressed (roughly 2,000 entries a minute from the
gateway); nothing deleted or compressed anything, so 90 days would take 60 GB. Requirement:
keep at least 90 days. Decided: keep 180 days, gzip each day's file once it is 7 days old,
both ages taken from the date in the file name. A new standard-library module,
`syslog_retention.py`, does it as the first step of `daily_check.sh` (before the pull, so a
failed pull never skips it, and a failure of the step itself is logged, not fatal);
`spark_logs.py` reads `.gz` days transparently. Expected size: under 5 GB for the whole window.
Outcome: built the same day, test-first (8 tests on the module, one on the script's ordering,
one on reading a compressed day; the whole suite, 119 tests, passes). The first file to be
compressed is 2026-10-28's, on 2026-11-04; the measured size of a compressed day is to be
recorded then.

### D4. Domains and URLs keep a 180-day re-verification (decided 2026-10-28)

Asked: should domains and URLs, like hashes, never be re-verified, since they will always be
malicious? Answer: no, and the difference is what the indicator names. A hash names content;
the content cannot change, so a malicious file is malicious forever. A domain or URL names a
*place*, and places change hands: malicious domains lapse and get re-registered by someone
legitimate, parked, or sinkholed; a URL on a compromised legitimate site is cleaned up and
serves the original site again; shared-hosting and CDN names serve many tenants. Keeping such
a row blocks legitimate traffic later, which on a firewall is worse than a missed dormant
domain. Note that nothing is removed by age alone: a 180-day-old domain that VirusTotal still
flags is kept with a fresh date. Decided: keep 180 days for domains and URLs; the owner agreed
with the reasoning.

### D5. Rows added without a VirusTotal check join the clock after 90 days; IPs seen in our own logs run a longer clock from their last sighting (decided and built 2026-10-28)

As of 2026-10-28, 1,111 of the feed's 1,783 rows were added without a check (external exports
of 2026-10-22), and `--recheck` never looks at them. Requested: apply the same expiration logic
to indicators brought in by hand, with a first check after 90 days; and treat an IP that has
appeared in the gateway's own logs differently, because a probe of this network is first-hand
evidence of an attack, where VirusTotal's count for a scanner decays while the scanning goes on.

Proposed rule:

- A trusted row (IP, domain or URL) is re-verified on VirusTotal 90 days after it was added;
  hashes never. If VirusTotal flags it above the admission bar it becomes an ordinary checked
  row (`VT a/b malicious <date>`, confidence from the ratio) and continues on the normal
  clock; if not, it is removed. Of the 1,111 trusted rows, 168 IPs, 94 domains and 115 URLs
  come up together on 2027-01-20 (about 95 minutes of lookups at the free key's rate), and
  734 hashes never.
- An IP that appears in the gateway's logs as an inbound source carries a `seen in Spark logs
  <date>` note in its COMMENT, stamped by the daily job when the IP is added and refreshed
  when it is seen again and the stamp is older than 30 days (so the feed is not rewritten
  every day for the same scanner). Whatever its origin, trusted or checked, such an IP is
  re-verified 180 days after its *last sighting* rather than 60 days after its last check,
  and is removed only if VirusTotal no longer flags it then. An IP that keeps probing is
  therefore never removed; one that stopped is re-verified half a year after it stopped.

Consequence accepted by the owner: a targeted-attack indicator that VirusTotal never catches
and that never appears in the gateway's logs leaves the feed 90 days after it was added,
unless re-added.

Outcome: built the same day, test-first (11 new tests; the suite stands at 130 and passes).
`vt_check.recheck_due` holds the rule, `vt_check.stamp_seen` the sighting note, and the
daily check stamps every inbound source that is a feed IP, the ones it just added included.
A trusted row that passes its check keeps its `UNIQ-NAME`, so the gateway sees an updated
row, not a removal and an addition. Against the real feed on 2026-10-28 nothing was due; the
checked IPs come up from 2026-12-18 (316 rows over four days), the trusted IPs, domains and
URLs on 2027-01-20 (377 rows, about 95 minutes of lookups), the checked domains and URLs
from 2027-04-17.

### D6. Alerts, the daily brief and manual additions go through a Telegram bot (designed and built 2026-10-28)

Requested: alerts on Telegram instead of only macOS notifications; a daily brief of attack
attempts and of indicators added; a way to send the bot indicators to be added, with or
without a VirusTotal check; and, for each attacker, a second message saying who they are and
why they attack. Settled with the owner on 2026-10-28, one question at a time:

- An *attack attempt* is an inbound probe the firewall dropped or rejected, a Threat
  Prevention detection, or a connection the firewall accepted whose source VirusTotal then
  flagged and the daily check sent to block; the outbound counterpart, a LAN device reaching
  a flagged destination, is reported beside it. The per-minute Threat Emulation and
  Anti-Malware statistics rows are not attack attempts.
- The brief is one message a morning, short enough for a phone: totals, then everything
  that needs a decision in full, then the noise counted with a top ten. The complete list of
  sources, thousands a day (672 distinct sources in the receiver's first hour), is available
  on request as a file, not sent daily.
- Two events alert within minutes: a LAN device trying to reach an indicator already in the
  feed, and a Threat Prevention detection. Nothing else alerts live. (The detection rule was
  narrowed in the build and again after the whole-branch review; see "The live watcher".)
- A bare message to the bot means "check these on VirusTotal and add the flagged ones";
  `/trust` adds without a check. Only the owner's Telegram account is listened to.
- Every live alert and every source sent to block gets a second message with the attacker's
  context, written by Claude Opus 5.5 from gathered facts; `/who` gives the same on demand.
  (As built, a live alert gets one only when there is an attacker to explain; see "The live
  watcher".)

#### Design

**Approaches considered.** (a) One always-on process that both talks to Telegram and watches
the live capture; (b) two processes, a watcher and a bot; (c) a webhook bot, which needs an
inbound HTTPS port through the gateway. Chosen: (a), one LaunchAgent like the receiver,
long-polling Telegram (`getUpdates`) in one thread and tailing today's capture in another,
because it is one more process to keep alive and nothing to open on the firewall. The
morning brief is not the bot's job: `daily_check.sh` builds and sends it at the end of its
run, so it reports exactly what that run did.

**Components** (new files; standard library only, like the rest):

| File | Role |
|---|---|
| `keychain.py` | `item(account, env_var)`: a secret from an environment variable, else from the login Keychain (service `spark-ioc-feed`); the scripts read every key and token through it |
| `feed_lock.py` | the `syslog/.feed-lock` directory lock, as a context manager with a wait and a stale-lock takeover, for the bot; `daily_check.sh` takes the same directory |
| `telegram_api.py` | `send_message`, `send_document`, `get_updates` over HTTPS; the bot token and the owner's chat id from the login Keychain (`spark-ioc-feed` / `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`), the same mechanism as the VirusTotal key |
| `telegram_bot.py` | the LaunchAgent `com.spark-ioc-feed.telegram` (Python.app program, `KeepAlive`): the command loop, the watcher's thread and the note thread; `--pair` for first-time setup |
| `capture_watcher.py` | the live watcher: follows today's capture, raises the alerts under the caps, saves its place; split out of `telegram_bot.py` in the fix wave |
| `spark_brief.py` | composes the morning brief from yesterday's capture, the daily run's log and the feed; `--send` posts it, otherwise prints it; called by `daily_check.sh` as its last step |
| `attacker_context.py` | gathers the facts about an indicator and asks Opus 5.5 for the note; used by the brief, the live alerts and `/who` |
| `launchd/com.spark-ioc-feed.telegram.plist` | keeps the bot running, logs to `~/Library/Logs/spark-ioc-feed/telegram-bot.log` |

**First-time setup** (the owner's steps): create the bot in BotFather and store its token
(`security add-generic-password -s spark-ioc-feed -a TELEGRAM_BOT_TOKEN -w '<token>' -U`);
send the bot `/start` from the owner's own account (a private chat) and run
`python3 telegram_bot.py --pair`: it lists each chat that wrote with its type and sender, refuses
a group, and prints a private chat's id and the `security` command that stores it; install the
plist like the other two. A stored chat id that is not a number stops the bot like a missing one,
with `TELEGRAM_CHAT_ID is not a number` in the log and never the value. The README's "Setting it
up" has the checklist and the end-to-end check.

**The bot's commands.** Only the owner's private chat is served (chat type `private` and the
stored id, which is then the owner's own user id); a message from any other chat, a group the
owner is in included, is ignored (logged once a day per chat), since in a group every member
could add to the public feed. Text is split on whitespace and commas (a URL keeps its commas);
leading tokens that `vt_check.classify` accepts, defanged or not, are the indicators, and the
rest is the label that goes into `COMMENT` and the commit subject, without quotes or Unicode
control and format characters (bidi, zero-width), commas made spaces, at most 120 characters.
Both adding paths refuse, with `refused: <value> is on the never-block list`, a domain or URL
host that `spark_logs.allowed` covers (the vendor list and `syslog/allow.txt`) or one this
system depends on: `github.com`, `raw.githubusercontent.com`, `api.telegram.org`,
`api.anthropic.com`, `www.virustotal.com`. There is no override and no removal command.

- *bare text*: `vt_check.run()` on the indicators, at most 50 a message (the rest are
  reported as `N not checked, send them again`), one lookup every 15 s; the bot first replies
  how many it is checking and how long that takes. Then one reply line per indicator as
  `vt_check` prints it (`evil.com: added (Domain 11/94 malicious)`, `clean (…)`, `in-feed`,
  `invalid (…)`, `not-found (VirusTotal has no record)`), a counts line, and a commit
  `Add N indicator(s) sent from Telegram: <label>` of the feed alone, pushed at once; the last
  line says `Committed and pushed.`, or that the push failed and the commit waits for the next
  daily run. The row's COMMENT is `<label> - sent from Telegram - VT n/m malicious <date>`.
  The command loop is single-threaded, so it answers nothing else while a check runs; the
  watcher, a thread of its own, is not held up.
- `/trust <indicators> [label]`: `vt_check.add_trusted()`, so the rows get the
  `added without VirusTotal check <date>` note and the 90-day first check of D5; then the
  same commit and push.
- `/who <indicator>`: the attacker-context note (below).
- `/sources [YYYY-MM-DD]`: every inbound source that probed on that day (default yesterday),
  busiest first with its count and whether it is in the feed, as an attached text file.
- `/status`: five lines. Whether the receiver is writing (today's capture modified within the
  last two minutes); when the daily check last ran and how it ended, with the lookups it
  used; the next re-check date (the earliest `recheck_due` over the feed); the bot's uptime;
  and the last error the bot logged, or `last error: none`. It reads the last 64 KB of the
  daily check's log.
- `/help`, and anything unrecognised: the list above.

**Writing the feed from two places.** The daily check and the bot both commit the feed, on
the same clone. A directory lock, `syslog/.feed-lock` (`mkdir` is atomic, and bash and
Python can both take it), is held by `daily_check.sh` from before its pull until right after
its push (so that the brief's notes may use VirusTotal) and by the bot for the length of an
addition: seconds for `/trust`, about 13 minutes for a 50-indicator check at
one lookup every 15 s. The bot waits `LOCK_WAIT` = 60 s for it; if the daily check still
holds it, the bot tells the owner the daily check has been writing the feed for so many
minutes (the lock's age) and to send the indicators again later, so that its command loop
never stalls for a whole run. `daily_check.sh` waits up to twenty minutes for the bot before
it gives up and fails the run, and a lock older than three hours is treated as stale and
taken over (`feed_lock.py` and the script use the same limit). Both commit only
`spark-ioc-feed.csv` and push at once. The bot commits whenever `git diff` shows the feed
changed and counts the added rows from `git diff --numstat`, so rows a killed check left behind
go out with its next addition, never under the daily check's message.

**The live watcher.** A thread follows today's capture (`syslog/spark-<today>.log`, moving
to the new file at midnight) and raises an alert for two kinds of entry:

1. A LAN device and a feed member: the entry's source is a private address and its
   destination, host name or resource host is in the feed (`spark_logs.feed_members`,
   which also covers `IP Range` rows). Whether the gateway dropped it or let it through is
   said in the alert; an accepted one is the louder case.
2. A Threat Prevention detection: an entry from Anti-Malware, Anti-Bot, IPS/SmartDefense,
   Threat Emulation or Anti-Virus that names a protection or attack and carries a source and
   destination; the statistics rows those blades emit every minute (counters, no
   addresses) are not detections.

As built, the second kind is narrower than that list. A detection alerts only when its
`Action`, stripped and lower-cased, is one of `prevent`, `drop`, `reject`, `block`, `detect`, and
a public address is involved; a blank Action, `monitor`, `accept`, `inspect` and anything else,
and every detection between two LAN addresses, are counted in the brief and raise no alert. The
measurement behind the first narrowing: on 2026-10-28 the capture held 44 detection rows (22
distinct source/destination/protection combinations), all SmartDefense; 32 rows were `monitor`
for "HTTP Methods" from one LAN device, six were LAN-only "Max Ping Size" rows, and none was
inbound. Alerting on all of them would have sent about 22 alert-and-note pairs that day. The
whole-branch review then found that a blank Action, which the IP-reputation rows on dropped
probes carry, is no evidence of enforcement and the likeliest flood, hence the explicit list.
The Spark's system log lines (`<stamp> <tag>: <text>`, forwarded since 2026-10-28) parse as
`{"received", "tag", "system"}` with no key="value" pairs and never alert.

An alert is one message. A feed alert reads `HH:MM:SS — <device> tried to reach <indicator>
(<the feed row's COMMENT>) — <action>; N× today`, an empty action shown as `detected`; a
detection reads `HH:MM:SS — Threat Prevention: <blade> <protection> from <source> to
<destination> — <action>`. Every string taken from the capture goes through
`attacker_context.clean` (one line, at most 100 characters, no control or format characters),
and a source or destination is shown as the address it parses to, else cleaned the same way:
since the receiver keeps only the gateway's datagrams this is defence in depth, but the capture
is now an alert channel. The same pair (for a detection: source, destination and protection) is
not alerted again for an hour (`COOLDOWN`). At most ten alerts go out in any sliding ten
minutes: the first one over is replaced by `Alert cap reached: further alerts in the next 10
minutes are counted, not sent`, and when those ten minutes are over one message says `N alerts
suppressed between HH:MM and HH:MM:` followed by the distinct `<device> → <indicator>, <action>`
pairs, one a line, ten at most, then `… and M more`. It names them because the brief would not:
a feed hit the gateway logs only as a firewall row is counted nowhere else.

The attacker-context note follows a feed alert (on the indicator), an inbound detection (on its
source) and an outbound Anti-Bot, Anti-Virus, Anti-Malware or Threat Emulation detection (on its
destination, the host name the row names or else the address: these blades name attacker
infrastructure); an outbound IPS/SmartDefense detection, a protocol anomaly, gets none. Notes are
capped at six an hour, thirty a local day and one per indicator in 24 hours; an alert whose note
is over a cap goes out alone. They run in a daemon thread fed by a queue of ten (one more is
dropped and logged), so an alert never waits on a note, and a pass's alerts still go out before
its notes because the queue keeps their order. The caps live in the watcher and run on its
clock, which the tests replace.

After each pass the watcher saves its place, `syslog/watcher-offset.json` (`{"day", "inode",
"offset"}`, the end of the last whole line). When it starts and that names today's capture
(same day, same inode), the lines up to the offset are only counted and the ones after it, written
while it was down, are alerted with the prefix `late: `, without notes and under the alert cap; a
same-day restart (a crash, a `kickstart`, the five-minute wait for a missing secret, a watcher
restarted after a failure) therefore repeats no alert and silences none. Otherwise what today's
capture holds at start is counted without alerting. A line that cannot be read in any way costs
only itself, and a pass logs how many it skipped and the first one's line number, never their
content. The receiver's file is read, never the socket, so the watcher cannot disturb the capture.

**The morning brief** (`daily_check.sh` runs `spark_brief.py --send` after the push; the
format approved on 2026-10-28):

```
Spark brief — Wed 2026-10-28
Probes dropped: 41,207 from 3,912 sources · TP detections: 2 · Sent to block: 1 · Outbound hits: 1

SENT TO BLOCK (passed the firewall, VirusTotal flags them)
  47.79.34.208     VT 11/94   probed 20×   →  added
OUTBOUND HIT — look at this device
  192.168.2.121 reached c2.example.net (VT 9/94)
THREAT PREVENTION
  Anti-Malware: 1 ·  IPS: 1
TOP PROBING SOURCES (all dropped)
  93.152.221.36   312×  (in feed)
  … 8 more
INDICATORS ENTERED: 3 from the Spark's logs · 5 from news · 0 by hand
Lookups: 45 of 500 · next re-check 2026-12-18 · no errors
```

Inputs: the previous calendar day's capture (drops and rejects from the External zone,
distinct sources, top ten with the in-feed mark, Threat Prevention detections), the run's
log (rows added with their ratio and probe count, outbound hits, lookups used, the lines
that say something went wrong, `spark_logs.py: error: …` included), the feed's commits since the previous brief grouped by the origin in `COMMENT`
(`Spark syslog`, the news agent's label, `Telegram`, `added without VirusTotal check`), and
`recheck_due` over the feed for the next date. Sections with nothing to say are left out,
but the message is always sent, so a quiet morning still shows the system ran: every exit of
`daily_check.sh` ends with one Telegram message. A run that fails after its check sends the
brief with the failure as an `ERROR` line; one that fails before it sends the one line `Daily
check failed: <reason>` (`spark_brief.py --notice`); a brief that cannot be sent is followed by
that line, and nothing recurses. A missing capture is the first error listed, and the Spark's
system log lines are counted apart (`System log: N lines`). Each source under "sent to block"
then gets its attacker-context message. With no bot token or chat id in the Keychain the brief
is printed in the daily check's log instead. A delivered brief records
the feed's commit in `syslog/last-brief.json`, so the next one counts the rows committed
since and none twice (the first counts the feed's commits of the last 36 hours).

**Attacker context** (`attacker_context.py`). Facts first, from read-only requests to public
services, each optional so one failure never blocks the note:

| Source | Contributes |
|---|---|
| the capture (today and yesterday) | ports and services tried, counts, first and last seen, dropped or accepted |
| VirusTotal (one lookup, counted against the 500 a day) | owner network and country, engines flagging it and their categories; for a domain also the registrar |
| RDAP (`rdap.org`) | the registrant of the address block or domain, abuse contact |
| Shodan InternetDB (no key) | the attacker's own open ports, tags such as `honeypot`, `tor`, `vpn`, known vulnerable software |
| GreyNoise community API, only if a `GREYNOISE_API_KEY` item exists in the Keychain (optional; not stored as of 2026-10-28) | whether it is a known mass scanner, benign or malicious |

Then one request to Claude Opus 5.5 (`claude-opus-5-5`) on the Messages API, over HTTPS
from the standard library because this Mac's only Python is the Command Line Tools' 3.9 and
the Anthropic SDK needs 3.10; the key comes from the Keychain (`ANTHROPIC_API_KEY`, stored
2026-10-28). The request carries the facts as data, the `web_search` server tool
(`web_search_20260209`, at most three searches) for what the address and its network are
known for, `output_config.effort` `medium`, `max_tokens` 4000 (the plan's 1500 was raised in
the fix wave: adaptive thinking shares the cap, and a note could end mid-sentence after three
searches), and Anthropic's server-side refusal fallback (`fallbacks: "default"`). The facts
travel inside `<facts>…</facts>`, which the system prompt names (a forged tag inside them is
dropped). The instructions ask for at most eight plain lines, and the note is cut to eight lines
and 1,200 characters whatever the model writes, with ` (note cut short)` when the reply stopped
at `max_tokens`: who (network,
country, what the address is known as), what they did here, whether this is aimed at this
network or internet-wide scanning, and what to do; no motive is to be invented, and when
the pattern is mass scanning the note says so. Search results are untrusted text and are
never treated as instructions. The cost is measured, not estimated: each note logs
`note usage: input=N output=N searches=N seconds=N` from the replies' `usage` (summed over
`pause_turn` continuations) in the bot's log, and the brief's notes in the daily check's log;
the first week of those lines is what the caps should be tuned on. (The design's "one to three
cents a note" left out the web-search results' tokens and the per-search fee.) If the request
fails, the facts go out alone with one line saying the note is unavailable.

**Errors.** The public services are asked once, with a 15 s timeout, and nothing is
retried. A 404 is the service's answer (`no record`; for GreyNoise
`GreyNoise: no record (not observed scanning)`),
and any other failure (an HTTP error, a timeout, an answer that is not JSON) shows that
source as `unavailable` while the others carry on. The Claude request carries the server-side
fallback (`fallbacks: "default"`), which re-runs a request the model's safeguards declined on
another model; when the model cannot be asked, or refuses in the end, the facts go out
alone with a line saying why (`the model gave no note` for a refusal). The bot logs a failed
Telegram poll and tries again after 10 s, and starts the watcher again after 10 s if it
fails; the watcher survives a missing or rotated file. A failed push leaves the commit for
the next daily run, as today. A check interrupted by a network error (or a refused key) keeps
and commits the rows added so far and says `stopped: …`. An update the bot cannot handle is
logged and skipped, never replayed. Every error is logged to the bot's
log with a timestamp, and the `/status` reply shows the last one.

**VirusTotal quota.** The free key allows 500 lookups a day and 4 a minute. The daily check
spends up to 400 (`MAX_LOOKUPS` lowers it); the bot's checks (one lookup per indicator), each
`/who` and each attacker note (one lookup each) share the remaining 100. While
`syslog/.feed-lock` exists, whoever holds it, notes and `/who` skip VirusTotal and say
`VirusTotal: skipped (a feed check is running)`, so they cannot push a check past the 4 a minute;
the daily check gives the lock back before its brief, so the brief's notes keep VirusTotal. A
lookup that meets a 429 anyway (`vt_check.lookup_retrying`, in `run` and `recheck`) waits 61 s
and tries once more; a second 429 is the quota stop as before.

**Commits.** The bot's commits read `Add N indicator(s) sent from Telegram: <label>` and
carry no `Co-Authored-By` trailer, like the daily check's: they are a program's commits, not
a model's.

**Known limits, left as they are** (README, "Limits"): two full 50-indicator messages back to
back at 07:30 can hold the lock past the daily check's twenty-minute wait, which then fails
with its notice; a bot killed mid-check leaves the lock until the three-hour takeover
(`rmdir syslog/.feed-lock` clears it); an alert Telegram refuses is logged, not resent, and the
brief's counts still include the event. The logs are rotated only by a `newsyslog.d` entry the
owner installs (README, "Rotating the logs").

**Tests** (unit, no network, in the repository's style): parsing of bare messages and
labels, the allowlist, the `/trust` and bare paths against `FakeVT`, the lock between the
script and the bot, watcher matching for both alert kinds with midnight rollover and the
one-hour cooldown, brief rendering from a fixture capture and run log, context gathering
with each source failing in turn, the Opus request body and the handling of its response and
of a refusal, the plist. The fix wave added: the receiver's source filter over a loopback
socket, the alert and note caps on a fake clock, an alert sent while a slow note runs, a
same-day restart that alerts its gap late and one after a day change that does not, the system
log lines exactly as the live capture shows them, every exit of the daily check sending its one
message, and one `Bot.add` against real git (a bare origin, a staged file of the owner's, a
commit pushed elsewhere).

**Done means:** the brief arrives after the 07:30 run; an indicator sent to the bot is added,
committed and pushed within a minute, and the bot says so; an entry appended to today's
capture for a LAN device reaching a feed indicator raises an alert within a minute with a
context note behind it; `/who`, `/sources` and `/status` answer; the bot comes back after
a kill like the receiver does.

Outcome: built 2026-10-28 on branch worktree-telegram-bot (499 tests). A fix wave after the
whole-branch review (the receiver's source filter, the caps, the note thread, the saved watcher
position, explicit alert actions, the daily check's failure message, the private-chat rule and
the never-block list, among others) followed on the same branch, and its re-review was clean.
Merged into main by fast-forward on 2026-10-28 at 23:25 and running since 23:44 as the
LaunchAgent, paired with the owner's private chat the same evening; on 2026-10-29 BotFather's
`/setjoingroups` was set to disabled, so the bot cannot be added to a group. First night in
production: three Threat Prevention alerts (one source probing the WAN address at 02:09, 04:47
and 06:40) reached the phone, each with its note naming the port it went for and the
provider's abuse contact. The owner completed the end-to-end check (README, "Setting it up")
on 2026-10-29: `/status` and `/help` answer; a test address that VirusTotal flags 5/92 was
added, committed and pushed from the phone within a minute, its row labelled as sent from
Telegram; `/sources` sent the previous day's probing sources as a 42 KB file; the morning
brief arrived at 09:14 when the scheduled run ended; the crafted-capture item was covered by
the real alerts above; and the bot comes back after a kill, as it did after the restart that
followed each merge (the LaunchAgent restarts it; a same-day restart alerts what it missed as
`late:`). Learned in production and recorded under D9: while the daily check holds the feed
lock, about 100 minutes from 07:30, an addition from the phone is answered with "the feed is
locked" and the notes skip VirusTotal. Known limitation left for the first week of alerts: a Threat Prevention
row whose source is a public address is read as inbound and its note describes that source; if
the Spark ever logs such a row after NAT with the line's own WAN address as the source, the note
would describe the owner's own address.

### D7. A daily news-sourcing agent (requested 2026-10-28, design pending)

Requested: a daily job that finds indicators worth adding in current security reporting,
checks them and adds them. To be built on the Claude API (Opus 5.5, web search), its key in
the Keychain, output fed to `vt_check.py` so admission, deduplication and expiration apply
unchanged. Sources, caps and cost are the open design questions. Rows from the news agent
will carry a COMMENT starting with `News`, so the brief's origin count ("from news") can show
them; the morning brief already recognises that convention.

### D8. The public repository names nothing of the owner's network, lints the feed before every commit and pins its workflow (decided 2026-10-28, built 2026-10-28/29)

Decision: the repository is public and the gateway reads the feed from it as is, so three rules.
(1) No address, hostname or handle of the owner's network appears in it. Fixtures copied from real
log lines use stand-ins: `185.1.3.x` for the line's own address, which `spark_logs.candidate` and
`_learn_wan_ip` need to look public, so no RFC 5737 range would do; `185.1.2.x` for attackers;
`192.168.1.x` and `192.168.2.x` for the two LANs; `Home-Spark` for the gateway. This document
names no address. The LaunchAgent plists keep `/Users/home-server`: the account name is generic
and the installed copies must match the repository's. (2) `feed_lint.py` runs before every commit
of the feed, in all three writers: the daily check after its pull (a bad web edit on main stops
the run, with the problem in the morning message) and again before its commit; the Telegram bot
before its commit (a failing file is left for the owner and the reply says what is wrong); the
monthly re-check before its commit. It holds the file to the gateway's format: the exact header,
seven fields with all but the COMMENT filled in (the gateway would default an empty CONFIDENCE or
SEVERITY to high and an empty PRODUCT to AV, wrong for an address or a name), a VALUE of its TYPE
and normalised, no VALUE or UNIQ-NAME twice, no hidden character, none of the hosts the system
itself needs nor a Domain that covers one of them (that list moved from the bot into the lint).
Each problem names its line, its field and what to use instead, because the owner reads it in a
Telegram notice, not in a log. A feed that fails after the pull stops the whole daily run, not
only its commit: the check would otherwise write rows into a broken file and fail the second lint
anyway, and the two-day window makes up the skipped day when the file is fixed before the next
run. (3)
`actions/checkout` is pinned to a commit, and the repository's Actions settings are to require
SHA pinning once the pinned workflow is on main, so a moved tag cannot change what runs with write
access to the feed.

Why: the file is written by three unattended jobs and now and then by hand in a web editor, and
whatever reaches main is on the gateway within half an hour and on the public internet at once.
The checks at intake (`vt_check.classify`, the bot's never-block list) covered neither a hand
edit nor a stray real address in a fixture. Rewriting the published history to remove the
addresses already public was declined: they are DHCP addresses that rotate, and a force-push is
what the ruleset on main forbids.

Outcome: built 2026-10-28/29 on branch `worktree-repo-hardening`, test-first and reviewed by a
fresh reader, after the GitHub side was set on 2026-10-28 by hand: a ruleset on main that refuses
force-pushes and deletion, Actions limited to GitHub's and verified creators', secret scanning
with push protection, the owner's no-reply identity on every new commit; merged and pushed on
2026-10-29, and the Actions settings then set to require SHA-pinned actions (read back as set), so
the monthly re-check can run nothing a moved tag points at. The thirty-one commits on
main that this work is published together with, none of them public until then, carry in their
history three more private LAN addresses on the two subnets the public history already names; they
were not rewritten before the push, since such an address reveals nothing new and the stand-ins at
the tip are what a reader of the files sees. Known limits: the lint's verdict follows the Python it
runs under (3.9 on the Mac, newer on Actions: a character assigned after Unicode 13 counts as
hidden on the Mac only, and `is_global` differs for a few special-purpose blocks);
`vt_check.refang` runs once, so a doubly defanged value typed by hand is reported as not normalised
rather than repaired; the rows the writers produce have no round-trip test of their own through the
lint, the committed feed (every row of it theirs) and the bot's tests standing in for one. The
owner's items were settled on 2026-10-29: two-factor authentication is on, both e-mail privacy
toggles are on, the bot cannot be added to groups (BotFather's `/setjoingroups`), the token the
Mac pushes with stays a classic token by the owner's choice (the tooling then works on the whole
account; the risk accepted is a token in this Mac's Keychain that reaches every repository), and
the vendor exports are not named: every COMMENT that read `<vendor> export <date>` or named a
national alert now reads `External export <date>` or `External alert phishing`, `cyberint_xlsx.py`
writes the External label, and no new row names where it came from. The rows themselves stay
public; what is withheld is whose export they were.

### D9. The daily check spends its lookups inbound first, then the busiest addresses, then names collapsed into families (decided and built 2026-10-29)

Found on the first full day of capture after the receiver rewrite (one line per datagram of
the gateway, accepted connections included): the capture runs at fifteen to thirty thousand
lines an hour, and the 07:30 run of 2026-10-29 found 4,277 inbound sources and 3,694 outbound
destinations in its two-day window, 2,441 of them to check, against a 400-lookup budget of
which the run the day before had used 45. Under the order of the time (outbound names, then
addresses, then inbound sources) the whole budget went to 1,160 names; the addresses and the 20
inbound sources, the rows the feed is built from, were never reached, and would never be while
the names alone exceed 400 a day. Measured on that capture: of the 1,211 names in the window,
109 apexes with three or more hosts stood for 689 names (the biggest a streaming service's 42,
a software updater's 26 and a video CDN's 18) and 522 were lone hosts; day to day a third
of the names and a quarter of the apexes were new, more than half of the bare addresses, and
18 of the 20 busiest inbound sources.

Decision, approved by the owner the same morning:

- Shares of the budget, in this order: inbound sources first, at most 20 as before; then the
  40 busiest bare addresses reached three or more times (`--max-ips`, new); then outbound names
  take what is left, 340 on a full day. A share a group does not use passes down to the names.
  Inbound sources and addresses can no longer be starved by names.
- Names are grouped by apex: the last two labels, or three under a second-level registry of a
  country code (co.uk, com.au, go.jp; a short built-in list, not the public suffix list). An
  apex with three or more hosts in the window is one lookup, the apex, cached under the apex;
  a lone host is looked up as itself. A host under an apex checked clean is not skipped: a
  CDN's tail of hostnames is one service, while an infected device's one host under a
  dynamic-DNS or hosting apex is exactly what VirusTotal flags by host and not by apex.
  Hosts under a shared platform (`x.netlify.app` and its like: `SHARED_PLATFORMS`, the list
  the feed's import already used, now kept in `vt_check.py`) never make a family however many there are: the
  platform's apex is always clean and each tenant's page is its own indicator, the stance
  the feed's import takes. This exception came out of the review below, before the first run.
  A family whose apex is itself a feed Domain row is skipped like any feed member, its hosts
  with it: the gateway blocks that domain already. A hit on a family is reported as the apex,
  the devices that reached it and the hosts it stands for.
- The 400 budget stays (100 of the free key's 500 remain for the bot and for runs by hand), the
  gateway's forwarding stays as it is, and no top-sites list is fetched or maintained.

Expected effect on that window: 20, 40 and 340 lookups, with 291 of the 631 name entries left
for the next day; at the measured churn about 250 name entries a day fit inside the share, so
the backlog clears in two or three days. Known limit: the run still takes about 100 minutes and
holds the feed lock throughout, so the bot cannot add indicators until about 09:10 each
morning; this change narrows what is checked, not how long the check takes.

Outcome: built the same morning on branch `worktree-narrow-check`, test-first (12 new tests on
the ordering, the apex rule, the family cache, the shared-platform exception and the listing;
the suite stands at 534 and passes, also under `python3 -I`). An independent review of the
branch before the merge found that the family rule as approved would have swallowed the
sub-hosts of shared hosting platforms (three tenants' pages under one platform would have
become a single clean lookup of the platform, cached for thirty days), the opposite of the
stance the feed's import takes; the shared-platform exception and the hosts line under a
family hit above come from that review. A dry listing of the same two-day window under the new order
reads "to check: 20 inbound sources, 40 outbound addresses, 631 outbound names (111 family
apexes)", with 501 names under the allowed vendor domains skipped; the biggest families were a
streaming service's 27 hosts, the gateway vendor's 20 and a software updater's 19 (at 09:40, with
the morning run's 400 names in the cache and the exception in, the same window read 20, 40 and
553 names, 113 family apexes). The 07:30 run
of 2026-10-29, the last on the old order, confirmed the finding: its 400 lookups all went to
names (394 clean, 6 unknown to VirusTotal), it added nothing and left 2,041 for another day.
Merged into main on the owner's word the same morning, with the shared-platform exception; the
first run on the new order is 2026-10-30 07:30.

## 5. Operating it

- Is the system up? Send `/status` to the bot first: five lines, the receiver, the last daily
  check, the next re-check, the bot's uptime and its last error. No answer means the bot or
  Telegram is down, or the bot is busy with a long check (up to about 13 minutes);
  `launchctl list | grep telegram` shows a PID next to `com.spark-ioc-feed.telegram` when the
  job is running.
- Is the receiver up? `launchctl list | grep spark` shows a PID next to `com.spark-ioc-feed.syslog`;
  `lsof -nP -iUDP:5514` shows Python on `*:5514`; today's `syslog/spark-<day>.log` grows, and
  `~/Library/Logs/spark-ioc-feed/syslog-receiver.log` says `receiving from <the gateway>`. A
  `dropping datagrams from <address>` line names a sender that is not the gateway; a `WARNING`
  that the default route could not be read means it keeps every sender until restarted.
- Did the daily job run? `~/Library/Logs/spark-ioc-feed/daily-check.log`, one timestamped line
  per step; `OUTBOUND HIT` lines are the ones to read.
- Run the daily job now: `launchctl start com.spark-ioc-feed.daily`. Until its push it holds
  the feed lock, and the bot answers an addition by saying so. A lock left by a killed bot is
  taken over after three hours; `rmdir syslog/.feed-lock` clears it at once.
- The bot's log is `~/Library/Logs/spark-ioc-feed/telegram-bot.log`: a timestamped line for
  its start, for a message ignored from another chat, and for each error. Restart the bot: `launchctl kickstart -k gui/$(id -u)/com.spark-ioc-feed.telegram`.
  Stop it: `launchctl bootout gui/$(id -u)/com.spark-ioc-feed.telegram`.
- If the Keychain items are missing the bot logs that it found no `TELEGRAM_BOT_TOKEN` or
  `TELEGRAM_CHAT_ID` (service `spark-ioc-feed`), or that `TELEGRAM_CHAT_ID is not a number`, and
  exits after 300 s, and launchd starts
  it again, so the line repeats every five minutes until they are stored. To see which
  is missing: `security find-generic-password -s spark-ioc-feed -a TELEGRAM_BOT_TOKEN` (and
  the same with `-a TELEGRAM_CHAT_ID`) prints the item or says it was not found. Store it
  (README, "Setting it up") and restart the bot as above. A note that says `(context note
  unavailable: …)` names its reason, such as a missing `ANTHROPIC_API_KEY`.
- After a reboot: unlock FileVault; nothing else to do.
- The gateway's side: Logs & Monitoring → External Log Servers → Syslog Servers must point at
  this Mac's LAN address, UDP 5514, Security logs; the address has a DHCP reservation.

## 6. Open items

1. Done 2026-10-29: `sha_pinning_required` is set in the repository's Actions settings (D8), once
   the pinned `actions/checkout` was on main; it could not be set while the workflow named a tag.
2. Design D7 (news agent) and record it here with its outcome; D6 is built (record the owner's
   end-to-end check under its outcome).
3. Merge the two duplicate-check implementations when `vt_check.py` is next changed.
4. The Telegram bot's alert rule (which detections alert, which get a note) and its caps were set
   on measured data and the review's arithmetic; tune them on the first week of `note usage`
   lines and alerts.
5. The owner's hardening items listed under D8's outcome.
