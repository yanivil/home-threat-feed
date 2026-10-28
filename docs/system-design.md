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
Spark 1595 (10.45.60.1)                         GitHub: yanivil/spark-ioc-feed
   | security logs, syslog over UDP 5514              ^            |
   v                                                  | push       | the Spark pulls
iMac "home-server" (10.45.60.100), user home-server   |            v  spark-ioc-feed.csv
   |                                                  |
   +-- syslog_receiver.py  (LaunchAgent com.spark-ioc-feed.syslog, always on)
   |      -> syslog/spark-YYYY-MM-DD.log   one entry per line, one file per day
   |
   +-- daily_check.sh      (LaunchAgent com.spark-ioc-feed.daily, 07:30)
   |      git pull -> spark_logs.py --days 2 --check -> vt_check.run() -> CSV -> commit, push
   |      macOS notification on outbound hits and on errors
   |
   +-- by hand: vt_check.py <indicators> | --trusted | cyberint_xlsx.py -> TSV -> vt_check.py --trusted

GitHub Actions, 1st of the month: .github/workflows/recheck.yml -> vt_check.py --recheck -> CSV
```

| Piece | Runs | Reads | Writes |
|---|---|---|---|
| `syslog_receiver.py` | always, restarted by launchd if it dies | UDP 5514 | `syslog/spark-<day>.log` |
| `daily_check.sh` | 07:30 daily (a run missed while asleep happens on wake) | capture of the last 2 days, `syslog/checked.json`, `syslog/allow.txt`, VT key from the Keychain | the feed, `syslog/checked.json`, `~/Library/Logs/spark-ioc-feed/daily-check.log`, a notification |
| `syslog_retention.py` | first step of the daily job | capture file names (the date in them) | `.log` → `.log.gz` after 7 days; removes both after 180 |
| `spark_logs.py` | from the daily job or by hand | capture files, plain or `.gz` | feed rows (through `vt_check.run`) |
| `vt_check.py` | by hand, from the daily job, from Actions | VirusTotal API v3 | feed rows; with `--recheck`, rewrites rows in place |
| `cyberint_xlsx.py` | by hand | Cyberint `.xlsx` exports | a TSV for `vt_check.py --trusted` |
| `recheck.yml` | monthly on GitHub | the feed, `VT_API_KEY` secret | the feed |

Both LaunchAgents run the Command Line Tools `Python.app` binary as their program (see
decision D1), with logs in `~/Library/Logs/spark-ioc-feed/`.

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
in this order: outbound names (minus well-known vendor domains), outbound addresses seen 3+
times, inbound sources, capped at 400 a day; the rest waits for another day.

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

As of 2026-10-28, 1,111 of the feed's 1,783 rows were added without a check (Cyberint exports,
2026-10-22), and `--recheck` never looks at them. Requested: apply the same expiration logic
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

### D6. Alerts and the daily brief go to Telegram (requested 2026-10-28, design pending)

Requested: alerts on Telegram instead of only macOS notifications; a daily brief of attack
attempts and of indicators added; and a way to send the bot an indicator to be added, either
after a VirusTotal check or without one. To be designed as a separate always-on LaunchAgent
(the bot) with its token in the login Keychain beside the VirusTotal key. Open questions,
to be settled with the owner: what counts as an "attack attempt" in the brief; who may talk
to the bot; whether to also alert on live matches (a LAN device reaching a feed indicator)
within minutes rather than at the daily run.

### D7. A daily news-sourcing agent (requested 2026-10-28, design pending)

Requested: a daily job that finds indicators worth adding in current security reporting,
checks them and adds them. To be built on the Claude API (Opus 5.5, web search), its key in
the Keychain, output fed to `vt_check.py` so admission, deduplication and expiration apply
unchanged. Sources, caps and cost are the open design questions.

## 5. Operating it

- Is the receiver up? `launchctl list | grep spark` shows a PID next to `com.spark-ioc-feed.syslog`;
  `lsof -nP -iUDP:5514` shows Python on `*:5514`; today's `syslog/spark-<day>.log` grows.
- Did the daily job run? `~/Library/Logs/spark-ioc-feed/daily-check.log`, one timestamped line
  per step; `OUTBOUND HIT` lines are the ones to read.
- Run the daily job now: `launchctl start com.spark-ioc-feed.daily`.
- After a reboot: unlock FileVault; nothing else to do.
- The gateway's side: Logs & Monitoring → External Log Servers → Syslog Servers must point at
  `10.45.60.100`, UDP 5514, Security logs; the address has a DHCP reservation.

## 6. Open items

1. Commit the D1 plist and README changes, D3, D5 and this document.
2. Design D6 (Telegram), then D7 (news agent); record each decision here with its outcome.
3. Merge the two duplicate-check implementations when `vt_check.py` is next changed.
