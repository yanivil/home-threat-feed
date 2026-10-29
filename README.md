# spark-ioc-feed

Custom Indicators of Compromise (IoC) feed for a Check Point Quantum Spark gateway
(locally managed, Threat Prevention → IoC Feeds).

## Feed URL

```
https://raw.githubusercontent.com/yanivil/home-threat-feed/main/spark-ioc-feed.csv
```

## Gateway setup (Quantum Spark 1595, R82.00.11, locally managed)

Threat Prevention → IoC Feeds → New: Resource = the feed URL above, Action = Prevent.

- **The "Test" button fails ("URL test failed") even though the feed loads.** The WebUI test
  uses the gateway's own curl, whose CA bundle trusts neither GitHub's nor jsDelivr's
  certificate chain; the feeder daemon validates through Check Point's store and fetches the
  file fine. Proof is in `/opt/fw1/log/ioc_feeder.elg` (`github-custom: success`), reachable
  over SSH (`ssh admin@<LAN IP>`, then `expert`). A feed that is active cannot be deleted;
  deactivate it first.
- **What each indicator type enforces without SSL inspection:** IPs and IP ranges block in
  both directions (Anti-Bot logs them as "Prevent" on the WAN). Domains and URLs block the
  HTTP Host header and **DNS lookups that cross the gateway**; the TLS SNI is not used for
  blocking. Hashes are enforced by Anti-Virus on HTTP downloads.
- **For domains to work over HTTPS, client DNS must pass through the gateway**, not end at
  the gateway's own resolver: Device → Network → each LAN → DHCPv4 Settings → DNS → "Use the
  following IP addresses" with an external resolver (e.g. 9.9.9.9 / 149.112.112.112). Then
  the Anti-Bot DNS trap answers feed domains with `62.0.58.94` and nothing connects.
- **Close the bypasses** with outgoing firewall rules above the cleanup rule: block service
  QUIC (UDP 443, otherwise HTTP/3 skips inspection); block DoH and DoT (the `DoH` application,
  a custom TCP 853 service, and URL entries for `dns.google`, `cloudflare-dns.com`,
  `one.one.one.one`, `mozilla.cloudflare-dns.com`, `dns.quad9.net`, `doh.opendns.com`,
  `dns.nextdns.io`, `dns.adguard.com`); block NetBIOS and SMB to the Internet (the `NetBios`
  service group, `microsoft-ds-udp`, and a custom TCP 445 service), which Windows otherwise
  leaks outward.
- **IoT policy vs. external DNS:** the Spark's IoT protection in *Prevent* mode only allows what
  Check Point's per-device profile lists. After the DNS change, the Roomba's lookups to 9.9.9.9 and
  its AWS IoT session (`*.iot.us-east-1.amazonaws.com`) fell outside its profile and were dropped
  silently for 36 hours. Keep IoT assets on *Monitor* (or add their real endpoints), and reboot a
  device that has gone quiet; its boot shows in syslog as an NTP burst.
- **Verify from a LAN device:** `dig +short <a domain from the feed>` must return `62.0.58.94`.

## Format

Check Point indicator CSV. Header line must stay exactly as is:

```
# UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT
```

| Column     | Values |
|------------|--------|
| UNIQ-NAME  | any unique text |
| VALUE      | the indicator |
| TYPE       | IP, IP Range (`a.b.c.d-a.b.c.e`), Domain, URL, MD5, SHA1, SHA256 |
| CONFIDENCE | low / medium / high / critical (optional to the gateway, default high; required here) |
| SEVERITY   | low / medium / high / critical (optional to the gateway, default high; required here) |
| PRODUCT    | AB for IP / IP Range / Domain / URL, AV for hashes (optional to the gateway, default AV, which is wrong for an address or a name; required here) |
| COMMENT    | free text (optional) |

The gateway re-fetches the file every 30 minutes (configurable under IoC Feeds → Settings).

`feed_lint.py` holds the file to this format and refuses the rest: the header exactly as above,
seven fields in every row with all but the COMMENT filled in (the gateway's defaults never apply
by accident), a VALUE of its TYPE and normalised (lower-case domains and hashes, public
addresses, ranges as `a.b.c.d-a.b.c.e`), no VALUE or UNIQ-NAME twice, no hidden character, and
none of the hosts this system itself needs (github.com, raw.githubusercontent.com,
api.telegram.org, api.anthropic.com, www.virustotal.com) nor a Domain that covers one of them.
Every writer runs it before committing: the daily check (after its pull and again before its
commit), the Telegram bot and the monthly re-check; a hand edit is committed the same way
(`python3 feed_lint.py && git commit …`, as in the recipes below). By hand, `python3 feed_lint.py`
lists the problems as `line N: …`, each naming the field to fix.

## Adding an indicator

Edit `spark-ioc-feed.csv` in the GitHub web editor, add one line per indicator, commit.
No spaces around commas. Do not put commas inside the COMMENT field. A web edit reaches main
unchecked: when it broke the file, the next daily run stops at its lint with the problem in its
log and in the morning message, and adds nothing until the file is fixed.

## Adding indicators checked on VirusTotal

`vt_check.py` looks up each indicator on VirusTotal and appends the ones that enough
engines flag as malicious to `spark-ioc-feed.csv`. It needs Python 3 only (no packages)
and a VirusTotal API key, read from the `VT_API_KEY` environment variable or, when that is
not set, from the login Keychain item described under "Daily check on this Mac" below.
Never commit the key — this repository is public.

```
export VT_API_KEY=your-key
python3 vt_check.py evil.com 203.0.113.7 https://bad.example/x 275a021b...fd0f
python3 vt_check.py -f iocs.txt --dry-run      # preview, change nothing
python3 vt_check.py -f iocs.txt
python3 feed_lint.py && git commit -am "Add VirusTotal-confirmed indicators" && git push
```

In an indicators file, each line holds one indicator, optionally followed by whitespace and
a label (group, source) that goes into COMMENT; tab-separated label fields are joined with
` - `. Blank lines and `#` lines are skipped, and defanged input (`evil[.]com`, `hxxps://`)
is accepted.

- **Added** when enough VirusTotal engines flag it: 3 for domains, URLs and hashes, 5 for
  IPs (hosting addresses pick up a few blocklist hits just for being on a busy provider).
  `--min-malicious N` applies N to every type instead.
- **CONFIDENCE** follows the detection count: 10+ high, 5–9 medium, below 5 low. Whether
  low/medium-confidence indicators are blocked or only logged depends on the gateway's
  Threat Prevention policy. SEVERITY is always high.
- **Skipped without a lookup**: values already in the feed, duplicates, IP ranges, private
  IPs, URLs containing commas.
- **Rate limit**: the free API allows 4 lookups/min and 500/day, so the script waits 15 s
  between lookups (`--delay`). If the daily quota runs out it stops, keeps what it already
  added, and lists the indicators still to check.

## Adding indicators from a source you trust (no VirusTotal)

`--trusted` appends indicators without looking them up, for feeds whose publisher you vouch
for. Rows get CONFIDENCE high and a COMMENT ending in `added without VirusTotal check <date>`.
They are not exempt from "Keeping the feed fresh" below: 90 days after that date `--recheck`
looks them up once, keeps the ones VirusTotal flags as ordinary checked rows, and removes the
rest (hashes are never re-checked). An indicator the source still vouches for after that is
yours to add again.

```
python3 vt_check.py --trusted -f iocs.tsv
```

For **Cyberint IOC exports** (`Cyberint_<Group>_IOCs_<date>.xlsx`), `cyberint_xlsx.py` turns the
spreadsheets into that list, labelling each row with the group and `External export <date>` (the
feed names no vendor in its COMMENT column: the rows are republished, the export is not), and drops what a
blocking feed must not contain: shared platforms (an apex like `somee.com`, relays like
`smp10.simplex.im`; an attacker's own sub-host such as `x.netlify.app` is kept), CDN front-end
addresses (Cloudflare, Google, Akamai, Fastly, CloudFront), Tor addresses, placeholders like
`{REDACTED}`, CIDRs and anything else the format can't hold. It needs no spreadsheet package.

```
python3 cyberint_xlsx.py ~/Downloads/Cyberint_*_IOCs_2026-10-22.xlsx > iocs.tsv   # dropped values go to stderr
python3 vt_check.py --trusted -f iocs.tsv
```

Even with a trusted source, read the domain list once before adding: vendor exports sometimes
include a victim's or a legitimate company's domain, which VirusTotal would have caught.

## Mining the gateway's own logs

The Spark cannot export its security logs, but it can send them as syslog. Two scripts turn
that stream into checked indicators:

1. **`syslog_receiver.py`** listens on UDP 5514 and writes one entry per line to
   `syslog/spark-YYYY-MM-DD.log` (git-ignored), re-joining the entries the gateway splits over
   several datagrams. It keeps only the gateway's datagrams: those from the address given with
   `--source ADDR` (repeatable; `--source any` keeps every one), by default from the Mac's
   default-route gateway, which on this network is the Spark, read with `route -n get default`
   when the receiver starts. Its log (`~/Library/Logs/spark-ioc-feed/syslog-receiver.log`) says
   `accepting datagrams from <address> only (the default route's gateway)`, then
   `receiving from <address>` once the first one arrives. A datagram from any other address is
   dropped: the first from each such address is logged (`dropping datagrams from <address>: not
   an allowed source`, the address only), and the running total at most once an hour. If the
   default route cannot be read, the log says so in a `WARNING` and every datagram is kept, so
   the capture never stops silently. A line break inside a datagram becomes a space: one
   datagram never makes two capture lines. On the Spark: Logs & Monitoring → External Log
   Servers → Syslog Servers → Configure: UDP, the Mac's LAN address, port 5514, Security logs.
   The Spark forwards its system logs over the same stream too (`rsyslogd: …`, `root: …`,
   `lua: [AUDIT] …`); they stay in the capture, and every reader below sets them apart (the
   brief counts them as `System log: N lines`) and never takes them for traffic. Give that Mac a
   DHCP reservation (Users and Objects → Network Objects → Single IP → "Reserve IP address in
   DHCP service for MAC"). `launchd/com.spark-ioc-feed.syslog.plist` keeps the receiver
   running across reboots; the install steps are in its comment. The capture grows by a few
   hundred MB a day, so `syslog_retention.py`, run by the daily check before anything else,
   gzips a day's file once it is a week old and removes it after 180 days; `spark_logs.py`
   reads the compressed days like the plain ones.
2. **`spark_logs.py`** reads the capture and sorts what it finds into two kinds:
   - **outbound**: names (or addresses) that LAN devices connected to. Hits are **reported,
     never added**, with the devices that reached them, because an outbound hit means a
     device needs looking at.
   - **inbound**: public addresses that probed the WAN. With `--check`, those VirusTotal
     flags (5+ engines) are added to the feed, labelled `Inbound probe of WAN - Spark syslog`.

```
python3 spark_logs.py                       # list what a run would check, from today's capture
python3 spark_logs.py --days 3              # ... from the last three days
python3 spark_logs.py --check               # look them up (VT_API_KEY in the environment)
python3 spark_logs.py --check --max-lookups 100
```

Lookups are the scarce resource (the free key allows 500 a day), so a run spends them in
this order, each group busiest first:

- **Inbound sources first**, but only those that probed at least `--min-inbound-hits` times
  (5: persistent probing, not one-off background noise), at most `--max-inbound` (20) a run.
  These are the rows the feed gains; adding every scanner that knocked once would grow it by
  a hundred rows a day of no value.
- **Then outbound addresses** that carried no name and were reached at least `--min-ip-hits`
  times (3), at most `--max-ips` (40) a run. A command-and-control server reached by address
  recurs; a CDN edge is seen once and never again.
- **Then outbound names**, the hunting signal: every host name a LAN device reached, except
  hosts under the well-known vendor domains listed in `ALLOWED_SUFFIXES` at the top of the
  script (`apple.com`, `googleapis.com`, `office.com`, `akamaiedge.net`, `whatsapp.net`, ...),
  matched by suffix. `syslog/allow.txt` (one suffix per line, `#` comments, git-ignored like
  the rest of that folder) extends the list for the vendors your own devices talk to. Three
  or more hosts under one apex (`rr2---sn-….googlevideo.com` and its siblings; the apex is
  the last two labels, or three under `co.uk`, `com.au` and the like) are one lookup, the
  apex: a CDN's tail of hostnames is one service. Fewer stay separate lookups, so one
  device's one host under a dynamic-DNS or hosting domain keeps its own verdict, whatever
  the apex's; hosts under a shared platform (`x.netlify.app` and its like: `SHARED_PLATFORMS`
  in `vt_check.py`, the list the import uses too) never form a family at all, since each
  tenant's page is its own indicator. A hit on a family is reported with the hosts it stands for.

The first two caps give those groups a share of the run that the names cannot take; a share
a group does not use passes down to the names. Indicators already in the feed, or looked up
within `--recheck-days` (30; `syslog/checked.json` remembers them, a family under its apex),
are skipped, and `--max-lookups` (default 400, under two hours at 15 s each) caps a run;
what does not fit is left for another day. Without `--check` the script lists the three
groups in that order, with counts (a family as its apex, with how many hosts it stands for),
so you can see what a run will do before it spends anything. The daily check below runs it
for you and pushes what it adds.

### Daily check on this Mac

`daily_check.sh` does the whole round once: `git pull`, then `spark_logs.py --days 2 --check`
with the script's own defaults, then a commit of `spark-ioc-feed.csv` (and nothing else) and a
push when rows were added. It holds the feed lock that it shares with the Telegram bot from
before the pull until right after the push, and ends by sending the morning brief; see
"Telegram" below. `launchd/com.spark-ioc-feed.daily.plist` runs it every morning at 07:30 local
time.

1. Store the key once in the login Keychain. Both scripts fall back to it when `VT_API_KEY`
   is not set, and the LaunchAgent has no other way to get it:
   ```
   security add-generic-password -s spark-ioc-feed -a VT_API_KEY -w 'your-key' -U
   ```
2. Install the agent (edit the two paths in the plist first if the repository lives elsewhere):
   ```
   cp launchd/com.spark-ioc-feed.daily.plist ~/Library/LaunchAgents/
   launchctl load ~/Library/LaunchAgents/com.spark-ioc-feed.daily.plist
   launchctl start com.spark-ioc-feed.daily      # run it now instead of waiting for 07:30
   ```

3. If the repository lives on an external disk, grant Full Disk Access once to the Command
   Line Tools' `Python.app` (System Settings → Privacy & Security → Full Disk Access → `+`,
   then ⌘⇧G and the path in the plist's `ProgramArguments`). All four plists (the receiver, the
   daily check, the news check, the Telegram bot) run their job through that binary because macOS denies
   `/usr/bin/python3` and `/bin/bash` on external volumes
   without prompting; `docs/system-design.md`, decision D1, has the details.

- Everything a run prints goes to `~/Library/Logs/spark-ioc-feed/daily-check.log`, with a timestamped line for
  each step. **Outbound hits are only reported there**, as
  `OUTBOUND HIT <destination> (<ratio>) reached by <devices>`, and raise a macOS notification
  titled "Spark IoC feed" (allow notifications from Script Editor if macOS asks the first time).
  Nothing else records them, so glance at the log now and then.
- Two days of capture are read because at 07:30 today's file holds only a few hours;
  `syslog/checked.json` keeps yesterday's indicators from being looked up twice. The default
  400 lookups take under two hours, fine for a morning job, and leave 100 of the free key's
  500 a day: 40 for the news check ("News agent" below) and 60 for the bot and runs by hand.
- The pull first brings in rows committed elsewhere (the GitHub web editor, the monthly
  re-check on Actions). A pull or push that fails is logged as `ERROR` with a notification,
  the run exits non-zero, and a commit that could not be pushed stays local until the next run
  pushes it. A run missed while the Mac slept happens on wake; one missed while it was off is
  skipped.
- The feed is linted (`feed_lint.py`, "Format" above) right after the pull and again before the
  commit. A feed that fails stops the run before the check, with `Daily check failed: the feed on
  main fails its lint, nothing was checked: line N: …; fix spark-ioc-feed.csv` as the morning
  message (`on this Mac (uncommitted changes)` instead of `on main` when the bad row is a hand
  edit here that the bot refused to commit); rows the check wrote that fail stay uncommitted and
  the brief's ERRORS line names the problem. Fix `spark-ioc-feed.csv` and the next run goes on.
- Every run ends with one Telegram message. A run that fails after the check (the commit or the
  push) sends the brief with the failure among its errors; one that fails before it (the lock,
  `syslog/`, the pull) sends one line, `Daily check failed: <reason>`; and when the brief itself
  cannot be sent, that line follows it as `Daily check failed: the morning brief was not sent
  (spark_brief.py exited N)`. Without a bot token or chat id these are printed in the log.
- By hand with other settings: `DAYS=3 MAX_LOOKUPS=50 bash daily_check.sh`.

## Telegram: alerts, the morning brief and sending indicators

`telegram_bot.py` is the part of the system you talk to from your phone. Its watcher
(`capture_watcher.py`, a thread of the bot) follows today's capture and messages you within a
minute or two when a LAN device reaches something in the feed, or when the gateway's Threat
Prevention prevents, drops, rejects, blocks or detects something on traffic with a public
address; every morning the daily check sends you a brief of the previous day through the same
bot; and indicators you send it are checked on VirusTotal, and the flagged ones added to the
feed, committed and pushed. Only your own private chat with the bot is served: a message from
any other chat, a group you are in included, is ignored (and logged, once a day per chat). The
bot runs on this Mac as the LaunchAgent `com.spark-ioc-feed.telegram` and logs to
`~/Library/Logs/spark-ioc-feed/telegram-bot.log`. `docs/system-design.md`, decision D6, has the
design.

### Setting it up

The bot's token and your chat id live in the login Keychain under the service `spark-ioc-feed`,
like the VirusTotal key; nothing about the bot is stored in the repository. This is your
checklist, once:

1. Create the bot. In Telegram open BotFather, send `/newbot` and answer its questions; it
   replies with the bot's token. Store it:
   ```
   security add-generic-password -s spark-ioc-feed -a TELEGRAM_BOT_TOKEN -w '<token>' -U
   ```
2. Pair your chat. Open the bot in Telegram from your own account (a private chat with it, not
   a group) and send it `/start`, then run
   ```
   python3 telegram_bot.py --pair
   ```
   It waits up to 50 seconds, then lists every chat that wrote to the bot with its type and
   sender, `private chat <id> from @<username> (<first name>)` (an account without a username
   shows as `from first name "<first name>" (no username)`), refuses a group (`group chat
   from …: refused — send /start to the bot from your own account, not from a group`, without
   its id), and prints the private chat's id with the command that stores it:
   ```
   security add-generic-password -s spark-ioc-feed -a TELEGRAM_CHAT_ID -w '<chat id>' -U
   ```
   Check that the sender is you, then run that command. (Bots can be found by name: if someone
   else wrote to it first, both private chats are listed and you store your own.) Without the
   chat id the bot does not start: it logs what is missing, waits five minutes and exits, as in
   step 3. A stored chat id that is not a number (the two items swapped, say) is treated the
   same way and logged as `TELEGRAM_CHAT_ID is not a number`, never with the value.
3. Install the agent (edit the paths in the plist first if the repository or your home
   directory lives elsewhere). It runs through the same `Python.app` as the other agents,
   so the Full Disk Access grant described above covers it:
   ```
   cp launchd/com.spark-ioc-feed.telegram.plist ~/Library/LaunchAgents/
   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.spark-ioc-feed.telegram.plist
   ```
   If the token or the chat id is missing, the agent logs that and exits after five minutes,
   and launchd starts it again; store them and it picks them up on a later start.
4. Optional: a GreyNoise community API key adds GreyNoise's view (a known mass scanner or not)
   to the attacker notes. Without it that line says `skipped (no key)`.
   ```
   security add-generic-password -s spark-ioc-feed -a GREYNOISE_API_KEY -w '<key>' -U
   ```
5. The notes also need an Anthropic API key in the Keychain item `ANTHROPIC_API_KEY` (already
   stored on this Mac; on another one, store it the same way):
   ```
   security add-generic-password -s spark-ioc-feed -a ANTHROPIC_API_KEY -w '<key>' -U
   ```
   Without it a note is the facts followed by
   `(context note unavailable: no ANTHROPIC_API_KEY in the Keychain)`.

Then check it end to end, and tick each line:

- [ ] `launchctl list | grep telegram` shows a process id next to `com.spark-ioc-feed.telegram`.
- [ ] The receiver's log shows `receiving from <the Spark's address>`, and today's capture keeps
  growing.
- [ ] `/status` and `/help` both answer in Telegram.
- [ ] Send one test indicator that VirusTotal flags (a domain that 3 engines flag, or an IP that
  5 do) with a label, for example `<indicator> bot test`. The bot replies that it is checking,
  then `<indicator>: added (...)` and `Committed and pushed.`; `git log -1` shows
  `Add 1 indicator sent from Telegram: bot test`, and the commit is on GitHub.
- [ ] Append a crafted line to today's capture for a LAN device reaching that indicator (this
  one is for a domain; for an IP put it in `dst` instead of using `destination_domain_name`).
  Within a minute an alert arrives, and after it the attacker note:
  ```
  printf '%s Action="drop" inzone="Internal" outzone="External" service_id="HTTPS" src="192.168.1.50" dst="104.18.32.47" proto="6" destination_domain_name="<the test domain>" ProductName="VPN-1 & FireWall-1"\n' "$(date +%Y-%m-%dT%H:%M:%S)" >> syslog/spark-$(date +%F).log
  ```
- [ ] `/sources` sends yesterday's probing sources as a text file (or says there are none).
- [ ] `launchctl start com.spark-ioc-feed.daily` and the brief arrives when the run ends, which
  with the default 400 lookups can be up to about two hours later (`MAX_LOOKUPS=20 bash
  daily_check.sh` is a shorter run by hand). Do the steps above first: until its push the daily
  check holds the feed lock and the bot will not add indicators.
- [ ] Kill the bot's process id (`kill <pid>`, the number `launchctl list | grep telegram`
  shows); a few seconds later the same command shows a new one, because launchd restarts the
  job.

To stop the bot: `launchctl bootout gui/$(id -u)/com.spark-ioc-feed.telegram`.

### Talking to it

Send the bot a message and it answers in the same chat. `/help` lists what it understands:

- **Indicators, with no command.** A message of indicators (IPs, domains, URLs, hashes;
  defanged input such as `evil[.]com` and `hxxps://` is fine), then an optional label:
  ```
  evil[.]com hxxps://bad[.]example/x MuddyWater - Unit 42
  ```
  Every leading word that is an indicator is checked on VirusTotal and added when enough engines
  flag it (the thresholds under "Adding indicators checked on VirusTotal"); indicators may be
  separated by spaces or commas (`a.example,b.example`). The first word that is not one starts
  the label, which loses quotes and invisible characters (control, bidi and zero-width marks),
  has its commas made spaces and is cut to 120 characters. The bot first says
  `Checking 2 indicators on VirusTotal, about 1 minute.` as a message of its own; the reply then
  has one line per indicator, a count, and what happened to the commit:
  ```
  evil.com: added (Domain 11/94 malicious)
  https://bad.example/x: clean (URL 0/94 malicious)
  1 added, 1 clean, 0 unknown to VirusTotal, 0 already in the feed
  Committed and pushed.
  ```
  An indicator can also come back `in-feed`, `duplicate`, `not-found (VirusTotal has no
  record)`, `invalid (...)`, `error (...)`, `quota (...)` or `unchecked`. With nothing added
  the last line is `Nothing added, nothing committed.`; when the file fails `feed_lint.py` (a
  hand edit of it on the Mac, never the bot's own rows) it is `The feed failed its lint, nothing
  committed (fix spark-ioc-feed.csv on the Mac): line N: …` and the rows wait, uncommitted, for
  the fix.
- **`/trust <indicators> [label]`** adds them without a VirusTotal check, as
  `vt_check.py --trusted` does: the rows carry `added without VirusTotal check <date>` and join
  the 90-day first check under "Keeping the feed fresh". There is no wait, so the reply comes
  in seconds.
- Both refuse what the gateway must never block, with `refused: <value> is on the never-block
  list`: a domain, or a URL's host, under the vendor domains the daily check never looks up
  (`ALLOWED_SUFFIXES` and `syslog/allow.txt`), and `github.com`, `raw.githubusercontent.com`
  (where the gateway pulls this feed from), `api.telegram.org`, `api.anthropic.com` and
  `www.virustotal.com`, or a domain that covers one of those (`telegram.org`): the same rule as
  the lint's, so a value taken here is never one the lint then refuses to commit. There is no
  override and no `/remove`: for such a value, or to take a
  row out, edit the CSV on the Mac.
- **`/who <indicator>`** says who is behind an indicator and what it did here: the facts and the
  note described under "Alerts" below.
- **`/sources [YYYY-MM-DD]`** sends that day's probing sources as a text file, busiest first,
  each with its count and `(in feed)` when the feed has it. The default is yesterday.
- **`/status`** answers in five lines:
  ```
  receiver: writing
  last daily check: 2026-10-28 07:30 done, 45 lookups
  next re-check 2026-12-18
  bot: up since 2026-10-28 09:12
  last error: none
  ```
  The receiver line says `no capture for N minutes` once today's capture has not been written
  for two minutes, and `no capture today` before the first line arrives. The last daily check is
  `running`, `done, N lookups` or `failed: <the error>`, read from the last 64 KB of the daily
  check's log. The last error is the latest one the bot logged, with its time.
- **`/help`** prints the list. So does any command the bot does not know; a message with no
  indicator in it gets the list after `No indicator in that message.`

What to expect of an addition:

- At most 50 indicators are taken from one message; the rest are reported as `N not checked,
  send them again`.
- Lookups on the free key are 15 seconds apart, so a full message of 50 takes about 13 minutes.
  The bot says how long before it starts, answers nothing else until it is done (messages sent
  meanwhile wait their turn; alerts keep coming, the watcher has a thread of its own), and holds
  the feed lock the whole time.
- The label becomes `<label> - sent from Telegram` in the row's COMMENT, ahead of the
  VirusTotal note (`sent from Telegram` alone without a label). The commit holds
  `spark-ioc-feed.csv` only and reads `Add N indicator(s) sent from Telegram: <label>`.
- The bot pulls before it writes. If the pull fails nothing is added and the reply says so.
- If the daily check holds the feed lock (from before its pull until right after its push), the
  bot waits 60 seconds for it, then replies
  `The daily check has been writing the feed for N minute(s); send the indicators again later.`
  and adds nothing. The daily check, for its part, waits up to twenty minutes for the bot.
- If a check is interrupted (a refused key, a network error) the reply says `stopped: <why>`;
  the rows added so far are kept and committed.
- The bot commits whatever the feed holds that git has not committed, and the count in the
  commit message is the rows git says were added. Rows a check killed before its commit left
  behind (a restart, say) therefore go out with the next addition, under the bot's message,
  never under the daily check's.
- If the push fails the reply says `Committed, but the push failed (...); the daily check will
  push it.` The commit stays local and the next daily check pushes it.

### Alerts

Two things alert, each as one message:

- **A LAN device reached something in the feed**, by its name or by its address:
  ```
  13:05:17 — 192.168.1.50 tried to reach c2.example.net (MuddyWater - VT 9/94 malicious 2026-10-01) — drop; 1× today
  ```
  That is the time, the device, the feed member with its row's COMMENT, what the gateway did
  with the connection (`drop`, `accept`, ...), and how many times that device has reached that
  indicator today.
- **Threat Prevention acted** (Anti-Malware, Anti-Virus, Anti-Bot, IPS or SmartDefense, Threat
  Emulation):
  ```
  10:02:11 — Threat Prevention: Anti-Bot Trojan.Win32.Agent.C2 from 192.168.1.50 to 203.0.113.70 — prevent
  ```
  A Threat Prevention row alerts only when its Action, whatever its case, is `prevent`, `drop`,
  `reject`, `block` or `detect`, and one of its two addresses is public. A blank Action,
  `monitor`, `accept`, `inspect` and any other, and rows between two LAN addresses, are counted
  in the morning brief and raise no alert. Text from the capture (the protection, the action,
  the services, a source or destination that is not an address) reaches an alert or a note on
  one line of at most 100 characters, without control, bidi or zero-width characters. The
  Spark's system log lines never alert.

The same pair alerts at most once an hour (a detection's pair is its source, destination and
protection). At most ten alerts go out in any ten minutes. The first one over that is replaced
by `Alert cap reached: further alerts in the next 10 minutes are counted, not sent`, and when
those ten minutes are over one message says `N alerts suppressed between HH:MM and HH:MM:` and
lists what they were, one `<device> → <indicator>, <action>` a line, ten at most, then `… and M
more`: the brief does not count every one of them (a feed hit logged only as a firewall row is
in it nowhere).

The watcher saves its place in today's capture after each pass (`syslog/watcher-offset.json`).
After a restart on the same day it counts the lines up to that place without alerting and alerts
the ones written while it was down, each starting with `late: `, without a note, under the same
cap: a same-day restart repeats no alert and silences none. After a restart on another day, or
with no saved place for today's file, what the capture already holds is counted without alerts.

The attacker note is a second message. It follows a feed alert (on the indicator), an inbound
detection (on its source) and an outbound Anti-Bot, Anti-Virus, Anti-Malware or Threat
Emulation detection (on its destination: the host name the row names, else the address); an
outbound IPS or SmartDefense detection gets none, and neither does a late alert. It starts with
the facts: what the capture holds about the indicator, then one line per public service
(VirusTotal; for an IP also RDAP, Shodan InternetDB and, with a key, GreyNoise; for a domain
also RDAP). Then comes a note from Claude Opus 5.5, which may search the web, on who the
attacker is, what it did here, whether it is aimed at this network or scanning everything, and
what to do: at most eight lines and 1,200 characters, ending in `(note cut short)` when the
model ran out of room. A service that cannot be asked shows as `unavailable`; if the model
cannot be asked, the facts arrive alone with a line saying why. Notes are capped too: at most
six an hour, thirty a day, and one per indicator a day; an alert whose note is over a cap goes
out alone. They are written in a thread of their own, ten at most waiting (one more is dropped
and logged), so no alert waits for a note, and the alerts of one moment still go out before
their notes. Each note logs `note usage: input=N output=N searches=N seconds=N` (tokens, web
searches, time) in the bot's log, and the brief's notes in the daily check's log, so the cost
is measured rather than guessed.

### The morning brief

`daily_check.sh` sends it as its last step, after the push and even when the check stopped early,
so it reports what that run did; a run that fails after its check sends it with the failure among
its errors, and one that fails before sends `Daily check failed: <reason>` instead. It is one
message about the previous day, with these sections (a section with nothing in it is left out):

- the title and a totals line: probes dropped and from how many sources, Threat Prevention
  detections, sources sent to block, outbound hits;
- `SENT TO BLOCK`: the sources the run added, with their VirusTotal ratio and how often they
  probed;
- `OUTBOUND HIT`: LAN devices that reached a flagged destination;
- `THREAT PREVENTION`: the detections counted per blade;
- `TOP PROBING SOURCES`: the ten busiest, with `(in feed)` where the feed has them, and how many
  more there were;
- `INDICATORS ENTERED`: rows added since the last brief, from the Spark's logs, from news, by
  hand (Telegram or `--trusted`), and other;
- `ERRORS`: `no syslog capture for <day>` first when the receiver wrote nothing that day, then
  the run's error lines, five at most, then a count;
- `System log: N lines` when the Spark forwarded system logs that day;
- a last line: lookups used of 500, the next re-check date, and the error count.

Each source sent to block then gets its attacker note as a message of its own. When there is no
bot token or chat id in the Keychain the brief is printed in the daily check's log instead
(`~/Library/Logs/spark-ioc-feed/daily-check.log`). `syslog/last-brief.json` records the feed
commit a delivered brief covered, so the next one counts the rows committed since and none
twice. `python3 spark_brief.py` prints yesterday's brief by hand (`--date YYYY-MM-DD` for another
day).

### Quotas

The free VirusTotal key allows 500 lookups a day and 4 a minute. The daily check spends up to
400 of the day's 500 (`MAX_LOOKUPS` lowers that) and the 06:30 news check up to 40
(`MAX_CANDIDATES`, "News agent" below); your checks through the bot (one lookup per
indicator), each `/who` and each attacker note (one lookup each) share the remaining 60. While
a check is writing the feed (`syslog/.feed-lock` exists: the daily check until its push, the news
check from before its pull until its push, or the bot's own check), notes and `/who` do not ask
VirusTotal, so they cannot push a check over the
4 a minute; their facts then say `VirusTotal: skipped (a feed check is running)`. The daily check
gives the lock back before its brief, so the brief's notes do ask it. A lookup that still meets a
429 waits 61 seconds and tries once more; a second 429 is the quota stop: the check keeps the rows
it added and lists the indicators it did not check, to be sent again. Nothing else the bot asks of
the public services is retried: a service that does not answer shows as `unavailable`, and a 404 is
read as its answer (`no record`, or for GreyNoise `GreyNoise: no record (not observed scanning)`).

### Limits

- Two full messages of 50 indicators sent back to back around 07:30 can hold the feed lock for
  about 26 minutes, longer than the twenty the daily check waits: that morning's run then fails
  and sends its notice. Send large batches at another time of day.
- A bot killed in the middle of a check (`kill -9`, a power cut) leaves `syslog/.feed-lock`
  behind. Until it is three hours old and taken over, the bot answers additions with "The daily
  check has been writing the feed for N minutes" and a daily check in that window waits and
  fails. `rmdir syslog/.feed-lock` clears it by hand.
- An alert Telegram refuses (an outage, a rate limit) is logged in the bot's log and not sent
  again; the morning brief's counts still include the event.

### Rotating the logs

The scripts never rotate `~/Library/Logs/spark-ioc-feed/*.log`. macOS's `newsyslog` can: install
this entry once, with your user name for `<you>` (it rotates a log past 10 MB, keeping five):

```
sudo tee /etc/newsyslog.d/spark-ioc-feed.conf <<'EOF'
# logfilename                                    [owner:group]  mode count size(KB) when flags
/Users/<you>/Library/Logs/spark-ioc-feed/*.log   <you>:staff    644  5     10240    *    GN
EOF
```

The daily check's log is opened afresh by every run. The receiver and the bot keep theirs open
through launchd, so after a rotation they go on writing to the renamed file until they next
start: restart them then (`launchctl kickstart -k gui/$(id -u)/com.spark-ioc-feed.telegram`,
and the same with `com.spark-ioc-feed.syslog`). The entry leaves the rotated files uncompressed
for that reason.

## News agent: indicators from the week's public reporting

`news_agent.py` asks Claude (Opus 5.5 with web search and web fetch, one call) which network
indicators the last seven days of public security reporting name, keeps the home-relevant ones,
and lets VirusTotal decide; `news_check.sh` does that every morning at 06:30 through
`launchd/com.spark-ioc-feed.news.plist` and commits what VirusTotal confirms. The design and the
reasons are in `docs/system-design.md`, D7.

Home-relevant, to the agent: consumer phishing (banks, parcel and tax portals, streaming
services, marketplaces), the delivery and command-and-control of commodity malware that runs on
home devices (info-stealers, Android banking trojans, router and camera botnets), fake installers
and updates, scam and tech-support domains. Not: enterprise-only and state-actor infrastructure,
file hashes (the gateway blocks by network indicator), abused legitimate services, victims'
names, anything reported more than seven days ago.

The model names candidates; this repository's code decides what reaches VirusTotal; VirusTotal
decides what reaches the feed:

- `vt_check.classify` keeps IPs, domains and URLs (defanged forms accepted) and drops hashes and
  anything else.
- Out go names under the vendor suffixes (`spark_logs.ALLOWED_SUFFIXES` and `syslog/allow.txt`),
  the bare apexes of shared platforms (`netlify.app`, `pages.dev`, …), the hosts this system
  needs (the `feed_lint.py` list), private and reserved addresses, candidates with no report date
  or one more than seven days old, duplicates, values already in the feed, names and URL hosts
  that are private (`router.lan`, `nas.local`, `http://192.168.1.1/…`), and anything
  `syslog/checked.json` (the daily check's cache) or
  `syslog/news-checked.json` (this job's) shows looked up within the last three days.
- At most 40 are kept, newest report first, and written to `syslog/news-<date>.txt` as
  `indicator<TAB>label`, the `vt_check.py -f` format, so you can run them by hand. The label is
  `News <report date> <theme>`: the theme is a few words from the model reduced to plain words
  (letters, digits, hyphens, apostrophes) and cut at 60 characters; a host, URL, date or the
  outlet's name never survives, and a theme that reads like one of the feed's own notes is
  dropped whole. The source URLs are printed in the run log only, so no feed row names a
  publication.
- `python3 news_agent.py --check syslog/news-<date>.txt` looks them up exactly as `vt_check.py -f`
  would (3 engines for a domain or URL, 5 for an IP) and records every verdict in
  `syslog/news-checked.json`, so the following days skip them. It never writes the daily check's
  `syslog/checked.json`: a clean verdict there would keep the daily check from looking that
  destination up for thirty days, and a reported indicator is often clean on VirusTotal the first
  day and flagged a week later. With `--dry-run` nothing is recorded or written.

Setting it up, once:

1. Both keys in the login Keychain: `VT_API_KEY` ("Daily check on this Mac" above) and
   `ANTHROPIC_API_KEY` ("Setting it up" under Telegram, step 5).
2. A dry run by hand, which reads the week's reporting, looks the candidates up and commits and
   pushes nothing (the feed and the caches are left as they were):
   ```
   DRY_RUN=1 bash news_check.sh
   ```
3. Install the agent (edit the two paths in the plist first if the repository lives elsewhere).
   It runs through the same `Python.app` as the other agents, so the Full Disk Access grant
   covers it:
   ```
   cp launchd/com.spark-ioc-feed.news.plist ~/Library/LaunchAgents/
   launchctl load ~/Library/LaunchAgents/com.spark-ioc-feed.news.plist
   launchctl start com.spark-ioc-feed.news      # run it now instead of waiting for 06:30
   ```

What a run does:

- The model call runs first and outside the feed lock, so the bot is not held up while Claude
  reads. Then the lock is taken under the daily check's rules (wait up to twenty minutes, take
  over a lock older than three hours), `git pull`, `feed_lint.py`, the lookups, `feed_lint.py`
  again, a commit of `spark-ioc-feed.csv` only, `Add N indicators from news <date>`, a push, and
  the lock is given back. A day with no candidates takes no lock and ends.
- It sends no brief: the 07:30 daily check's brief counts its rows as `from news`.
- Everything is logged to `~/Library/Logs/spark-ioc-feed/news-check.log`: the agent's one
  `news usage: input=N output=N searches=N fetches=N seconds=N` line (what the call cost; the
  design budgets about $0.80 a run, $25 a month), `N candidates for VirusTotal from M named
  (dropped: 2 vendor domain, 1 older than 7 days, …)` with one line per candidate and its
  source, then the lookups as `vt_check.py` prints them, `News check: 2 added, 3 clean`,
  `Committed: …`, `Pushed to origin/main`, `News check done`.
- A run that fails sends one Telegram line, `News check failed: <reason>` (printed in the log
  without a bot token), raises a macOS notification and exits 1. The reasons: no
  `ANTHROPIC_API_KEY` in the Keychain; the model call failed (an error after one retry, a
  refusal, a reply cut short or without the candidates list; the log has the detail); the feed on
  main fails its lint (fix `spark-ioc-feed.csv`, nothing was looked up); no `VT_API_KEY`; the
  VirusTotal quota reached, or VirusTotal refused the key or some lookups failed (in each case
  the rows done so far are committed and pushed first; the rest are candidates again the next
  morning while a report still names them); the feed locked for over twenty minutes; a pull or
  push that failed (the commit stays local and the next run pushes it).
- By hand: `MAX_CANDIDATES=10 bash news_check.sh` lowers the cap for the day;
  `python3 news_agent.py` alone writes today's candidates file and prints them, their labels and
  sources, without a lookup; `python3 news_agent.py --check syslog/news-<date>.txt --dry-run`
  previews the lookups.

## Keeping the feed fresh

Attacker infrastructure rotates: command-and-control servers are re-leased within weeks,
so a static blocklist slowly fills with addresses that VirusTotal no longer flags and that
may by now serve legitimate traffic. `--recheck` re-verifies the rows the script added:

```
python3 vt_check.py --recheck --dry-run      # list what would change, write nothing
python3 vt_check.py --recheck                # IPs checked 60+ days ago, domains and URLs 180+, unchecked rows 90+
python3 vt_check.py --recheck --max-age 30   # every type, 30+ days ago (0 = every row)
python3 feed_lint.py && git commit -am "Re-verify stale indicators" && git push
```

- Rows are looked up one every 15 s, and only once due for their TYPE, read from the dates
  in COMMENT: IPs 60 days after their `VT n/m malicious YYYY-MM-DD` note (attacker servers
  are re-leased within weeks), domains and URLs 180 (domains drop and get re-registered on a
  scale of months), rows `added without VirusTotal check YYYY-MM-DD` 90 days after that,
  hashes never (a malicious file stays malicious, so a hash can never block something
  legitimate). An IP carrying `seen in Spark logs YYYY-MM-DD`, which the daily check writes
  for every feed IP that probed the WAN, is in addition never due before 180 days after that
  sighting: a probe of this network is first-hand evidence, and VirusTotal's count for a
  scanner decays while the scanning goes on. `--max-age DAYS` applies DAYS to every row's own
  date, hashes included. Rows with no date at all (hand-written ones) are never touched.
- Rows still flagged by enough engines (3, or 5 for IPs, unless `--min-malicious` says
  otherwise) get a fresh ratio, date and CONFIDENCE in place; rows that fell below are
  removed.
- The header line, the order of the rows and every other row stay exactly as they are.
- The file is rewritten after every change, so if the daily quota runs out (or you press
  Ctrl-C) it is left consistent. Refreshed rows carry today's date and are skipped next time,
  so running the command again the next day resumes where it stopped.

### Monthly re-check on GitHub Actions

`.github/workflows/recheck.yml` runs `--recheck` on the 1st of every month (or on demand
from the Actions tab, optionally with a `--max-age` override) and commits the result. It does nothing until
the repository has a `VT_API_KEY` secret: Settings → Secrets and variables → Actions →
New repository secret. A full run takes about 15 s per stale row, within the free key's
500 lookups a day; if it stops early the rows done so far are still committed and the job
is marked failed so GitHub notifies you. Note that GitHub pauses scheduled workflows in
repositories with no activity for 60 days.

Tests: `python3 -m unittest`
