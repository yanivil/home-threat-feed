# spark-ioc-feed

Custom Indicators of Compromise (IoC) feed for a Check Point Quantum Spark gateway
(locally managed, Threat Prevention → IoC Feeds).

## Feed URL

```
https://raw.githubusercontent.com/yanivil/spark-ioc-feed/main/spark-ioc-feed.csv
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
| CONFIDENCE | low / medium / high / critical (optional, default high) |
| SEVERITY   | low / medium / high / critical (optional, default high) |
| PRODUCT    | AB for IP/Domain/URL, AV for hashes (optional, default AV) |
| COMMENT    | free text (optional) |

The gateway re-fetches the file every 30 minutes (configurable under IoC Feeds → Settings).

## Adding an indicator

Edit `spark-ioc-feed.csv` in the GitHub web editor, add one line per indicator, commit.
No spaces around commas. Do not put commas inside the COMMENT field.

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
git commit -am "Add VirusTotal-confirmed indicators" && git push
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
spreadsheets into that list, labelling each row with the group and export date, and drops what a
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
   several datagrams. On the Spark: Logs & Monitoring → External Log Servers → Syslog
   Servers → Configure: UDP, the Mac's LAN address, port 5514, Security logs. Give that Mac a
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

Lookups are the scarce resource (the free key allows 500 a day), so a run spends them where
an infected device would show, in this order:

- **Outbound names first.** Every host name a LAN device reached, busiest first, except
  hosts under the well-known vendor domains listed in `ALLOWED_SUFFIXES` at the top of the
  script (`apple.com`, `googleapis.com`, `office.com`, `akamaiedge.net`, `whatsapp.net`, ...),
  matched by suffix. `syslog/allow.txt` (one suffix per line, `#` comments, git-ignored like
  the rest of that folder) extends the list for the vendors your own devices talk to.
- **Then outbound addresses** that carried no name and were reached at least `--min-ip-hits`
  times (3). A command-and-control server reached by address recurs; a CDN edge is seen once
  and never again.
- **Then inbound sources**, but only those that probed at least `--min-inbound-hits` times
  (5: persistent probing, not one-off background noise), at most `--max-inbound` (20) a run.
  Adding every scanner that knocked once would grow the feed by a hundred rows a day of no
  value, while the outbound names that matter waited.

Indicators already in the feed, or looked up within `--recheck-days` (30; `syslog/checked.json`
remembers them), are skipped, and `--max-lookups` (default 400, under two hours at 15 s each)
caps a run; what does not fit is left for another day. Without `--check` the script lists the
three groups in that order, with counts, so you can see what a run will do before it spends
anything. The daily check below runs it for you and pushes what it adds.

### Daily check on this Mac

`daily_check.sh` does the whole round once: `git pull`, then `spark_logs.py --days 2 --check`
with the script's own defaults, then a commit of `spark-ioc-feed.csv` (and nothing else) and a
push when rows were added. `launchd/com.spark-ioc-feed.daily.plist` runs it every morning at
07:30 local time.

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
   then ⌘⇧G and the path in the plist's `ProgramArguments`). Both plists run their job through
   that binary because macOS denies `/usr/bin/python3` and `/bin/bash` on external volumes
   without prompting; `docs/system-design.md`, decision D1, has the details.

- Everything a run prints goes to `~/Library/Logs/spark-ioc-feed/daily-check.log`, with a timestamped line for
  each step. **Outbound hits are only reported there**, as
  `OUTBOUND HIT <destination> (<ratio>) reached by <devices>`, and raise a macOS notification
  titled "Spark IoC feed" (allow notifications from Script Editor if macOS asks the first time).
  Nothing else records them, so glance at the log now and then.
- Two days of capture are read because at 07:30 today's file holds only a few hours;
  `syslog/checked.json` keeps yesterday's indicators from being looked up twice. The default
  400 lookups take under two hours, fine for a morning job, and leave 100 of the free key's
  500 a day for manual runs.
- The pull first brings in rows committed elsewhere (the GitHub web editor, the monthly
  re-check on Actions). A pull or push that fails is logged as `ERROR` with a notification,
  the run exits non-zero, and a commit that could not be pushed stays local until the next run
  pushes it. A run missed while the Mac slept happens on wake; one missed while it was off is
  skipped.
- By hand with other settings: `DAYS=3 MAX_LOOKUPS=50 bash daily_check.sh`.

## Telegram: alerts, the morning brief and sending indicators

`telegram_bot.py` is the part of the system you talk to from your phone. It follows today's
capture and messages you within a minute or two when a LAN device reaches something in the
feed, or when the gateway's Threat Prevention enforces something against a public address;
every morning the daily check sends you a brief of the previous day through the same bot; and
indicators you send it are checked on VirusTotal, and the flagged ones added to the feed,
committed and pushed. Only your own chat is served: a message from any other chat is ignored
(and logged, once a day per chat). The bot runs on this Mac as the LaunchAgent
`com.spark-ioc-feed.telegram` and logs to `~/Library/Logs/spark-ioc-feed/telegram-bot.log`.
`docs/system-design.md`, decision D6, has the design.

### Setting it up

The bot's token and your chat id live in the login Keychain under the service `spark-ioc-feed`,
like the VirusTotal key; nothing about the bot is stored in the repository. This is your
checklist, once:

1. Create the bot. In Telegram open BotFather, send `/newbot` and answer its questions; it
   replies with the bot's token. Store it:
   ```
   security add-generic-password -s spark-ioc-feed -a TELEGRAM_BOT_TOKEN -w '<token>' -U
   ```
2. Pair your chat. Send the bot any message from your Telegram account, then run
   ```
   python3 telegram_bot.py --pair
   ```
   It waits up to 50 seconds for a message, then prints your chat id and the command that
   stores it, which looks like
   ```
   security add-generic-password -s spark-ioc-feed -a TELEGRAM_CHAT_ID -w '<chat id>' -U
   ```
   Run that command. Without the chat id the bot serves nobody.
3. Install the agent (edit the paths in the plist first if the repository or your home
   directory lives elsewhere). It runs through the same `Python.app` as the other two agents,
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
5. The notes also need an Anthropic API key in the Keychain item `ANTHROPIC_API_KEY`, which is
   already stored on this Mac. Without it a note is the facts followed by
   `(context note unavailable: no ANTHROPIC_API_KEY in the Keychain)`.

Then check it end to end, and tick each line:

- [ ] `launchctl list | grep telegram` shows a process id next to `com.spark-ioc-feed.telegram`.
- [ ] `/status` and `/help` both answer in Telegram.
- [ ] Send one test indicator that VirusTotal flags (a domain that 3 engines flag, or an IP that
  5 do) with a label, for example `<indicator> bot test`. The bot replies that it is checking,
  then `<indicator>: added (...)` and `Committed and pushed.`; `git log -1` shows
  `Add 1 indicator sent from Telegram: bot test`, and the commit is on GitHub.
- [ ] Append a crafted line to today's capture for a LAN device reaching that indicator (this
  one is for a domain; for an IP put it in `dst` instead of using `destination_domain_name`).
  Within a minute an alert arrives, and after it the attacker note:
  ```
  printf '%s Action="drop" inzone="Internal" outzone="External" service_id="HTTPS" src="10.45.60.50" dst="104.18.32.47" proto="6" destination_domain_name="<the test domain>" ProductName="VPN-1 & FireWall-1"\n' "$(date +%Y-%m-%dT%H:%M:%S)" >> syslog/spark-$(date +%F).log
  ```
- [ ] `/sources` sends yesterday's probing sources as a text file (or says there are none).
- [ ] `launchctl start com.spark-ioc-feed.daily` and the brief arrives when the run ends. Do the
  steps above first: while the daily check runs it holds the feed lock and the bot will not add
  indicators.
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
  flag it (the thresholds under "Adding indicators checked on VirusTotal"); the first word that
  is not one starts the label, and commas in the label become spaces. The reply has one line per
  indicator, a count, and what happened to the commit:
  ```
  Checking 2 indicators on VirusTotal, about 1 minute.
  evil.com: added (Domain 11/94 malicious)
  harmless.example: clean (Domain 0/94 malicious)
  1 added, 1 clean, 0 unknown to VirusTotal, 0 already in the feed
  Committed and pushed.
  ```
  An indicator can also come back `in-feed`, `duplicate`, `not-found (VirusTotal has no
  record)`, `invalid (...)`, `error (...)`, `quota (...)` or `unchecked`. With nothing added
  the last line is `Nothing added, nothing committed.`
- **`/trust <indicators> [label]`** adds them without a VirusTotal check, as
  `vt_check.py --trusted` does: the rows carry `added without VirusTotal check <date>` and join
  the 90-day first check under "Keeping the feed fresh". There is no wait, so the reply comes
  in seconds.
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
  `running`, `done, N lookups` or `failed: <the error>`. The last error is the latest one the
  bot logged, with its time.
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
- If the daily check holds the feed lock, the bot waits 60 seconds for it, then replies
  `The daily check has been writing the feed for N minute(s); send the indicators again later.`
  and adds nothing. The daily check, for its part, waits up to twenty minutes for the bot.
- If a check is interrupted (a refused key, a network error) the reply says `stopped: <why>`;
  the rows added so far are kept and committed.
- If the push fails the reply says `Committed, but the push failed (...); the daily check will
  push it.` The commit stays local and the next daily check pushes it.

### Alerts

Two things alert, each as one message:

- **A LAN device reached something in the feed**, by its name or by its address:
  ```
  13:05:17 — 10.45.60.50 tried to reach c2.example.net (MuddyWater - VT 9/94 malicious 2026-10-01) — drop; 1× today
  ```
  That is the time, the device, the feed member with its row's COMMENT, what the gateway did
  with the connection (`drop`, `accept`, ...), and how many times that device has reached that
  indicator today.
- **Threat Prevention enforced something** (Anti-Malware, Anti-Virus, Anti-Bot, IPS or
  SmartDefense, Threat Emulation):
  ```
  10:02:11 — Threat Prevention: SmartDefense Header Spoofing from 31.14.32.6 to 10.45.60.50 — drop
  ```
  A detection alerts only when the gateway's action is not `monitor` (monitor mode enforces
  nothing) and one of its two addresses is public. Monitor-mode detections and detections
  between two LAN addresses appear in the morning brief's count and nowhere else.

The same pair alerts at most once an hour (a detection's pair is its source, destination and
protection). After a restart the bot reads what today's capture already holds and counts it
without sending alerts, so a restart repeats none and silences none.

A feed alert, and a detection whose source is the public address (an attack coming in), is
followed by a second message, the attacker note. It starts with the facts: what the capture
holds about the indicator, then one line per public service (VirusTotal; for an IP also RDAP,
Shodan InternetDB and, with a key, GreyNoise; for a domain also RDAP). Then comes a note of at
most eight lines from Claude Opus 5.5, which may search the web, on who the attacker is, what
it did here, whether it is aimed at this network or scanning everything, and what to do. A
detection where a LAN device is the source gets no note. A service that cannot be asked shows as
`unavailable`; if the model cannot be asked, the facts arrive alone with a line saying why. All
the alerts of one moment go out before their notes, which take tens of seconds each.

### The morning brief

`daily_check.sh` sends it as its last step, after the push and even when the check stopped early,
so it reports what that run did. It is one message about the previous day, with these sections
(a section with nothing in it is left out):

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
- `ERRORS`: the first five error lines of the run, then a count;
- a last line: lookups used of 500, the next re-check date, and the error count.

Each source sent to block then gets its attacker note as a message of its own. When there is no
bot token or chat id in the Keychain the brief is printed in the daily check's log instead
(`~/Library/Logs/spark-ioc-feed/daily-check.log`). `syslog/last-brief.json` records the feed
commit a delivered brief covered, so the next one counts the rows committed since and none
twice. `python3 spark_brief.py` prints yesterday's brief by hand (`--date YYYY-MM-DD` for another
day).

### Quotas

The free VirusTotal key allows 500 lookups a day and 4 a minute. The daily check spends up to
400 of the day's 500 (`MAX_LOOKUPS` lowers that); your checks through the bot (one lookup per
indicator), each `/who` and each attacker note (one lookup each) share the remaining 100. A
note's lookup made while a check is running can exceed the 4 a minute; the check then stops,
keeps the rows it added and lists the indicators it did not check, and you send those again.
Nothing the bot asks of the public services is retried: a service that does not answer shows as
`unavailable`, and a 404 is read as its answer (`no record`, or for GreyNoise `not observed
scanning`).

## Keeping the feed fresh

Attacker infrastructure rotates: command-and-control servers are re-leased within weeks,
so a static blocklist slowly fills with addresses that VirusTotal no longer flags and that
may by now serve legitimate traffic. `--recheck` re-verifies the rows the script added:

```
python3 vt_check.py --recheck --dry-run      # list what would change, write nothing
python3 vt_check.py --recheck                # IPs checked 60+ days ago, domains and URLs 180+, unchecked rows 90+
python3 vt_check.py --recheck --max-age 30   # every type, 30+ days ago (0 = every row)
git commit -am "Re-verify stale indicators" && git push
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
