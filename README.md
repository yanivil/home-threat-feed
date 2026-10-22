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

## Mining the gateway's own logs

The Spark cannot export its security logs, but it can send them as syslog. Two scripts turn
that stream into checked indicators:

1. **`syslog_receiver.py`** listens on UDP 5514 and writes one entry per line to
   `syslog/spark-YYYY-MM-DD.log` (git-ignored), re-joining the entries the gateway splits over
   several datagrams. On the Spark: Logs & Monitoring → External Log Servers → Syslog
   Servers → Configure: UDP, the Mac's LAN address, port 5514, Security logs. Give that Mac a
   DHCP reservation (Users and Objects → Network Objects → Single IP → "Reserve IP address in
   DHCP service for MAC"). `launchd/com.spark-ioc-feed.syslog.plist` keeps the receiver
   running across reboots; the install steps are in its comment.
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

- Everything a run prints goes to `/tmp/spark-daily-check.log`, with a timestamped line for
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

## Keeping the feed fresh

Attacker infrastructure rotates: command-and-control servers are re-leased within weeks,
so a static blocklist slowly fills with addresses that VirusTotal no longer flags and that
may by now serve legitimate traffic. `--recheck` re-verifies the rows the script added:

```
python3 vt_check.py --recheck --dry-run      # list what would change, write nothing
python3 vt_check.py --recheck                # IPs checked 60+ days ago, domains and URLs 180+
python3 vt_check.py --recheck --max-age 30   # every type, 30+ days ago (0 = every row)
git commit -am "Re-verify stale indicators" && git push
```

- Only rows whose COMMENT ends in `VT n/m malicious YYYY-MM-DD` (the note the script
  writes) are looked up, one every 15 s, and only once old enough for their TYPE: IPs after
  60 days (attacker servers are re-leased within weeks), domains and URLs after 180 (domains
  drop and get re-registered on a scale of months), hashes never (a malicious file stays
  malicious, so a hash can never block something legitimate). `--max-age DAYS` applies DAYS
  to every type, hashes included. Hand-written rows are never touched.
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
