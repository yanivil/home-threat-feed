# spark-ioc-feed

Custom Indicators of Compromise (IoC) feed for a Check Point Quantum Spark gateway
(locally managed, Threat Prevention → IoC Feeds).

## Feed URL

```
https://raw.githubusercontent.com/yanivil/spark-ioc-feed/main/spark-ioc-feed.csv
```

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
and a VirusTotal API key in the `VT_API_KEY` environment variable. Never commit the key —
this repository is public.

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
