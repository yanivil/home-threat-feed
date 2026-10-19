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

- **Added** when at least `--min-malicious` engines (default 3) flag it.
- **CONFIDENCE** follows the detection count: 10+ high, 5–9 medium, below 5 low. Whether
  low/medium-confidence indicators are blocked or only logged depends on the gateway's
  Threat Prevention policy. SEVERITY is always high.
- **Skipped without a lookup**: values already in the feed, duplicates, IP ranges, private
  IPs, URLs containing commas.
- **Rate limit**: the free API allows 4 lookups/min and 500/day, so the script waits 15 s
  between lookups (`--delay`). If the daily quota runs out it stops, keeps what it already
  added, and lists the indicators still to check.

Tests: `python3 -m unittest`
