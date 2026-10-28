# Changelog

All notable changes to this feed are recorded here.

## [Unreleased]

### Added
- Two internet-wide scanner networks observed sweeping the WAN IP on 2026-10-19/20:
  Colocatel "ColocationX" (109.205.211.0/24) and Modat B.V. (212.73.148.0/24),
  as `IP Range` indicators plus the individual hosts seen in the Spark logs.
- This changelog.
- A Telegram bot (`telegram_bot.py`, `capture_watcher.py`, LaunchAgent
  `com.spark-ioc-feed.telegram`): live alerts from the Spark's capture with attacker-context
  notes, the morning brief sent by the daily check, and indicators sent from the phone checked
  on VirusTotal and added. Only the owner's private chat is served, and values the gateway must
  never block (GitHub, Telegram, Anthropic, VirusTotal and the vendor list) are refused. See the
  README, "Telegram", and `docs/system-design.md`, D6.

### Changed
- `syslog_receiver.py` keeps only the gateway's datagrams (`--source`, by default the default
  route's gateway) and writes one capture line per datagram.
- The Spark's system log lines, now forwarded with the security logs, are recognised and never
  read as traffic.
- Live alerts: explicit Threat Prevention actions only, at most ten in ten minutes, notes capped
  and written in a thread of their own; a same-day restart alerts what it missed as `late:`.
- The daily check gives the feed lock back right after its push and always ends with one
  Telegram message (`Daily check failed: <reason>` when it fails before its check).
- VirusTotal: a 429 is tried once more after 61 s, and notes and `/who` skip VirusTotal while a
  feed check runs.

## [1.0.0] - 2026-10-19

### Added
- Initial feed with two test indicators (`example.com` domain, EICAR MD5).
- README with feed URL, column reference and editing rules.
