# Telegram Bot, Alerts and Daily Brief (D6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Telegram bot on the home-server iMac that sends the morning brief and live alerts, takes indicators to add, and explains each attacker with a note written by Claude Opus 5.5.

**Architecture:** One always-on LaunchAgent (`telegram_bot.py`) long-polls Telegram in one thread and tails today's capture in another; `daily_check.sh` composes and sends the brief at the end of its run through `spark_brief.py`; `attacker_context.py` gathers facts from public services and asks Opus 5.5 over HTTPS; a directory lock keeps the bot and the daily job from writing the feed at once. Every piece reuses `vt_check` (lookups, trusted rows, Keychain) and `spark_logs` (capture parsing, feed membership).

**Tech Stack:** Python 3.9 standard library only (`urllib`, `json`, `threading`, `gzip`); Telegram Bot API over HTTPS; Anthropic Messages API over HTTPS (`claude-opus-5-5`, `web_search_20260209`); macOS launchd and login Keychain; `unittest`.

**Spec:** `docs/system-design.md`, decision D6 (and D5 for the re-check clock the brief reports).

## Global Constraints

- Python 3.9.6 (`/usr/bin/python3`); no third-party packages; every new module runs with `python3 -I`.
- Tests: `python3 -m unittest`, no network, no real Keychain: subprocess tests put `tests/stubs` first on `PATH` (its `security` finds nothing) and pass fakes for HTTP.
- Secrets only in the login Keychain, service `spark-ioc-feed`, accounts `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `ANTHROPIC_API_KEY`, `GREYNOISE_API_KEY` (optional); never in the repository or in logs.
- Only the owner's chat id is served; every other sender is ignored.
- Telegram messages are plain text (no `parse_mode`), at most 4096 characters each; longer text is split at line boundaries.
- A LaunchAgent's program is `/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/Current/Resources/Python.app/Contents/MacOS/Python` (D1); logs under `/Users/home-server/Library/Logs/spark-ioc-feed/`.
- The feed is committed alone (`spark-ioc-feed.csv`), after `git pull --rebase --autostash`, under the lock `syslog/.feed-lock`.
- Attacker-context model: `claude-opus-5-5`; `output_config: {"effort": "medium"}`; `tools: [{"type": "web_search_20260209", "name": "web_search", "max_uses": 3}]`; `fallbacks: "default"` with header `anthropic-beta: server-side-fallback-2026-07-01`; `anthropic-version: 2023-06-01`; no `thinking` field; `max_tokens: 1500`.
- Commit messages end with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.

## Review Focus

1. A message pasting hundreds of indicators: the bot must check at most 50 per message, reply which it left out, and never block the command loop for an hour — pinned by `test_at_most_fifty_indicators_per_message` (Task 6).
2. The receiver's file for today does not exist yet when the bot starts (receiver down, or just after midnight): the watcher must wait and attach when it appears, not crash — `test_watcher_waits_for_a_missing_capture` (Task 6).
3. A restart of the bot must not replay old messages and add the same indicators twice: the last `update_id` is persisted in `syslog/telegram-offset.json` — `test_offset_survives_a_restart` (Task 6).
4. Labels or indicators carrying quotes, newlines or shell characters reach `git commit -m`: the message is built from a cleaned label and passed as an argument list, never a shell string — `test_commit_message_is_safe_with_odd_labels` (Task 6).
5. Every public service in the context gather can time out at once; the note must still go out with what the capture alone says, within the alert's one-minute budget — `test_note_with_every_source_failing` (Task 5).

---

### Task 1: Keychain access shared by every secret

**Files:**
- Create: `keychain.py`
- Modify: `vt_check.py:api_key` (delegate; keep its signature and tests)
- Test: `tests/test_keychain.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `keychain.item(account, env_var=None, environ=None, run=None) -> str` — the `env_var` value from `environ` (default `os.environ`) when set and non-blank, else the Keychain item `-s spark-ioc-feed -a <account> -w` read through `run` (default `subprocess.run`, 30 s timeout), else `""`. `keychain.SERVICE = "spark-ioc-feed"`.

- [ ] **Step 1: Write the failing tests** in `tests/test_keychain.py`, reusing `keychain_with` from `tests/test_vt_check.py`:

```python
def test_environment_variable_wins_over_the_keychain(self):
    run = keychain_with("from-keychain")
    self.assertEqual(keychain.item("ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY", environ={"ANTHROPIC_API_KEY": " k1 "}, run=run), "k1")
    self.assertEqual(run.calls, [])

def test_keychain_item_is_read_with_the_service_and_account(self):
    run = keychain_with("tok")
    self.assertEqual(keychain.item("TELEGRAM_BOT_TOKEN", environ={}, run=run), "tok")
    self.assertEqual(run.calls, [["security", "find-generic-password", "-s", "spark-ioc-feed", "-a", "TELEGRAM_BOT_TOKEN", "-w"]])

def test_missing_item_and_failing_security_give_empty(self):
    self.assertEqual(keychain.item("X", environ={}, run=keychain_with(None)), "")
    self.assertEqual(keychain.item("X", environ={}, run=Mock(side_effect=OSError)), "")
```

- [ ] **Step 2: Run** `python3 -m unittest tests.test_keychain -v` — expected: ERROR, `No module named 'keychain'`.
- [ ] **Step 3: Implement `keychain.py`** with `SERVICE`, `item(...)` as specified; make `vt_check.api_key(environ=None, run=None)` return `keychain.item("VT_API_KEY", "VT_API_KEY", environ, run)` and keep `KEYCHAIN_SERVICE`/`KEYCHAIN_ACCOUNT` for the help text.
- [ ] **Step 4: Run** `python3 -m unittest` — expected: all pass, including `ApiKeyTest` unchanged.
- [ ] **Step 5: Commit:** `git add keychain.py vt_check.py tests/test_keychain.py && git commit -m "Read every secret from the login Keychain through one helper"`

### Task 2: Telegram transport

**Files:**
- Create: `telegram_api.py`
- Test: `tests/test_telegram_api.py`

**Interfaces:**
- Consumes: `keychain.item`.
- Produces: class `Telegram(token, chat_id, http=None)` where `http(url, data=None, headers=None, timeout=60) -> (status, body_dict)` defaults to a `urllib` implementation; methods `send_message(text) -> list[int]` (message ids; splits text over 4096 characters at the last newline before the limit), `send_document(filename, data: bytes, caption="") -> int` (multipart/form-data built by hand), `get_updates(offset, timeout=50) -> list[dict]` (the `result` list; raises `TelegramError` on `ok: false` or HTTP ≠ 200). Module functions `chunks(text, limit=4096) -> list[str]`, `from_keychain() -> Telegram | None` (None when the token or chat id is missing). `API = "https://api.telegram.org/bot{token}/{method}"`.

- [ ] **Step 1: Write the failing tests** with a fake `http` that records `(url, data, headers)` and returns scripted bodies:

```python
def test_send_message_posts_plain_text_to_the_owner(self):
    tg = telegram_api.Telegram("T", 42, http=self.fake({"ok": True, "result": {"message_id": 7}}))
    self.assertEqual(tg.send_message("hello"), [7])
    url, data, _ = self.fake.calls[0]
    self.assertEqual(url, "https://api.telegram.org/botT/sendMessage")
    self.assertEqual(json.loads(data), {"chat_id": 42, "text": "hello", "disable_web_page_preview": True})

def test_long_text_is_split_at_line_boundaries(self):
    lines = [f"line {i:04}" for i in range(600)]          # 5,400 characters
    parts = telegram_api.chunks("\n".join(lines))
    self.assertEqual(len(parts), 2)
    self.assertTrue(all(len(p) <= 4096 for p in parts))
    self.assertEqual("\n".join(parts).split("\n"), lines)

def test_send_document_is_multipart_with_the_file(self):
    ... assert "multipart/form-data; boundary=" in headers["Content-Type"] and b'filename="sources-2026-10-28.txt"' in data and b"1.2.3.4 12" in data

def test_get_updates_passes_offset_and_long_poll_timeout(self):
    ... url ends with "/getUpdates", json body == {"offset": 10, "timeout": 50}; returns the result list

def test_api_errors_raise(self):
    ... http returns (200, {"ok": False, "description": "Bad Request: chat not found"}) → TelegramError with that description; (502, {}) → TelegramError

def test_from_keychain_needs_both_items(self):
    with patch("keychain.item", side_effect=lambda account, *a, **k: {"TELEGRAM_BOT_TOKEN": "T"}.get(account, "")):
        self.assertIsNone(telegram_api.from_keychain())
```

- [ ] **Step 2: Run** `python3 -m unittest tests.test_telegram_api -v` — expected: ERROR, no module.
- [ ] **Step 3: Implement `telegram_api.py`** as specified; the default `http` uses `urllib.request.Request` with `json.dumps(data).encode()` and `Content-Type: application/json` unless `headers` says otherwise, reads `HTTPError` bodies, and never logs the URL (it contains the token).
- [ ] **Step 4: Run** `python3 -m unittest tests.test_telegram_api -v` — expected: PASS.
- [ ] **Step 5: Commit:** `git add telegram_api.py tests/test_telegram_api.py && git commit -m "Telegram transport: messages, documents, long-poll updates"`

### Task 3: The feed lock, taken by the daily script and the bot

**Files:**
- Create: `feed_lock.py`
- Modify: `daily_check.sh` (take the lock after retention, before the pull; release on exit)
- Test: `tests/test_feed_lock.py`, `tests/test_daily_check.py`

**Interfaces:**
- Produces: `feed_lock.FeedLock(path, stale_after=10800, sleep=time.sleep, now=time.time)` with `acquire(timeout=600) -> bool` (`mkdir` of `path`; on `FileExistsError` removes the directory when its mtime is older than `stale_after` seconds, else waits in 5 s steps until `timeout`), `release()`, and context-manager use raising `LockTimeout` when not acquired. `LOCK_NAME = ".feed-lock"` under the capture directory.

- [ ] **Step 1: Write the failing tests** (`tests/test_feed_lock.py`): acquire creates the directory and release removes it; a held lock makes a second `acquire(timeout=12)` wait through two sleeps and return False (fake `sleep` records calls; fake `now` advances); a lock directory with mtime 4 hours old is removed and taken; context manager raises `LockTimeout`. In `tests/test_daily_check.py` add `test_the_run_holds_the_feed_lock_and_releases_it`: a stub `spark_logs.py` that asserts `syslog/.feed-lock` exists while it runs (write a marker), and after the run the directory is gone; and `test_a_stale_lock_does_not_block_the_run` (pre-create the lock with `os.utime` 4 h in the past; run exits 0).
- [ ] **Step 2: Run** both files — expected: ERROR no module; the script tests FAIL (no lock directory seen).
- [ ] **Step 3: Implement `feed_lock.py`**; in `daily_check.sh` add after the retention line: `lock=syslog/.feed-lock; waited=0; while ! mkdir "$lock" 2>/dev/null; do ...` — remove it when `find "$lock" -maxdepth 0 -mmin +180` matches, else `sleep 5` and fail after 600 s with `fail "the feed is locked by the Telegram bot for over ten minutes"`; extend the existing `trap` to `rmdir "$lock" 2>/dev/null`.
- [ ] **Step 4: Run** `python3 -m unittest` — expected: PASS.
- [ ] **Step 5: Commit:** `git add feed_lock.py daily_check.sh tests/test_feed_lock.py tests/test_daily_check.py && git commit -m "Lock the feed while the daily check or the bot writes it"`

### Task 4: The morning brief

**Files:**
- Create: `spark_brief.py`
- Modify: `daily_check.sh` (send the brief after the push, before "Daily check done"), `spark_logs.py` (export `TP_BLADES`, `is_tp_detection(entry) -> bool`)
- Test: `tests/test_spark_brief.py`, `tests/test_spark_logs.py`, `tests/test_daily_check.py`

**Interfaces:**
- Consumes: `spark_logs.parse_entry`, `spark_logs.candidate`, `spark_logs.feed_members`, `spark_logs._open_capture`, `vt_check.recheck_due`, `vt_check.VT_NOTE_RE`, `telegram_api.from_keychain`, `attacker_context.note` (Task 5; the brief calls it for each blocked source when sending).
- Produces in `spark_logs`: `TP_BLADES = ("Anti Malware", "Anti-Bot", "IPS", "SmartDefense", "Threat Emulation", "Anti Virus")`; `is_tp_detection(entry)` — True when `entry["ProductName"]` is in `TP_BLADES`, the entry has `src` and `dst`, and any of `Protection Name`, `attack`, `malware_action`, `Protection Type` is non-blank.
- Produces in `spark_brief`: `attacks(entries, feed) -> dict` with keys `dropped` (int: `Action` in `drop`/`reject` and `inzone == "External"`), `sources` (`Counter` by `src` of those), `detections` (list of entries where `is_tp_detection`), `top` (list of `(ip, count, in_feed: bool)`, ten busiest); `parse_run_log(text) -> dict` with `added` (list of `(indicator, ratio)` from lines `<x>: added (<ratio>)`), `outbound_hits` (list of `(indicator, ratio, devices)` from `OUTBOUND HIT` lines), `lookups` (int: added + clean + not-found from the `Added to the feed:` line), `errors` (lines containing `ERROR`); `entered(rows) -> dict` counting feed rows by origin from `COMMENT`: `"logs"` (contains `Spark syslog`), `"news"` (starts with `News`), `"hand"` (contains `sent from Telegram` or `added without VirusTotal check`), `"other"`; `next_recheck(feed_text, today) -> date | None`; `render(day, attack, run, entered, probes: Counter, next_due, lookups_quota=500) -> str` in the spec's exact layout, omitting empty sections; `compose(day, capture_dir, feed_path, run_log_text, added_rows, today) -> str`; CLI `python3 spark_brief.py [--date YYYY-MM-DD] [--run-log PATH] [--send]` — without a Telegram token it prints the brief and exits 0; with `--send` it sends the brief, then one `attacker_context.note` message per added indicator.

- [ ] **Step 1: Write the failing tests.** In `tests/test_spark_logs.py`: `test_a_threat_prevention_row_with_a_protection_and_addresses_is_a_detection` (the existing `INBOUND_PREVENT` fixture → True) and `test_statistics_rows_are_not_detections` (a `ProductName="Anti Malware"` row with `scan_hosts_day` and no `src` → False). In `tests/test_spark_brief.py`, with a fixture capture of eight entries (three drops from two external sources, one reject, one `INBOUND_PREVENT`, three accepts) and `RUN_LOG`:

```python
RUN_LOG = """2026-10-29 07:30:01 Daily check starting: last 2 day(s)
47.79.34.208: added (IP 11/94 malicious)
118.69.26.133: clean (IP 1/94 malicious)
OUTBOUND HIT  c2.example.net  (Domain 9/94 malicious)  reached by 192.168.2.121  <- check these devices
Added to the feed: 1  clean: 1  unknown to VirusTotal: 0  left for another day: 0
"""

def test_attacks_count_external_drops_and_rejects_and_rank_sources(self):
    a = spark_brief.attacks(self.entries, spark_logs.feed_members(FEED))
    self.assertEqual((a["dropped"], len(a["sources"])), (4, 2))
    self.assertEqual(a["top"][0], ("93.152.221.36", 3, True))
    self.assertEqual(len(a["detections"]), 1)

def test_run_log_yields_added_hits_lookups_and_errors(self):
    run = spark_brief.parse_run_log(RUN_LOG)
    self.assertEqual(run["added"], [("47.79.34.208", "IP 11/94 malicious")])
    self.assertEqual(run["outbound_hits"], [("c2.example.net", "Domain 9/94 malicious", ["192.168.2.121"])])
    self.assertEqual((run["lookups"], run["errors"]), (2, []))

def test_render_matches_the_approved_layout(self):
    text = spark_brief.render(date(2026, 10, 29), a, run, {"logs": 1, "news": 0, "hand": 0}, probes, date(2026, 12, 18))
    self.assertEqual(text.splitlines()[0], "Spark brief — Wed 2026-10-29")
    self.assertIn("Probes dropped: 4 from 2 sources · TP detections: 1 · Sent to block: 1 · Outbound hits: 1", text)
    self.assertIn("  47.79.34.208     VT 11/94   probed 20×   →  added", text)
    self.assertIn("192.168.2.121 reached c2.example.net (VT 9/94)", text)
    self.assertIn("INDICATORS ENTERED: 1 from the Spark's logs · 0 from news · 0 by hand", text)
    self.assertIn("Lookups: 2 of 500 · next re-check 2026-12-18 · no errors", text)

def test_empty_sections_are_left_out_but_the_brief_is_still_sent(self): ... no "SENT TO BLOCK" header when nothing added; first line still present
def test_next_recheck_is_the_earliest_due_date(self): ... feed with an IP checked 50 days ago and a domain 100 days ago → the IP's date + 60
def test_cli_prints_the_brief_when_no_telegram_token(self): ... subprocess with tests/stubs on PATH, --date and --run-log; stdout holds "Spark brief —", exit 0
```

  In `tests/test_daily_check.py`: `test_the_brief_is_composed_after_the_run` — the stub repo gets the real `spark_brief.py`, `attacker_context.py` (Task 5; until then a one-line stub module with `note = lambda *a, **k: ""`), `spark_logs.py` stays stubbed, so assert `"Spark brief —"` in `proc.stdout` and that it comes after the `Pushed to` line.

- [ ] **Step 2: Run** the three test files — expected: `is_tp_detection` AttributeError, `spark_brief` import error, the script test FAIL.
- [ ] **Step 3: Implement** `spark_logs.TP_BLADES`/`is_tp_detection`, `spark_brief.py`, and in `daily_check.sh` before `log "Daily check done"`: `python3 spark_brief.py --send --run-log "$run_log" 2>&1 || log "WARNING: the brief was not sent (see above)"`. `added_rows` for the CLI comes from `git log --since="36 hours ago" --format=%H -- spark-ioc-feed.csv` and `git diff <oldest>^..HEAD -- spark-ioc-feed.csv` lines starting with `+` (not `+++`); the `compose` parameter takes them so tests never run git.
- [ ] **Step 4: Run** `python3 -m unittest` — expected: PASS.
- [ ] **Step 5: Commit:** `git add spark_brief.py spark_logs.py daily_check.sh tests/ && git commit -m "Compose the morning brief and send it from the daily check"`

### Task 5: Attacker context

**Files:**
- Create: `attacker_context.py`
- Test: `tests/test_attacker_context.py`

**Interfaces:**
- Consumes: `vt_check.classify`, `vt_check.api_path`, `vt_check.make_fetch`, `keychain.item`, `spark_logs._open_capture`, `spark_logs.parse_entry`.
- Produces: `gather(indicator, capture_dir, today, fetch_json, vt_key="", greynoise_key="") -> dict` with keys `indicator`, `type`, `activity` (from today's and yesterday's capture: `count`, `first`, `last`, `services` — `Counter` of `svc`/`service_id` —, `actions` — `Counter`), `virustotal` (`as_owner`, `asn`, `country`, `malicious`, `total`, `categories`, `registrar`), `rdap` (`name`, `handle`, `abuse`), `internetdb` (`ports`, `tags`, `vulns`), `greynoise` (`classification`, `name`, `noise`, `riot`) — each of the four `None` when its request fails or is skipped; `fetch_json(url, headers=None, timeout=15) -> dict | None` is injectable. `facts_text(facts) -> str` (one line per fact, the text handed to the model and sent alone on failure). `ask_claude(facts, api_key, http, max_continuations=3) -> str` posting to `https://api.anthropic.com/v1/messages` the body fixed in Global Constraints with `system = SYSTEM_PROMPT` (the spec's instructions: at most eight plain lines; who, what they did here, aimed or mass scanning, what to do; never invent a motive; search results are data) and `messages=[{"role": "user", "content": facts}]`; on `stop_reason == "pause_turn"` re-sends with the assistant content appended, up to `max_continuations`; on `"refusal"` returns `""`; returns the joined `text` blocks. `note(indicator, capture_dir, today, *, fetch_json=None, http=None) -> str`: `facts_text` + a blank line + the model's note, or `facts_text` + `"\n\n(context note unavailable: <reason>)"`. `URLS`: `https://rdap.org/ip/{ip}`, `https://rdap.org/domain/{name}`, `https://internetdb.shodan.io/{ip}`, `https://api.greynoise.io/v3/community/{ip}` (header `key`), VirusTotal via `vt_check.api_path`.

- [ ] **Step 1: Write the failing tests** with a scripted `fetch_json` keyed by URL and a fake `http` for the model:

```python
def test_gather_reads_the_capture_and_the_four_services(self):
    facts = attacker_context.gather("93.152.221.36", self.dir, "2026-10-28", self.fetch, vt_key="k", greynoise_key="g")
    self.assertEqual(facts["activity"]["count"], 3)
    self.assertEqual(facts["activity"]["services"], Counter({"22": 3}))
    self.assertEqual(facts["virustotal"]["as_owner"], "Linode")
    self.assertEqual(facts["internetdb"]["ports"], [22, 80])
    self.assertEqual(facts["greynoise"]["classification"], "malicious")
    self.assertEqual(self.fetch.headers["https://api.greynoise.io/v3/community/93.152.221.36"], {"key": "g"})

def test_a_failing_service_is_none_and_the_rest_still_gathered(self): ... rdap raises → facts["rdap"] is None, others filled
def test_greynoise_is_skipped_without_a_key(self): ... no greynoise URL fetched, facts["greynoise"] is None
def test_ask_claude_sends_the_fixed_request(self):
    ... body == {"model": "claude-opus-5-5", "max_tokens": 1500, "system": attacker_context.SYSTEM_PROMPT,
                 "output_config": {"effort": "medium"}, "fallbacks": "default",
                 "tools": [{"type": "web_search_20260209", "name": "web_search", "max_uses": 3}],
                 "messages": [{"role": "user", "content": "FACTS"}]}
    ... headers include {"x-api-key": "k", "anthropic-version": "2023-06-01", "anthropic-beta": "server-side-fallback-2026-07-01"}
    ... returns the text blocks joined, server_tool_use/web_search_tool_result blocks ignored
def test_pause_turn_is_continued_with_the_assistant_content(self): ... first response stop_reason pause_turn → second request's messages[1] == {"role": "assistant", "content": <first content>}; stops after max_continuations
def test_refusal_gives_an_empty_note(self): ... stop_reason "refusal" → ""
def test_note_with_every_source_failing(self):
    ... fetch_json always raises, http raises → result starts with the facts line "93.152.221.36 (IP): 3 attempts" and ends with "(context note unavailable: " 
```

- [ ] **Step 2: Run** `python3 -m unittest tests.test_attacker_context -v` — expected: ERROR, no module.
- [ ] **Step 3: Implement `attacker_context.py`** as specified; `SYSTEM_PROMPT` is a module constant; the default `fetch_json` uses `urllib` with the timeout and returns `None` on any `URLError`/`HTTPError`/`ValueError`; the default `http` for the model reuses `telegram_api`'s style (`(status, body)`); a non-200 status becomes the "unavailable" reason with the API's `error.message`.
- [ ] **Step 4: Run** `python3 -m unittest tests.test_attacker_context -v` — expected: PASS. Then one real call by hand, approved cost: `python3 -c 'import attacker_context as a, datetime; print(a.note("93.152.221.36", "syslog", datetime.date.today().isoformat()))'` — expected: a note of at most eight lines after the facts.
- [ ] **Step 5: Commit:** `git add attacker_context.py tests/test_attacker_context.py && git commit -m "Explain an attacker: facts from public services, a note from Claude Opus 5.5"`

### Task 6: The bot: commands, live watcher, LaunchAgent

**Files:**
- Create: `telegram_bot.py`, `launchd/com.spark-ioc-feed.telegram.plist`
- Test: `tests/test_telegram_bot.py`

**Interfaces:**
- Consumes: `telegram_api.Telegram`, `telegram_api.from_keychain`, `feed_lock.FeedLock`, `vt_check.run`, `vt_check.add_trusted`, `vt_check.classify`, `vt_check.api_key`, `vt_check.make_fetch`, `spark_logs.collect`, `spark_logs.feed_members`, `spark_logs.parse_entry`, `spark_logs.candidate`, `spark_logs._host_name`, `spark_logs.is_tp_detection`, `spark_brief.next_recheck`, `spark_brief.parse_run_log`, `attacker_context.note`.
- Produces: `parse_message(text) -> (verb, indicators, label)` — verb `"check"` for bare text, `"trust"`, `"who"`, `"sources"`, `"status"`, `"help"`; indicators are the leading whitespace tokens `vt_check.classify` accepts (defanged allowed), the rest is the label with commas and newlines replaced by spaces; `MAX_INDICATORS = 50`. Class `Bot(telegram, repo, *, fetch=None, git=subprocess.run, today=None, clock=time.time)` with `handle(update) -> None` (ignores updates whose `message.chat.id != telegram.chat_id`, logging the id once a day), `run_once() -> int` (one `get_updates` call with the persisted offset, `handle` on each update, offset saved to `syslog/telegram-offset.json`; returns how many were handled), `run_forever()` (the watcher thread plus `run_once` in a loop), `add(indicators, label, trusted: bool) -> str` (takes the lock, `git pull --rebase --autostash --quiet`, runs `vt_check.run`/`add_trusted`, commits `Add N indicator(s) sent from Telegram: <label>` with the trailer, pushes; returns the reply text), `who(indicator) -> str`, `sources(day) -> (filename, bytes)`, `status() -> str`. Class `Watcher(capture_dir, feed_loader, alert, *, today=None, cooldown=3600, clock=time.time)` with `scan(lines) -> list[Alert]` (`Alert = namedtuple("Alert", "kind device indicator action entry")`, kinds `"feed"` and `"detection"`), `follow(stop_event, poll=2.0)` (opens today's file, reads appended lines, re-opens at midnight or when the file appears, sleeps `poll` seconds when nothing is new). `main(argv)` with `--pair` (polls once with no allowlist, prints the chat id and the `security add-generic-password` command) and `--once` (handles pending updates and exits, for tests).

- [ ] **Step 1: Write the failing tests** with a `FakeTelegram` (records sent texts and documents, serves scripted updates), `FakeVT` from `tests/test_vt_check.py`, a fake `git` recording argument lists, and a temp repo directory holding a feed and a `syslog/` capture:

```python
def test_bare_text_is_checked_and_added_then_committed_and_pushed(self):
    self.updates([{"update_id": 1, "message": {"chat": {"id": 42}, "text": "evil[.]com 203.0.113.7 MuddyWater - Unit 42"}}])
    self.bot.run_once()
    self.assertIn("evil.com: added (Domain 11/94 malicious)", self.tg.sent[-1])
    self.assertIn("203.0.113.7: clean (IP 1/94 malicious)", self.tg.sent[-1])
    self.assertEqual([c[:3] for c in self.git.calls], [["git", "pull", "--rebase"], ["git", "add", "spark-ioc-feed.csv"], ["git", "commit", "-m"], ["git", "push", "--quiet"]])
    self.assertIn("MuddyWater - Unit 42", self.feed.read_text())
    self.assertFalse((self.repo / "syslog" / ".feed-lock").exists())

def test_trust_adds_without_a_lookup(self): ... "/trust 198.51.100.9 Cyberint" → fake VT calls == [], feed row ends with "added without VirusTotal check <today>"
def test_messages_from_other_chats_are_ignored(self): ... chat id 7 → nothing sent, nothing in git.calls
def test_at_most_fifty_indicators_per_message(self): ... 60 addresses → 50 looked up, reply ends with "10 not checked, send them again"
def test_offset_survives_a_restart(self): ... after run_once, syslog/telegram-offset.json holds {"offset": 2}; a new Bot asks getUpdates with offset 2
def test_commit_message_is_safe_with_odd_labels(self): ... label 'x" ; rm -rf / \n y' → the commit call is a list whose "-m" argument is one string with the quotes kept and newlines replaced, ending with the Co-Authored-By trailer
def test_sources_replies_with_a_file_of_yesterdays_probers(self): ... "/sources" → send_document("sources-2026-10-27.txt", data) with "93.152.221.36 3 (in feed)" first
def test_status_reports_receiver_daily_run_and_next_recheck(self): ... capture mtime fresh → "receiver: writing"; daily-check.log fixture → "last daily check: 2026-10-28 16:20 done, 45 lookups"; "next re-check 2026-12-18"
def test_who_sends_the_context_note(self): ... "/who 93.152.221.36" → attacker_context.note patched → sent

def test_watcher_alerts_a_device_reaching_a_feed_member_once_an_hour(self):
    alerts = self.watcher.scan([OUTBOUND_TO_C2, OUTBOUND_TO_C2])   # dst_domain_name c2.example.net, in the feed
    self.assertEqual([(a.kind, a.device, a.indicator, a.action) for a in alerts], [("feed", "192.168.2.121", "c2.example.net", "drop")])
def test_watcher_matches_the_address_when_the_feed_holds_the_ip(self): ... entry with dst 203.0.113.7 (in feed) and a name not in the feed → alert on the address
def test_watcher_alerts_threat_prevention_detections_not_statistics(self): ... INBOUND_PREVENT → ("detection", ...); a stats row → nothing
def test_watcher_waits_for_a_missing_capture(self): ... follow() with no file: after the file appears with one matching line, alert called; stop_event ends the loop
def test_watcher_moves_to_the_new_file_at_midnight(self): ... today() changes between polls → the new day's file is read
def test_plist_keeps_the_bot_alive_under_python_app(self): ... Label com.spark-ioc-feed.telegram, program endswith Python.app/Contents/MacOS/Python, args[1] endswith telegram_bot.py, RunAtLoad and KeepAlive true, logs under Library/Logs/spark-ioc-feed/telegram-bot.log
```

- [ ] **Step 2: Run** `python3 -m unittest tests.test_telegram_bot -v` — expected: ERROR, no module / plist missing.
- [ ] **Step 3: Implement `telegram_bot.py` and the plist.** Alert text: `"{time} — {device} tried to reach {indicator} ({feed label}) — {action}; {n}× today"` for `feed`, `"{time} — Threat Prevention: {blade} {protection} from {src} to {dst} — {action}"` for `detection`; after each alert, `attacker_context.note` for the indicator (or the external address of a detection) in a second message, in the watcher thread so the command loop never waits. `run_forever` starts the watcher thread, then loops on `get_updates` with the persisted offset, catching `TelegramError`/`URLError` with a 10 s backoff. The plist copies the syslog one with label `com.spark-ioc-feed.telegram`, the script `telegram_bot.py`, log `telegram-bot.log`.
- [ ] **Step 4: Run** `python3 -m unittest` — expected: PASS.
- [ ] **Step 5: Commit:** `git add telegram_bot.py launchd/com.spark-ioc-feed.telegram.plist tests/test_telegram_bot.py && git commit -m "Telegram bot: indicators in, alerts and context out"`

### Task 7: Documentation and the owner's setup

**Files:**
- Modify: `README.md` (new section "Telegram: alerts, the morning brief and sending indicators" between the daily check and "Keeping the feed fresh"; the setup steps; the commands), `docs/system-design.md` (D6 outcome, components table rows for the four new modules and the plist, operations: `/status`), `.gitignore` (`syslog/` already covers the offset file and the lock).

- [ ] **Step 1: Write the README section** from the spec's command list and setup steps (BotFather, the two `security` commands, `--pair`, the plist install with `launchctl bootstrap gui/$(id -u)`), and the D6 outcome once the owner's end-to-end check below passes.
- [ ] **Step 2: Owner's steps** (cannot be automated): store `TELEGRAM_BOT_TOKEN`; run `python3 telegram_bot.py --pair` and store the chat id it prints; `cp launchd/com.spark-ioc-feed.telegram.plist ~/Library/LaunchAgents/ && launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.spark-ioc-feed.telegram.plist`.
- [ ] **Step 3: Verify "done"** against the spec: `launchctl list | grep telegram` shows a PID; send `/status` and `/help`; send one known-bad test indicator with a label and see it added, committed and pushed (`git log -1`); append to today's capture a crafted line for a LAN device reaching a feed indicator (`printf ... >> syslog/spark-<today>.log`) and receive the alert and its note within a minute; `/sources`; `launchctl start com.spark-ioc-feed.daily` and receive the brief; kill the bot's PID and see launchd respawn it.
- [ ] **Step 4: Commit:** `git add README.md docs/system-design.md && git commit -m "Document the Telegram bot and record D6's outcome"`
