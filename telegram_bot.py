#!/usr/bin/env python3
"""The Telegram bot the owner talks to, and the live watcher of the Spark's capture.

    python3 telegram_bot.py           # what the LaunchAgent runs: commands and alerts until stopped
    python3 telegram_bot.py --pair    # first-time setup: prints your chat id and the command that stores it
    python3 telegram_bot.py --once    # handle the messages waiting and exit

A message of indicators (defanged is fine) and an optional label is checked on VirusTotal and the
flagged ones are added to the feed, committed and pushed; /trust adds without a check; /who,
/sources, /status and /help answer from the capture and the feed. Only the owner's private chat
(the Keychain's TELEGRAM_CHAT_ID) is served, and nothing on the never-block list is added. A second
thread (capture_watcher.Watcher) follows today's capture and alerts when a LAN device reaches a feed
member or a Threat Prevention blade acts on traffic with a public address; a third writes the
attacker-context notes those alerts ask for, under the caps. The design is docs/system-design.md, D6.
"""

import argparse
import json
import math
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
import unicodedata
from collections import Counter
from datetime import date, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import attacker_context
import feed_lock
from capture_watcher import Alert, FeedFile, Notice, Watcher, log
import keychain
import spark_brief
import spark_logs
import telegram_api
import vt_check

REPO = Path(__file__).resolve().parent
FEED_NAME = "spark-ioc-feed.csv"
OFFSET_NAME = "telegram-offset.json"  # in the capture directory, beside checked.json
DAILY_LOG = Path.home() / "Library/Logs/spark-ioc-feed/daily-check.log"
MAX_INDICATORS = 50  # a message's indicators handled at once: 50 lookups take about 12 minutes
POLL_TIMEOUT = 50  # seconds a getUpdates long poll waits
LOCK_WAIT = 60  # the daily check holds the lock for its whole run; the command loop must not stall that long
BACKOFF = 10  # seconds before Telegram, or a failed watcher, is tried again
WRITING = 120  # seconds since the capture's last write for the receiver to count as writing
DAILY_LOG_TAIL = 64 * 1024  # bytes of the daily check's log /status reads: the last run, not the year
MISSING_WAIT = 300  # without the bot in the Keychain: seconds before exiting (launchd starts the job again)
GIT_TIMEOUT = 300
LABEL_LIMIT = 120  # characters of a label: it goes into the CSV row and the commit subject
NOTE_QUEUE = 10  # notes waiting for the note thread; one more is dropped
# What this system talks to: the feed's home (the gateway pulls it from raw.githubusercontent.com),
# Telegram, the note's model and VirusTotal. With spark_logs' vendor list, never added to the feed.
NEVER_BLOCK = frozenset({"github.com", "raw.githubusercontent.com", "api.telegram.org", "api.anthropic.com",
                         "www.virustotal.com"})

HELP = """Send indicators (IPs, domains, URLs, hashes; defanged is fine), then an optional label:
  evil[.]com hxxps://bad[.]example/x MuddyWater - Unit 42
They are checked on VirusTotal and the flagged ones added to the feed.
/trust <indicators> [label] - add them without a VirusTotal check
/who <indicator> - who is behind it, and what it did here
/sources [YYYY-MM-DD] - that day's probing sources as a file (default yesterday)
/status - receiver, last daily check, next re-check, uptime
/help - this list"""
COMMANDS = ("trust", "who", "sources", "status", "help")
URL_RE = re.compile(r"h(?:tt|xx)ps?://", re.IGNORECASE)  # a URL, defanged or not
STATUS_RE = re.compile(r"\S+: (\S+)")  # vt_check's "<indicator>: <status> (<detail>)"
SUMMARY = {"added": "added", "clean": "clean", "not-found": "unknown to VirusTotal", "in-feed": "already in the feed"}
RUN_START = "Daily check starting"
RUN_END_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} (?:Daily check done|ERROR: (.*))$", re.M)

def _hidden(char):
    """True for a quote and for every control, format (bidi, zero-width), surrogate, private-use or
    unassigned character: none of them may reach the gateway's CSV or the public commit."""
    return char == '"' or unicodedata.category(char).startswith("C")


def _tokens(words):
    """The words cut at their commas, empty pieces dropped ("a.example,b.example", "a , b"); a URL is
    kept whole but for trailing commas (one with a comma inside is no indicator: the label starts there)."""
    tokens = []
    for word in words:
        if URL_RE.match(word):
            tokens.append(word.rstrip(","))
        else:
            tokens += [piece for piece in word.split(",") if piece]
    return tokens


def parse_message(text):
    """(verb, indicators, label) of a message: verb "check" for bare text, else the command
    (an unknown one is "help"); the indicators are the leading words vt_check.classify accepts,
    normalised, commas between them allowed; the label is the rest, without quotes or hidden
    characters (_hidden), commas and line breaks made spaces, at most LABEL_LIMIT characters."""
    words = text.split()
    verb = "check"
    if words and words[0].startswith("/"):
        command = words.pop(0)[1:].split("@")[0].lower()
        verb = command if command in COMMANDS else "help"
    tokens = _tokens(words)
    indicators = []
    for token in tokens:
        if any(map(_hidden, token)):
            break
        try:
            indicators.append(vt_check.classify(token)[1])
        except ValueError:
            break
    label = "".join(c for c in " ".join(tokens[len(indicators):]) if not _hidden(c))
    return verb, indicators, " ".join(label.replace(",", " ").split())[:LABEL_LIMIT].rstrip()


def tail(path, size):
    """The last `size` bytes of the file at `path`, as text (a character cut in two is replaced)."""
    with open(path, "rb") as f:
        f.seek(max(0, os.fstat(f.fileno()).st_size - size))
        return f.read().decode("utf-8", errors="replace")


def summary(statuses, trusted):
    """The counts line of a check's (or with `trusted`, a /trust's) reply."""
    shown = ("added", "in-feed") if trusted else tuple(SUMMARY)
    return ", ".join([f"{statuses[status]} {SUMMARY[status]}" for status in shown]
                     + [f"{n} {status}" for status, n in statuses.items() if status not in shown and n])


class Bot:
    """The owner's commands, read from `telegram` (a telegram_api.Telegram) and carried out on the
    repository `repo`: its feed, its capture directory (syslog/) and its git clone."""

    def __init__(self, telegram, repo, *, fetch=None, git=subprocess.run, today=None, clock=time.time,
                 sleep=time.sleep, daily_log=DAILY_LOG):
        self.telegram = telegram
        self.repo = Path(repo)
        self.syslog = self.repo / "syslog"
        self.feed = self.repo / FEED_NAME
        self.fetch = fetch
        self.git = git
        self.today = today or date.today
        self.clock = clock
        self.sleep = sleep
        self.daily_log = Path(daily_log)
        self.started = clock()
        self.last_error = None  # (when, message) of the last error logged, for /status
        self.ignored = {}  # "<chat type> <chat id>" -> the day it was last logged
        self.offset = self.load_offset()
        self.watcher = Watcher(self.syslog, FeedFile(self.feed), self.on_alerts, today=self.today, clock=clock,
                               log=self.error)
        self.note_queue = queue.Queue(maxsize=NOTE_QUEUE)  # the notes' indicators, for the note thread
        self.note_thread = None  # started with the first note

    def error(self, text):
        """Log an error and keep it as the last one /status shows; called from both threads."""
        at = datetime.fromtimestamp(self.clock())
        self.last_error = (at, text)
        log(text, at)

    # The command loop.

    def load_offset(self):
        try:
            return int(json.loads((self.syslog / OFFSET_NAME).read_text())["offset"])
        except (OSError, ValueError, KeyError, TypeError):
            return 0

    def run_once(self, timeout=POLL_TIMEOUT):
        """Handle the updates one long poll brings; returns how many. The offset is saved after
        each, so a restart neither loses nor repeats one."""
        updates = self.telegram.get_updates(self.offset, timeout=timeout)
        for update in updates:
            try:
                self.handle(update)
            except Exception as e:  # an update this code cannot read would otherwise come back for ever
                self.error(f"an update could not be handled: {e!r}")
            self.offset = update["update_id"] + 1
            self.syslog.mkdir(exist_ok=True)
            (self.syslog / OFFSET_NAME).write_text(json.dumps({"offset": self.offset}) + "\n")
        return len(updates)

    def run_forever(self):
        """The watcher in a thread of its own, the command loop in this one, until Ctrl-C."""
        stop = threading.Event()
        watcher = threading.Thread(target=self.watch, args=(stop,), name="watcher", daemon=True)
        watcher.start()
        log(f"bot started, watching {self.syslog}")
        try:
            while True:
                try:
                    self.run_once()
                except Exception as e:  # URLError, timeouts, an odd answer: dying would only replay the update
                    detail = e if isinstance(e, telegram_api.TelegramError) else repr(e)
                    self.error(f"Telegram: {detail}; trying again in {BACKOFF} s")
                    self.sleep(BACKOFF)
        except KeyboardInterrupt:
            stop.set()
            watcher.join()

    def watch(self, stop):
        """Run the watcher until `stop` is set, starting it again BACKOFF seconds after it fails."""
        while not stop.is_set():
            try:
                self.watcher.follow(stop)
            except Exception as e:  # the alerts must not stop for good over one bad line or file
                self.error(f"watcher failed, starting again in {BACKOFF} s: {e!r}")
                stop.wait(BACKOFF)

    def handle(self, update):
        message = update.get("message") or {}
        if not message:
            return
        chat = message.get("chat") or {}
        # Only the owner's private chat, whose id is the owner's own: in a group, every member could
        # add to the public feed.
        if chat.get("type") != "private" or chat.get("id") != self.telegram.chat_id:
            seen = f"{chat.get('type')} {chat.get('id')}"
            if self.ignored.get(seen) != self.today():
                self.ignored[seen] = self.today()
                log(f"ignored a message from {chat.get('type') or 'a'} chat {chat.get('id')}: "
                    "only the owner's private chat is served")
            return
        if not message.get("text"):
            return
        verb, indicators, label = parse_message(message["text"])
        try:
            reply = self.respond(verb, indicators, label)
        except Exception as e:  # one failing command must not stop the bot
            self.error(f"{verb} failed: {e!r}")
            reply = f"{verb} failed: {e}"
        if reply:
            self.send(reply)

    def send(self, text):
        try:
            self.telegram.send_message(text)
        except Exception as e:  # Telegram refusing it, the network, an odd answer
            self.error(f"a message to the owner was not sent: {e}")

    def respond(self, verb, indicators, label):
        """Carry the command out; returns the reply, or None when it went out as a document."""
        if verb in ("check", "trust"):
            if not indicators:
                return f"No indicator in that message.\n\n{HELP}"
            return self.add(indicators, label, trusted=verb == "trust")
        if verb == "who":
            return self.who(indicators[0]) if indicators else "Send /who <indicator>, e.g. /who 93.152.221.36"
        if verb == "sources":
            try:
                day = date.fromisoformat(label) if label else self.today() - timedelta(days=1)
            except ValueError:
                return "Send /sources, or /sources YYYY-MM-DD for another day."
            filename, data = self.sources(day)
            if not data:
                return f"No inbound sources in the capture of {day}."
            self.telegram.send_document(filename, data, caption=f"Inbound sources on {day}, busiest first")
            return None
        if verb == "status":
            return self.status()
        return HELP

    # The commands.

    def add(self, indicators, label, trusted):
        """Add the indicators to the feed, after a VirusTotal check unless `trusted`, then commit and
        push the feed; returns the reply. At most MAX_INDICATORS are taken, and one the gateway must
        never block (never_block) is refused."""
        taken, rest = indicators[:MAX_INDICATORS], len(indicators) - MAX_INDICATORS
        refused = [f"refused: {value} is on the never-block list" for value in taken if self.never_block(value)]
        taken = [value for value in taken if not self.never_block(value)]
        if not taken:
            return "\n".join(refused)
        fetch = None
        if not trusted:
            fetch = self.fetch or self._keychain_fetch()
            if fetch is None:
                return f"No VirusTotal key: {vt_check.NO_KEY_HELP}"
        lock = feed_lock.FeedLock(self.syslog / feed_lock.LOCK_NAME, sleep=self.sleep, now=self.clock)
        self.syslog.mkdir(exist_ok=True)
        if not lock.acquire(timeout=LOCK_WAIT):
            try:
                held = int((self.clock() - os.stat(lock.path).st_mtime) // 60)
            except FileNotFoundError:
                held = 0
            return (f"The daily check has been writing the feed for {spark_brief._count(held, 'minute')}; "
                    "send the indicators again later.")
        try:  # from here on, whatever happens (SIGTERM included), the lock is given back
            if not trusted:
                minutes = max(1, math.ceil((len(taken) - 1) * vt_check.FREE_API_DELAY / 60))
                self.send(f"Checking {spark_brief._count(len(taken), 'indicator')} on VirusTotal, "
                          f"about {spark_brief._count(minutes, 'minute')}.")
            lines = self._write(taken, label, fetch)
        finally:
            lock.release()
        if rest > 0:
            lines.append(f"{rest} not checked, send them again")
        return "\n".join(refused + lines)

    def never_block(self, value):
        """True when the feed must not hold `value`: a domain, or a URL's host, that spark_logs never
        looks up (its vendor list and syslog/allow.txt) or that this system needs (NEVER_BLOCK)."""
        try:
            host = urlsplit(value).hostname if "://" in value else value
        except ValueError:  # "https://[::1": no host to compare
            return False
        suffixes = spark_logs.load_allow(self.syslog / spark_logs.ALLOW_NAME) | NEVER_BLOCK
        return bool(host) and spark_logs.allowed(host, suffixes)

    @staticmethod
    def _keychain_fetch():
        """VirusTotal's fetch with the key from the environment or the Keychain; None without one."""
        key = vt_check.api_key()
        return vt_check.make_fetch(key) if key else None

    def _write(self, indicators, label, fetch):
        """The reply lines of an addition made under the lock: pull, add (looked up through `fetch`,
        or trusted when it is None), commit and push whatever the feed now holds that git does not."""
        ok, output = self._git("pull", "--rebase", "--autostash", "--quiet")
        if not ok:
            self.error(f"git pull failed: {output}")
            return [f"git pull failed, nothing was added: {output}"]
        lines = []
        pairs = [(indicator, f"{label} - sent from Telegram" if label else "sent from Telegram")
                 for indicator in indicators]
        today = self.today().isoformat()
        stopped = None
        try:
            if fetch is None:
                vt_check.add_trusted(pairs, self.feed, today=today, out=lines.append)
            else:
                vt_check.run(pairs, self.feed, fetch, sleep=self.sleep, today=today, out=lines.append)
        except Exception as e:  # a refused key, the network, an odd answer: commit the rows already written
            stopped = f"stopped: {e}"
            self.error(f"the check of {len(indicators)} indicator(s) {stopped}")
        statuses = Counter(m.group(1) for m in map(STATUS_RE.match, lines) if m)  # vt_check's lines only
        if stopped:
            lines.append(stopped)
        lines.append(summary(statuses, trusted=fetch is None))
        lines.append(self._commit(label))
        return lines

    def _commit(self, label):
        """Commit and push the feed whenever git sees it changed: the rows this check added, and any an
        interrupted one left behind (they would otherwise go out under the daily check's message). The
        message counts the rows git says were added. Returns the reply's last line."""
        status, _, said = self._run_git("diff", "--quiet", "--", FEED_NAME)
        if status == 0:
            return "Nothing added, nothing committed."
        if status == 1:
            status, stdout, said = self._run_git("diff", "--numstat", "--", FEED_NAME)
        if status != 0:
            self.error(f"git diff failed: {said}")
            return f"git diff failed, the rows are in the feed file but not committed: {said}"
        added = int(stdout.split()[0]) if stdout.split() and stdout.split()[0].isdigit() else 0
        message = f"Add {spark_brief._count(added, 'indicator')} sent from Telegram" + (f": {label}" if label else "")
        message = " ".join(message.split())  # one line, whatever the label holds
        for args in (("add", FEED_NAME), ("commit", "-m", message, "--", FEED_NAME)):
            ok, output = self._git(*args)
            if not ok:
                self.error(f"git {args[0]} failed: {output}")
                return f"git {args[0]} failed, the rows are in the feed file but not committed: {output}"
        ok, output = self._git("push", "--quiet")
        if not ok:
            self.error(f"git push failed: {output}")
            return f"Committed, but the push failed ({output}); the daily check will push it."
        return "Committed and pushed."

    def _git(self, *args):
        """(whether git succeeded, what it said) for one git command in the repository."""
        status, _, said = self._run_git(*args)
        return status == 0, said

    def _run_git(self, *args):
        """(exit status, standard output, what it said) of one git command in the repository; the status
        is None when git could not run."""
        try:
            proc = self.git(["git", *args], cwd=self.repo, capture_output=True, text=True, timeout=GIT_TIMEOUT)
        except (OSError, subprocess.SubprocessError, ValueError) as e:  # ValueError: a NUL in an argument
            return None, "", str(e)
        return proc.returncode, proc.stdout or "", (proc.stderr or proc.stdout or "").strip()

    def who(self, indicator):
        return attacker_context.note(indicator, self.syslog, self.today().isoformat(), report=log)

    def sources(self, day):
        """(file name, contents) of the list of `day`'s inbound sources, busiest first; empty contents
        when the day has none."""
        inbound = spark_logs.collect(self.syslog, days=1, today=day.isoformat())["inbound"]
        feed = spark_logs.feed_members(self.feed.read_text())
        rows = sorted(inbound.items(), key=lambda item: (-item[1], item[0]))
        text = "".join(f"{ip} {count}" + (" (in feed)" if ip in feed else "") + "\n" for ip, count in rows)
        return f"sources-{day}.txt", text.encode()

    def status(self):
        try:
            due = spark_brief.next_recheck(self.feed.read_text(), self.today())
        except OSError:
            due = None
        last = self.last_error  # read once: the watcher thread may replace it meanwhile
        return "\n".join([self._receiver(), self._daily_check(),
                          f"next re-check {due}" if due else "no re-check due",
                          f"bot: up since {datetime.fromtimestamp(self.started):%Y-%m-%d %H:%M}",
                          f"last error: {last[0]:%Y-%m-%d %H:%M} {last[1]}" if last else "last error: none"])

    def _receiver(self):
        try:
            age = self.clock() - (self.syslog / f"spark-{self.today():%Y-%m-%d}.log").stat().st_mtime
        except FileNotFoundError:
            return "receiver: no capture today"
        if age <= WRITING:
            return "receiver: writing"
        return f"receiver: no capture for {spark_brief._count(int(age // 60), 'minute')}"

    def _daily_check(self):
        """How the last run in the daily check's log went (its lines: "YYYY-MM-DD HH:MM:SS <message>")."""
        try:
            text = tail(self.daily_log, DAILY_LOG_TAIL)
        except OSError:
            return "last daily check: no log"
        start = text.rfind(RUN_START)
        if start == -1:
            return "last daily check: none in the log"
        run = text[text.rfind("\n", 0, start) + 1:]
        when, end = run[:16], RUN_END_RE.search(run)
        if end is None:
            return f"last daily check: {when} running"
        if end.group(1) is not None:
            return f"last daily check: {when} failed: {end.group(1)}"
        return f"last daily check: {when} done, {spark_brief.parse_run_log(run)['lookups']} lookups"

    # The watcher's alerts, sent from its thread.

    def on_alerts(self, items):
        """Send every alert and notice of one pass, then queue the attacker-context notes (tens of seconds
        each) on the indicators the alerts name (Alert.note: the cases with an attacker). The note thread
        works through the queue in order, so a pass's notes follow its alerts and no alert waits."""
        for item in items:
            self.send(item.text if isinstance(item, Notice) else self.watcher.describe(item))
        for item in items:
            if isinstance(item, Alert) and item.note:
                self.queue_note(item.note)

    def queue_note(self, indicator):
        if self.note_thread is None:
            self.note_thread = threading.Thread(target=self._notes, name="notes", daemon=True)
            self.note_thread.start()
        try:
            self.note_queue.put_nowait(indicator)
        except queue.Full:
            log(f"the note on {indicator} was dropped: {NOTE_QUEUE} notes are already waiting")

    def _notes(self):
        """The note thread: write and send each queued note until a None arrives."""
        while True:
            indicator = self.note_queue.get()
            try:
                if indicator is None:
                    return
                note = attacker_context.note(indicator, self.syslog, self.today().isoformat(), report=log)
                if note:
                    self.send(note)
            except Exception as e:  # one note failing must not stop the next
                self.error(f"the note on {indicator} failed: {e!r}")
            finally:
                self.note_queue.task_done()

    def stop_notes(self, timeout=5):
        """End the note thread once the notes queued before are done (or `timeout` seconds pass)."""
        thread, self.note_thread = self.note_thread, None
        if thread is None:
            return
        try:
            self.note_queue.put(None, timeout=timeout)
        except queue.Full:
            return
        thread.join(timeout)


BOTFATHER_HELP = f"""No bot token in the Keychain. To create the bot:
  1. In Telegram, open BotFather, send /newbot and answer its questions; it replies with the bot's token.
  2. Store the token:
       security add-generic-password -s {keychain.SERVICE} -a TELEGRAM_BOT_TOKEN -w '<token>' -U
  3. Run python3 telegram_bot.py --pair again and send the bot any message."""


GROUP_REFUSAL = "send /start to the bot from your own account, not from a group"
STORE_CHAT_ID = f"security add-generic-password -s {keychain.SERVICE} -a TELEGRAM_CHAT_ID -w '{{}}' -U"


def _sender(message):
    """Who sent `message`: "@username (first name)", or what Telegram gives of the two."""
    sender = message.get("from") or {}
    username, first = sender.get("username"), sender.get("first_name")
    name = " ".join(str(first).split()) if first else ""
    if username:
        return f"@{username} ({name})" if name else f"@{username}"
    return name or "an unknown sender"


def pair():
    """First-time setup: list the chats that wrote to the bot, with their type and sender, and print
    the chat id of a private one (a group's id is never offered: every member could use the bot)."""
    token = keychain.item("TELEGRAM_BOT_TOKEN")
    if not token:
        print(BOTFATHER_HELP)
        return 1
    telegram = telegram_api.Telegram(token, None)
    print(f"Waiting up to {POLL_TIMEOUT} s for a message to the bot: send it /start from your own Telegram account.",
          flush=True)
    try:
        updates = telegram.get_updates(0, timeout=POLL_TIMEOUT)
    except (telegram_api.TelegramError, OSError) as e:
        print(f"error: Telegram did not answer: {e}", file=sys.stderr)
        return 1
    private, listed = [], set()
    for update in updates:
        message = update.get("message") or {}
        chat = message.get("chat") or {}
        kind = chat.get("type") or "unknown"
        if "id" not in chat or (kind, chat["id"]) in listed:
            continue
        listed.add((kind, chat["id"]))
        if kind == "private":
            private.append(chat["id"])
            print(f"  private chat {chat['id']} from {_sender(message)}")
        else:
            print(f"  {kind} chat from {_sender(message)}: refused — {GROUP_REFUSAL}")
    if not listed:
        print("No message arrived. Send the bot a message first, then run python3 telegram_bot.py --pair again.")
        return 1
    if not private:
        print(f"No private chat wrote to the bot: {GROUP_REFUSAL}, then run python3 telegram_bot.py --pair again.")
        return 1
    if len(private) == 1:
        print(f"Your chat id is {private[0]}. Store it with:\n  {STORE_CHAT_ID.format(private[0])}")
    else:
        print("More than one account wrote to the bot. Check the senders above and store the id of your own with:\n"
              f"  {STORE_CHAT_ID.format('<the id of your own account>')}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="The Telegram bot: indicators in, alerts and context out.")
    parser.add_argument("--pair", action="store_true",
                        help="first-time setup: print the chat id of the next message the bot receives "
                             "and the command that stores it in the Keychain")
    parser.add_argument("--once", action="store_true", help="handle the messages waiting and exit (no watcher)")
    args = parser.parse_args(argv)

    if args.pair:
        return pair()
    try:
        telegram, problem = telegram_api.from_keychain(), None
    except telegram_api.TelegramError as e:  # its message never carries the stored value
        telegram, problem = None, str(e)
    if telegram is None:
        problem = problem or f"no TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID in the Keychain (service {keychain.SERVICE})"
        log(f"{problem}: see python3 telegram_bot.py --pair; exiting in {MISSING_WAIT // 60} minutes")
        time.sleep(MISSING_WAIT)  # launchd's KeepAlive starts the job again; the wait keeps the log quiet
        return 1
    bot = Bot(telegram, REPO)
    if args.once:
        try:
            bot.run_once(timeout=0)
        except (telegram_api.TelegramError, OSError) as e:
            log(f"Telegram: {e}")
            return 1
        return 0
    signal.signal(signal.SIGTERM, _exit_on_sigterm)
    bot.run_forever()
    return 0


def _exit_on_sigterm(signum, frame):
    # launchctl bootout sends SIGTERM; as an exception it runs the finally that releases the feed lock.
    raise SystemExit(0)


if __name__ == "__main__":
    sys.exit(main())
