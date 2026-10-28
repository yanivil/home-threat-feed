"""The live watcher of the Spark's capture: follows today's file and raises the alerts the Telegram
bot sends (telegram_bot.py runs it in a thread of its own).

An alert is a LAN device reaching a member of the feed, or a Threat Prevention row with an explicit
action (ALERT_ACTIONS) on traffic with a public address. The same pair alerts at most once an hour;
at most ALERT_LIMIT alerts go out in ALERT_WINDOW seconds and the notes they ask for are capped
too (NoteCap). The watcher's place in the capture is saved after each pass, so a same-day restart
alerts, late, what was written while it was down. The design is docs/system-design.md, D6.
"""

import itertools
import json
import os
import sys
import time
from collections import Counter, deque, namedtuple
from datetime import date, datetime
from pathlib import Path

import attacker_context
import spark_brief
import spark_logs

POSITION_NAME = "watcher-offset.json"  # the watcher's place in today's capture, beside it
COOLDOWN = 3600  # an alert on the same pair waits this long
WATCH_POLL = 2.0
BATCH = 1000  # capture lines read per pass
ALERT_LIMIT, ALERT_WINDOW = 10, 600  # alerts sent in any sliding ten minutes
NOTES_PER_HOUR, NOTES_PER_DAY = 6, 30  # attacker-context notes: each one is a paid model call
NOTE_REPEAT = 86400  # seconds before the same indicator gets another note
CAP_REACHED = "Alert cap reached: further alerts in the next 10 minutes are counted, not sent"
SUPPRESSED_LISTED = 10  # (device → indicator, action) pairs the suppression summary names

# A Threat Prevention row alerts live only with one of these actions (stripped, lower-cased); a blank
# Action, monitor, accept, inspect and the rest are the morning brief's alone.
ALERT_ACTIONS = frozenset({"prevent", "drop", "reject", "block", "detect"})
# The blades whose outbound detection names attacker infrastructure: its alert gets a note on the
# destination (an IPS/SmartDefense protocol anomaly does not). "Anti Malware" is the Spark's name for
# the Anti-Virus and Anti-Bot family.
NOTE_BLADES = frozenset({"Anti-Bot", "Anti Virus", "Threat Emulation", "Anti Malware"})

# `note`: the indicator the alert's attacker-context note is about, None for no note; `late`: raised from
# lines written while the watcher was down (a same-day restart), sent with "late: " and no note.
Alert = namedtuple("Alert", "kind device indicator action entry note late", defaults=(None, False))
Notice = namedtuple("Notice", "text")  # a message of the watcher's own, sent like an alert (the caps)



def log(text, at=None):
    # One write per line: the command loop and the watcher thread both log.
    sys.stderr.write(f"{at or datetime.now():%Y-%m-%d %H:%M:%S} {text}\n")
    sys.stderr.flush()


class Feed:
    """The feed's members (spark_logs.feed_members) and each row's COMMENT, which an alert shows."""

    def __init__(self, text):
        self.members = spark_logs.feed_members(text)
        self.labels, self.ranges = {}, []
        for line in text.splitlines():
            fields = line.split(",")
            if line.startswith("#") or len(fields) != 7:
                continue
            self.labels[fields[1].strip().lower()] = fields[6].strip()
            if fields[2].strip() == "IP Range":
                self.ranges.append((spark_logs.feed_members(line), fields[6].strip()))

    def __contains__(self, indicator):
        return indicator in self.members

    def label(self, indicator):
        if indicator.lower() in self.labels:
            return self.labels[indicator.lower()]
        return next((comment for members, comment in self.ranges if indicator in members), "")


class FeedFile:
    """The Feed in `path`, read again when the file changes (the daily check and the bot rewrite it)."""

    def __init__(self, path):
        self.path = Path(path)
        self.mtime = None
        self.feed = Feed("")

    def __call__(self):
        try:
            mtime = self.path.stat().st_mtime_ns
        except FileNotFoundError:
            return self.feed
        if mtime != self.mtime:
            self.feed, self.mtime = Feed(self.path.read_text()), mtime
        return self.feed


def _protection(entry):
    return next((entry[key].strip() for key in ("Protection Name", "attack", "Protection Type")
                 if entry.get(key, "").strip()), "")


def _address(text):
    """A capture field that should hold an address: the address when it is one, else the text clean()ed."""
    ip = spark_logs._ip((text or "").strip())
    return str(ip) if ip is not None else attacker_context.clean(text) or "?"


def _external(entry):
    """(public address, the other end) of a detection, the source first; None when both are on the LAN."""
    src, dst = entry["src"], entry["dst"]
    for public, other in ((src, dst), (dst, src)):
        ip = spark_logs._ip(public.strip())
        if ip is not None and ip.is_global:
            return str(ip), _address(other)
    return None


def _note_target(entry, external):
    """What a detection's note is about: an inbound one's source; an outbound one's destination (the host
    name the row names, else the address) when a NOTE_BLADES blade made it; else None."""
    if external == _address(entry["src"]):
        return external
    if entry.get("ProductName") in NOTE_BLADES:
        try:
            return spark_logs._host_name(entry) or external
        except ValueError:  # a malformed resource URL
            return external
    return None


class AlertCap:
    """At most `limit` alerts in any sliding `window` seconds. The first alert over the limit starts
    a suppression of `window` seconds: it and the ones after it are counted, not sent, and tick()
    reports them once the suppression is over, naming what they were: the morning brief never
    counts a feed hit the gateway logged only as a firewall row, so the summary is the only record."""

    def __init__(self, limit=ALERT_LIMIT, window=ALERT_WINDOW):
        self.limit, self.window = limit, window
        self.sent = deque()  # when the alerts in the window went out
        self.capped = None  # when the suppression began
        self.suppressed = 0
        self.pairs = {}  # the distinct (device, indicator, action) suppressed, in order

    def admit(self, now, pair=None):
        """(whether the alert goes out, the message to send in its place or None); `pair` is the
        alert's (device, indicator, action), named in the summary if it is suppressed."""
        if self.capped is None:
            while self.sent and now - self.sent[0] >= self.window:
                self.sent.popleft()
            if len(self.sent) < self.limit:
                self.sent.append(now)
                return True, None
            self.capped, notice = now, CAP_REACHED
        else:
            notice = None
        self.suppressed += 1
        if pair is not None:
            self.pairs.setdefault(pair, None)
        return False, notice

    def tick(self, now):
        """The message that the suppression is over, how many alerts it held and which (at most
        SUPPRESSED_LISTED distinct pairs, one a line), once; else None."""
        if self.capped is None or now - self.capped < self.window:
            return None
        start, count, pairs = self.capped, self.suppressed, list(self.pairs)
        self.capped, self.suppressed, self.pairs = None, 0, {}
        self.sent.clear()
        lines = [f"{spark_brief._count(count, 'alert')} suppressed between {datetime.fromtimestamp(start):%H:%M} "
                 f"and {datetime.fromtimestamp(now):%H:%M}:"]
        lines += [f"  {device} → {indicator}, {action}" for device, indicator, action in pairs[:SUPPRESSED_LISTED]]
        if len(pairs) > SUPPRESSED_LISTED:
            lines.append(f"  … and {len(pairs) - SUPPRESSED_LISTED} more")
        return "\n".join(lines)


class NoteCap:
    """At most `per_hour` notes in any sliding hour and `per_day` in a local day, and one per
    indicator in `repeat` seconds."""

    def __init__(self, per_hour=NOTES_PER_HOUR, per_day=NOTES_PER_DAY, repeat=NOTE_REPEAT):
        self.per_hour, self.per_day, self.repeat = per_hour, per_day, repeat
        self.hour = deque()  # when the notes of the last hour were admitted
        self.day, self.day_count = None, 0
        self.last = {}  # indicator -> when its last note was admitted

    def admit(self, indicator, now):
        day = datetime.fromtimestamp(now).date()
        if day != self.day:
            self.day, self.day_count = day, 0
        while self.hour and now - self.hour[0] >= 3600:
            self.hour.popleft()
        self.last = {key: at for key, at in self.last.items() if now - at < self.repeat}
        key = indicator.lower()
        if key in self.last or len(self.hour) >= self.per_hour or self.day_count >= self.per_day:
            return False
        self.hour.append(now)
        self.day_count += 1
        self.last[key] = now
        return True


class Watcher:
    """Follows today's capture in `capture_dir` and raises an Alert for a LAN device reaching a member
    of the feed `feed_loader()` returns ("feed") and for a Threat Prevention row whose Action is one of
    ALERT_ACTIONS (prevent, drop, reject, block, detect) on traffic with a public address ("detection";
    a blank Action, monitor, accept, anything else and the LAN-only rows are left to the morning
    brief). The same pair is alerted at most once per `cooldown` seconds of `clock`. Each Alert names
    the indicator its note is about: a feed hit's, an inbound detection's source, an outbound
    Anti-Bot, Anti-Virus or Threat Emulation detection's destination. gate() holds the alerts to
    ALERT_LIMIT in ALERT_WINDOW seconds (a Notice says when the cap is reached and, once the window
    clears, how many were held and which) and the notes to NoteCap's limits. `alert(items)` gets each pass's
    Alerts and Notices in one call, so their texts can all go out before the slower notes. After each
    pass the place reached in the capture is saved (POSITION_NAME), for a restart to pick up from;
    `log(text)` reports what the watcher could not do."""

    def __init__(self, capture_dir, feed_loader, alert, *, today=None, cooldown=COOLDOWN, clock=time.time,
                 log=log):
        self.capture_dir = Path(capture_dir)
        self.position = self.capture_dir / POSITION_NAME
        self.log = log
        self.feed_loader = feed_loader
        self.alert = alert
        self.today = today or date.today
        self.cooldown = cooldown
        self.clock = clock
        self.feed = Feed("")
        self.day = None
        self.counts = Counter()  # (device, indicator) -> feed hits seen today
        self.alerted = {}  # (kind, ...pair) -> when it last alerted
        self.alert_cap = AlertCap()
        self.note_cap = NoteCap()
        self.pending = b""  # the start of a line the receiver is still writing
        self.line_no = 0  # complete lines read from the open capture
        self.quiet_end = self.late_end = 0  # its bytes only counted, then alerted late (see follow)
        self.position_failed = False

    def scan(self, lines, catch_up=False, first_line=1):
        """The Alerts the capture `lines` raise, past the cooldown. With `catch_up` the feed hits are
        only counted: no Alert, and no cooldown started. A line that cannot be read in any way costs
        only itself; the pass logs how many there were and the first one's number (`first_line` is the
        number of the first of `lines`), never what they hold."""
        self.feed = self.feed_loader()
        today = self.today()
        if today != self.day:
            self.day = today
            self.counts.clear()
            now = self.clock()
            self.alerted = {key: at for key, at in self.alerted.items() if now - at < self.cooldown}
        alerts, failed = [], []
        for number, line in enumerate(lines, first_line):
            if not line.strip():
                continue
            try:
                found = self._match(spark_logs.parse_entry(line.rstrip("\n")))
            except Exception as e:  # the alerts must not stop over one line
                failed.append((number, type(e).__name__))
                continue
            if found and not catch_up and self._due(found[1]):
                alerts.append(found[0])
        if failed:
            self.log(f"the watcher skipped {spark_brief._count(len(failed), 'capture line')} it could not read, "
                     f"the first at line {failed[0][0]} ({failed[0][1]})")
        return alerts

    def _match(self, entry):
        """(Alert, cooldown key) when the entry is worth an alert, else None."""
        if "system" in entry:  # the Spark's own programs: never an alert
            return None
        action = attacker_context.clean(entry.get("Action")) or ""
        found = spark_logs.candidate(entry)
        if found and found[0] == "outbound":
            _, indicator, device = found
            for target in dict.fromkeys((indicator, entry["dst"])):  # the host name it names, then the address
                if target in self.feed:
                    self.counts[device, target] += 1
                    alert = Alert("feed", device, target, action or "detected", entry, note=target)
                    return alert, ("feed", device, target)
        if spark_logs.is_tp_detection(entry) and action.lower() in ALERT_ACTIONS:
            ends = _external(entry)
            if ends:  # a detection between two LAN addresses is left to the brief
                external, device = ends
                key = ("detection", entry["src"], entry["dst"], _protection(entry))
                note = _note_target(entry, external)
                return Alert("detection", device, external, action.lower(), entry, note), key
        return None

    def gate(self, alerts, late=False):
        """The pass's `alerts` under the caps, with the Notices they call for: the alerts past the
        alert cap are counted and dropped, a note past the note cap is taken off its alert. `late`
        alerts are marked so, and get no note."""
        now = self.clock()
        cleared = self.alert_cap.tick(now)
        items = [Notice(cleared)] if cleared else []
        for alert in alerts:
            send, notice = self.alert_cap.admit(now, (alert.device, alert.indicator, alert.action))
            if notice:
                items.append(Notice(notice))
            if not send:
                continue
            if late:
                alert = alert._replace(note=None, late=True)
            elif alert.note and not self.note_cap.admit(alert.note, now):
                alert = alert._replace(note=None)
            items.append(alert)
        return items

    def _due(self, key):
        now = self.clock()
        if key in self.alerted and now - self.alerted[key] < self.cooldown:
            return False
        self.alerted[key] = now
        return True

    def describe(self, alert):
        """The alert's message, "late: " first for a late one."""
        text = self._describe(alert)
        return f"late: {text}" if alert.late else text

    def _describe(self, alert):
        entry = alert.entry
        at = attacker_context.clean(entry.get("received", "").partition("T")[2][:8]) or ""
        if alert.kind == "feed":
            label = self.feed.label(alert.indicator) or "in the feed"
            n = self.counts[alert.device, alert.indicator]
            return f"{at} — {alert.device} tried to reach {alert.indicator} ({label}) — {alert.action}; {n}× today"
        # Every string the capture holds is clean()ed, every address checked: a forged row's text must
        # not reach the owner's chat as more than one short line.
        blade = spark_brief.BLADE_NAMES.get(entry.get("ProductName"), entry.get("ProductName"))
        what = " ".join(part for part in map(attacker_context.clean, (blade, _protection(entry))) if part)
        return (f"{at} — Threat Prevention: {what} from {_address(entry['src'])} to {_address(entry['dst'])}"
                f" — {alert.action}")

    def follow(self, stop_event, poll=WATCH_POLL):
        """Alert on the lines written to today's capture until `stop_event` is set, waiting `poll`
        seconds whenever nothing is new: a missing file is waited for, a replaced one read again, and
        at midnight the new day's file followed. What today's file holds when the watcher starts is
        counted without alerting, except that when the saved position names this very file (same day,
        same inode) only the lines up to it are counted and the ones after it, written while the
        watcher was down, are alerted late: a same-day restart repeats no alert and silences none."""
        day = handle = None
        starting = True
        self.day = None  # count today afresh
        try:
            while not stop_event.is_set():
                today = self.today()
                if handle is not None and today != day:
                    self._pass(handle, day, list(self._lines(handle)))  # the old day's last lines
                    handle.close()
                    handle = None
                if handle is None:
                    day, handle = today, self._open(today)
                    self._start(handle, day, starting)
                    starting = False
                batch = list(itertools.islice(self._lines(handle), BATCH)) if handle else []
                if batch:
                    self._pass(handle, day, batch)
                else:
                    self._deliver(self.gate([]))  # the alert cap's window may clear without a new alert
                    if handle is not None and self._replaced(handle):
                        handle.close()
                        handle = None
                    stop_event.wait(poll)
        finally:
            if handle is not None:
                handle.close()

    def _start(self, handle, day, starting):
        """Set what of the capture just opened is only counted and what is alerted late: nothing of a
        file opened later on (a new day, a replaced file); for the one open at start, everything it
        holds, or with a saved position for it, only what lies before the position."""
        self.pending, self.line_no = b"", 0
        self.quiet_end = self.late_end = 0
        if handle is None or not starting:
            return
        stat = os.fstat(handle.fileno())
        self.quiet_end = self.late_end = stat.st_size
        saved = self._saved()
        if saved and saved[0] == day.isoformat() and saved[1] == stat.st_ino and saved[2] <= stat.st_size:
            self.quiet_end = saved[2]

    def _saved(self):
        """(day, inode, offset) of the saved position; None without a readable one."""
        try:
            position = json.loads(self.position.read_text())
            day, inode, offset = position["day"], position["inode"], position["offset"]
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if not (isinstance(day, str) and all(isinstance(n, int) and not isinstance(n, bool) and n >= 0
                                             for n in (inode, offset))):
            return None
        return day, inode, offset

    def _pass(self, handle, day, batch):
        """Scan one batch of (line, end offset, number), deliver what it raises, save the position."""
        if not batch:
            return
        parts = (([item for item in batch if item[1] <= self.quiet_end], "counted"),
                 ([item for item in batch if self.quiet_end < item[1] <= self.late_end], "late"),
                 ([item for item in batch if item[1] > self.late_end], "live"))
        items = []
        for part, mode in parts:
            if part:
                alerts = self.scan([line for line, _, _ in part], catch_up=mode == "counted", first_line=part[0][2])
                items += self.gate(alerts, late=mode == "late")
        self._deliver(items)
        self._save(day, handle, batch[-1][1])

    def _save(self, day, handle, offset):
        position = {"day": day.isoformat(), "inode": os.fstat(handle.fileno()).st_ino, "offset": offset}
        temporary = self.position.with_name(self.position.name + ".tmp")
        try:
            temporary.write_text(json.dumps(position) + "\n")
            os.replace(temporary, self.position)
        except OSError as e:
            if not self.position_failed:  # once: it would fail on every pass
                self.position_failed = True
                self.log(f"the watcher's position could not be saved ({e}); a restart will only count what it missed")

    def _deliver(self, items):
        if items:
            self.alert(items)

    def _open(self, day):
        try:
            return (self.capture_dir / f"spark-{day:%Y-%m-%d}.log").open("rb")
        except FileNotFoundError:
            return None

    def _lines(self, handle):
        """(line, the offset just past it, its number) for each complete line written to `handle` since
        the last read; a line still being written waits in `pending` for its end."""
        for raw in iter(handle.readline, b""):
            if not raw.endswith(b"\n"):
                self.pending += raw
                return
            raw, self.pending = self.pending + raw, b""
            self.line_no += 1
            yield raw.decode("utf-8", errors="replace"), handle.tell(), self.line_no

    @staticmethod
    def _replaced(handle):
        try:
            return os.stat(handle.name).st_ino != os.fstat(handle.fileno()).st_ino
        except FileNotFoundError:
            return True
