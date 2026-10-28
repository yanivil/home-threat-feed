"""The lock that keeps the daily check and the Telegram bot from writing the feed at once.

    with FeedLock(Path("syslog") / LOCK_NAME):
        ...  # edit spark-ioc-feed.csv, commit, push

The lock is a directory because mkdir is atomic and both Python and daily_check.sh, which takes
the same one, can make it. A holder that died without releasing leaves the directory behind, so
one older than `stale_after` seconds is taken over (daily_check.sh uses the same 180 minutes).
Standard library only.
"""

import os
import time

LOCK_NAME = ".feed-lock"  # under the capture directory
STALE_AFTER = 10800
WAIT_TIMEOUT = 600
POLL_SECONDS = 5


class LockTimeout(Exception):
    """The lock stayed held for the whole wait."""


class FeedLock:
    def __init__(self, path, stale_after=STALE_AFTER, sleep=time.sleep, now=time.time):
        self.path = path
        self.stale_after = stale_after
        self.sleep = sleep
        self.now = now

    def acquire(self, timeout=WAIT_TIMEOUT):
        """Take the lock, waiting up to `timeout` seconds for its holder; False if it stayed held.

        A missing parent directory is a misconfiguration, not a held lock: FileNotFoundError
        propagates.
        """
        started = self.now()
        while True:
            try:
                os.mkdir(self.path)
                return True
            except FileExistsError:
                pass
            try:
                age = self.now() - os.stat(self.path).st_mtime
            except FileNotFoundError:
                continue  # released since the mkdir: take it
            if age > self.stale_after:
                self.release()  # its holder is long gone
                continue
            waited = self.now() - started
            if waited >= timeout:
                return False
            self.sleep(min(POLL_SECONDS, timeout - waited))

    def release(self):
        try:
            os.rmdir(self.path)
        except FileNotFoundError:
            pass

    def __enter__(self):
        if not self.acquire():
            raise LockTimeout(f"{self.path} is held by another process")
        return self

    def __exit__(self, *exc_info):
        self.release()
