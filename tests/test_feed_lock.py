"""feed_lock.py: the lock directory the daily check and the Telegram bot take before they write the feed."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import feed_lock
from feed_lock import FeedLock, LockTimeout

HOUR = 3600


class Clock:
    """A fake `now` and `sleep`: sleeping records the wait and moves the time on by it."""

    def __init__(self, start=1_000_000.0):
        self.time = start
        self.sleeps = []

    def now(self):
        return self.time

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.time += seconds


class FeedLockTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.path = self.dir / feed_lock.LOCK_NAME
        self.clock = Clock()

    def lock(self, **kwargs):
        return FeedLock(self.path, sleep=self.clock.sleep, now=self.clock.now, **kwargs)

    def hold(self, age=0):
        """Another process's lock, taken `age` seconds before the fake clock's now."""
        self.path.mkdir()
        taken = self.clock.time - age
        os.utime(self.path, (taken, taken))

    def test_the_lock_is_a_directory_named_feed_lock(self):
        self.assertEqual(feed_lock.LOCK_NAME, ".feed-lock")

    def test_acquire_makes_the_directory_and_release_removes_it(self):
        lock = FeedLock(self.path)  # the real clock and sleep

        self.assertTrue(lock.acquire())
        self.assertTrue(self.path.is_dir())

        lock.release()
        self.assertFalse(self.path.exists())

    def test_release_when_the_directory_is_already_gone_is_harmless(self):
        lock = self.lock()
        lock.acquire()

        lock.release()
        lock.release()

        self.assertFalse(self.path.exists())

    def test_a_held_lock_is_waited_on_in_five_second_steps_never_past_the_timeout(self):
        self.hold()
        start = self.clock.time

        self.assertFalse(self.lock().acquire(timeout=12))

        self.assertEqual(self.clock.sleeps, [5, 5, 2])
        self.assertEqual(self.clock.time - start, 12)
        self.assertTrue(self.path.is_dir(), "the other holder's lock must be left alone")

    def test_the_default_wait_is_ten_minutes(self):
        self.hold()

        self.assertFalse(self.lock().acquire())

        self.assertEqual(sum(self.clock.sleeps), 600)
        self.assertEqual(set(self.clock.sleeps), {5})

    def test_a_lock_released_during_the_wait_is_taken(self):
        self.hold()

        def holder_finishes_during_the_second_sleep(seconds):
            self.clock.sleep(seconds)
            if len(self.clock.sleeps) == 2:
                self.path.rmdir()

        lock = FeedLock(self.path, sleep=holder_finishes_during_the_second_sleep, now=self.clock.now)

        self.assertTrue(lock.acquire())
        self.assertEqual(self.clock.sleeps, [5, 5])
        self.assertTrue(self.path.is_dir())

    def test_a_lock_older_than_three_hours_is_stale_and_taken_at_once(self):
        self.hold(age=4 * HOUR)

        self.assertTrue(self.lock().acquire())

        self.assertEqual(self.clock.sleeps, [])
        self.assertTrue(self.path.is_dir())

    def test_a_lock_two_hours_old_is_still_held(self):
        self.hold(age=2 * HOUR)

        self.assertFalse(self.lock().acquire(timeout=5))
        self.assertTrue(self.path.is_dir())

    def test_stale_after_sets_how_old_a_lock_must_be_to_be_taken_over(self):
        self.hold(age=2 * HOUR)

        self.assertTrue(self.lock(stale_after=HOUR).acquire())
        self.assertEqual(self.clock.sleeps, [])

    def test_a_lock_that_vanishes_before_its_age_is_read_is_taken_at_once(self):
        self.hold(age=4 * HOUR)
        real_stat = os.stat
        released = []

        def holder_releases_first(path, *args, **kwargs):
            if not released and Path(path) == self.path:
                released.append(True)
                os.rmdir(path)
            return real_stat(path, *args, **kwargs)

        with mock.patch("os.stat", holder_releases_first):
            self.assertTrue(self.lock().acquire())

        self.assertEqual(self.clock.sleeps, [])
        self.assertTrue(self.path.is_dir())

    def test_a_stale_lock_someone_else_removes_first_is_not_an_error(self):
        self.hold(age=4 * HOUR)
        real_rmdir = os.rmdir

        def other_process_removes_it_first(path, *args, **kwargs):
            real_rmdir(path, *args, **kwargs)
            raise FileNotFoundError(path)

        with mock.patch("os.rmdir", other_process_removes_it_first):
            self.assertTrue(self.lock().acquire())

        self.assertEqual(self.clock.sleeps, [])
        self.assertTrue(self.path.is_dir())

    def test_a_missing_parent_directory_is_an_error_not_a_held_lock(self):
        lock = FeedLock(self.dir / "no-such-dir" / feed_lock.LOCK_NAME, sleep=self.clock.sleep, now=self.clock.now)

        with self.assertRaises(FileNotFoundError):
            lock.acquire()
        self.assertEqual(self.clock.sleeps, [])

    def test_with_holds_the_lock_for_the_block_and_releases_it_after_an_error(self):
        with self.lock():
            self.assertTrue(self.path.is_dir())
        self.assertFalse(self.path.exists())

        with self.assertRaises(ValueError):
            with self.lock():
                raise ValueError("the block failed")
        self.assertFalse(self.path.exists())

    def test_with_raises_lock_timeout_after_the_default_wait_when_the_lock_is_held(self):
        self.hold()
        entered = []

        with self.assertRaises(LockTimeout):
            with self.lock():
                entered.append(True)

        self.assertEqual(entered, [])
        self.assertEqual(sum(self.clock.sleeps), 600)
        self.assertTrue(self.path.is_dir(), "the other holder's lock must be left alone")


if __name__ == "__main__":
    unittest.main()
