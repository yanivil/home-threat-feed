import unittest
from unittest.mock import Mock

import keychain
from tests.test_vt_check import keychain_with


class ItemTest(unittest.TestCase):
    def test_environment_variable_wins_over_the_keychain(self):
        run = keychain_with("from-keychain")

        self.assertEqual(
            keychain.item("ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY", environ={"ANTHROPIC_API_KEY": " k1 "}, run=run),
            "k1",
        )
        self.assertEqual(run.calls, [])

    def test_keychain_item_is_read_with_the_service_and_account(self):
        run = keychain_with("tok")

        self.assertEqual(keychain.item("TELEGRAM_BOT_TOKEN", environ={}, run=run), "tok")
        self.assertEqual(
            run.calls,
            [["security", "find-generic-password", "-s", "spark-ioc-feed", "-a", "TELEGRAM_BOT_TOKEN", "-w"]],
        )

    def test_missing_item_and_failing_security_give_empty(self):
        self.assertEqual(keychain.item("X", environ={}, run=keychain_with(None)), "")
        self.assertEqual(keychain.item("X", environ={}, run=Mock(side_effect=OSError)), "")
