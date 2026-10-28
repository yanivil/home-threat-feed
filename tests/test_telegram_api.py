import email
import io
import json
import traceback
import unittest
import urllib.error
from unittest.mock import patch

import telegram_api

TOKEN = "123456:SECRET-token"


class FakeHttp:
    """An `http` stand-in. Records (url, data, headers) as they would go on the wire (a JSON call's dict
    encoded the way the default http encodes it) and answers with the scripted replies in order, the
    last one repeating. A reply is a body dict (HTTP 200) or a (status, body) pair."""

    def __init__(self, *replies):
        self.replies = replies
        self.calls = []
        self.timeouts = []

    def __call__(self, url, data=None, headers=None, timeout=60):
        if "Content-Type" not in (headers or {}):
            data = json.dumps(data).encode()
        self.calls.append((url, data, headers))
        self.timeouts.append(timeout)
        reply = self.replies[min(len(self.calls), len(self.replies)) - 1]
        return reply if isinstance(reply, tuple) else (200, reply)


def sent(message_id):
    return {"ok": True, "result": {"message_id": message_id}}


class SendMessageTest(unittest.TestCase):
    def test_posts_plain_text_to_the_owner(self):
        http = FakeHttp(sent(7))
        tg = telegram_api.Telegram("T", 42, http=http)

        self.assertEqual(tg.send_message("hello"), [7])

        url, data, _ = http.calls[0]
        self.assertEqual(url, "https://api.telegram.org/botT/sendMessage")
        self.assertEqual(json.loads(data), {"chat_id": 42, "text": "hello", "disable_web_page_preview": True})

    def test_long_text_goes_out_as_one_message_per_part_in_order(self):
        text = "\n".join(f"line {i:04}" for i in range(600))
        http = FakeHttp(sent(7), sent(8))
        tg = telegram_api.Telegram("T", 42, http=http)

        self.assertEqual(tg.send_message(text), [7, 8])

        texts = [json.loads(data)["text"] for _, data, _ in http.calls]
        self.assertEqual(len(texts), 2)
        self.assertTrue(all(len(t) <= 4096 for t in texts))
        self.assertEqual("\n".join(texts), text)


class ChunksTest(unittest.TestCase):
    def test_long_text_is_split_at_line_boundaries(self):
        lines = [f"line {i:04}" for i in range(600)]  # 5,999 characters
        parts = telegram_api.chunks("\n".join(lines))
        self.assertEqual(len(parts), 2)
        self.assertTrue(all(len(p) <= 4096 for p in parts))
        self.assertEqual("\n".join(parts).split("\n"), lines)

    def test_text_that_fits_is_one_part(self):
        self.assertEqual(telegram_api.chunks("a\nb"), ["a\nb"])
        self.assertEqual(telegram_api.chunks("x" * 4096), ["x" * 4096])

    def test_a_newline_right_at_the_limit_ends_the_part(self):
        self.assertEqual(telegram_api.chunks("x" * 10 + "\nyy", limit=10), ["x" * 10, "yy"])

    def test_a_line_longer_than_the_limit_is_cut_at_the_limit(self):
        parts = telegram_api.chunks("short\n" + "x" * 25 + "\ntail", limit=10)

        self.assertEqual(parts, ["short", "x" * 10, "x" * 10, "x" * 5 + "\ntail"])
        self.assertTrue(all(len(p) <= 10 for p in parts))

    def test_empty_text_is_one_empty_part(self):
        self.assertEqual(telegram_api.chunks(""), [""])


class SendDocumentTest(unittest.TestCase):
    def test_is_multipart_with_the_file(self):
        http = FakeHttp(sent(9))
        tg = telegram_api.Telegram("T", 42, http=http)
        report = b"1.2.3.4 12\n5.6.7.8 3\n"

        self.assertEqual(tg.send_document("sources-2026-10-28.txt", report, caption="Top sources"), 9)

        url, data, headers = http.calls[0]
        self.assertEqual(url, "https://api.telegram.org/botT/sendDocument")
        self.assertIn("multipart/form-data; boundary=", headers["Content-Type"])
        self.assertIn(b'filename="sources-2026-10-28.txt"', data)
        self.assertIn(b"1.2.3.4 12", data)

    def test_parts_carry_the_chat_the_caption_and_the_file_untouched(self):
        http = FakeHttp(sent(9))
        tg = telegram_api.Telegram("T", 42, http=http)
        report = "1.2.3.4 12\r\n5.6.7.8 3\né".encode()

        tg.send_document("s.txt", report, caption="Top sources")

        _, data, headers = http.calls[0]
        message = email.message_from_bytes(b"Content-Type: " + headers["Content-Type"].encode() + b"\r\n\r\n" + data)
        parts = {part.get_param("name", header="content-disposition"): part for part in message.get_payload()}
        self.assertEqual(set(parts), {"chat_id", "caption", "document"})
        self.assertEqual(parts["chat_id"].get_payload(), "42")
        self.assertEqual(parts["caption"].get_payload(decode=True).decode(), "Top sources")
        self.assertEqual(parts["document"].get_filename(), "s.txt")
        self.assertEqual(parts["document"].get_content_type(), "text/plain")
        self.assertEqual(parts["document"].get_payload(decode=True), report)

    def test_no_caption_field_when_the_caption_is_empty(self):
        http = FakeHttp(sent(9))

        telegram_api.Telegram("T", 42, http=http).send_document("s.txt", b"x")

        self.assertNotIn(b'name="caption"', http.calls[0][1])

    def test_every_call_gets_its_own_boundary(self):
        http = FakeHttp(sent(9))
        tg = telegram_api.Telegram("T", 42, http=http)

        tg.send_document("s.txt", b"x")
        tg.send_document("s.txt", b"x")

        self.assertNotEqual(http.calls[0][2]["Content-Type"], http.calls[1][2]["Content-Type"])


class GetUpdatesTest(unittest.TestCase):
    def test_passes_offset_and_long_poll_timeout(self):
        updates = [{"update_id": 10, "message": {"text": "/status"}}]
        http = FakeHttp({"ok": True, "result": updates})
        tg = telegram_api.Telegram("T", 42, http=http)

        self.assertEqual(tg.get_updates(10), updates)

        url, data, _ = http.calls[0]
        self.assertEqual(url, "https://api.telegram.org/botT/getUpdates")
        self.assertEqual(json.loads(data), {"offset": 10, "timeout": 50})

    def test_the_http_timeout_outlasts_the_long_poll(self):
        http = FakeHttp({"ok": True, "result": []})
        tg = telegram_api.Telegram("T", 42, http=http)

        tg.get_updates(0)
        tg.get_updates(0, timeout=5)

        self.assertGreater(http.timeouts[0], 50)
        self.assertGreater(http.timeouts[1], 5)
        self.assertEqual(json.loads(http.calls[1][1])["timeout"], 5)


class ErrorTest(unittest.TestCase):
    def raised(self, reply):
        tg = telegram_api.Telegram(TOKEN, 42, http=FakeHttp(reply))
        with self.assertRaises(telegram_api.TelegramError) as caught:
            tg.send_message("hello")
        return str(caught.exception)

    def test_not_ok_raises_with_the_apis_description(self):
        message = self.raised((200, {"ok": False, "description": "Bad Request: chat not found"}))

        self.assertEqual(message, "Bad Request: chat not found")

    def test_not_ok_without_a_description_still_raises(self):
        self.assertTrue(self.raised((200, {"ok": False})))

    def test_bad_gateway_with_an_empty_body_raises(self):
        self.assertTrue(self.raised((502, {})))

    def test_http_error_is_not_masked_by_ok_true(self):
        self.assertTrue(self.raised((401, {"ok": True})))

    def test_the_message_never_carries_the_url_or_token(self):
        for reply in [(200, {"ok": False}), (502, {}), (404, {"ok": False, "description": "Not Found"})]:
            with self.subTest(reply=reply):
                message = self.raised(reply)
                self.assertNotIn("SECRET", message)
                self.assertNotIn("api.telegram.org", message)

    def test_every_method_checks_its_response(self):
        calls = {
            "send_message": lambda tg: tg.send_message("hello"),
            "send_document": lambda tg: tg.send_document("s.txt", b"x"),
            "get_updates": lambda tg: tg.get_updates(0),
        }
        for name, call in calls.items():
            with self.subTest(name):
                tg = telegram_api.Telegram(TOKEN, 42, http=FakeHttp((502, {})))
                with self.assertRaises(telegram_api.TelegramError):
                    call(tg)


class FromKeychainTest(unittest.TestCase):
    def items(self, **stored):
        return patch("keychain.item", side_effect=lambda account, *a, **k: stored.get(account, ""))

    def test_needs_both_items(self):
        with self.items(TELEGRAM_BOT_TOKEN="T"):
            self.assertIsNone(telegram_api.from_keychain())
        with self.items(TELEGRAM_CHAT_ID="42"):
            self.assertIsNone(telegram_api.from_keychain())
        with self.items():
            self.assertIsNone(telegram_api.from_keychain())

    def test_builds_the_client_with_the_chat_id_as_an_int(self):
        # The owner's private chat: its id is the owner's user id, a positive integer.
        with self.items(TELEGRAM_BOT_TOKEN="T", TELEGRAM_CHAT_ID="4242"):
            tg = telegram_api.from_keychain()

        self.assertEqual((tg.token, tg.chat_id), ("T", 4242))

    def test_a_chat_id_that_is_not_a_number_is_an_error_that_never_carries_it(self):
        # With the two items swapped, the stored chat id is the bot token: it must reach no log.
        for stored in ("abc-123-secret", "123456:SECRET-token", "42 43", "4.2", "4_2", "\u0664\u0662"):
            with self.subTest(stored=stored), self.items(TELEGRAM_BOT_TOKEN="T", TELEGRAM_CHAT_ID=stored):
                with self.assertRaises(telegram_api.TelegramError) as caught:
                    telegram_api.from_keychain()

                self.assertEqual(str(caught.exception), "TELEGRAM_CHAT_ID is not a number")
                printed = "".join(traceback.format_exception(type(caught.exception), caught.exception,
                                                             caught.exception.__traceback__))
                self.assertNotIn(stored, printed)


class DefaultHttpTest(unittest.TestCase):
    """The urllib implementation, with urlopen replaced: nothing here touches the network."""

    def response(self, body, status=200):
        response = io.BytesIO(body)
        response.status = status
        return response

    def http_error(self, status, body=b""):
        return urllib.error.HTTPError("https://api.telegram.org/bot/x", status, "x", {}, io.BytesIO(body))

    def test_json_data_goes_out_as_a_json_post(self):
        with patch("urllib.request.urlopen", return_value=self.response(b'{"ok": true}')) as urlopen:
            reply = telegram_api.default_http("https://example.test/m", {"a": 1}, timeout=12)

        self.assertEqual(reply, (200, {"ok": True}))
        request = urlopen.call_args[0][0]
        self.assertEqual(request.full_url, "https://example.test/m")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.data, b'{"a": 1}')
        self.assertEqual(request.get_header("Content-type"), "application/json")
        self.assertEqual(urlopen.call_args[1]["timeout"], 12)

    def test_given_content_type_means_the_data_is_already_encoded(self):
        headers = {"Content-Type": "multipart/form-data; boundary=b"}
        with patch("urllib.request.urlopen", return_value=self.response(b"{}")) as urlopen:
            telegram_api.default_http("https://example.test/m", b"raw bytes", headers)

        request = urlopen.call_args[0][0]
        self.assertEqual(request.data, b"raw bytes")
        self.assertEqual(request.get_header("Content-type"), "multipart/form-data; boundary=b")

    def test_an_error_status_returns_its_json_body(self):
        error = self.http_error(400, b'{"ok": false, "description": "Bad Request"}')
        with patch("urllib.request.urlopen", side_effect=error):
            reply = telegram_api.default_http("https://example.test/m", {})

        self.assertEqual(reply, (400, {"ok": False, "description": "Bad Request"}))

    def test_an_error_status_with_an_empty_or_odd_body_returns_an_empty_dict(self):
        for body in (b"", b"<html>Bad Gateway</html>", b"[1, 2]"):
            with self.subTest(body=body), patch("urllib.request.urlopen", side_effect=self.http_error(502, body)):
                self.assertEqual(telegram_api.default_http("https://example.test/m", {}), (502, {}))

    def test_a_success_status_with_a_body_that_is_not_json_returns_an_empty_dict(self):
        with patch("urllib.request.urlopen", return_value=self.response(b"<html>portal</html>")):
            self.assertEqual(telegram_api.default_http("https://example.test/m", {}), (200, {}))

    def test_network_failures_propagate_for_the_caller_to_retry(self):
        for failure in (urllib.error.URLError("down"), TimeoutError()):
            with self.subTest(failure=failure), patch("urllib.request.urlopen", side_effect=failure):
                with self.assertRaises(type(failure)):
                    telegram_api.default_http("https://example.test/m", {})

    def test_telegram_uses_it_unless_given_another(self):
        tg = telegram_api.Telegram("T", 42)

        self.assertIs(tg.http, telegram_api.default_http)

