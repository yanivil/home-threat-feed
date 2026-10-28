"""Telegram Bot API transport: plain-text messages, documents and long-poll updates.

The bot token and the owner's chat id live in the login Keychain (see from_keychain). Every
call goes through an `http(url, data=None, headers=None, timeout=60) -> (status, body_dict)`
callable, so tests pass a fake. The URL carries the token: nothing here logs it or puts it
into an exception.
"""

import json
import re
import secrets
import urllib.error
import urllib.request

import keychain

API = "https://api.telegram.org/bot{token}/{method}"
MESSAGE_LIMIT = 4096  # characters per sendMessage text
HTTP_MARGIN = 10  # seconds the HTTP timeout outlasts a long poll
CHAT_ID_RE = re.compile(r"-?[0-9]+")


class TelegramError(Exception):
    """A call Telegram refused or could not answer; the message never includes the URL."""


def read_json(fp):
    """The JSON object in `fp`, or {} when it holds none."""
    try:
        body = json.load(fp)
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def default_http(url, data=None, headers=None, timeout=60):
    """POST to `url`; `data` is a dict sent as JSON unless `headers` gives a Content-Type, in
    which case it is the bytes to send. Returns (status, body_dict), an error status included;
    URLError and timeouts propagate."""
    headers = dict(headers or {})
    if "Content-Type" not in headers:
        data = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, read_json(response)
    except urllib.error.HTTPError as e:
        return e.code, read_json(e)


def chunks(text, limit=MESSAGE_LIMIT):
    """`text` in parts of at most `limit` characters, each cut at the last newline before the limit
    (the newline itself dropped), a line longer than the limit cut at the limit. No part is empty,
    except the one part of an empty text: Telegram refuses an empty message."""
    parts = []
    while len(text) > limit:
        cut = text.rfind("\n", 1, limit + 1)
        if cut == -1:
            parts.append(text[:limit])
            text = text[limit:]
        else:
            parts.append(text[:cut])
            text = text[cut + 1:]
    if text or not parts:
        parts.append(text)
    return parts


def multipart(fields, filename, content):
    """(Content-Type header value, body) of a multipart/form-data upload: the text `fields`, then
    `content` as the file part "document"."""
    boundary = secrets.token_hex(16)
    body = b""
    for name, value in fields.items():
        body += (f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n').encode()
    body += (f'--{boundary}\r\nContent-Disposition: form-data; name="document"; filename="{filename}"\r\n'
             f'Content-Type: text/plain\r\n\r\n').encode()
    body += content + f"\r\n--{boundary}--\r\n".encode()
    return f"multipart/form-data; boundary={boundary}", body


class Telegram:
    def __init__(self, token, chat_id, http=None):
        self.token = token
        self.chat_id = chat_id
        self.http = http or default_http

    def call(self, method, data, headers=None, timeout=60):
        """The `result` of a Bot API method; TelegramError unless HTTP 200 with ok true."""
        url = API.format(token=self.token, method=method)
        status, body = self.http(url, data, headers, timeout)
        if status != 200 or not body.get("ok"):
            raise TelegramError(body.get("description") or f"{method} failed (HTTP {status})")
        if "result" not in body:
            raise TelegramError(f"{method} answered without a result")
        return body["result"]

    def send_message(self, text):
        """Send `text` as plain text to the owner, in several messages when it is over the limit.
        Returns the message ids."""
        return [self.call("sendMessage", {"chat_id": self.chat_id, "text": part,
                                          "disable_web_page_preview": True})["message_id"]
                for part in chunks(text)]

    def send_document(self, filename, data, caption=""):
        """Send the bytes `data` to the owner as the text file `filename`. Returns the message id."""
        fields = {"chat_id": self.chat_id}
        if caption:
            fields["caption"] = caption
        content_type, body = multipart(fields, filename, data)
        return self.call("sendDocument", body, {"Content-Type": content_type})["message_id"]

    def get_updates(self, offset, timeout=50):
        """The updates from `offset` on, waiting up to `timeout` seconds for one (long poll)."""
        return self.call("getUpdates", {"offset": offset, "timeout": timeout},
                         timeout=timeout + HTTP_MARGIN)


def from_keychain():
    """The client for the bot in the Keychain, None when its token or the owner's chat id is missing.
    Raises TelegramError("TELEGRAM_CHAT_ID is not a number") when the stored chat id is not an
    integer; the message never carries the value, which may be the token (the items swapped)."""
    token = keychain.item("TELEGRAM_BOT_TOKEN")
    chat_id = keychain.item("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return None
    if not CHAT_ID_RE.fullmatch(chat_id):  # int() would echo the value in its ValueError
        raise TelegramError("TELEGRAM_CHAT_ID is not a number")
    return Telegram(token, int(chat_id))
