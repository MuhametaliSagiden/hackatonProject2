import httpx

from radar.notify.email import EmailChannel
from radar.notify.telegram import TelegramChannel


def test_email_channel(monkeypatch):
    sent = []

    class SMTP:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def send_message(self, message):
            sent.append(message)

    monkeypatch.setattr("smtplib.SMTP", SMTP)
    assert EmailChannel("localhost", 25, "radar@example", ["admin@example"]).send("test")
    assert len(sent) == 1


def test_email_channel_authentication(monkeypatch):
    credentials = []

    class SMTP:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def login(self, user, password):
            credentials.append((user, password))

        def send_message(self, message):
            pass

    monkeypatch.setattr("smtplib.SMTP", SMTP)
    assert EmailChannel("localhost", 25, "radar@example", ["admin@example"], "user", "password").send("test")
    assert credentials == [("user", "password")]


def test_telegram_channel(monkeypatch):
    class Response:
        def raise_for_status(self):
            pass

    monkeypatch.setattr("httpx.post", lambda *args, **kwargs: Response())
    assert TelegramChannel("token", "chat").send("test")


def test_telegram_channel_mock_transport():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"ok": True})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert TelegramChannel("token", "chat", client).send("test")

    assert requests[0].url.path == "/bottoken/sendMessage"
    assert requests[0].content == b"chat_id=chat&text=test"
