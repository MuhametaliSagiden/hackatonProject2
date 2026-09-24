from radar.notify.email import EmailChannel
from radar.notify.telegram import TelegramChannel

def test_email_channel(monkeypatch):
    sent=[]
    class SMTP:
        def __init__(self,*args,**kwargs): pass
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def send_message(self,message): sent.append(message)
    monkeypatch.setattr("smtplib.SMTP", SMTP)
    assert EmailChannel("localhost",25,"radar@example",["admin@example"]).send("test")
    assert len(sent) == 1

def test_telegram_channel(monkeypatch):
    class Response:
        def raise_for_status(self): pass
    monkeypatch.setattr("httpx.post", lambda *args,**kwargs: Response())
    assert TelegramChannel("token","chat").send("test")
