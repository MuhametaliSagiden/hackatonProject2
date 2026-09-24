from email.message import EmailMessage
import smtplib


class EmailChannel:
    def __init__(
        self,
        host: str,
        port: int,
        sender: str,
        recipients: list[str],
        user: str | None = None,
        password: str | None = None,
    ):
        self.host = host
        self.port = port
        self.sender = sender
        self.recipients = recipients
        self.user = user
        self.password = password

    def send(self, message: str) -> bool:
        email = EmailMessage()
        email["Subject"] = "Certificate Radar"
        email["From"] = self.sender
        email["To"] = ", ".join(self.recipients)
        email.set_content(message)

        if self.port == 465:
            smtp = smtplib.SMTP_SSL(self.host, self.port, timeout=10)
        else:
            smtp = smtplib.SMTP(self.host, self.port, timeout=10)

        with smtp:
            if self.user and self.password:
                smtp.login(self.user, self.password)
            smtp.send_message(email)
        return True
