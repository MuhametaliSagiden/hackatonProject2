import httpx


class TelegramChannel:
    def __init__(self, token, chat_id, client: httpx.Client | None = None):
        self.url = f"https://api.telegram.org/bot{token}/sendMessage"
        self.chat_id = chat_id
        self.client = client

    def send(self, message):
        if self.client:
            response = self.client.post(
                self.url,
                data={"chat_id": self.chat_id, "text": message},
                timeout=10,
            )
        else:
            response = httpx.post(
                self.url,
                data={"chat_id": self.chat_id, "text": message},
                timeout=10,
            )
        response.raise_for_status()
        return True
