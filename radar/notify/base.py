from typing import Protocol


class Channel(Protocol):
    def send(self, message: str) -> bool: ...
