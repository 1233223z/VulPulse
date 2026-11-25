"""Channel abstraction and the message passed to every channel."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class NotificationMessage:
    subject: str
    text: str
    markdown: str
    url: str


class NotificationChannel(ABC):
    name: str = "base"

    @abstractmethod
    async def send(self, message: NotificationMessage) -> None:
        """Deliver one message or raise an exception."""

    async def close(self) -> None:
        """Release resources. The default implementation is a no-op."""
        return None
