from enum import Enum


class Channel(str, Enum):
    EMAIL = "email"
    IN_APP = "in_app"
    SLACK = "slack"
    WEBHOOK = "webhook"

    def __str__(self) -> str:
        return str(self.value)
