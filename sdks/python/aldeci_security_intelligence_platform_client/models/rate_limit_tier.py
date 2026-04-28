from enum import Enum


class RateLimitTier(str, Enum):
    ADMIN = "admin"
    DEFAULT = "default"
    QUERY = "query"
    SCAN = "scan"
    WEBHOOK = "webhook"
    WRITE = "write"

    def __str__(self) -> str:
        return str(self.value)
