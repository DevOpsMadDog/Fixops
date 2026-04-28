from enum import Enum


class DigestFrequency(str, Enum):
    DAILY = "daily"
    HOURLY = "hourly"
    IMMEDIATE = "immediate"
    WEEKLY = "weekly"

    def __str__(self) -> str:
        return str(self.value)
