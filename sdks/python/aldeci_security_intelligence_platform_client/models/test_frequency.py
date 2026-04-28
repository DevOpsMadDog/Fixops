from enum import Enum


class TestFrequency(str, Enum):
    DAILY = "daily"
    MONTHLY = "monthly"
    ONCE = "once"
    QUARTERLY = "quarterly"
    WEEKLY = "weekly"

    def __str__(self) -> str:
        return str(self.value)
