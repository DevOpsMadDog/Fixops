from enum import Enum


class TrendPeriod(str, Enum):
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    WEEKLY = "weekly"

    def __str__(self) -> str:
        return str(self.value)
