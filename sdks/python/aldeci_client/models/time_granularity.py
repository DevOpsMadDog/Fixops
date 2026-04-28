from enum import Enum


class TimeGranularity(str, Enum):
    DAILY = "daily"
    MONTHLY = "monthly"
    WEEKLY = "weekly"

    def __str__(self) -> str:
        return str(self.value)
