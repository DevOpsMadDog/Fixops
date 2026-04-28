from enum import Enum


class ReportFrequency(str, Enum):
    MONTHLY = "monthly"
    ON_DEMAND = "on_demand"
    QUARTERLY = "quarterly"
    WEEKLY = "weekly"

    def __str__(self) -> str:
        return str(self.value)
