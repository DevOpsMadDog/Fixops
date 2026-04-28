from enum import Enum


class TrendDirection(str, Enum):
    DEGRADING = "degrading"
    IMPROVING = "improving"
    STABLE = "stable"

    def __str__(self) -> str:
        return str(self.value)
