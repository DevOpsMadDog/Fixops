from enum import Enum


class MetricTrend(str, Enum):
    DOWN = "down"
    STABLE = "stable"
    UP = "up"

    def __str__(self) -> str:
        return str(self.value)
