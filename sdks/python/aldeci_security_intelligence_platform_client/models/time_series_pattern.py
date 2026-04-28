from enum import Enum


class TimeSeriesPattern(str, Enum):
    DROP = "drop"
    SEASONALITY_VIOLATION = "seasonality_violation"
    SPIKE = "spike"
    TREND_DOWN = "trend_down"
    TREND_UP = "trend_up"

    def __str__(self) -> str:
        return str(self.value)
