from enum import Enum


class AnomalyType(str, Enum):
    DRIFT = "drift"
    DROP = "drop"
    PATTERN_BREAK = "pattern_break"
    SPIKE = "spike"
    THRESHOLD_BREACH = "threshold_breach"
    UNUSUAL_TIMING = "unusual_timing"

    def __str__(self) -> str:
        return str(self.value)
