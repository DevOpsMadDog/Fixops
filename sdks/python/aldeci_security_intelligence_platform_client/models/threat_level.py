from enum import Enum


class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    LOW = "low"
    MEDIUM = "medium"
    NONE = "none"

    def __str__(self) -> str:
        return str(self.value)
