from enum import Enum


class ChangeRisk(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    LOW = "low"
    MEDIUM = "medium"
    NONE = "none"

    def __str__(self) -> str:
        return str(self.value)
