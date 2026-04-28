from enum import Enum


class RiskTier(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"

    def __str__(self) -> str:
        return str(self.value)
