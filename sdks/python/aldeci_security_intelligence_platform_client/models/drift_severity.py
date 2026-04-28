from enum import Enum


class DriftSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"

    def __str__(self) -> str:
        return str(self.value)
