from enum import Enum


class LicenseRisk(str, Enum):
    HIGH = "high"
    LOW = "low"
    MEDIUM = "medium"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return str(self.value)
