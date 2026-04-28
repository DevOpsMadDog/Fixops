from enum import Enum


class SegmentationStatus(str, Enum):
    COMPLIANT = "compliant"
    UNKNOWN = "unknown"
    VIOLATION = "violation"
    WARNING = "warning"

    def __str__(self) -> str:
        return str(self.value)
