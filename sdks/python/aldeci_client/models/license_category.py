from enum import Enum


class LicenseCategory(str, Enum):
    NON_COMMERCIAL = "non_commercial"
    PERMISSIVE = "permissive"
    PROPRIETARY = "proprietary"
    STRONG_COPYLEFT = "strong_copyleft"
    UNKNOWN = "unknown"
    WEAK_COPYLEFT = "weak_copyleft"

    def __str__(self) -> str:
        return str(self.value)
