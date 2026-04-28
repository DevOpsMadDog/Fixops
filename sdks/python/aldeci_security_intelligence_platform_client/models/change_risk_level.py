from enum import Enum


class ChangeRiskLevel(str, Enum):
    EMERGENCY = "emergency"
    NORMAL = "normal"
    STANDARD = "standard"

    def __str__(self) -> str:
        return str(self.value)
