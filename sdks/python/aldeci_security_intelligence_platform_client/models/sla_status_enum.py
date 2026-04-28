from enum import Enum


class SLAStatusEnum(str, Enum):
    AT_RISK = "AT_RISK"
    BREACHED = "BREACHED"
    ON_TRACK = "ON_TRACK"
    RESOLVED = "RESOLVED"

    def __str__(self) -> str:
        return str(self.value)
