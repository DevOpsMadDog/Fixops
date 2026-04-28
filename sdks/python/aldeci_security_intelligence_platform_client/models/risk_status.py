from enum import Enum


class RiskStatus(str, Enum):
    ACCEPTED = "accepted"
    CLOSED = "closed"
    IN_TREATMENT = "in_treatment"
    OPEN = "open"
    TRANSFERRED = "transferred"

    def __str__(self) -> str:
        return str(self.value)
