from enum import Enum


class RemediationStatus(str, Enum):
    ACCEPTED = "accepted"
    IN_PROGRESS = "in_progress"
    OPEN = "open"
    RESOLVED = "resolved"

    def __str__(self) -> str:
        return str(self.value)
