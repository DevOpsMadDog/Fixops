from enum import Enum


class FindingStatus(str, Enum):
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    IN_PROGRESS = "in_progress"
    OPEN = "open"
    RESOLVED = "resolved"

    def __str__(self) -> str:
        return str(self.value)
