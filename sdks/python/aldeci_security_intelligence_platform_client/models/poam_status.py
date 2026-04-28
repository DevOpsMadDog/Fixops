from enum import Enum


class POAMStatus(str, Enum):
    COMPLETED = "completed"
    DELAYED = "delayed"
    IN_PROGRESS = "in_progress"
    OPEN = "open"
    RISK_ACCEPTED = "risk_accepted"

    def __str__(self) -> str:
        return str(self.value)
