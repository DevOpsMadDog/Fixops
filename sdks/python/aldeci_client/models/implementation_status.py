from enum import Enum


class ImplementationStatus(str, Enum):
    BLOCKED = "blocked"
    IMPLEMENTED = "implemented"
    IN_PROGRESS = "in_progress"
    NOT_STARTED = "not_started"
    VERIFIED = "verified"

    def __str__(self) -> str:
        return str(self.value)
