from enum import Enum


class BackupStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    IN_PROGRESS = "in_progress"
    PENDING = "pending"
    VERIFIED = "verified"

    def __str__(self) -> str:
        return str(self.value)
