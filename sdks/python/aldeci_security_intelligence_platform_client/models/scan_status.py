from enum import Enum


class ScanStatus(str, Enum):
    COMPLETE = "complete"
    FAILED = "failed"
    PENDING = "pending"
    RUNNING = "running"

    def __str__(self) -> str:
        return str(self.value)
