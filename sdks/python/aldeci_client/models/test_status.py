from enum import Enum


class TestStatus(str, Enum):
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    FAILED = "failed"
    RUNNING = "running"
    SCHEDULED = "scheduled"

    def __str__(self) -> str:
        return str(self.value)
