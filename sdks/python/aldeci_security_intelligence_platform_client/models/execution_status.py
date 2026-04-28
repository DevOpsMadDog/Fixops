from enum import Enum


class ExecutionStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"
    PENDING = "pending"
    RUNNING = "running"

    def __str__(self) -> str:
        return str(self.value)
