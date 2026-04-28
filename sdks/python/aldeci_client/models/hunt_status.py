from enum import Enum


class HuntStatus(str, Enum):
    ACTIVE = "active"
    ANALYSIS = "analysis"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    PENDING = "pending"

    def __str__(self) -> str:
        return str(self.value)
