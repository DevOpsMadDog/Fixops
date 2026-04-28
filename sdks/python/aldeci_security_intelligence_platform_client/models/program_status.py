from enum import Enum


class ProgramStatus(str, Enum):
    ACTIVE = "active"
    CLOSED = "closed"
    PAUSED = "paused"

    def __str__(self) -> str:
        return str(self.value)
