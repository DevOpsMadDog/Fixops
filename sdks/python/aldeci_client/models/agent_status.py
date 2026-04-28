from enum import Enum


class AgentStatus(str, Enum):
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    ERROR = "error"
    EXECUTING = "executing"
    IDLE = "idle"
    WAITING = "waiting"

    def __str__(self) -> str:
        return str(self.value)
