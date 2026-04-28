from enum import Enum


class PatchStatus(str, Enum):
    AVAILABLE = "available"
    DEPLOYED = "deployed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    SCHEDULED = "scheduled"
    TESTING = "testing"

    def __str__(self) -> str:
        return str(self.value)
