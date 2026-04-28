from enum import Enum


class LifecycleStage(str, Enum):
    ASSIGNED = "assigned"
    CLOSED = "closed"
    DISCOVERED = "discovered"
    FIXED = "fixed"
    IN_PROGRESS = "in_progress"
    REOPENED = "reopened"
    TRIAGED = "triaged"
    VERIFIED = "verified"
    WONT_FIX = "wont_fix"

    def __str__(self) -> str:
        return str(self.value)
