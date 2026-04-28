from enum import Enum


class ReachabilityLevel(str, Enum):
    CONFIRMED_REACHABLE = "confirmed_reachable"
    NOT_REACHABLE = "not_reachable"
    POTENTIALLY_REACHABLE = "potentially_reachable"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return str(self.value)
