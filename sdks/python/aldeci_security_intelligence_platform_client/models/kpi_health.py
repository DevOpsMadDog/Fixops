from enum import Enum


class KPIHealth(str, Enum):
    GREEN = "green"
    RED = "red"
    UNKNOWN = "unknown"
    YELLOW = "yellow"

    def __str__(self) -> str:
        return str(self.value)
