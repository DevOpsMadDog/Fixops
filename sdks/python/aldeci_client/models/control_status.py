from enum import Enum


class ControlStatus(str, Enum):
    IMPLEMENTED = "implemented"
    NOT_APPLICABLE = "not_applicable"
    PARTIAL = "partial"
    PLANNED = "planned"

    def __str__(self) -> str:
        return str(self.value)
