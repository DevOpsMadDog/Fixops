from enum import Enum


class ReviewPriority(str, Enum):
    ELEVATED = "elevated"
    ROUTINE = "routine"
    URGENT = "urgent"

    def __str__(self) -> str:
        return str(self.value)
