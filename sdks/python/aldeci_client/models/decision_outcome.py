from enum import Enum


class DecisionOutcome(str, Enum):
    ALERT = "alert"
    ALLOW = "allow"
    BLOCK = "block"
    REVIEW = "review"

    def __str__(self) -> str:
        return str(self.value)
