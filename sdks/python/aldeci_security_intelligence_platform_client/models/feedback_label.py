from enum import Enum


class FeedbackLabel(str, Enum):
    FALSE_POSITIVE = "false_positive"
    NEEDS_INVESTIGATION = "needs_investigation"
    TRUE_POSITIVE = "true_positive"

    def __str__(self) -> str:
        return str(self.value)
