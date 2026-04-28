from enum import Enum


class OperatorFeedbackRequestFeedbackType(str, Enum):
    MERGE_ALLOWED = "merge_allowed"
    MERGE_BLOCKED = "merge_blocked"
    SPLIT_CLUSTER = "split_cluster"

    def __str__(self) -> str:
        return str(self.value)
