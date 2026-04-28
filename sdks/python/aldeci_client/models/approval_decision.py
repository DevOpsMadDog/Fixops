from enum import Enum


class ApprovalDecision(str, Enum):
    APPROVED = "approved"
    CONDITIONAL = "conditional"
    REJECTED = "rejected"

    def __str__(self) -> str:
        return str(self.value)
