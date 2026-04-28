from enum import Enum


class RewardStatus(str, Enum):
    APPROVED = "approved"
    DISPUTED = "disputed"
    PAID = "paid"
    PENDING = "pending"
    WAIVED = "waived"

    def __str__(self) -> str:
        return str(self.value)
