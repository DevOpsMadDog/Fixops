from enum import Enum


class ExceptionStatus(str, Enum):
    APPROVED = "approved"
    EXPIRED = "expired"
    PENDING = "pending"
    REJECTED = "rejected"

    def __str__(self) -> str:
        return str(self.value)
