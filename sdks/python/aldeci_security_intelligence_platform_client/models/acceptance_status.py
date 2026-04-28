from enum import Enum


class AcceptanceStatus(str, Enum):
    APPROVED = "approved"
    EXPIRED = "expired"
    PENDING = "pending"
    REJECTED = "rejected"
    REVOKED = "revoked"

    def __str__(self) -> str:
        return str(self.value)
