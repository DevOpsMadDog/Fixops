from enum import Enum


class EvidenceStatus(str, Enum):
    COLLECTED = "collected"
    EXPIRED = "expired"
    PENDING = "pending"
    REJECTED = "rejected"
    VERIFIED = "verified"

    def __str__(self) -> str:
        return str(self.value)
