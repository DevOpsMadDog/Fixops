from enum import Enum


class VerificationStatus(str, Enum):
    FAILED = "failed"
    PASSED = "passed"
    PENDING = "pending"
    SKIPPED = "skipped"

    def __str__(self) -> str:
        return str(self.value)
