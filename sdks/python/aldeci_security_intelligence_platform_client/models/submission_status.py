from enum import Enum


class SubmissionStatus(str, Enum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    FIXED = "fixed"
    INFORMATIONAL = "informational"
    NEW = "new"
    REJECTED = "rejected"
    TRIAGING = "triaging"

    def __str__(self) -> str:
        return str(self.value)
