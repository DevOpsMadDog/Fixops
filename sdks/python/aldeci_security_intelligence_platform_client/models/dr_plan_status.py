from enum import Enum


class DRPlanStatus(str, Enum):
    APPROVED = "approved"
    ARCHIVED = "archived"
    DRAFT = "draft"
    UNDER_REVIEW = "under_review"

    def __str__(self) -> str:
        return str(self.value)
