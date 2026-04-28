from enum import Enum


class ClassificationLevel(str, Enum):
    CONFIDENTIAL = "CONFIDENTIAL"
    CUI = "CUI"
    SECRET = "SECRET"
    TOP_SECRET = "TOP_SECRET"
    UNCLASSIFIED = "UNCLASSIFIED"

    def __str__(self) -> str:
        return str(self.value)
