from enum import Enum


class ApplicationStatus(str, Enum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    DEPRECATED = "deprecated"

    def __str__(self) -> str:
        return str(self.value)
