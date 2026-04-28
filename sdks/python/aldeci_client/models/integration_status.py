from enum import Enum


class IntegrationStatus(str, Enum):
    ACTIVE = "active"
    ERROR = "error"
    INACTIVE = "inactive"

    def __str__(self) -> str:
        return str(self.value)
