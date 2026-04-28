from enum import Enum


class SSOStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"

    def __str__(self) -> str:
        return str(self.value)
