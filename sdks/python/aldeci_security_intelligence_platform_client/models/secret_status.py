from enum import Enum


class SecretStatus(str, Enum):
    ACTIVE = "active"
    FALSE_POSITIVE = "false_positive"
    ROTATED = "rotated"

    def __str__(self) -> str:
        return str(self.value)
