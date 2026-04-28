from enum import Enum


class DataAccessLevel(str, Enum):
    CONFIDENTIAL = "confidential"
    INTERNAL = "internal"
    NONE = "none"
    PUBLIC = "public"
    RESTRICTED = "restricted"
    SECRET = "secret"

    def __str__(self) -> str:
        return str(self.value)
