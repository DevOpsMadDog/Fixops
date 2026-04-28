from enum import Enum


class DataClassification(str, Enum):
    CONFIDENTIAL = "confidential"
    INTERNAL = "internal"
    PUBLIC = "public"
    RESTRICTED = "restricted"
    SECRET = "secret"

    def __str__(self) -> str:
        return str(self.value)
