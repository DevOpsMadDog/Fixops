from enum import Enum


class AccessLevel(str, Enum):
    ADMIN = "admin"
    NONE = "none"
    OWNER = "owner"
    READ = "read"
    WRITE = "write"

    def __str__(self) -> str:
        return str(self.value)
