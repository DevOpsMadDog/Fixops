from enum import Enum


class UserRole(str, Enum):
    ADMIN = "admin"
    DEVELOPER = "developer"
    SECURITY_ANALYST = "security_analyst"
    VIEWER = "viewer"

    def __str__(self) -> str:
        return str(self.value)
