from enum import Enum


class ChangeCategory(str, Enum):
    ACCESS = "access"
    APPLICATION = "application"
    CODE_DEPLOYMENT = "code_deployment"
    CONFIGURATION = "configuration"
    DATABASE = "database"
    INFRASTRUCTURE = "infrastructure"
    NETWORK = "network"
    SECURITY = "security"

    def __str__(self) -> str:
        return str(self.value)
