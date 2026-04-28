from enum import Enum


class Environment(str, Enum):
    DEVELOPMENT = "development"
    DR = "dr"
    PRODUCTION = "production"
    STAGING = "staging"
    TEST = "test"

    def __str__(self) -> str:
        return str(self.value)
