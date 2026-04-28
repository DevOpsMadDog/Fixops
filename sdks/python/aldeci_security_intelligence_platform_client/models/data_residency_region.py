from enum import Enum


class DataResidencyRegion(str, Enum):
    APAC = "apac"
    EU = "eu"
    GLOBAL = "global"
    UNKNOWN = "unknown"
    US = "us"

    def __str__(self) -> str:
        return str(self.value)
