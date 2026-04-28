from enum import Enum


class BackupType(str, Enum):
    CONFIG_ONLY = "config_only"
    FULL = "full"
    INCREMENTAL = "incremental"

    def __str__(self) -> str:
        return str(self.value)
