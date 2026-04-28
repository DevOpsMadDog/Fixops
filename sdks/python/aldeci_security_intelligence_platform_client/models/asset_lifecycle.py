from enum import Enum


class AssetLifecycle(str, Enum):
    ACTIVE = "active"
    DECOMMISSIONED = "decommissioned"
    DEPRECATED = "deprecated"
    DISCOVERED = "discovered"
    MAINTENANCE = "maintenance"
    PROVISIONED = "provisioned"

    def __str__(self) -> str:
        return str(self.value)
