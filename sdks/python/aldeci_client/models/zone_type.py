from enum import Enum


class ZoneType(str, Enum):
    DMZ = "dmz"
    EXTERNAL = "external"
    INTERNAL = "internal"
    MANAGEMENT = "management"
    RESTRICTED = "restricted"

    def __str__(self) -> str:
        return str(self.value)
