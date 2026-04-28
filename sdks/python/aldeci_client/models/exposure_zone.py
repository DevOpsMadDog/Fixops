from enum import Enum


class ExposureZone(str, Enum):
    DMZ = "dmz"
    INTERNAL = "internal"
    INTERNET_FACING = "internet_facing"
    ISOLATED = "isolated"

    def __str__(self) -> str:
        return str(self.value)
