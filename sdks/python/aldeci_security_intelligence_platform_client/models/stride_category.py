from enum import Enum


class STRIDECategory(str, Enum):
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"
    ELEVATION_OF_PRIVILEGE = "ELEVATION_OF_PRIVILEGE"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    REPUDIATION = "REPUDIATION"
    SPOOFING = "SPOOFING"
    TAMPERING = "TAMPERING"

    def __str__(self) -> str:
        return str(self.value)
