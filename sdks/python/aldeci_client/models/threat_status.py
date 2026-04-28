from enum import Enum


class ThreatStatus(str, Enum):
    ACCEPTED = "accepted"
    IDENTIFIED = "identified"
    MITIGATED = "mitigated"

    def __str__(self) -> str:
        return str(self.value)
