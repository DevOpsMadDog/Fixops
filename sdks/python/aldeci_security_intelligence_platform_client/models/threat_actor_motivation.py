from enum import Enum


class ThreatActorMotivation(str, Enum):
    ESPIONAGE = "espionage"
    FINANCIAL = "financial"
    HACKTIVISM = "hacktivism"
    SABOTAGE = "sabotage"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return str(self.value)
