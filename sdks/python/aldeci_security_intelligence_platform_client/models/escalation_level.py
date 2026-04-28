from enum import Enum


class EscalationLevel(str, Enum):
    CISO = "ciso"
    DIRECTOR = "director"
    NONE = "none"
    TEAM_LEAD = "team_lead"

    def __str__(self) -> str:
        return str(self.value)
