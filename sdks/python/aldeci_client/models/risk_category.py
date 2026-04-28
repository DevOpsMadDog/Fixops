from enum import Enum


class RiskCategory(str, Enum):
    COMPLIANCE = "compliance"
    OPERATIONAL = "operational"
    REPUTATIONAL = "reputational"
    STRATEGIC = "strategic"
    TECHNICAL = "technical"

    def __str__(self) -> str:
        return str(self.value)
