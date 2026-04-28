from enum import Enum


class KPICategory(str, Enum):
    COMPLIANCE = "compliance"
    COVERAGE = "coverage"
    DETECTION = "detection"
    EFFICIENCY = "efficiency"
    PREVENTION = "prevention"
    RESPONSE = "response"

    def __str__(self) -> str:
        return str(self.value)
