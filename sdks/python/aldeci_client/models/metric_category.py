from enum import Enum


class MetricCategory(str, Enum):
    ATTACK_SURFACE = "attack_surface"
    COMPLIANCE = "compliance"
    OPERATIONAL = "operational"
    POSTURE = "posture"
    SCANNER = "scanner"
    SLA = "sla"
    VULNERABILITY = "vulnerability"

    def __str__(self) -> str:
        return str(self.value)
