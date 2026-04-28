from enum import Enum


class SLAStatusV2(str, Enum):
    APPROACHING = "approaching"
    BREACHED = "breached"
    EXEMPT = "exempt"
    RESOLVED = "resolved"
    SEVERELY_BREACHED = "severely_breached"
    WITHIN_SLA = "within_sla"

    def __str__(self) -> str:
        return str(self.value)
