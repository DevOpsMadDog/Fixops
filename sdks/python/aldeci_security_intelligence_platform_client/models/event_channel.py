from enum import Enum


class EventChannel(str, Enum):
    ALERTS = "alerts"
    COMPLIANCE = "compliance"
    FINDINGS = "findings"
    INCIDENTS = "incidents"
    POSTURE = "posture"
    SYSTEM = "system"

    def __str__(self) -> str:
        return str(self.value)
