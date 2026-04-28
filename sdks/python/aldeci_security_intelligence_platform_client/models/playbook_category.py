from enum import Enum


class PlaybookCategory(str, Enum):
    COMPLIANCE = "compliance"
    HARDENING = "hardening"
    INCIDENT_RESPONSE = "incident_response"
    REMEDIATION = "remediation"

    def __str__(self) -> str:
        return str(self.value)
