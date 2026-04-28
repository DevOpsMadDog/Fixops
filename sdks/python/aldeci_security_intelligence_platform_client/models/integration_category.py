from enum import Enum


class IntegrationCategory(str, Enum):
    CI_CD = "ci_cd"
    CLOUD = "cloud"
    COMPLIANCE = "compliance"
    CUSTOM = "custom"
    NOTIFICATION = "notification"
    SCANNER = "scanner"
    SIEM = "siem"
    TICKETING = "ticketing"

    def __str__(self) -> str:
        return str(self.value)
