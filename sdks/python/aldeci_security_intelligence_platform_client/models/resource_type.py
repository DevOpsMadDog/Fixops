from enum import Enum


class ResourceType(str, Enum):
    ASSET = "asset"
    AUDIT_LOG = "audit_log"
    COMPLIANCE = "compliance"
    CONFIG = "config"
    DASHBOARD = "dashboard"
    FINDING = "finding"
    INCIDENT = "incident"
    REPORT = "report"

    def __str__(self) -> str:
        return str(self.value)
