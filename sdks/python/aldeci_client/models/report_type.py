from enum import Enum


class ReportType(str, Enum):
    COMPLIANCE_STATUS = "compliance_status"
    EXECUTIVE_SUMMARY = "executive_summary"
    INCIDENT_SUMMARY = "incident_summary"
    RISK_TRENDS = "risk_trends"
    SCANNER_EFFECTIVENESS = "scanner_effectiveness"
    SECURITY_POSTURE = "security_posture"

    def __str__(self) -> str:
        return str(self.value)
