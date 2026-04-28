from enum import Enum


class PlaybookTrigger(str, Enum):
    ANOMALY_DETECTED = "anomaly_detected"
    COMPLIANCE_GAP = "compliance_gap"
    FINDING_CRITICAL = "finding_critical"
    FINDING_HIGH = "finding_high"
    INCIDENT_CREATED = "incident_created"
    INSIDER_THREAT = "insider_threat"
    SLA_BREACH = "sla_breach"

    def __str__(self) -> str:
        return str(self.value)
