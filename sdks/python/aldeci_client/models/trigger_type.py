from enum import Enum


class TriggerType(str, Enum):
    ASSET_DISCOVERED = "asset.discovered"
    COMPLIANCE_GAP = "compliance.gap"
    FINDING_CREATED = "finding.created"
    FINDING_UPDATED = "finding.updated"
    INCIDENT_CREATED = "incident.created"
    RISK_SCORE_CHANGED = "risk.score_changed"
    SCAN_COMPLETED = "scan.completed"
    SLA_BREACH = "sla.breach"

    def __str__(self) -> str:
        return str(self.value)
