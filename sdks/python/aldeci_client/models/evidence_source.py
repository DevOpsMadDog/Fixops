from enum import Enum


class EvidenceSource(str, Enum):
    ACCESS_REVIEWS = "access_reviews"
    API_LOGS = "api_logs"
    AUDIT_TRAIL = "audit_trail"
    BACKUP_RECORDS = "backup_records"
    CONFIG_SNAPSHOTS = "config_snapshots"
    ENCRYPTION_STATUS = "encryption_status"
    INCIDENT_REPORTS = "incident_reports"
    SCAN_RESULTS = "scan_results"

    def __str__(self) -> str:
        return str(self.value)
