from enum import Enum


class HuntTriggerType(str, Enum):
    COMPLIANCE_FAILURE = "compliance_failure"
    IOC_MATCH = "ioc_match"
    MANUAL = "manual"
    NETWORK_ANOMALY = "network_anomaly"
    NEW_CVE = "new_cve"

    def __str__(self) -> str:
        return str(self.value)
