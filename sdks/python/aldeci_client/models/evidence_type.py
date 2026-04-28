from enum import Enum


class EvidenceType(str, Enum):
    APPROVAL = "approval"
    CERTIFICATE = "certificate"
    CONFIG = "config"
    LOG = "log"
    POLICY_DOC = "policy_doc"
    REPORT = "report"
    SCAN_RESULT = "scan_result"
    SCREENSHOT = "screenshot"

    def __str__(self) -> str:
        return str(self.value)
