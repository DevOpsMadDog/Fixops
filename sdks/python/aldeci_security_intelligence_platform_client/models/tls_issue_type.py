from enum import Enum


class TLSIssueType(str, Enum):
    DEPRECATED_PROTOCOL = "deprecated_protocol"
    EXPIRED = "expired"
    EXPIRING_SOON = "expiring_soon"
    MISSING_CT_LOG = "missing_ct_log"
    WEAK_CIPHER = "weak_cipher"

    def __str__(self) -> str:
        return str(self.value)
