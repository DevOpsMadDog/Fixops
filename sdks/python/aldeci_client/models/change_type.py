from enum import Enum


class ChangeType(str, Enum):
    CERT_EXPIRING = "cert_expiring"
    EXPOSURE_CHANGED = "exposure_changed"
    NEW_ASSET = "new_asset"
    NEW_PORT = "new_port"
    REMOVED_ASSET = "removed_asset"
    SCORE_CHANGED = "score_changed"
    WAF_REMOVED = "waf_removed"

    def __str__(self) -> str:
        return str(self.value)
