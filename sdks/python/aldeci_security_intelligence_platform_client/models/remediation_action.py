from enum import Enum


class RemediationAction(str, Enum):
    ACCEPT_RISK = "accept_risk"
    MITIGATE = "mitigate"
    PATCH = "patch"
    UPGRADE = "upgrade"
    WORKAROUND = "workaround"

    def __str__(self) -> str:
        return str(self.value)
