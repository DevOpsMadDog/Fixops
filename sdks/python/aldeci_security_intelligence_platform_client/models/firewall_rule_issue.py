from enum import Enum


class FirewallRuleIssue(str, Enum):
    BIDIRECTIONAL_UNNECESSARY = "bidirectional_unnecessary"
    EXPIRED = "expired"
    OVERLY_PERMISSIVE = "overly_permissive"
    SHADOWED = "shadowed"

    def __str__(self) -> str:
        return str(self.value)
