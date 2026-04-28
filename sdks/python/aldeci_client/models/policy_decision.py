from enum import Enum


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    WARN = "warn"

    def __str__(self) -> str:
        return str(self.value)
