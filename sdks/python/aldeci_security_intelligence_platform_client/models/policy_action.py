from enum import Enum


class PolicyAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"
    WARN = "warn"

    def __str__(self) -> str:
        return str(self.value)
