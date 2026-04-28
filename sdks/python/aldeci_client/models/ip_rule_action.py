from enum import Enum


class IPRuleAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"

    def __str__(self) -> str:
        return str(self.value)
