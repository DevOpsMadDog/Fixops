from enum import Enum


class PolicyLanguage(str, Enum):
    ALDECI_RULES = "aldeci_rules"
    JSON_LOGIC = "json_logic"
    REGO_COMPAT = "rego_compat"

    def __str__(self) -> str:
        return str(self.value)
