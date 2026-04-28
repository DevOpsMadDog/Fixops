from enum import Enum


class ExceptionType(str, Enum):
    COMPENSATING_CONTROL = "compensating_control"
    EXTENDED_DEADLINE = "extended_deadline"
    FALSE_POSITIVE = "false_positive"
    RISK_ACCEPTANCE = "risk_acceptance"

    def __str__(self) -> str:
        return str(self.value)
