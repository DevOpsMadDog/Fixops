from enum import Enum


class ConditionOperator(str, Enum):
    AND = "and"
    CONTAINS = "contains"
    EQUALS = "equals"
    GREATER_THAN = "greater_than"
    IN = "in"
    LESS_THAN = "less_than"
    NOT_EQUALS = "not_equals"
    NOT_IN = "not_in"
    OR = "or"

    def __str__(self) -> str:
        return str(self.value)
