from enum import Enum


class IndustryVertical(str, Enum):
    EDUCATION = "education"
    FINTECH = "fintech"
    GOVERNMENT = "government"
    HEALTHCARE = "healthcare"
    MANUFACTURING = "manufacturing"
    RETAIL = "retail"
    SAAS = "saas"

    def __str__(self) -> str:
        return str(self.value)
