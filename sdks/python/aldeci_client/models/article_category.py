from enum import Enum


class ArticleCategory(str, Enum):
    ARCHITECTURE = "architecture"
    BEST_PRACTICE = "best_practice"
    COMPLIANCE = "compliance"
    INCIDENT_RESPONSE = "incident_response"
    REMEDIATION = "remediation"
    VULNERABILITY = "vulnerability"

    def __str__(self) -> str:
        return str(self.value)
