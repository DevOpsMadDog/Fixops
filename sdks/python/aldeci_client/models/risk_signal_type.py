from enum import Enum


class RiskSignalType(str, Enum):
    BREACH_HISTORY = "breach_history"
    CERT_EXPIRY = "cert_expiry"
    COMPLIANCE_CHANGE = "compliance_change"
    FINANCIAL_STABILITY = "financial_stability"
    NEWS_ALERT = "news_alert"
    SECURITY_RATING = "security_rating"
    VULNERABILITY_DISCLOSURE = "vulnerability_disclosure"

    def __str__(self) -> str:
        return str(self.value)
