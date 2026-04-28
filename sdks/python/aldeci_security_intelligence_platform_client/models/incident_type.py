from enum import Enum


class IncidentType(str, Enum):
    API_ABUSE = "api_abuse"
    CLOUD_MISCONFIGURATION = "cloud_misconfiguration"
    COMPLIANCE_VIOLATION = "compliance_violation"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    DATA_BREACH = "data_breach"
    DATA_EXFILTRATION = "data_exfiltration"
    DDOS = "ddos"
    INSIDER_THREAT = "insider_threat"
    MALWARE_INFECTION = "malware_infection"
    PHISHING_CAMPAIGN = "phishing_campaign"
    RANSOMWARE = "ransomware"
    SUPPLY_CHAIN_ATTACK = "supply_chain_attack"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    WEBSITE_DEFACEMENT = "website_defacement"
    ZERO_DAY_EXPLOIT = "zero_day_exploit"

    def __str__(self) -> str:
        return str(self.value)
