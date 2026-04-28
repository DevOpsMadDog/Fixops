from enum import Enum


class AttackScenario(str, Enum):
    APT_CAMPAIGN = "apt_campaign"
    CREDENTIAL_THEFT = "credential_theft"
    DATA_EXFILTRATION = "data_exfiltration"
    INSIDER_THREAT = "insider_threat"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RANSOMWARE = "ransomware"
    SUPPLY_CHAIN = "supply_chain"

    def __str__(self) -> str:
        return str(self.value)
