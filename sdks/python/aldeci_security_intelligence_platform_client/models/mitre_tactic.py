from enum import Enum


class MitreTactic(str, Enum):
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    CREDENTIAL_ACCESS = "credential_access"
    DEFENSE_EVASION = "defense_evasion"
    DISCOVERY = "discovery"
    EXECUTION = "execution"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    INITIAL_ACCESS = "initial_access"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"

    def __str__(self) -> str:
        return str(self.value)
