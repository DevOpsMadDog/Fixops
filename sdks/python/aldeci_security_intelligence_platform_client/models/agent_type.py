from enum import Enum


class AgentType(str, Enum):
    COMPLIANCE = "compliance"
    ORCHESTRATOR = "orchestrator"
    PENTEST = "pentest"
    REMEDIATION = "remediation"
    SECURITY_ANALYST = "security_analyst"

    def __str__(self) -> str:
        return str(self.value)
