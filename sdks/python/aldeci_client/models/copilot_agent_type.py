from enum import Enum


class CopilotAgentType(str, Enum):
    COMPLIANCE = "compliance"
    GENERAL = "general"
    PENTEST = "pentest"
    REMEDIATION = "remediation"
    SECURITY_ANALYST = "security_analyst"

    def __str__(self) -> str:
        return str(self.value)
