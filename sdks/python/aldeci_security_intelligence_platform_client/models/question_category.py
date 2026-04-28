from enum import Enum


class QuestionCategory(str, Enum):
    ACCESS_CONTROL = "access_control"
    COMPLIANCE = "compliance"
    DATA_HANDLING = "data_handling"
    ENCRYPTION = "encryption"
    INCIDENT_RESPONSE = "incident_response"
    INFRASTRUCTURE = "infrastructure"
    MONITORING = "monitoring"
    VENDOR_MANAGEMENT = "vendor_management"

    def __str__(self) -> str:
        return str(self.value)
