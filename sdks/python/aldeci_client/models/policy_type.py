from enum import Enum


class PolicyType(str, Enum):
    ACCEPTABLE_USE = "acceptable_use"
    ACCESS_CONTROL = "access_control"
    BUSINESS_CONTINUITY = "business_continuity"
    CHANGE_MANAGEMENT = "change_management"
    DATA_CLASSIFICATION = "data_classification"
    ENCRYPTION = "encryption"
    INCIDENT_RESPONSE = "incident_response"
    PASSWORD = "password"
    PATCH_MANAGEMENT = "patch_management"
    VENDOR_MANAGEMENT = "vendor_management"

    def __str__(self) -> str:
        return str(self.value)
