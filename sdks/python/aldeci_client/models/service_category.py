from enum import Enum


class ServiceCategory(str, Enum):
    CLOUD_INFRASTRUCTURE = "cloud_infrastructure"
    COMMUNICATION = "communication"
    DATA_PROCESSING = "data_processing"
    DEVELOPMENT_TOOLS = "development_tools"
    HR_PAYROLL = "hr_payroll"
    NETWORKING = "networking"
    OTHER = "other"
    PAYMENT_PROCESSING = "payment_processing"
    PROFESSIONAL_SERVICES = "professional_services"
    SAAS_APPLICATION = "saas_application"
    SECURITY_TOOLING = "security_tooling"

    def __str__(self) -> str:
        return str(self.value)
