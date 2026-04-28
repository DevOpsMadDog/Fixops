from enum import Enum


class TrainingCategory(str, Enum):
    DATA_HANDLING = "data_handling"
    INCIDENT_REPORTING = "incident_reporting"
    PASSWORDS = "passwords"
    PHISHING = "phishing"
    SOCIAL_ENGINEERING = "social_engineering"

    def __str__(self) -> str:
        return str(self.value)
