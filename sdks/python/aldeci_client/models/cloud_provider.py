from enum import Enum


class CloudProvider(str, Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    ON_PREM = "ON_PREM"

    def __str__(self) -> str:
        return str(self.value)
