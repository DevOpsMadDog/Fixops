from enum import Enum


class DataCategory(str, Enum):
    CONFIGURATION = "CONFIGURATION"
    CREDENTIALS = "CREDENTIALS"
    FINANCIAL = "FINANCIAL"
    PCI = "PCI"
    PHI = "PHI"
    PII = "PII"
    SOURCE_CODE = "SOURCE_CODE"
    TELEMETRY = "TELEMETRY"

    def __str__(self) -> str:
        return str(self.value)
