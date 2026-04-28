from enum import Enum


class FedRAMPBaseline(str, Enum):
    HIGH = "HIGH"
    LOW = "LOW"
    MODERATE = "MODERATE"

    def __str__(self) -> str:
        return str(self.value)
