from enum import Enum


class TreatmentAction(str, Enum):
    ACCEPT = "accept"
    AVOID = "avoid"
    MITIGATE = "mitigate"
    TRANSFER = "transfer"

    def __str__(self) -> str:
        return str(self.value)
