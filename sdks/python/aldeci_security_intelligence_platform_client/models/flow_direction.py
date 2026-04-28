from enum import Enum


class FlowDirection(str, Enum):
    INBOUND = "inbound"
    LATERAL = "lateral"
    OUTBOUND = "outbound"

    def __str__(self) -> str:
        return str(self.value)
