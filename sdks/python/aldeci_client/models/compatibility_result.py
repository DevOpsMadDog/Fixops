from enum import Enum


class CompatibilityResult(str, Enum):
    COMPATIBLE = "compatible"
    CONDITIONAL = "conditional"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return str(self.value)
