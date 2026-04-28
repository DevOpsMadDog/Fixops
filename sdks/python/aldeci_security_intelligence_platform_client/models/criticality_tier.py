from enum import Enum


class CriticalityTier(str, Enum):
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"
    T4 = "T4"

    def __str__(self) -> str:
        return str(self.value)
