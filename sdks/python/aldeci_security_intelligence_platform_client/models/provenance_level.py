from enum import Enum


class ProvenanceLevel(str, Enum):
    SLSA_0 = "slsa_0"
    SLSA_1 = "slsa_1"
    SLSA_2 = "slsa_2"
    SLSA_3 = "slsa_3"
    SLSA_4 = "slsa_4"

    def __str__(self) -> str:
        return str(self.value)
