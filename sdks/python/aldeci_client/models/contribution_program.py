from enum import Enum


class ContributionProgram(str, Enum):
    CERT = "cert"
    CISA = "cisa"
    MITRE = "mitre"
    VENDOR = "vendor"

    def __str__(self) -> str:
        return str(self.value)
