from enum import Enum


class ComplianceFramework(str, Enum):
    FEDRAMP = "fedramp"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    ISO27001 = "iso27001"
    NIST = "nist"
    PCI_DSS = "pci-dss"
    SOC2 = "soc2"

    def __str__(self) -> str:
        return str(self.value)
