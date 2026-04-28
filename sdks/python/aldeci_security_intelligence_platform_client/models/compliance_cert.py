from enum import Enum


class ComplianceCert(str, Enum):
    CSA_STAR = "csa_star"
    FEDRAMP = "fedramp"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    ISO27001 = "iso27001"
    NIST_CSF = "nist_csf"
    PCI_DSS = "pci_dss"
    SOC2_TYPE1 = "soc2_type1"
    SOC2_TYPE2 = "soc2_type2"

    def __str__(self) -> str:
        return str(self.value)
