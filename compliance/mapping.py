"""CWE-to-Control compliance mapping for FixOps."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from risk.enrichment import EnrichmentEvidence

logger = logging.getLogger(__name__)


@dataclass
class ControlMapping:
    """Mapping of CWE to compliance controls."""

    cwe_id: str
    control_families: List[str] = field(default_factory=list)
    nist_800_53: List[str] = field(default_factory=list)
    nist_ssdf: List[str] = field(default_factory=list)
    pci_dss: List[str] = field(default_factory=list)
    iso_27001: List[str] = field(default_factory=list)
    owasp_category: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "cwe_id": self.cwe_id,
            "control_families": list(self.control_families),
            "nist_800_53": list(self.nist_800_53),
            "nist_ssdf": list(self.nist_ssdf),
            "pci_dss": list(self.pci_dss),
            "iso_27001": list(self.iso_27001),
            "owasp_category": self.owasp_category,
        }


@dataclass
class ComplianceMappingResult:
    """Compliance mapping result for a CVE."""

    cve_id: str
    cwe_ids: List[str] = field(default_factory=list)
    control_mappings: List[ControlMapping] = field(default_factory=list)
    frameworks_affected: List[str] = field(default_factory=list)
    compliance_gaps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "cve_id": self.cve_id,
            "cwe_ids": list(self.cwe_ids),
            "control_mappings": [m.to_dict() for m in self.control_mappings],
            "frameworks_affected": list(self.frameworks_affected),
            "compliance_gaps": list(self.compliance_gaps),
        }


DEFAULT_CWE_MAPPINGS: Dict[str, ControlMapping] = {
    "CWE-89": ControlMapping(  # SQL Injection
        cwe_id="CWE-89",
        control_families=["Input Validation", "Secure Coding"],
        nist_800_53=["SI-10", "SA-11"],
        nist_ssdf=["PW.8", "PW.7"],
        pci_dss=["6.5.1"],
        iso_27001=["A.14.2.1", "A.14.2.5"],
        owasp_category="A03:2021-Injection",
    ),
    "CWE-79": ControlMapping(  # Cross-Site Scripting (XSS)
        cwe_id="CWE-79",
        control_families=["Input Validation", "Output Encoding"],
        nist_800_53=["SI-10", "SA-11"],
        nist_ssdf=["PW.8", "PW.7"],
        pci_dss=["6.5.7"],
        iso_27001=["A.14.2.1", "A.14.2.5"],
        owasp_category="A03:2021-Injection",
    ),
    "CWE-78": ControlMapping(  # OS Command Injection
        cwe_id="CWE-78",
        control_families=["Input Validation", "Least Privilege"],
        nist_800_53=["SI-10", "AC-6"],
        nist_ssdf=["PW.8", "PW.7"],
        pci_dss=["6.5.1"],
        iso_27001=["A.14.2.1", "A.9.4.1"],
        owasp_category="A03:2021-Injection",
    ),
    "CWE-287": ControlMapping(  # Improper Authentication
        cwe_id="CWE-287",
        control_families=["Authentication", "Access Control"],
        nist_800_53=["IA-2", "IA-5", "AC-7"],
        nist_ssdf=["PW.1", "PW.8"],
        pci_dss=["8.2", "8.3"],
        iso_27001=["A.9.2.1", "A.9.4.2"],
        owasp_category="A07:2021-Identification and Authentication Failures",
    ),
    "CWE-798": ControlMapping(  # Hard-coded Credentials
        cwe_id="CWE-798",
        control_families=["Credential Management", "Secure Coding"],
        nist_800_53=["IA-5", "SA-11"],
        nist_ssdf=["PW.8", "PS.1"],
        pci_dss=["8.2.1"],
        iso_27001=["A.9.4.3"],
        owasp_category="A07:2021-Identification and Authentication Failures",
    ),
    "CWE-862": ControlMapping(  # Missing Authorization
        cwe_id="CWE-862",
        control_families=["Access Control", "Authorization"],
        nist_800_53=["AC-3", "AC-6"],
        nist_ssdf=["PW.1", "PW.8"],
        pci_dss=["7.1", "7.2"],
        iso_27001=["A.9.4.1"],
        owasp_category="A01:2021-Broken Access Control",
    ),
    "CWE-327": ControlMapping(  # Broken or Risky Crypto
        cwe_id="CWE-327",
        control_families=["Cryptography", "Data Protection"],
        nist_800_53=["SC-12", "SC-13"],
        nist_ssdf=["PW.8"],
        pci_dss=["6.5.3", "4.1"],
        iso_27001=["A.10.1.1", "A.10.1.2"],
        owasp_category="A02:2021-Cryptographic Failures",
    ),
    "CWE-326": ControlMapping(  # Inadequate Encryption Strength
        cwe_id="CWE-326",
        control_families=["Cryptography", "Data Protection"],
        nist_800_53=["SC-12", "SC-13"],
        nist_ssdf=["PW.8"],
        pci_dss=["6.5.3", "4.1"],
        iso_27001=["A.10.1.1"],
        owasp_category="A02:2021-Cryptographic Failures",
    ),
    "CWE-119": ControlMapping(  # Buffer Overflow
        cwe_id="CWE-119",
        control_families=["Memory Safety", "Secure Coding"],
        nist_800_53=["SI-16", "SA-11"],
        nist_ssdf=["PW.7", "PW.8"],
        pci_dss=["6.5.2"],
        iso_27001=["A.14.2.1"],
        owasp_category="A06:2021-Vulnerable and Outdated Components",
    ),
    "CWE-120": ControlMapping(  # Buffer Copy without Checking Size
        cwe_id="CWE-120",
        control_families=["Memory Safety", "Input Validation"],
        nist_800_53=["SI-16", "SI-10"],
        nist_ssdf=["PW.7", "PW.8"],
        pci_dss=["6.5.2"],
        iso_27001=["A.14.2.1"],
        owasp_category="A06:2021-Vulnerable and Outdated Components",
    ),
    "CWE-22": ControlMapping(  # Path Traversal
        cwe_id="CWE-22",
        control_families=["Input Validation", "File Access Control"],
        nist_800_53=["SI-10", "AC-3"],
        nist_ssdf=["PW.8"],
        pci_dss=["6.5.8"],
        iso_27001=["A.14.2.1", "A.9.4.1"],
        owasp_category="A01:2021-Broken Access Control",
    ),
    "CWE-502": ControlMapping(  # Deserialization of Untrusted Data
        cwe_id="CWE-502",
        control_families=["Input Validation", "Secure Coding"],
        nist_800_53=["SI-10", "SA-11"],
        nist_ssdf=["PW.8"],
        pci_dss=["6.5.1"],
        iso_27001=["A.14.2.1"],
        owasp_category="A08:2021-Software and Data Integrity Failures",
    ),
    "CWE-200": ControlMapping(  # Information Exposure
        cwe_id="CWE-200",
        control_families=["Data Protection", "Error Handling"],
        nist_800_53=["SC-8", "SI-11"],
        nist_ssdf=["PW.8"],
        pci_dss=["6.5.5"],
        iso_27001=["A.13.1.3", "A.18.1.3"],
        owasp_category="A04:2021-Insecure Design",
    ),
    "CWE-918": ControlMapping(  # Server-Side Request Forgery
        cwe_id="CWE-918",
        control_families=["Input Validation", "Network Segmentation"],
        nist_800_53=["SI-10", "SC-7"],
        nist_ssdf=["PW.8"],
        pci_dss=["6.5.1"],
        iso_27001=["A.13.1.3"],
        owasp_category="A10:2021-Server-Side Request Forgery",
    ),
}


def load_control_mappings(
    overlay: Optional[Mapping[str, Any]] = None,
) -> Dict[str, ControlMapping]:
    """Load CWE-to-Control mappings from overlay config.

    Parameters
    ----------
    overlay:
        Optional overlay configuration with custom mappings.

    Returns
    -------
    Dict[str, ControlMapping]
        Mapping of CWE ID to control mapping.
    """
    mappings = dict(DEFAULT_CWE_MAPPINGS)

    if isinstance(overlay, Mapping):
        custom_mappings = overlay.get("cwe_control_mappings", {})
        if isinstance(custom_mappings, Mapping):
            for cwe_id, mapping_data in custom_mappings.items():
                if not isinstance(mapping_data, Mapping):
                    continue

                mapping = ControlMapping(
                    cwe_id=str(cwe_id),
                    control_families=list(mapping_data.get("control_families", [])),
                    nist_800_53=list(mapping_data.get("nist_800_53", [])),
                    nist_ssdf=list(mapping_data.get("nist_ssdf", [])),
                    pci_dss=list(mapping_data.get("pci_dss", [])),
                    iso_27001=list(mapping_data.get("iso_27001", [])),
                    owasp_category=mapping_data.get("owasp_category"),
                )
                mappings[str(cwe_id)] = mapping

    logger.info("Loaded %d CWE-to-Control mappings", len(mappings))
    return mappings


def map_cve_to_controls(
    enrichment_map: Dict[str, EnrichmentEvidence],
    control_mappings: Dict[str, ControlMapping],
    required_frameworks: Optional[List[str]] = None,
) -> Dict[str, ComplianceMappingResult]:
    """Map CVEs to compliance controls.

    Parameters
    ----------
    enrichment_map:
        Mapping of CVE ID to enrichment evidence.
    control_mappings:
        Mapping of CWE ID to control mapping.
    required_frameworks:
        Optional list of required compliance frameworks.

    Returns
    -------
    Dict[str, ComplianceMappingResult]
        Mapping of CVE ID to compliance mapping result.
    """
    required_frameworks = required_frameworks or []
    compliance_map: Dict[str, ComplianceMappingResult] = {}

    for cve_id, evidence in enrichment_map.items():
        cwe_ids = evidence.cwe_ids

        mappings: List[ControlMapping] = []
        frameworks_affected: set[str] = set()

        for cwe_id in cwe_ids:
            mapping = control_mappings.get(cwe_id)
            if mapping:
                mappings.append(mapping)

                if mapping.nist_800_53:
                    frameworks_affected.add("NIST 800-53")
                if mapping.nist_ssdf:
                    frameworks_affected.add("NIST SSDF")
                if mapping.pci_dss:
                    frameworks_affected.add("PCI DSS")
                if mapping.iso_27001:
                    frameworks_affected.add("ISO 27001")

        compliance_gaps: List[str] = []
        for framework in required_frameworks:
            framework_upper = framework.upper().replace("_", " ")
            if framework_upper not in frameworks_affected:
                compliance_gaps.append(
                    f"No controls mapped for {framework_upper} framework"
                )

        result = ComplianceMappingResult(
            cve_id=cve_id,
            cwe_ids=cwe_ids,
            control_mappings=mappings,
            frameworks_affected=list(frameworks_affected),
            compliance_gaps=compliance_gaps,
        )

        compliance_map[cve_id] = result

    logger.info(
        "Mapped %d CVEs to controls: %d with mappings, %d with gaps",
        len(compliance_map),
        sum(1 for r in compliance_map.values() if r.control_mappings),
        sum(1 for r in compliance_map.values() if r.compliance_gaps),
    )

    return compliance_map


__all__ = [
    "ControlMapping",
    "ComplianceMappingResult",
    "load_control_mappings",
    "map_cve_to_controls",
]
