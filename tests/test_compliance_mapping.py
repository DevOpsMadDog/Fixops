"""Unit tests for compliance mapping module."""

from __future__ import annotations

from compliance.mapping import (
    DEFAULT_CWE_MAPPINGS,
    ComplianceMappingResult,
    ControlMapping,
    load_control_mappings,
    map_cve_to_controls,
)

from risk.enrichment import EnrichmentEvidence


class TestControlMapping:
    """Test ControlMapping dataclass."""

    def test_create_control_mapping(self):
        """Test creating control mapping."""
        mapping = ControlMapping(
            cwe_id="CWE-89",
            control_families=["Input Validation", "Secure Coding"],
            nist_800_53=["SI-10", "SA-11"],
            nist_ssdf=["PW.8", "PW.7"],
            pci_dss=["6.5.1"],
            iso_27001=["A.14.2.1", "A.14.2.5"],
            owasp_category="A03:2021-Injection",
        )

        assert mapping.cwe_id == "CWE-89"
        assert len(mapping.control_families) == 2
        assert len(mapping.nist_800_53) == 2
        assert mapping.owasp_category == "A03:2021-Injection"

    def test_to_dict(self):
        """Test converting control mapping to dictionary."""
        mapping = ControlMapping(
            cwe_id="CWE-89",
            nist_800_53=["SI-10"],
        )

        result = mapping.to_dict()

        assert isinstance(result, dict)
        assert result["cwe_id"] == "CWE-89"
        assert result["nist_800_53"] == ["SI-10"]


class TestComplianceMappingResult:
    """Test ComplianceMappingResult dataclass."""

    def test_create_compliance_result(self):
        """Test creating compliance mapping result."""
        result = ComplianceMappingResult(
            cve_id="CVE-2023-1234",
            cwe_ids=["CWE-89", "CWE-79"],
            control_mappings=[
                ControlMapping(cwe_id="CWE-89", nist_800_53=["SI-10"]),
            ],
            frameworks_affected=["NIST 800-53", "PCI DSS"],
            compliance_gaps=["No controls for ISO 27001"],
        )

        assert result.cve_id == "CVE-2023-1234"
        assert len(result.cwe_ids) == 2
        assert len(result.control_mappings) == 1
        assert len(result.frameworks_affected) == 2

    def test_to_dict(self):
        """Test converting compliance result to dictionary."""
        result = ComplianceMappingResult(
            cve_id="CVE-2023-1234",
            cwe_ids=["CWE-89"],
        )

        output = result.to_dict()

        assert isinstance(output, dict)
        assert output["cve_id"] == "CVE-2023-1234"
        assert output["cwe_ids"] == ["CWE-89"]


class TestDefaultCWEMappings:
    """Test default CWE mappings."""

    def test_default_mappings_exist(self):
        """Test that default mappings are defined."""
        assert len(DEFAULT_CWE_MAPPINGS) > 0

    def test_sql_injection_mapping(self):
        """Test SQL injection (CWE-89) mapping."""
        mapping = DEFAULT_CWE_MAPPINGS.get("CWE-89")

        assert mapping is not None
        assert mapping.cwe_id == "CWE-89"
        assert "SI-10" in mapping.nist_800_53
        assert "6.5.1" in mapping.pci_dss
        assert mapping.owasp_category == "A03:2021-Injection"

    def test_xss_mapping(self):
        """Test XSS (CWE-79) mapping."""
        mapping = DEFAULT_CWE_MAPPINGS.get("CWE-79")

        assert mapping is not None
        assert mapping.cwe_id == "CWE-79"
        assert "6.5.7" in mapping.pci_dss

    def test_authentication_mapping(self):
        """Test improper authentication (CWE-287) mapping."""
        mapping = DEFAULT_CWE_MAPPINGS.get("CWE-287")

        assert mapping is not None
        assert "IA-2" in mapping.nist_800_53
        assert "8.2" in mapping.pci_dss

    def test_crypto_mapping(self):
        """Test broken crypto (CWE-327) mapping."""
        mapping = DEFAULT_CWE_MAPPINGS.get("CWE-327")

        assert mapping is not None
        assert "SC-12" in mapping.nist_800_53
        assert "4.1" in mapping.pci_dss


class TestLoadControlMappings:
    """Test load_control_mappings function."""

    def test_load_default_mappings(self):
        """Test loading default mappings."""
        mappings = load_control_mappings()

        assert len(mappings) > 0
        assert "CWE-89" in mappings
        assert "CWE-79" in mappings

    def test_load_with_custom_overlay(self):
        """Test loading with custom overlay mappings."""
        overlay = {
            "cwe_control_mappings": {
                "CWE-999": {
                    "control_families": ["Custom Control"],
                    "nist_800_53": ["XX-1"],
                    "pci_dss": ["9.9"],
                }
            }
        }

        mappings = load_control_mappings(overlay)

        assert "CWE-999" in mappings
        assert mappings["CWE-999"].cwe_id == "CWE-999"
        assert "XX-1" in mappings["CWE-999"].nist_800_53

    def test_load_overlay_extends_defaults(self):
        """Test that overlay extends default mappings."""
        overlay = {
            "cwe_control_mappings": {
                "CWE-999": {
                    "nist_800_53": ["XX-1"],
                }
            }
        }

        mappings = load_control_mappings(overlay)

        assert "CWE-89" in mappings  # Default
        assert "CWE-999" in mappings  # Custom


class TestMapCVEToControls:
    """Test map_cve_to_controls function."""

    def test_map_cve_basic(self):
        """Test basic CVE to controls mapping."""
        enrichment_map = {
            "CVE-2023-1234": EnrichmentEvidence(
                cve_id="CVE-2023-1234",
                cwe_ids=["CWE-89"],
            )
        }
        control_mappings = load_control_mappings()

        result = map_cve_to_controls(enrichment_map, control_mappings)

        assert len(result) == 1
        assert "CVE-2023-1234" in result

        compliance = result["CVE-2023-1234"]
        assert compliance.cve_id == "CVE-2023-1234"
        assert "CWE-89" in compliance.cwe_ids
        assert len(compliance.control_mappings) == 1
        assert len(compliance.frameworks_affected) > 0

    def test_map_cve_multiple_cwes(self):
        """Test mapping CVE with multiple CWEs."""
        enrichment_map = {
            "CVE-2023-1234": EnrichmentEvidence(
                cve_id="CVE-2023-1234",
                cwe_ids=["CWE-89", "CWE-79"],
            )
        }
        control_mappings = load_control_mappings()

        result = map_cve_to_controls(enrichment_map, control_mappings)

        compliance = result["CVE-2023-1234"]
        assert len(compliance.control_mappings) == 2
        assert "NIST 800-53" in compliance.frameworks_affected
        assert "PCI DSS" in compliance.frameworks_affected

    def test_map_cve_unknown_cwe(self):
        """Test mapping CVE with unknown CWE."""
        enrichment_map = {
            "CVE-2023-1234": EnrichmentEvidence(
                cve_id="CVE-2023-1234",
                cwe_ids=["CWE-9999"],  # Unknown CWE
            )
        }
        control_mappings = load_control_mappings()

        result = map_cve_to_controls(enrichment_map, control_mappings)

        compliance = result["CVE-2023-1234"]
        assert len(compliance.control_mappings) == 0
        assert len(compliance.frameworks_affected) == 0

    def test_map_cve_compliance_gaps(self):
        """Test identifying compliance gaps."""
        enrichment_map = {
            "CVE-2023-1234": EnrichmentEvidence(
                cve_id="CVE-2023-1234",
                cwe_ids=["CWE-89"],
            )
        }
        control_mappings = load_control_mappings()
        required_frameworks = ["NIST 800-53", "ISO 27001", "SOC2"]

        result = map_cve_to_controls(
            enrichment_map,
            control_mappings,
            required_frameworks,
        )

        compliance = result["CVE-2023-1234"]
        assert len(compliance.compliance_gaps) > 0

    def test_map_cve_no_gaps(self):
        """Test when no compliance gaps exist."""
        enrichment_map = {
            "CVE-2023-1234": EnrichmentEvidence(
                cve_id="CVE-2023-1234",
                cwe_ids=["CWE-89"],
            )
        }
        control_mappings = load_control_mappings()
        required_frameworks = ["NIST 800-53", "PCI DSS"]

        result = map_cve_to_controls(
            enrichment_map,
            control_mappings,
            required_frameworks,
        )

        compliance = result["CVE-2023-1234"]
        assert len(compliance.compliance_gaps) == 0

    def test_map_multiple_cves(self):
        """Test mapping multiple CVEs."""
        enrichment_map = {
            "CVE-2023-1234": EnrichmentEvidence(
                cve_id="CVE-2023-1234",
                cwe_ids=["CWE-89"],
            ),
            "CVE-2023-5678": EnrichmentEvidence(
                cve_id="CVE-2023-5678",
                cwe_ids=["CWE-79"],
            ),
        }
        control_mappings = load_control_mappings()

        result = map_cve_to_controls(enrichment_map, control_mappings)

        assert len(result) == 2
        assert "CVE-2023-1234" in result
        assert "CVE-2023-5678" in result

    def test_map_empty_enrichment(self):
        """Test mapping with empty enrichment map."""
        control_mappings = load_control_mappings()

        result = map_cve_to_controls({}, control_mappings)

        assert len(result) == 0

    def test_map_cve_no_cwes(self):
        """Test mapping CVE with no CWEs."""
        enrichment_map = {
            "CVE-2023-1234": EnrichmentEvidence(
                cve_id="CVE-2023-1234",
                cwe_ids=[],
            )
        }
        control_mappings = load_control_mappings()

        result = map_cve_to_controls(enrichment_map, control_mappings)

        compliance = result["CVE-2023-1234"]
        assert len(compliance.control_mappings) == 0
        assert len(compliance.frameworks_affected) == 0
