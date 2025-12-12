"""Rigorous tests for threat modeling functionality.

These tests verify CVSS parsing, reachability scoring, attack path analysis,
and threat model computation with realistic scenarios and proper assertions.
"""


from risk.enrichment import EnrichmentEvidence
from risk.threat_model import (
    ThreatModelResult,
    _calculate_reachability_score,
    _determine_exposure_level,
    _find_affected_components,
    _parse_cvss_vector,
    compute_threat_model,
)


class TestThreatModelResult:
    """Tests for ThreatModelResult dataclass."""

    def test_result_defaults(self):
        """Verify ThreatModelResult has correct default values."""
        result = ThreatModelResult(cve_id="CVE-2024-1234")
        assert result.cve_id == "CVE-2024-1234"
        assert result.attack_path_found is False
        assert result.critical_assets == []
        assert result.weak_links == []
        assert result.vector_explanation == ""
        assert result.reachability_score == 0.0
        assert result.exposure_level == "internal"
        assert result.attack_complexity == "high"
        assert result.privileges_required == "high"
        assert result.user_interaction == "required"

    def test_result_with_all_fields(self):
        """Verify ThreatModelResult stores all fields correctly."""
        result = ThreatModelResult(
            cve_id="CVE-2024-5678",
            attack_path_found=True,
            critical_assets=["web-server", "database"],
            weak_links=[{"type": "network_exposure", "severity": "high"}],
            vector_explanation="Remotely exploitable",
            reachability_score=0.85,
            exposure_level="internet",
            attack_complexity="low",
            privileges_required="none",
            user_interaction="none",
        )
        assert result.attack_path_found is True
        assert len(result.critical_assets) == 2
        assert result.reachability_score == 0.85
        assert result.exposure_level == "internet"

    def test_result_to_dict(self):
        """Verify to_dict produces correct dictionary structure."""
        result = ThreatModelResult(
            cve_id="CVE-2024-9999",
            attack_path_found=True,
            critical_assets=["asset1"],
            weak_links=[{"type": "test", "severity": "medium"}],
            vector_explanation="Test explanation",
            reachability_score=0.12345,
        )
        d = result.to_dict()
        assert d["cve_id"] == "CVE-2024-9999"
        assert d["attack_path_found"] is True
        assert d["critical_assets"] == ["asset1"]
        assert d["weak_links"] == [{"type": "test", "severity": "medium"}]
        assert d["reachability_score"] == 0.123  # Rounded to 3 decimal places


class TestParseCVSSVector:
    """Tests for _parse_cvss_vector function."""

    def test_parse_cvss_v31_vector(self):
        """Verify CVSS 3.1 vector is parsed correctly."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        components = _parse_cvss_vector(vector)
        assert components["CVSS"] == "3.1"
        assert components["AV"] == "N"
        assert components["AC"] == "L"
        assert components["PR"] == "N"
        assert components["UI"] == "N"
        assert components["S"] == "U"
        assert components["C"] == "H"
        assert components["I"] == "H"
        assert components["A"] == "H"

    def test_parse_cvss_v30_vector(self):
        """Verify CVSS 3.0 vector is parsed correctly."""
        vector = "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N"
        components = _parse_cvss_vector(vector)
        assert components["CVSS"] == "3.0"
        assert components["AV"] == "A"
        assert components["AC"] == "H"
        assert components["PR"] == "L"
        assert components["UI"] == "R"

    def test_parse_cvss_empty_vector(self):
        """Verify empty vector returns empty dict."""
        assert _parse_cvss_vector("") == {}
        assert _parse_cvss_vector(None) == {}

    def test_parse_cvss_partial_vector(self):
        """Verify partial vector is parsed."""
        vector = "AV:N/AC:L"
        components = _parse_cvss_vector(vector)
        assert components["AV"] == "N"
        assert components["AC"] == "L"


class TestCalculateReachabilityScore:
    """Tests for _calculate_reachability_score function."""

    def test_network_attack_vector_high_score(self):
        """Verify network attack vector contributes to high score."""
        components = {"AV": "N", "AC": "L", "PR": "N", "UI": "N"}
        score = _calculate_reachability_score(components, "internet", False)
        assert score > 0.5  # Should be high for network + low complexity + no privs

    def test_local_attack_vector_low_score(self):
        """Verify local attack vector contributes to low score."""
        components = {"AV": "L", "AC": "H", "PR": "H", "UI": "R"}
        score = _calculate_reachability_score(components, "internal", False)
        assert score < 0.3  # Should be low for local + high complexity

    def test_internet_exposure_multiplier(self):
        """Verify internet exposure increases score."""
        components = {"AV": "N", "AC": "L", "PR": "N", "UI": "N"}
        score_internet = _calculate_reachability_score(components, "internet", False)
        score_internal = _calculate_reachability_score(components, "internal", False)
        assert score_internet > score_internal

    def test_vendor_advisory_reduces_score(self):
        """Verify vendor advisory reduces score."""
        components = {"AV": "N", "AC": "L", "PR": "N", "UI": "N"}
        score_no_advisory = _calculate_reachability_score(components, "internet", False)
        score_with_advisory = _calculate_reachability_score(
            components, "internet", True
        )
        assert score_with_advisory < score_no_advisory

    def test_score_bounded_0_to_1(self):
        """Verify score is bounded between 0 and 1."""
        # Maximum possible score
        components = {"AV": "N", "AC": "L", "PR": "N", "UI": "N"}
        score = _calculate_reachability_score(components, "internet", False)
        assert 0.0 <= score <= 1.0

        # Minimum possible score
        components = {"AV": "P", "AC": "H", "PR": "H", "UI": "R"}
        score = _calculate_reachability_score(components, "internal", True)
        assert 0.0 <= score <= 1.0

    def test_adjacent_attack_vector(self):
        """Verify adjacent attack vector score."""
        components = {"AV": "A", "AC": "L", "PR": "N", "UI": "N"}
        score = _calculate_reachability_score(components, "internal", False)
        assert 0.0 < score < 1.0

    def test_physical_attack_vector(self):
        """Verify physical attack vector has lowest score."""
        components_physical = {"AV": "P", "AC": "L", "PR": "N", "UI": "N"}
        components_local = {"AV": "L", "AC": "L", "PR": "N", "UI": "N"}
        score_physical = _calculate_reachability_score(
            components_physical, "internal", False
        )
        score_local = _calculate_reachability_score(components_local, "internal", False)
        assert score_physical < score_local


class TestFindAffectedComponents:
    """Tests for _find_affected_components function."""

    def test_find_components_with_graph(self):
        """Verify components are found in graph."""
        graph = {
            "nodes": [
                {"id": "vuln-CVE-2024-1234", "type": "vulnerability"},
                {"id": "comp-lodash", "type": "component", "name": "lodash"},
                {"id": "comp-express", "type": "component", "name": "express"},
            ],
            "edges": [
                {"source": "comp-lodash", "target": "vuln-CVE-2024-1234"},
                {"source": "comp-express", "target": "vuln-CVE-2024-1234"},
            ],
        }
        components = _find_affected_components("CVE-2024-1234", graph)
        assert "lodash" in components
        assert "express" in components

    def test_find_components_no_graph(self):
        """Verify empty list returned when no graph."""
        assert _find_affected_components("CVE-2024-1234", None) == []

    def test_find_components_empty_graph(self):
        """Verify empty list returned for empty graph."""
        assert (
            _find_affected_components("CVE-2024-1234", {"nodes": [], "edges": []}) == []
        )

    def test_find_components_cve_not_in_graph(self):
        """Verify empty list when CVE not in graph."""
        graph = {
            "nodes": [
                {"id": "vuln-CVE-2024-9999", "type": "vulnerability"},
            ],
            "edges": [],
        }
        assert _find_affected_components("CVE-2024-1234", graph) == []

    def test_find_components_invalid_graph_structure(self):
        """Verify handles invalid graph structure."""
        assert (
            _find_affected_components("CVE-2024-1234", {"invalid": "structure"}) == []
        )
        assert _find_affected_components("CVE-2024-1234", "not a dict") == []


class TestDetermineExposureLevel:
    """Tests for _determine_exposure_level function."""

    def test_internet_exposure(self):
        """Verify internet exposure is detected."""
        exposures = [
            {"asset": "web-server", "type": "internet-facing"},
        ]
        level = _determine_exposure_level(exposures, ["web-server"])
        assert level == "internet"

    def test_public_exposure(self):
        """Verify public exposure maps to internet."""
        exposures = [
            {"asset": "api-gateway", "type": "public"},
        ]
        level = _determine_exposure_level(exposures, ["api-gateway"])
        assert level == "internet"

    def test_partner_exposure(self):
        """Verify partner exposure is detected."""
        exposures = [
            {"asset": "partner-api", "type": "partner-network"},
        ]
        level = _determine_exposure_level(exposures, ["partner-api"])
        assert level == "partner"

    def test_external_exposure(self):
        """Verify external exposure maps to partner."""
        exposures = [
            {"asset": "external-service", "type": "external"},
        ]
        level = _determine_exposure_level(exposures, ["external-service"])
        assert level == "partner"

    def test_internal_default(self):
        """Verify internal is default when no match."""
        exposures = [
            {"asset": "other-service", "type": "internet"},
        ]
        level = _determine_exposure_level(exposures, ["my-service"])
        assert level == "internal"

    def test_no_exposures(self):
        """Verify internal when no exposures provided."""
        assert _determine_exposure_level(None, ["service"]) == "internal"
        assert _determine_exposure_level([], ["service"]) == "internal"


class TestComputeThreatModel:
    """Tests for compute_threat_model function."""

    def _create_evidence(
        self,
        cve_id: str = "CVE-2024-TEST",
        cvss_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score: float = 9.8,
        has_vendor_advisory: bool = False,
    ) -> EnrichmentEvidence:
        """Create test enrichment evidence."""
        return EnrichmentEvidence(
            cve_id=cve_id,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe_ids=["CWE-79"],
            epss_score=0.5,
            kev_listed=False,
            exploitdb_refs=[],
            age_days=30,
            has_vendor_advisory=has_vendor_advisory,
        )

    def test_compute_threat_model_basic(self):
        """Verify basic threat model computation."""
        enrichment_map = {
            "CVE-2024-1234": self._create_evidence(),
        }
        result = compute_threat_model(enrichment_map)

        assert "CVE-2024-1234" in result
        threat = result["CVE-2024-1234"]
        assert threat.cve_id == "CVE-2024-1234"
        assert threat.reachability_score > 0

    def test_compute_threat_model_attack_path_found(self):
        """Verify attack path is found for high-risk CVE."""
        # Network accessible, low complexity, no privileges
        enrichment_map = {
            "CVE-2024-HIGH": self._create_evidence(
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            ),
        }
        result = compute_threat_model(enrichment_map)

        threat = result["CVE-2024-HIGH"]
        assert threat.attack_path_found is True
        assert threat.attack_complexity == "low"
        assert threat.privileges_required == "none"

    def test_compute_threat_model_no_attack_path(self):
        """Verify no attack path for low-risk CVE."""
        # Local access, high complexity, high privileges
        enrichment_map = {
            "CVE-2024-LOW": self._create_evidence(
                cvss_vector="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N"
            ),
        }
        result = compute_threat_model(enrichment_map)

        threat = result["CVE-2024-LOW"]
        assert threat.attack_path_found is False
        assert threat.attack_complexity == "high"
        assert threat.privileges_required == "high"

    def test_compute_threat_model_with_graph(self):
        """Verify threat model uses knowledge graph."""
        enrichment_map = {
            "CVE-2024-1234": self._create_evidence(),
        }
        graph = {
            "nodes": [
                {"id": "vuln-CVE-2024-1234", "type": "vulnerability"},
                {"id": "comp-web", "type": "component", "name": "web-server"},
            ],
            "edges": [
                {"source": "comp-web", "target": "vuln-CVE-2024-1234"},
            ],
        }
        cnapp_exposures = [
            {"asset": "web-server", "type": "internet-facing"},
        ]

        result = compute_threat_model(enrichment_map, graph, cnapp_exposures)

        threat = result["CVE-2024-1234"]
        assert threat.exposure_level == "internet"
        assert "web-server" in threat.critical_assets

    def test_compute_threat_model_weak_links(self):
        """Verify weak links are identified."""
        enrichment_map = {
            "CVE-2024-WEAK": self._create_evidence(
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            ),
        }
        result = compute_threat_model(enrichment_map)

        threat = result["CVE-2024-WEAK"]
        # Should have weak links for low complexity and no privileges
        weak_link_types = [link["type"] for link in threat.weak_links]
        assert "low_complexity" in weak_link_types
        assert "no_privileges" in weak_link_types

    def test_compute_threat_model_vector_explanation(self):
        """Verify vector explanation is generated."""
        enrichment_map = {
            "CVE-2024-1234": self._create_evidence(
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            ),
        }
        result = compute_threat_model(enrichment_map)

        threat = result["CVE-2024-1234"]
        assert "remotely exploitable" in threat.vector_explanation.lower()
        assert "low complexity" in threat.vector_explanation.lower()
        assert "no privileges required" in threat.vector_explanation.lower()

    def test_compute_threat_model_multiple_cves(self):
        """Verify multiple CVEs are processed."""
        enrichment_map = {
            "CVE-2024-0001": self._create_evidence(),
            "CVE-2024-0002": self._create_evidence(
                cvss_vector="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N"
            ),
            "CVE-2024-0003": self._create_evidence(has_vendor_advisory=True),
        }
        result = compute_threat_model(enrichment_map)

        assert len(result) == 3
        assert "CVE-2024-0001" in result
        assert "CVE-2024-0002" in result
        assert "CVE-2024-0003" in result

    def test_compute_threat_model_empty_map(self):
        """Verify empty map returns empty result."""
        result = compute_threat_model({})
        assert result == {}

    def test_compute_threat_model_vendor_advisory_effect(self):
        """Verify vendor advisory reduces reachability score."""
        enrichment_no_advisory = {
            "CVE-2024-NO-ADV": self._create_evidence(has_vendor_advisory=False),
        }
        enrichment_with_advisory = {
            "CVE-2024-WITH-ADV": self._create_evidence(has_vendor_advisory=True),
        }

        result_no = compute_threat_model(enrichment_no_advisory)
        result_with = compute_threat_model(enrichment_with_advisory)

        assert (
            result_with["CVE-2024-WITH-ADV"].reachability_score
            < result_no["CVE-2024-NO-ADV"].reachability_score
        )

    def test_compute_threat_model_user_interaction(self):
        """Verify user interaction is correctly determined."""
        enrichment_no_ui = {
            "CVE-NO-UI": self._create_evidence(
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            ),
        }
        enrichment_with_ui = {
            "CVE-WITH-UI": self._create_evidence(
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
            ),
        }

        result_no = compute_threat_model(enrichment_no_ui)
        result_with = compute_threat_model(enrichment_with_ui)

        assert result_no["CVE-NO-UI"].user_interaction == "none"
        assert result_with["CVE-WITH-UI"].user_interaction == "required"
