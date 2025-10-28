"""Unit tests for risk threat modeling module."""

from __future__ import annotations

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
    """Test ThreatModelResult dataclass."""

    def test_create_threat_model(self):
        """Test creating threat model result."""
        threat_model = ThreatModelResult(
            cve_id="CVE-2023-1234",
            attack_path_found=True,
            critical_assets=["web-server", "api-gateway"],
            weak_links=[{"type": "network_exposure", "severity": "high"}],
            vector_explanation="Remotely exploitable with low complexity",
            reachability_score=0.85,
            exposure_level="internet",
            attack_complexity="low",
        )

        assert threat_model.cve_id == "CVE-2023-1234"
        assert threat_model.attack_path_found is True
        assert len(threat_model.critical_assets) == 2
        assert threat_model.reachability_score == 0.85

    def test_to_dict(self):
        """Test converting threat model to dictionary."""
        threat_model = ThreatModelResult(
            cve_id="CVE-2023-1234",
            attack_path_found=True,
            reachability_score=0.85,
        )

        result = threat_model.to_dict()

        assert isinstance(result, dict)
        assert result["cve_id"] == "CVE-2023-1234"
        assert result["attack_path_found"] is True
        assert result["reachability_score"] == 0.85


class TestParseCVSSVector:
    """Test CVSS vector parsing."""

    def test_parse_cvss_v3(self):
        """Test parsing CVSS v3.x vector."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

        components = _parse_cvss_vector(vector)

        assert components["AV"] == "N"
        assert components["AC"] == "L"
        assert components["PR"] == "N"
        assert components["UI"] == "N"

    def test_parse_cvss_v2(self):
        """Test parsing CVSS v2 vector."""
        vector = "AV:N/AC:L/Au:N/C:P/I:P/A:P"

        components = _parse_cvss_vector(vector)

        assert components["AV"] == "N"
        assert components["AC"] == "L"
        assert components["Au"] == "N"

    def test_parse_cvss_empty(self):
        """Test parsing empty CVSS vector."""
        components = _parse_cvss_vector(None)

        assert len(components) == 0


class TestCalculateReachabilityScore:
    """Test reachability score calculation."""

    def test_reachability_network_accessible(self):
        """Test reachability for network-accessible vulnerability."""
        cvss_components = {
            "AV": "N",  # Network
            "AC": "L",  # Low complexity
            "PR": "N",  # No privileges
            "UI": "N",  # No user interaction
        }

        score = _calculate_reachability_score(cvss_components, "internet", False)

        assert score > 0.7  # High reachability

    def test_reachability_local_access(self):
        """Test reachability for local-only vulnerability."""
        cvss_components = {
            "AV": "L",  # Local
            "AC": "H",  # High complexity
            "PR": "H",  # High privileges
            "UI": "R",  # User interaction required
        }

        score = _calculate_reachability_score(cvss_components, "internal", False)

        assert score < 0.3  # Low reachability

    def test_reachability_with_patch(self):
        """Test reachability when patch is available."""
        cvss_components = {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
        }

        score_no_patch = _calculate_reachability_score(
            cvss_components, "internet", False
        )
        score_with_patch = _calculate_reachability_score(
            cvss_components, "internet", True
        )

        assert score_with_patch < score_no_patch

    def test_reachability_exposure_multiplier(self):
        """Test exposure level multiplier effect."""
        cvss_components = {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
        }

        score_internet = _calculate_reachability_score(
            cvss_components, "internet", False
        )
        score_internal = _calculate_reachability_score(
            cvss_components, "internal", False
        )

        assert score_internet > score_internal


class TestFindAffectedComponents:
    """Test finding affected components."""

    def test_find_affected_components_basic(self):
        """Test finding affected components from graph."""
        graph = {
            "nodes": [
                {"id": "vuln:CVE-2023-1234", "type": "vulnerability"},
                {"id": "comp:log4j", "type": "component", "name": "log4j-core"},
            ],
            "edges": [
                {"source": "comp:log4j", "target": "vuln:CVE-2023-1234"},
            ],
        }

        components = _find_affected_components("CVE-2023-1234", graph)

        assert len(components) == 1
        assert "log4j-core" in components

    def test_find_affected_components_multiple(self):
        """Test finding multiple affected components."""
        graph = {
            "nodes": [
                {"id": "vuln:CVE-2023-1234", "type": "vulnerability"},
                {"id": "comp:log4j", "type": "component", "name": "log4j-core"},
                {"id": "comp:spring", "type": "component", "name": "spring-core"},
            ],
            "edges": [
                {"source": "comp:log4j", "target": "vuln:CVE-2023-1234"},
                {"source": "comp:spring", "target": "vuln:CVE-2023-1234"},
            ],
        }

        components = _find_affected_components("CVE-2023-1234", graph)

        assert len(components) == 2
        assert "log4j-core" in components
        assert "spring-core" in components

    def test_find_affected_components_no_graph(self):
        """Test finding components with no graph."""
        components = _find_affected_components("CVE-2023-1234", None)

        assert len(components) == 0


class TestDetermineExposureLevel:
    """Test exposure level determination."""

    def test_exposure_internet_facing(self):
        """Test determining internet exposure."""
        cnapp_exposures = [
            {
                "asset": "web-server",
                "type": "internet-facing",
            }
        ]
        affected_components = ["web-server"]

        level = _determine_exposure_level(cnapp_exposures, affected_components)

        assert level == "internet"

    def test_exposure_partner_network(self):
        """Test determining partner network exposure."""
        cnapp_exposures = [
            {
                "asset": "api-gateway",
                "type": "partner-network",
            }
        ]
        affected_components = ["api-gateway"]

        level = _determine_exposure_level(cnapp_exposures, affected_components)

        assert level == "partner"

    def test_exposure_internal_only(self):
        """Test determining internal-only exposure."""
        cnapp_exposures = [
            {
                "asset": "database",
                "type": "internal",
            }
        ]
        affected_components = ["database"]

        level = _determine_exposure_level(cnapp_exposures, affected_components)

        assert level == "internal"

    def test_exposure_no_cnapp_data(self):
        """Test determining exposure with no CNAPP data."""
        level = _determine_exposure_level(None, ["web-server"])

        assert level == "internal"  # Default to internal


class TestComputeThreatModel:
    """Test compute_threat_model function."""

    def test_compute_threat_model_basic(self):
        """Test basic threat model computation."""
        enrichment_map = {
            "CVE-2023-1234": EnrichmentEvidence(
                cve_id="CVE-2023-1234",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvss_score=9.8,
            )
        }

        result = compute_threat_model(enrichment_map)

        assert len(result) == 1
        assert "CVE-2023-1234" in result

        threat_model = result["CVE-2023-1234"]
        assert threat_model.cve_id == "CVE-2023-1234"
        assert threat_model.attack_complexity == "low"
        assert threat_model.privileges_required == "none"

    def test_compute_threat_model_with_graph(self):
        """Test threat model with knowledge graph."""
        enrichment_map = {
            "CVE-2023-1234": EnrichmentEvidence(
                cve_id="CVE-2023-1234",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            )
        }
        graph = {
            "nodes": [
                {"id": "vuln:CVE-2023-1234", "type": "vulnerability"},
                {"id": "comp:log4j", "type": "component", "name": "log4j-core"},
            ],
            "edges": [
                {"source": "comp:log4j", "target": "vuln:CVE-2023-1234"},
            ],
        }

        result = compute_threat_model(enrichment_map, graph)

        threat_model = result["CVE-2023-1234"]
        assert len(threat_model.critical_assets) == 0  # No internet exposure

    def test_compute_threat_model_with_cnapp(self):
        """Test threat model with CNAPP exposures."""
        enrichment_map = {
            "CVE-2023-1234": EnrichmentEvidence(
                cve_id="CVE-2023-1234",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            )
        }
        graph = {
            "nodes": [
                {"id": "vuln:CVE-2023-1234", "type": "vulnerability"},
                {"id": "comp:web-server", "type": "component", "name": "web-server"},
            ],
            "edges": [
                {"source": "comp:web-server", "target": "vuln:CVE-2023-1234"},
            ],
        }
        cnapp_exposures = [
            {
                "asset": "web-server",
                "type": "internet-facing",
            }
        ]

        result = compute_threat_model(enrichment_map, graph, cnapp_exposures)

        threat_model = result["CVE-2023-1234"]
        assert threat_model.exposure_level == "internet"
        assert threat_model.attack_path_found is True
        assert len(threat_model.critical_assets) > 0

    def test_compute_threat_model_attack_path_detection(self):
        """Test attack path detection logic."""
        enrichment_map = {
            "CVE-2023-1234": EnrichmentEvidence(
                cve_id="CVE-2023-1234",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            )
        }
        cnapp_exposures = [
            {
                "asset": "web-server",
                "type": "internet-facing",
            }
        ]

        result = compute_threat_model(enrichment_map, None, cnapp_exposures)

        threat_model = result["CVE-2023-1234"]
        assert threat_model.attack_path_found is True

    def test_compute_threat_model_weak_links(self):
        """Test weak link identification."""
        enrichment_map = {
            "CVE-2023-1234": EnrichmentEvidence(
                cve_id="CVE-2023-1234",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            )
        }

        result = compute_threat_model(enrichment_map)

        threat_model = result["CVE-2023-1234"]
        assert len(threat_model.weak_links) > 0
        weak_link_types = [link["type"] for link in threat_model.weak_links]
        assert "low_complexity" in weak_link_types
        assert "no_privileges" in weak_link_types

    def test_compute_threat_model_empty_map(self):
        """Test threat model with empty enrichment map."""
        result = compute_threat_model({})

        assert len(result) == 0
