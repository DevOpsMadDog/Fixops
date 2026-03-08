"""Unit tests for suite-attack/api/vuln_discovery_router.py.

Tests cover:
- Enum classes (DiscoverySource, VulnSeverity, VulnStatus, etc.)
- Pydantic request/response models
- Helper functions (_generate_id, _now, _generate_internal_id, _calculate_cvss)
- Feature engineering helpers (_enum_val, _vuln_to_features)
- All API endpoints via FastAPI TestClient
- ML model training flow
- CVSS vector validation
- Filtering and pagination
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Module imports
# ---------------------------------------------------------------------------

from api.vuln_discovery_router import (
    AffectedComponent,
    AttackVector,
    ContributionProgram,
    ContributeRequest,
    DiscoveredVulnRequest,
    DiscoverySource,
    ImpactType,
    RetrainRequest,
    VulnSeverity,
    VulnStatus,
    VulnerabilityEvidence,
    _calculate_cvss,
    _contributions,
    _discovered_vulns,
    _enum_val,
    _generate_id,
    _generate_internal_id,
    _now,
    _retrain_jobs,
    _vuln_to_features,
    router,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_vuln_store():
    """Clear persistent stores between tests."""
    _discovered_vulns.clear()
    _contributions.clear()
    _retrain_jobs.clear()
    yield
    _discovered_vulns.clear()
    _contributions.clear()
    _retrain_jobs.clear()


@pytest.fixture
def client():
    """FastAPI TestClient with the vuln_discovery router mounted."""
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ===================================================================
# Enum tests
# ===================================================================


class TestEnums:
    """Test all enum classes."""

    def test_discovery_source_values(self):
        assert DiscoverySource.PENTEST_MANUAL == "pentest_manual"
        assert DiscoverySource.FUZZING == "fuzzing"

    def test_vuln_severity_all_levels(self):
        levels = [VulnSeverity.CRITICAL, VulnSeverity.HIGH, VulnSeverity.MEDIUM,
                  VulnSeverity.LOW, VulnSeverity.INFO]
        assert len(levels) == 5

    def test_vuln_status_all_values(self):
        assert VulnStatus.DRAFT == "draft"
        assert VulnStatus.CVE_ASSIGNED == "cve_assigned"
        assert VulnStatus.PUBLIC == "public"
        assert VulnStatus.DISPUTED == "disputed"

    def test_contribution_program_values(self):
        assert ContributionProgram.MITRE == "mitre"
        assert ContributionProgram.CISA == "cisa"
        assert ContributionProgram.CERT == "cert"
        assert ContributionProgram.VENDOR == "vendor"

    def test_attack_vector_values(self):
        assert AttackVector.NETWORK == "network"
        assert AttackVector.LOCAL == "local"

    def test_impact_type_values(self):
        assert ImpactType.RCE == "remote_code_execution"
        assert ImpactType.SQL_INJECTION == "sql_injection"
        assert ImpactType.OTHER == "other"


# ===================================================================
# Helper function tests
# ===================================================================


class TestHelpers:
    """Test helper functions."""

    def test_generate_id_is_uuid(self):
        result = _generate_id()
        uuid.UUID(result)  # Raises if not valid UUID

    def test_generate_id_unique(self):
        ids = {_generate_id() for _ in range(100)}
        assert len(ids) == 100

    def test_now_returns_utc(self):
        now = _now()
        assert isinstance(now, datetime)
        assert now.tzinfo == timezone.utc

    def test_generate_internal_id_format(self):
        internal_id = _generate_internal_id()
        assert internal_id.startswith("ALDECI-")
        parts = internal_id.split("-")
        assert len(parts) == 3
        assert parts[1].isdigit()  # Year
        assert parts[2].isdigit()  # Counter

    def test_generate_internal_id_increments(self):
        id1 = _generate_internal_id()
        id2 = _generate_internal_id()
        num1 = int(id1.split("-")[2])
        num2 = int(id2.split("-")[2])
        assert num2 == num1 + 1

    def test_calculate_cvss_none_input(self):
        assert _calculate_cvss(None) is None

    def test_calculate_cvss_empty_string(self):
        assert _calculate_cvss("") is None

    def test_calculate_cvss_invalid_vector(self):
        # Invalid vector should return None
        result = _calculate_cvss("NOT-A-VECTOR")
        assert result is None

    def test_calculate_cvss_valid_vector(self):
        """Test with a valid CVSS vector if cvss library is available."""
        try:
            from cvss import CVSS3  # noqa: F401
            result = _calculate_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
            assert result is not None
            assert 0.0 <= result <= 10.0
        except ImportError:
            # cvss library not installed -- test that None is returned gracefully
            result = _calculate_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
            assert result is None


# ===================================================================
# Feature engineering helper tests
# ===================================================================


class TestFeatureEngineering:
    """Test ML feature engineering helpers."""

    def test_enum_val_with_enum(self):
        assert _enum_val(VulnSeverity.CRITICAL) == "critical"

    def test_enum_val_with_string(self):
        assert _enum_val("high") == "high"

    def test_enum_val_with_uppercase_string(self):
        assert _enum_val("HIGH") == "high"

    def test_vuln_to_features_basic(self):
        vuln = {
            "attack_vector": "network",
            "exploitation_difficulty": "medium",
            "cvss_score": 7.5,
            "proof_of_concept": "exploit code here",
            "affected_components": [{"vendor": "test"}],
            "impact_type": "remote_code_execution",
        }
        features = _vuln_to_features(vuln)
        assert isinstance(features, list)
        assert len(features) > 5  # base features + one-hot impact
        assert features[0] == 4  # network = 4
        assert features[1] == 2  # medium = 2
        assert features[2] == 7.5  # CVSS score
        assert features[3] == 1.0  # has PoC
        assert features[4] == 1.0  # 1 component

    def test_vuln_to_features_defaults(self):
        vuln = {}
        features = _vuln_to_features(vuln)
        assert isinstance(features, list)
        assert features[2] == 0.0  # default CVSS
        assert features[3] == 0.0  # no PoC

    def test_vuln_to_features_impact_onehot(self):
        vuln = {"impact_type": "sql_injection"}
        features = _vuln_to_features(vuln)
        # Index 1 in the impact type list
        impact_start = 5
        assert features[impact_start + 1] == 1.0  # sql_injection
        assert features[impact_start + 0] == 0.0  # NOT rce


# ===================================================================
# Pydantic model tests
# ===================================================================


class TestPydanticModels:
    """Test Pydantic request/response models."""

    def test_discovered_vuln_request_defaults(self):
        req = DiscoveredVulnRequest()
        assert req.title == "Untitled Vulnerability"
        assert req.severity == VulnSeverity.MEDIUM
        assert req.internal_only is True

    def test_discovered_vuln_request_custom(self):
        req = DiscoveredVulnRequest(
            title="SQL Injection in /api/login",
            severity=VulnSeverity.CRITICAL,
            impact_type=ImpactType.SQL_INJECTION,
        )
        assert req.title == "SQL Injection in /api/login"
        assert req.severity == VulnSeverity.CRITICAL

    def test_cvss_vector_validation_valid(self):
        req = DiscoveredVulnRequest(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert req.cvss_vector.startswith("CVSS:3.")

    def test_cvss_vector_validation_invalid(self):
        with pytest.raises(Exception):
            DiscoveredVulnRequest(cvss_vector="INVALID")

    def test_vulnerability_evidence_model(self):
        ev = VulnerabilityEvidence(type="screenshot", description="XSS popup")
        assert ev.type == "screenshot"
        assert ev.chain_of_custody == []

    def test_affected_component_model(self):
        ac = AffectedComponent(vendor="Apache", product="Tomcat", version="9.0.0")
        assert ac.vendor == "Apache"
        assert ac.cpe is None

    def test_contribute_request_model(self):
        req = ContributeRequest(
            vuln_id="abc123",
            program=ContributionProgram.MITRE,
            researcher_name="Alice",
            researcher_email="alice@example.com",
        )
        assert req.coordinate_with_vendor is True

    def test_retrain_request_defaults(self):
        req = RetrainRequest()
        assert "severity_predictor" in req.model_types
        assert "exploitability_predictor" in req.model_types
        assert req.include_external is True
        assert req.force_retrain is False


# ===================================================================
# API endpoint tests
# ===================================================================


class TestReportVulnerability:
    """Test POST /vulns/discovered endpoint."""

    def test_report_minimal(self, client):
        resp = client.post("/api/v1/vulns/discovered", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert "id" in data
        assert "internal_id" in data
        assert data["severity"] == "medium"
        assert data["status"] == "draft"

    def test_report_with_all_fields(self, client):
        payload = {
            "title": "Test XSS Vuln",
            "description": "Reflected XSS in search param",
            "severity": "critical",
            "impact_type": "cross_site_scripting",
            "attack_vector": "network",
            "discovery_source": "pentest_manual",
            "discovered_by": "Red Team",
            "proof_of_concept": "<script>alert(1)</script>",
            "remediation": "Sanitize input",
            "tags": ["xss", "web"],
        }
        resp = client.post("/api/v1/vulns/discovered", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["title"] == "Test XSS Vuln"
        assert data["severity"] == "critical"
        assert data["discovered_by"] == "Red Team"

    def test_report_creates_internal_id(self, client):
        resp = client.post("/api/v1/vulns/discovered", json={"title": "Test"})
        data = resp.json()
        assert data["internal_id"].startswith("ALDECI-")


class TestListVulnerabilities:
    """Test GET /vulns/discovered and /vulns/internal endpoints."""

    def test_list_empty(self, client):
        resp = client.get("/api/v1/vulns/discovered")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_after_report(self, client):
        client.post("/api/v1/vulns/discovered", json={"title": "V1"})
        client.post("/api/v1/vulns/discovered", json={"title": "V2"})
        resp = client.get("/api/v1/vulns/discovered")
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    def test_list_with_severity_filter(self, client):
        client.post("/api/v1/vulns/discovered", json={"title": "Crit", "severity": "critical"})
        client.post("/api/v1/vulns/discovered", json={"title": "Low", "severity": "low"})
        resp = client.get("/api/v1/vulns/discovered", params={"severity": "critical"})
        data = resp.json()
        assert len(data) == 1
        assert data[0]["severity"] == "critical"

    def test_list_with_pagination(self, client):
        for i in range(5):
            client.post("/api/v1/vulns/discovered", json={"title": f"V{i}"})
        resp = client.get("/api/v1/vulns/discovered", params={"limit": 2, "offset": 0})
        assert len(resp.json()) == 2

    def test_internal_list(self, client):
        client.post("/api/v1/vulns/discovered", json={"title": "Internal Test"})
        resp = client.get("/api/v1/vulns/internal")
        assert resp.status_code == 200
        assert len(resp.json()) >= 1


class TestGetInternalVulnerability:
    """Test GET /vulns/internal/{vuln_id} endpoint."""

    def test_get_existing(self, client):
        report_resp = client.post("/api/v1/vulns/discovered", json={"title": "GetMe"})
        vuln_id = report_resp.json()["id"]
        resp = client.get(f"/api/v1/vulns/internal/{vuln_id}")
        assert resp.status_code == 200
        assert resp.json()["title"] == "GetMe"

    def test_get_nonexistent(self, client):
        resp = client.get("/api/v1/vulns/internal/nonexistent-id")
        assert resp.status_code == 404


class TestUpdateInternalVulnerability:
    """Test PATCH /vulns/internal/{vuln_id} endpoint."""

    def test_update_title(self, client):
        report_resp = client.post("/api/v1/vulns/discovered", json={"title": "Original"})
        vuln_id = report_resp.json()["id"]
        resp = client.patch(
            f"/api/v1/vulns/internal/{vuln_id}",
            json={"title": "Updated"},
        )
        assert resp.status_code == 200
        assert resp.json()["title"] == "Updated"

    def test_update_nonexistent(self, client):
        resp = client.patch(
            "/api/v1/vulns/internal/nonexistent-id",
            json={"title": "Nope"},
        )
        assert resp.status_code == 404

    def test_update_ignores_disallowed_fields(self, client):
        report_resp = client.post("/api/v1/vulns/discovered", json={"title": "Test"})
        vuln_id = report_resp.json()["id"]
        resp = client.patch(
            f"/api/v1/vulns/internal/{vuln_id}",
            json={"id": "evil-override", "title": "OK"},
        )
        assert resp.status_code == 200
        assert resp.json()["id"] == vuln_id  # ID not overridden


class TestContributeEndpoint:
    """Test POST /vulns/contribute endpoint."""

    def test_contribute_existing_vuln(self, client):
        report_resp = client.post(
            "/api/v1/vulns/discovered",
            json={"title": "To Submit", "severity": "high"},
        )
        vuln_id = report_resp.json()["id"]
        contribute_resp = client.post(
            "/api/v1/vulns/contribute",
            json={
                "vuln_id": vuln_id,
                "program": "mitre",
                "researcher_name": "Alice",
                "researcher_email": "alice@example.com",
            },
        )
        assert contribute_resp.status_code == 200
        data = contribute_resp.json()
        assert data["status"] == "submitted"
        assert data["program"] == "mitre"

    def test_contribute_nonexistent_vuln(self, client):
        resp = client.post(
            "/api/v1/vulns/contribute",
            json={
                "vuln_id": "nonexistent",
                "program": "mitre",
                "researcher_name": "Bob",
                "researcher_email": "bob@example.com",
            },
        )
        assert resp.status_code == 404


class TestTrainingEndpoint:
    """Test POST /vulns/train endpoint."""

    def test_train_queues_job(self, client):
        resp = client.post("/api/v1/vulns/train", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "queued"
        assert "severity_predictor" in data["models_queued"]

    def test_train_custom_models(self, client):
        resp = client.post(
            "/api/v1/vulns/train",
            json={"model_types": ["zero_day_detector"]},
        )
        data = resp.json()
        assert "zero_day_detector" in data["models_queued"]


class TestTrainingJobStatus:
    """Test GET /vulns/train/{job_id} endpoint."""

    def test_get_job_status(self, client):
        # Create a job first
        train_resp = client.post("/api/v1/vulns/train", json={})
        job_id = train_resp.json()["job_id"]
        resp = client.get(f"/api/v1/vulns/train/{job_id}")
        assert resp.status_code == 200

    def test_get_nonexistent_job(self, client):
        resp = client.get("/api/v1/vulns/train/nonexistent-job-id")
        assert resp.status_code == 404


class TestStatsEndpoint:
    """Test GET /vulns/stats endpoint."""

    def test_stats_empty(self, client):
        resp = client.get("/api/v1/vulns/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_discovered"] == 0

    def test_stats_after_reports(self, client):
        client.post("/api/v1/vulns/discovered", json={"severity": "critical"})
        client.post("/api/v1/vulns/discovered", json={"severity": "low"})
        resp = client.get("/api/v1/vulns/stats")
        data = resp.json()
        assert data["total_discovered"] == 2
        assert data["by_severity"]["critical"] == 1
        assert data["by_severity"]["low"] == 1


class TestContributionsEndpoint:
    """Test GET /vulns/contributions endpoint."""

    def test_contributions_empty(self, client):
        resp = client.get("/api/v1/vulns/contributions")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0


class TestHealthEndpoint:
    """Test GET /vulns/health endpoint."""

    def test_health(self, client):
        resp = client.get("/api/v1/vulns/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["service"] == "aldeci-vuln-discovery"
