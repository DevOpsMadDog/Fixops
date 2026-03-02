"""Comprehensive unit tests for suite-attack/api/mpte_router.py.

Tests cover:
- Pydantic request/response models
- MPTE service initialization and configuration
- All CRUD endpoints for requests, results, and configs
- Vulnerability verification endpoint
- Comprehensive scan endpoint
- Continuous monitoring endpoint
- 19-phase verification generation
- Exploitability assessment
- Statistics endpoint
- Error handling and edge cases
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch, tmp_path):
    """Clean environment and use temp DB for every test."""
    monkeypatch.setenv("MPTE_BASE_URL", "https://localhost-test:8443")
    monkeypatch.setenv("FIXOPS_BOOTSTRAP_MPTE", "false")
    # Use temp DB path to isolate tests
    db_file = str(tmp_path / "mpte_test.db")
    monkeypatch.setattr("api.mpte_router.db", _make_db(db_file))
    # Reset global service and prevent auto-creation attempts to external MPTE
    import api.mpte_router as mod
    mod._mpte_service = None
    # Prevent slow service init that tries to connect to external MPTE
    monkeypatch.setattr("api.mpte_router.get_mpte_service", lambda: None)


def _make_db(db_path: str):
    """Create fresh MPTEDB instance with temp path."""
    from core.mpte_db import MPTEDB
    return MPTEDB(db_path=db_path)


@pytest.fixture
def client(monkeypatch, tmp_path):
    """FastAPI TestClient with the mpte router mounted."""
    from api.mpte_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ===================================================================
# Pydantic model tests
# ===================================================================


class TestPydanticModels:
    """Test all Pydantic request/response models."""

    def test_create_pen_test_request_model(self):
        from api.mpte_router import CreatePenTestRequestModel
        m = CreatePenTestRequestModel(
            finding_id="f-1",
            target_url="https://example.com",
            vulnerability_type="sqli",
            test_case="basic_test",
        )
        assert m.priority == "medium"
        assert m.auto_verify is True

    def test_verify_vulnerability_model(self):
        from api.mpte_router import VerifyVulnerabilityModel
        m = VerifyVulnerabilityModel(
            finding_id="f-1",
            target_url="https://example.com",
            vulnerability_type="xss",
            evidence="<script>alert(1)</script>",
        )
        assert m.finding_id == "f-1"

    def test_continuous_monitoring_model(self):
        from api.mpte_router import ContinuousMonitoringModel
        m = ContinuousMonitoringModel(targets=["https://a.com", "https://b.com"])
        assert m.interval_minutes == 60

    def test_comprehensive_scan_model(self):
        from api.mpte_router import ComprehensiveScanModel
        m = ComprehensiveScanModel(target="https://example.com")
        assert m.scan_types is None

    def test_update_pen_test_request_model(self):
        from api.mpte_router import UpdatePenTestRequestModel
        m = UpdatePenTestRequestModel()
        assert m.status is None
        assert m.mpte_job_id is None

    def test_create_pen_test_result_model(self):
        from api.mpte_router import CreatePenTestResultModel
        m = CreatePenTestResultModel(
            request_id="r-1",
            finding_id="f-1",
            exploitability="confirmed_exploitable",
            exploit_successful=True,
            evidence="PoC executed",
        )
        assert m.confidence_score == 0.0
        assert m.steps_taken == []

    def test_create_pen_test_config_model(self):
        from api.mpte_router import CreatePenTestConfigModel
        m = CreatePenTestConfigModel(
            name="test-config",
            mpte_url="https://mpte:8443",
        )
        assert m.enabled is True
        assert m.max_concurrent_tests == 5

    def test_update_pen_test_config_model(self):
        from api.mpte_router import UpdatePenTestConfigModel
        m = UpdatePenTestConfigModel(enabled=False, timeout_seconds=600)
        assert m.enabled is False
        assert m.mpte_url is None


# ===================================================================
# Config CRUD endpoint tests
# ===================================================================


class TestConfigCRUD:
    """Test MPTE configuration CRUD endpoints."""

    def test_create_config(self, client):
        resp = client.post("/api/v1/mpte/configs", json={
            "name": "test-config",
            "mpte_url": "https://mpte:8443",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "test-config"
        assert "id" in data

    def test_list_configs(self, client):
        client.post("/api/v1/mpte/configs", json={
            "name": "cfg-1",
            "mpte_url": "https://mpte:8443",
        })
        resp = client.get("/api/v1/mpte/configs")
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

    def test_get_config(self, client):
        create_resp = client.post("/api/v1/mpte/configs", json={
            "name": "cfg-get",
            "mpte_url": "https://mpte:8443",
        })
        config_id = create_resp.json()["id"]
        resp = client.get(f"/api/v1/mpte/configs/{config_id}")
        assert resp.status_code == 200
        assert resp.json()["name"] == "cfg-get"

    def test_get_config_not_found(self, client):
        resp = client.get("/api/v1/mpte/configs/nonexistent")
        assert resp.status_code == 404

    def test_update_config(self, client):
        create_resp = client.post("/api/v1/mpte/configs", json={
            "name": "cfg-update",
            "mpte_url": "https://mpte:8443",
        })
        config_id = create_resp.json()["id"]
        resp = client.put(f"/api/v1/mpte/configs/{config_id}", json={
            "enabled": False,
            "timeout_seconds": 600,
        })
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False
        assert resp.json()["timeout_seconds"] == 600

    def test_update_config_not_found(self, client):
        resp = client.put("/api/v1/mpte/configs/nonexistent", json={"enabled": False})
        assert resp.status_code == 404

    def test_delete_config(self, client):
        create_resp = client.post("/api/v1/mpte/configs", json={
            "name": "cfg-delete",
            "mpte_url": "https://mpte:8443",
        })
        config_id = create_resp.json()["id"]
        resp = client.delete(f"/api/v1/mpte/configs/{config_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"

    def test_delete_config_not_found(self, client):
        resp = client.delete("/api/v1/mpte/configs/nonexistent")
        assert resp.status_code == 404


# ===================================================================
# PenTest request CRUD endpoint tests
# ===================================================================


class TestRequestCRUD:
    """Test pen test request CRUD endpoints."""

    def _create_request(self, client):
        """Helper to create a pen test request via fallback (no service)."""
        resp = client.post("/api/v1/mpte/requests", json={
            "finding_id": "f-test",
            "target_url": "https://example.com",
            "vulnerability_type": "sqli",
            "test_case": "test_case",
            "priority": "high",
        })
        return resp

    def test_create_request(self, client):
        resp = self._create_request(client)
        assert resp.status_code == 201
        data = resp.json()
        assert data["finding_id"] == "f-test"
        assert data["priority"] == "high"

    def test_list_requests(self, client):
        self._create_request(client)
        resp = client.get("/api/v1/mpte/requests")
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

    def test_get_request(self, client):
        create_resp = self._create_request(client)
        req_id = create_resp.json()["id"]
        resp = client.get(f"/api/v1/mpte/requests/{req_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == req_id

    def test_get_request_not_found(self, client):
        resp = client.get("/api/v1/mpte/requests/nonexistent")
        assert resp.status_code == 404

    def test_update_request(self, client):
        create_resp = self._create_request(client)
        req_id = create_resp.json()["id"]
        resp = client.put(f"/api/v1/mpte/requests/{req_id}", json={
            "status": "running",
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "running"

    def test_update_request_not_found(self, client):
        resp = client.put("/api/v1/mpte/requests/nonexistent", json={"status": "running"})
        assert resp.status_code == 404

    def test_start_request(self, client):
        create_resp = self._create_request(client)
        req_id = create_resp.json()["id"]
        resp = client.post(f"/api/v1/mpte/requests/{req_id}/start")
        assert resp.status_code == 200
        assert resp.json()["status"] == "started"

    def test_start_request_not_found(self, client):
        resp = client.post("/api/v1/mpte/requests/nonexistent/start")
        assert resp.status_code == 404

    def test_cancel_request(self, client):
        create_resp = self._create_request(client)
        req_id = create_resp.json()["id"]
        resp = client.post(f"/api/v1/mpte/requests/{req_id}/cancel")
        assert resp.status_code == 200
        assert resp.json()["status"] == "cancelled"

    def test_cancel_request_not_found(self, client):
        resp = client.post("/api/v1/mpte/requests/nonexistent/cancel")
        assert resp.status_code == 404


# ===================================================================
# PenTest results endpoint tests
# ===================================================================


class TestResults:
    """Test pen test results endpoints."""

    def _create_request_and_result(self, client):
        """Create a request and a result for it."""
        req_resp = client.post("/api/v1/mpte/requests", json={
            "finding_id": "f-result-test",
            "target_url": "https://example.com",
            "vulnerability_type": "xss",
            "test_case": "reflected_xss",
            "priority": "medium",
        })
        req_id = req_resp.json()["id"]

        result_resp = client.post("/api/v1/mpte/results", json={
            "request_id": req_id,
            "finding_id": "f-result-test",
            "exploitability": "confirmed_exploitable",
            "exploit_successful": True,
            "evidence": "XSS payload executed",
            "steps_taken": ["Step 1: Inject", "Step 2: Execute"],
            "confidence_score": 0.95,
            "execution_time_seconds": 12.5,
        })
        return req_id, result_resp

    def test_create_result(self, client):
        _, resp = self._create_request_and_result(client)
        assert resp.status_code == 201
        data = resp.json()
        assert data["exploit_successful"] is True
        assert data["exploitability"] == "confirmed_exploitable"

    def test_list_results(self, client):
        self._create_request_and_result(client)
        resp = client.get("/api/v1/mpte/results")
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

    def test_get_result_by_request(self, client):
        req_id, _ = self._create_request_and_result(client)
        resp = client.get(f"/api/v1/mpte/results/by-request/{req_id}")
        assert resp.status_code == 200
        assert resp.json()["request_id"] == req_id

    def test_get_result_by_request_not_found(self, client):
        resp = client.get("/api/v1/mpte/results/by-request/nonexistent")
        assert resp.status_code == 404

    def test_result_marks_request_completed(self, client):
        req_id, _ = self._create_request_and_result(client)
        req_resp = client.get(f"/api/v1/mpte/requests/{req_id}")
        assert req_resp.json()["status"] == "completed"


# ===================================================================
# 19-phase verification tests
# ===================================================================


class TestPhaseGeneration:
    """Test _generate_phases function."""

    def test_generate_phases_confirmed(self):
        from api.mpte_router import _generate_phases
        phases = _generate_phases("confirmed", seed=42)
        assert len(phases) == 19
        assert all("phase" in p for p in phases)
        assert all("status" in p for p in phases)

    def test_generate_phases_not_exploitable(self):
        from api.mpte_router import _generate_phases
        phases = _generate_phases("not_exploitable", seed=42)
        assert len(phases) == 19
        # Not exploitable should have more fails/skips
        fail_count = sum(1 for p in phases if p["status"] in ("fail", "skip"))
        assert fail_count > 0

    def test_generate_phases_inconclusive(self):
        from api.mpte_router import _generate_phases
        phases = _generate_phases("possible", seed=42)
        assert len(phases) == 19

    def test_phase_structure(self):
        from api.mpte_router import _generate_phases
        phases = _generate_phases("confirmed", seed=1)
        for p in phases:
            assert "phase" in p
            assert "name" in p
            assert "description" in p
            assert "status" in p
            assert "duration_seconds" in p
            assert "evidence" in p
            assert "confidence_contribution" in p
            assert p["status"] in ("pass", "fail", "skip")

    def test_phase_names_match_19_phases(self):
        from api.mpte_router import _generate_phases
        phases = _generate_phases("confirmed", seed=1)
        assert phases[0]["name"] == "Reconnaissance"
        assert phases[-1]["name"] == "Report Generation"

    def test_skip_phase_has_zero_duration(self):
        from api.mpte_router import _generate_phases
        phases = _generate_phases("not_exploitable", seed=99)
        for p in phases:
            if p["status"] == "skip":
                assert p["duration_seconds"] == 0.0


# ===================================================================
# Verifications list endpoint
# ===================================================================


class TestVerifications:
    """Test verifications endpoints."""

    def test_list_verifications_empty_db(self, client):
        """When DB has no results, demo data is returned."""
        resp = client.get("/api/v1/mpte/verifications")
        assert resp.status_code == 200
        data = resp.json()
        assert "verifications" in data
        assert data["total"] > 0
        # Verify phase summary is present
        for v in data["verifications"]:
            assert "phases" in v
            assert "phase_summary" in v
            assert v["phase_summary"]["total"] == 19

    def test_get_verification_not_found(self, client):
        resp = client.get("/api/v1/mpte/verifications/nonexistent")
        assert resp.status_code == 404


# ===================================================================
# Exploitability endpoint
# ===================================================================


class TestExploitability:
    """Test finding exploitability endpoint."""

    def test_exploitability_no_results(self, client):
        resp = client.get("/api/v1/mpte/findings/f-unknown/exploitability")
        assert resp.status_code == 200
        data = resp.json()
        assert data["exploitability"] == "not_tested"

    def test_exploitability_with_result(self, client):
        # Create request + result
        req_resp = client.post("/api/v1/mpte/requests", json={
            "finding_id": "f-exploit",
            "target_url": "https://example.com",
            "vulnerability_type": "sqli",
            "test_case": "test",
            "priority": "high",
        })
        req_id = req_resp.json()["id"]
        client.post("/api/v1/mpte/results", json={
            "request_id": req_id,
            "finding_id": "f-exploit",
            "exploitability": "confirmed_exploitable",
            "exploit_successful": True,
            "evidence": "SQL injection confirmed",
        })
        resp = client.get("/api/v1/mpte/findings/f-exploit/exploitability")
        assert resp.status_code == 200
        assert resp.json()["exploitability"] == "confirmed_exploitable"


# ===================================================================
# Stats endpoint
# ===================================================================


class TestStats:
    """Test pen test statistics endpoint."""

    def test_stats_empty(self, client):
        resp = client.get("/api/v1/mpte/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_requests"] == 0
        assert data["total_results"] == 0

    def test_stats_with_data(self, client):
        client.post("/api/v1/mpte/requests", json={
            "finding_id": "f-stat",
            "target_url": "https://example.com",
            "vulnerability_type": "xss",
            "test_case": "test",
            "priority": "critical",
        })
        resp = client.get("/api/v1/mpte/stats")
        data = resp.json()
        assert data["total_requests"] == 1
        assert "critical" in data["by_priority"]


# ===================================================================
# Verify vulnerability endpoint (mocked service)
# ===================================================================


class TestVerifyVulnerability:
    """Test POST /mpte/verify endpoint."""

    def test_verify_falls_back_to_mpte_call(self, client):
        """When no service is available, it tries real MPTE then returns pending."""
        with patch("api.mpte_router._call_real_mpte_verify") as mock_verify:
            mock_verify.return_value = {
                "id": "test-id",
                "finding_id": "f-1",
                "status": "pending",
                "source": "queued",
            }
            resp = client.post("/api/v1/mpte/verify", json={
                "finding_id": "f-1",
                "target_url": "https://example.com",
                "vulnerability_type": "sqli",
                "evidence": "test payload",
            })
            assert resp.status_code == 201
            data = resp.json()
            assert data["finding_id"] == "f-1"


# ===================================================================
# Monitoring endpoint (mocked)
# ===================================================================


class TestMonitoring:
    """Test POST /mpte/monitoring endpoint."""

    def test_monitoring_no_service(self, client):
        """Without MPTE service configured, should return 503."""
        resp = client.post("/api/v1/mpte/monitoring", json={
            "targets": ["https://a.com"],
            "interval_minutes": 30,
        })
        assert resp.status_code == 503


# ===================================================================
# Comprehensive scan endpoint (mocked)
# ===================================================================


class TestComprehensiveScan:
    """Test POST /mpte/scan/comprehensive endpoint."""

    def test_scan_no_service(self, client):
        """Without MPTE service configured, should return 503."""
        resp = client.post("/api/v1/mpte/scan/comprehensive", json={
            "target": "https://example.com",
            "scan_types": ["xss", "sqli"],
        })
        assert resp.status_code == 503
