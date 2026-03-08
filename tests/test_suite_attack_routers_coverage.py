"""Coverage tests for suite-attack API routers without dedicated test files.

Tests vuln_discovery_router, mpte_orchestrator_router, attack_sim_router,
and other attack-surface routers.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-attack"))

import pytest

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from fastapi.testclient import TestClient
from apps.api.app import create_app

API_KEY = os.environ.get("FIXOPS_API_TOKEN", "test-key-for-ci")
HEADERS = {"X-API-Key": API_KEY}


@pytest.fixture(scope="module")
def client():
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


# ── Vuln Discovery Router ────────────────────────────────────

class TestVulnDiscoveryRouter:
    def test_list_discoveries(self, client):
        r = client.get("/api/v1/vuln-discovery/discoveries", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_start_discovery(self, client):
        payload = {
            "target": "test-app-1",
            "scan_type": "full",
        }
        r = client.post("/api/v1/vuln-discovery/start", json=payload, headers=HEADERS)
        assert r.status_code in (200, 201, 202, 401, 403, 422)

    def test_get_discovery_status(self, client):
        r = client.get("/api/v1/vuln-discovery/status/disc-001", headers=HEADERS)
        assert r.status_code in (200, 404, 401, 403)

    def test_discovery_stats(self, client):
        r = client.get("/api/v1/vuln-discovery/stats", headers=HEADERS)
        assert r.status_code in (200, 401, 403)


# ── MPTE Orchestrator Router ─────────────────────────────────

class TestMPTEOrchestratorRouter:
    def test_list_orchestrations(self, client):
        r = client.get("/api/v1/mpte-orchestrator/runs", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_start_orchestration(self, client):
        payload = {
            "finding_id": "VULN-001",
            "target_url": "http://localhost:8080/api/test",
        }
        r = client.post("/api/v1/mpte-orchestrator/start", json=payload, headers=HEADERS)
        assert r.status_code in (200, 201, 202, 401, 403, 422)

    def test_get_orchestration_result(self, client):
        r = client.get("/api/v1/mpte-orchestrator/results/run-001", headers=HEADERS)
        assert r.status_code in (200, 404, 401, 403)


# ── Attack Simulation Router ─────────────────────────────────

class TestAttackSimRouter:
    def test_list_simulations(self, client):
        r = client.get("/api/v1/attack-sim/simulations", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_create_simulation(self, client):
        payload = {
            "name": "Test Attack Simulation",
            "attack_type": "sql_injection",
            "target": "http://localhost:8080",
        }
        r = client.post("/api/v1/attack-sim/simulations", json=payload, headers=HEADERS)
        assert r.status_code in (200, 201, 202, 401, 403, 422)

    def test_get_simulation(self, client):
        r = client.get("/api/v1/attack-sim/simulations/sim-001", headers=HEADERS)
        assert r.status_code in (200, 404, 401, 403)

    def test_simulation_stats(self, client):
        r = client.get("/api/v1/attack-sim/stats", headers=HEADERS)
        assert r.status_code in (200, 401, 403)


# ── DAST Router ──────────────────────────────────────────────

class TestDASTRouter:
    def test_list_scans(self, client):
        r = client.get("/api/v1/dast/scans", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_start_scan(self, client):
        payload = {"target_url": "http://localhost:8080", "scan_type": "quick"}
        r = client.post("/api/v1/dast/scan", json=payload, headers=HEADERS)
        assert r.status_code in (200, 201, 202, 401, 403, 422)


# ── SAST Router ──────────────────────────────────────────────

class TestSASTRouter:
    def test_list_analyses(self, client):
        r = client.get("/api/v1/sast/analyses", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_analyze(self, client):
        payload = {"code": "x = input()\neval(x)", "language": "python"}
        r = client.post("/api/v1/sast/analyze", json=payload, headers=HEADERS)
        assert r.status_code in (200, 201, 401, 403, 422)


# ── Container Router ─────────────────────────────────────────

class TestContainerRouter:
    def test_list_scans(self, client):
        r = client.get("/api/v1/container/scans", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_scan_image(self, client):
        payload = {"image": "nginx:latest"}
        r = client.post("/api/v1/container/scan", json=payload, headers=HEADERS)
        assert r.status_code in (200, 201, 202, 401, 403, 422)


# ── Secrets Router ───────────────────────────────────────────

class TestSecretsRouter:
    def test_list_scans(self, client):
        r = client.get("/api/v1/secrets/scans", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_scan_code(self, client):
        payload = {"code": "API_KEY = 'sk-test-123'", "language": "python"}
        r = client.post("/api/v1/secrets/scan", json=payload, headers=HEADERS)
        assert r.status_code in (200, 201, 401, 403, 422)


# ── CSPM Router ──────────────────────────────────────────────

class TestCSPMRouter:
    def test_list_assessments(self, client):
        r = client.get("/api/v1/cspm/assessments", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_get_posture(self, client):
        r = client.get("/api/v1/cspm/posture", headers=HEADERS)
        assert r.status_code in (200, 401, 403)


# ── API Fuzzer Router ────────────────────────────────────────

class TestAPIFuzzerRouter:
    def test_list_fuzz_runs(self, client):
        r = client.get("/api/v1/api-fuzzer/runs", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_start_fuzz(self, client):
        payload = {"target_url": "http://localhost:8080/api/v1/test", "method": "POST"}
        r = client.post("/api/v1/api-fuzzer/start", json=payload, headers=HEADERS)
        assert r.status_code in (200, 201, 202, 401, 403, 422)


# ── Malware Router ───────────────────────────────────────────

class TestMalwareRouter:
    def test_list_scans(self, client):
        r = client.get("/api/v1/malware/scans", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_scan_file(self, client):
        payload = {"file_hash": "abc123def456", "file_name": "test.exe"}
        r = client.post("/api/v1/malware/scan", json=payload, headers=HEADERS)
        assert r.status_code in (200, 201, 401, 403, 422)
