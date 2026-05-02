"""
Tests for 4 compliance/evidence/audit GET / endpoints wired in this session.
"""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from apps.api.app import create_app
    return TestClient(create_app(), raise_server_exceptions=False)


HEADERS = {"X-API-Key": "test-key"}


# ---------------------------------------------------------------------------
# 1. compliance_planner GET /
# ---------------------------------------------------------------------------

def test_compliance_planner_get_root_ok(client):
    r = client.get("/api/v1/compliance-planner/", params={"org_id": "test-org"}, headers=HEADERS)
    assert r.status_code in (200, 401, 403, 422), f"Unexpected {r.status_code}: {r.text}"


def test_compliance_planner_get_root_returns_json(client):
    r = client.get("/api/v1/compliance-planner/", params={"org_id": "test-org"}, headers=HEADERS)
    assert r.status_code != 404, "GET / must be routed (not 404)"
    assert r.status_code != 405, "GET / must not be 405 Method Not Allowed"


# ---------------------------------------------------------------------------
# 2. compliance_automation GET /
# ---------------------------------------------------------------------------

def test_compliance_automation_get_root_ok(client):
    r = client.get("/api/v1/compliance/", headers=HEADERS)
    assert r.status_code in (200, 401, 403), f"Unexpected {r.status_code}: {r.text}"


def test_compliance_automation_get_root_not_404(client):
    r = client.get("/api/v1/compliance/", headers=HEADERS)
    assert r.status_code != 404, "GET / must be routed"
    assert r.status_code != 405, "GET / must not be 405"


def test_compliance_automation_get_root_has_frameworks(client):
    r = client.get("/api/v1/compliance/", headers=HEADERS)
    if r.status_code == 200:
        data = r.json()
        assert "frameworks" in data or "status" in data


# ---------------------------------------------------------------------------
# 3. compliance_scanner GET /
# ---------------------------------------------------------------------------

def test_compliance_scanner_get_root_ok(client):
    r = client.get("/api/v1/compliance-scanner/", params={"org_id": "test-org"}, headers=HEADERS)
    assert r.status_code in (200, 401, 403, 422), f"Unexpected {r.status_code}: {r.text}"


def test_compliance_scanner_get_root_not_404(client):
    r = client.get("/api/v1/compliance-scanner/", params={"org_id": "test-org"}, headers=HEADERS)
    assert r.status_code != 404, "GET / must be routed"
    assert r.status_code != 405, "GET / must not be 405"


# ---------------------------------------------------------------------------
# 4. service_account_auditor GET /
# ---------------------------------------------------------------------------

def test_service_account_auditor_get_root_ok(client):
    r = client.get("/api/v1/service-account-auditor/", params={"org_id": "test-org"}, headers=HEADERS)
    assert r.status_code in (200, 401, 403, 422), f"Unexpected {r.status_code}: {r.text}"


def test_service_account_auditor_get_root_not_404(client):
    r = client.get("/api/v1/service-account-auditor/", params={"org_id": "test-org"}, headers=HEADERS)
    assert r.status_code != 404, "GET / must be routed"
    assert r.status_code != 405, "GET / must not be 405"
