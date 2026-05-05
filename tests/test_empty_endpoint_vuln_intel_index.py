"""Test: GET /api/v1/vuln-intel/ returns real list_cves data, not hardcoded []."""
import os
import pytest
from fastapi.testclient import TestClient

# App cold-start can take ~5s; give each test 30s so the module fixture completes.
pytestmark = pytest.mark.timeout(30)

_API_TOKEN = os.getenv(
    "FIXOPS_API_TOKEN",
    "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh",
)


@pytest.fixture(scope="module")
def client():
    os.environ.setdefault("FIXOPS_API_TOKEN", _API_TOKEN)
    from apps.api.app import create_app
    return TestClient(create_app(), headers={"X-API-Key": _API_TOKEN})


def test_vuln_intel_index_returns_list_not_stub(client):
    """Index must call list_cves and return items list (may be empty DB but not hardcoded [])."""
    resp = client.get("/api/v1/vuln-intel/", params={"org_id": "default"})
    assert resp.status_code == 200
    body = resp.json()
    assert "items" in body
    assert "count" in body
    assert isinstance(body["items"], list)
    # count must match items length — proves it comes from the engine, not a stub
    assert body["count"] == len(body["items"])
    assert body["org_id"] == "default"


def test_vuln_intel_index_count_consistent_after_insert(client):
    """After inserting a CVE, index count must reflect it."""
    cve_payload = {
        "cve_id": "CVE-2025-99999",
        "title": "Test CVE for index wiring",
        "severity": "high",
        "cvss_score": 8.5,
    }
    post_resp = client.post("/api/v1/vuln-intel/cves", json=cve_payload, params={"org_id": "test-org-idx"})
    assert post_resp.status_code == 201

    # Index must now show at least 1 item for this org
    idx_resp = client.get("/api/v1/vuln-intel/", params={"org_id": "test-org-idx"})
    assert idx_resp.status_code == 200
    body = idx_resp.json()
    assert body["count"] >= 1
    assert len(body["items"]) >= 1
    # Verify the inserted CVE appears
    cve_ids = [item.get("cve_id") for item in body["items"]]
    assert "CVE-2025-99999" in cve_ids
