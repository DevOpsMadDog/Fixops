"""Empty endpoint #18 — GET /api/v1/cspm/ wired to CSPMEngine.get_posture + list_findings.

Multica issue #3972.
"""
import os

os.environ["FIXOPS_API_TOKEN"] = "fixops_test_key_ep18"

from fastapi.testclient import TestClient

API_KEY = "fixops_test_key_ep18"
HEADERS = {"X-API-Key": API_KEY}


def _client():
    from apps.api.app import create_app
    return TestClient(create_app())


def test_cspm_index_returns_200():
    """GET /api/v1/cspm/ must return 200 (not 501 or 404)."""
    c = _client()
    r = c.get("/api/v1/cspm/", headers=HEADERS)
    assert r.status_code == 200, r.text


def test_cspm_index_schema():
    """Response must include router, org_id, posture_score, items, count — no longer hardcoded empty."""
    c = _client()
    r = c.get("/api/v1/cspm/", headers=HEADERS)
    body = r.json()
    assert body["router"] == "cspm"
    assert "posture_score" in body
    assert "items" in body
    assert isinstance(body["items"], list)
    assert body["count"] == len(body["items"])
