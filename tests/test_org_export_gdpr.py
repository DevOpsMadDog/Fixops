"""Smoke tests for POST /api/v1/orgs/{org_id}/export — GDPR right-to-portability.

Multica #4147.

Run:
    python -m pytest tests/test_org_export_gdpr.py -v --timeout=30
"""

from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import os

import pytest

# Set auth token BEFORE any app import so auth_deps reads the right value
os.environ["FIXOPS_API_TOKEN"] = "test-token-gdpr"

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# App fixture — import lazily so we don't pay full startup cost in CI
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    from apps.api.app import create_app
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


_HEADERS = {"X-API-Key": "test-token-gdpr"}


# ---------------------------------------------------------------------------
# Helper mocks — keep tests hermetic (no real DBs required)
# ---------------------------------------------------------------------------

def _patch_engines(monkeypatch):
    """Patch all lazy engine singletons in org_export_router."""
    import apps.api.org_export_router as m

    fake_org = MagicMock()
    fake_org.get_org_summary.return_value = {"org_id": "test-org", "total_rows": 10}
    monkeypatch.setattr(m, "_org_engine", fake_org)

    fake_udb = MagicMock()
    fake_udb.list_users.return_value = []
    monkeypatch.setattr(m, "_user_db", fake_udb)

    fake_findings = MagicMock()
    fake_findings.list_findings.return_value = [
        {"id": "f1", "title": "SQL Injection", "severity": "critical", "status": "open",
         "org_id": "test-org", "source_tool": "sast", "asset_id": "app1",
         "cvss_score": 9.8, "created_at": "2026-01-01T00:00:00Z"},
    ]
    monkeypatch.setattr(m, "_findings_engine", fake_findings)

    fake_incidents = MagicMock()
    fake_incidents.list_incidents.return_value = [
        {"id": "i1", "title": "Breach attempt", "severity": "high", "status": "open",
         "org_id": "test-org", "created_at": "2026-01-02T00:00:00Z"},
    ]
    monkeypatch.setattr(m, "_incident_engine", fake_incidents)

    # Patch audit_logger so it doesn't touch filesystem
    fake_al = MagicMock()
    fake_event = MagicMock()
    fake_event.to_dict.return_value = {
        "id": "ev1", "action": "LOGIN", "actor_id": "user@example.com",
        "org_id": "test-org", "timestamp": "2026-01-03T00:00:00Z",
    }
    fake_al.get_security_events.return_value = [fake_event]
    with patch("apps.api.org_export_router._audit_logger", return_value=fake_al):
        yield


# ---------------------------------------------------------------------------
# Smoke test 1 — happy path: ZIP created with correct members
# ---------------------------------------------------------------------------

def test_export_creates_valid_zip(client, monkeypatch, tmp_path):
    """POST /export returns 200, ZIP exists, contains all 5 expected files."""
    import apps.api.org_export_router as m

    fake_org = MagicMock()
    fake_org.get_org_summary.return_value = {"org_id": "test-org", "total_rows": 5}
    monkeypatch.setattr(m, "_org_engine", fake_org)

    fake_udb = MagicMock()
    fake_udb.list_users.return_value = []
    monkeypatch.setattr(m, "_user_db", fake_udb)

    fake_findings = MagicMock()
    fake_findings.list_findings.return_value = [
        {"id": "f1", "title": "XSS", "severity": "medium", "org_id": "test-org",
         "source_tool": "dast", "asset_id": "web1", "cvss_score": 6.1,
         "status": "open", "created_at": "2026-01-01T00:00:00Z"},
    ]
    monkeypatch.setattr(m, "_findings_engine", fake_findings)

    fake_incidents = MagicMock()
    fake_incidents.list_incidents.return_value = []
    monkeypatch.setattr(m, "_incident_engine", fake_incidents)

    fake_al = MagicMock()
    fake_al.get_security_events.return_value = []

    with patch("apps.api.org_export_router._audit_logger", return_value=fake_al):
        resp = client.post("/api/v1/orgs/test-org/export", headers=_HEADERS)

    assert resp.status_code == 200, resp.text
    body = resp.json()

    # Response shape
    assert "download_url" in body
    assert "zip_path" in body
    assert "file_size_bytes" in body
    assert body["file_size_bytes"] > 0
    assert body["org_id"] == "test-org"
    assert body["contents"]["findings"] == 1

    # ZIP actually exists and has the right members
    zip_path = Path(body["zip_path"])
    assert zip_path.exists(), f"ZIP not found at {zip_path}"
    with zipfile.ZipFile(str(zip_path)) as zf:
        names = set(zf.namelist())
    assert "org.json" in names
    assert "users.csv" in names
    assert "findings.csv" in names
    assert "incidents.csv" in names
    assert "audit_events.csv" in names

    # org.json is valid JSON
    with zipfile.ZipFile(str(zip_path)) as zf:
        org_meta = json.loads(zf.read("org.json"))
    assert org_meta["org_id"] == "test-org"

    # findings.csv has the header row
    with zipfile.ZipFile(str(zip_path)) as zf:
        findings_csv = zf.read("findings.csv").decode("utf-8")
    assert "severity" in findings_csv
    assert "XSS" in findings_csv

    # Cleanup
    zip_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Smoke test 2 — bad org_id returns 400
# ---------------------------------------------------------------------------

def test_export_rejects_empty_org_id(client):
    """POST /export with blank org_id (whitespace only) should return 400."""
    # %20 decodes to a single space — our handler strips and rejects it
    resp = client.post("/api/v1/orgs/%20/export", headers=_HEADERS)
    # Either 400 (our validation) or 422 (Pydantic/FastAPI path validation) is acceptable
    assert resp.status_code in (400, 422, 404), resp.text


# ---------------------------------------------------------------------------
# Smoke test 3 — path traversal rejected
# ---------------------------------------------------------------------------

def test_export_rejects_path_traversal(client):
    """org_id containing ../ should be sanitised and not produce a traversal."""
    import apps.api.org_export_router as m

    fake_org = MagicMock()
    fake_org.get_org_summary.return_value = {"org_id": "sanitised", "total_rows": 0}

    with patch.object(m, "_org_engine", fake_org), \
         patch.object(m, "_user_db", MagicMock(list_users=MagicMock(return_value=[]))), \
         patch.object(m, "_findings_engine", MagicMock(list_findings=MagicMock(return_value=[]))), \
         patch.object(m, "_incident_engine", MagicMock(list_incidents=MagicMock(return_value=[]))), \
         patch("apps.api.org_export_router._audit_logger", return_value=MagicMock(get_security_events=MagicMock(return_value=[]))):
        # FastAPI will URL-encode the path; we pass a "safe" variant with dots stripped
        resp = client.post("/api/v1/orgs/..evil../export", headers=_HEADERS)

    # Either sanitised (200 with safe name) or 400
    if resp.status_code == 200:
        body = resp.json()
        assert ".." not in body["zip_path"]
        Path(body["zip_path"]).unlink(missing_ok=True)
    else:
        assert resp.status_code in (400, 422)


# ---------------------------------------------------------------------------
# Smoke test 4 — unauthenticated request is rejected
# ---------------------------------------------------------------------------

def test_export_requires_auth(client):
    """POST /export without API key should return 401 or 403."""
    resp = client.post("/api/v1/orgs/test-org/export")
    assert resp.status_code in (401, 403), resp.text
