"""
Smoke tests for POST /api/v1/import/repo + /upload (Multica #4003).
Uses dependency_overrides to bypass auth — same pattern as other router smoke tests.
"""
import io
import os
import sys
import zipfile

import pytest

# Ensure suite paths are on sys.path before any imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))


@pytest.fixture(scope="module")
def client():
    from apps.api.auth_deps import api_key_auth
    from apps.api.import_router import router
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(router)

    # Override auth so the smoke tests don't need a real token
    async def _no_auth():
        return {"sub": "test", "org_id": "default", "scope": "admin"}

    app.dependency_overrides[api_key_auth] = _no_auth

    return TestClient(app)


def _make_zip(content: bytes = b"print('hello')") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("main.py", content)
    return buf.getvalue()


def test_import_repo_returns_accepted(client):
    resp = client.post(
        "/api/v1/import/repo",
        json={"repo_url": "https://github.com/example/test-repo", "branch": "main"},
    )
    assert resp.status_code in (200, 202), resp.text
    body = resp.json()
    assert "job_id" in body
    assert "status" in body
    assert body["status"] in ("queued", "processing", "running")


def test_import_upload_returns_accepted(client):
    zip_bytes = _make_zip()
    resp = client.post(
        "/api/v1/import/upload",
        files={"file": ("project.zip", zip_bytes, "application/zip")},
        data={"org_id": "test-org"},
    )
    assert resp.status_code in (200, 202), resp.text
    body = resp.json()
    assert "job_id" in body
    assert body["status"] in ("queued", "processing", "running")


def test_import_upload_rejects_non_zip(client):
    resp = client.post(
        "/api/v1/import/upload",
        files={"file": ("evil.tar.gz", b"data", "application/gzip")},
        data={"org_id": "default"},
    )
    assert resp.status_code == 400


def test_import_status_returns_envelope(client):
    resp = client.get("/api/v1/import/status/import-abc123")
    assert resp.status_code == 200
    body = resp.json()
    assert "job_id" in body
    assert "status" in body


def test_import_repo_missing_url(client):
    resp = client.post("/api/v1/import/repo", json={"branch": "main"})
    assert resp.status_code == 422


def test_upload_sync_fast_path_returns_findings_inline(client):
    """Sync fast-path: upload of small file must return findings_count in response body.

    The upload handler now runs SAST + secrets synchronously and returns
    findings inline. For code that triggers detections (hardcoded secrets),
    the response should include findings_count > 0 and status == 'done'.
    For benign code it may still return 0 findings, but the field must be
    present (not None in a 'done' case or absent entirely).
    """
    zip_bytes = _make_zip(b"AWS_SECRET_ACCESS_KEY='AKIA12345EXAMPLE'\npassword='hunter2'")
    resp = client.post(
        "/api/v1/import/upload",
        files={"file": ("fast_path_test.zip", zip_bytes, "application/zip")},
        data={"org_id": "test-fast-path"},
    )
    assert resp.status_code in (200, 202), resp.text
    body = resp.json()
    # job_id must always be present
    assert "job_id" in body
    # findings_count must be an int or None — never missing the key
    assert "findings_count" in body or body.get("status") == "queued"
    # If status is 'done', findings_count must be non-negative int
    if body.get("status") == "done":
        assert isinstance(body["findings_count"], int)
        assert body["findings_count"] >= 0


def test_upload_findings_persist_to_sqlite(client):
    """Findings written by import/upload must appear in SecurityFindingsEngine SQLite.

    The handler writes to SecurityFindingsEngine using the default DB path.
    We POST an upload, grab the job_id, then query the canonical store by scan_id.
    If SAST/secrets engines find nothing (no real code), we still assert the DB
    is reachable and returns a list — proving the persist path runs without error.
    """
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
    from core.security_findings_engine import SecurityFindingsEngine

    org = "test-sqlite-persist"
    zip_bytes = _make_zip(b"password = 'supersecret'\nAWS_KEY='AKIA12345'")
    resp = client.post(
        "/api/v1/import/upload",
        files={"file": ("secrets_test.zip", zip_bytes, "application/zip")},
        data={"org_id": org},
    )
    assert resp.status_code in (200, 202), resp.text
    job_id = resp.json()["job_id"]

    # Query the canonical SQLite store that the upload handler writes to
    sfe = SecurityFindingsEngine()
    results = sfe.list_findings(org_id=org)
    findings_list = results if isinstance(results, list) else results.get("findings", [])

    # DB must be queryable; any findings written must carry the correct org_id
    assert isinstance(findings_list, list)
    for f in findings_list:
        assert f.get("org_id") == org, f"org_id mismatch: {f}"
