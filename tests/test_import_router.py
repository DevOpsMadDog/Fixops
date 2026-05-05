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
