import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.sast_router import router, _sanitize_filename


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("FIXOPS_API_TOKEN", os.getenv("FIXOPS_API_TOKEN", "test-token"))
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def auth_headers():
    return {"X-API-Key": os.getenv("FIXOPS_API_TOKEN", "test-token")}


def test_sanitize_filename_preserves_safe_relative_repo_path():
    assert _sanitize_filename("suite-core/core/sast_engine.py") == "suite-core/core/sast_engine.py"


def test_sanitize_filename_strips_traversal_but_preserves_structure():
    assert _sanitize_filename("../../suite-core/core/sast_engine.py") == "suite-core/core/sast_engine.py"


def test_scan_code_uses_sanitized_relative_path(client, monkeypatch, auth_headers):
    captured = {}

    class DummyResult:
        def to_dict(self):
            return {
                "scan_id": "sast-test",
                "files_scanned": 1,
                "total_findings": 0,
                "findings": [],
                "taint_flows": [],
                "by_severity": {},
                "by_cwe": {},
                "duration_ms": 0.1,
            }

    class DummyEngine:
        def scan_code(self, code, filename="input.py"):
            captured["code"] = code
            captured["filename"] = filename
            return DummyResult()

    monkeypatch.setattr("apps.api.sast_router.get_sast_engine", lambda: DummyEngine())

    response = client.post(
        "/api/v1/sast/scan/code",
        headers=auth_headers,
        json={
            "code": "print('ok')",
            "filename": "../../suite-core/core/sast_engine.py",
            "language": "python",
        },
    )

    assert response.status_code == 200
    assert captured["filename"] == "suite-core/core/sast_engine.py"
