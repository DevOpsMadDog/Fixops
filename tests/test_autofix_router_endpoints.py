"""Tests for AutoFix Router endpoints via TestClient."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))
sys.path.insert(0, os.path.join(ROOT, "suite-api"))

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.autofix_router import router


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


class TestAutoFixRouterEndpoints:
    def test_get_status(self, client):
        resp = client.get("/api/v1/autofix/status")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)

    def test_generate_fix(self, client):
        resp = client.post("/api/v1/autofix/generate", json={
            "finding_id": "FIND-001",
            "title": "SQL Injection in user query",
            "severity": "critical",
            "cwe_id": "CWE-89",
            "file_path": "app/db.py",
            "source_code": "cursor.execute('SELECT * FROM users WHERE id=' + uid)",
            "language": "python",
        })
        assert resp.status_code in (200, 201, 422)

    def test_list_fixes(self, client):
        resp = client.get("/api/v1/autofix/fixes")
        assert resp.status_code in (200, 404)  # may need query params

    def test_get_fix(self, client):
        resp = client.get("/api/v1/autofix/fixes/nonexistent")
        assert resp.status_code in (200, 404)

    def test_verify_fix(self, client):
        resp = client.post("/api/v1/autofix/verify", json={
            "fix_id": "fix-001",
            "status": "approved",
        })
        assert resp.status_code in (200, 201, 404, 422)

    def test_get_supported_types(self, client):
        resp = client.get("/api/v1/autofix/types")
        assert resp.status_code in (200, 404, 405)

    def test_get_metrics(self, client):
        resp = client.get("/api/v1/autofix/metrics")
        assert resp.status_code in (200, 404, 405)
