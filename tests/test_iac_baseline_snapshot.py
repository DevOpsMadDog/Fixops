"""Tests for IaC baseline snapshot endpoints.

Covers:
  POST /api/v1/iac/baselines                    — create snapshot
  GET  /api/v1/iac/baselines                    — list snapshots
  GET  /api/v1/iac/baselines/{id}/snapshot      — retrieve snapshot

Uses a minimal FastAPI app (IaC router only) to avoid full create_app() timeout.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-key")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-32-chars-minimum!")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from apps.api.iac_scanner_router import router as iac_router
    from apps.api.auth_deps import api_key_auth

    mini_app = FastAPI()
    mini_app.dependency_overrides[api_key_auth] = lambda: None
    mini_app.include_router(iac_router)

    with TestClient(mini_app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture(autouse=True)
def fresh_engine():
    """Each test gets a clean IaCScannerEngine (no cross-test finding leakage).

    Patches the module-level singleton in iac_scanner_engine so that
    _get_engine() in the router always returns our isolated instance.
    """
    import core.iac_scanner_engine as _eng_mod
    from core.iac_scanner_engine import IaCScannerEngine
    eng = IaCScannerEngine()
    prev = _eng_mod._engine
    _eng_mod._engine = eng
    yield eng
    _eng_mod._engine = prev


# ---------------------------------------------------------------------------
# POST /api/v1/iac/baselines — create baseline snapshot
# ---------------------------------------------------------------------------

class TestCreateBaselineSnapshot:
    def test_returns_201(self, client):
        r = client.post("/api/v1/iac/baselines?name=initial&org_id=org1")
        assert r.status_code == 201

    def test_response_has_id_and_name(self, client):
        r = client.post("/api/v1/iac/baselines?name=my-baseline&org_id=org1")
        data = r.json()
        assert "id" in data
        assert data["name"] == "my-baseline"

    def test_snapshot_captures_zero_findings_on_empty_engine(self, client):
        r = client.post("/api/v1/iac/baselines?name=empty-snap&org_id=org1")
        data = r.json()
        assert data["total_findings"] == 0
        assert data["finding_ids"] == []

    def test_snapshot_captures_findings_after_scan(self, client):
        tf_content = (
            'resource "aws_s3_bucket" "bad" {\n'
            '  bucket = "my-bucket"\n'
            '  acl    = "public-read"\n'
            '}\n'
        )
        scan_r = client.post(
            "/api/v1/iac/scan",
            json={"content": tf_content, "filename": "main.tf"},
        )
        assert scan_r.status_code == 200

        snap_r = client.post("/api/v1/iac/baselines?name=post-scan&org_id=org1")
        data = snap_r.json()
        assert data["total_findings"] >= 1
        assert len(data["finding_ids"]) >= 1


# ---------------------------------------------------------------------------
# GET /api/v1/iac/baselines — list snapshots
# ---------------------------------------------------------------------------

class TestListBaselineSnapshots:
    def test_returns_200(self, client):
        r = client.get("/api/v1/iac/baselines?org_id=org1")
        assert r.status_code == 200

    def test_empty_list_before_any_snapshot(self, client):
        r = client.get("/api/v1/iac/baselines?org_id=org1")
        data = r.json()
        assert data["total"] == 0
        assert data["baselines"] == []

    def test_lists_created_snapshots(self, client):
        client.post("/api/v1/iac/baselines?name=snap-a&org_id=orgA")
        client.post("/api/v1/iac/baselines?name=snap-b&org_id=orgA")
        r = client.get("/api/v1/iac/baselines?org_id=orgA")
        data = r.json()
        assert data["total"] == 2
        names = {b["name"] for b in data["baselines"]}
        assert names == {"snap-a", "snap-b"}

    def test_org_isolation(self, client):
        client.post("/api/v1/iac/baselines?name=snap-x&org_id=orgX")
        client.post("/api/v1/iac/baselines?name=snap-y&org_id=orgY")
        r = client.get("/api/v1/iac/baselines?org_id=orgX")
        data = r.json()
        assert data["total"] == 1
        assert data["baselines"][0]["name"] == "snap-x"


# ---------------------------------------------------------------------------
# GET /api/v1/iac/baselines/{id}/snapshot — retrieve snapshot
# ---------------------------------------------------------------------------

class TestGetBaselineSnapshot:
    def test_returns_200_for_existing_snapshot(self, client):
        create = client.post("/api/v1/iac/baselines?name=retrieve-me&org_id=org1")
        snap_id = create.json()["id"]
        r = client.get(f"/api/v1/iac/baselines/{snap_id}/snapshot?org_id=org1")
        assert r.status_code == 200

    def test_returns_correct_snapshot(self, client):
        create = client.post(
            "/api/v1/iac/baselines?name=my-snap&description=desc&org_id=org1"
        )
        snap_id = create.json()["id"]
        r = client.get(f"/api/v1/iac/baselines/{snap_id}/snapshot?org_id=org1")
        data = r.json()
        assert data["id"] == snap_id
        assert data["name"] == "my-snap"
        assert data["description"] == "desc"

    def test_returns_404_for_unknown_id(self, client):
        r = client.get("/api/v1/iac/baselines/nonexistent-id/snapshot?org_id=org1")
        assert r.status_code == 404

    def test_returns_404_for_wrong_org(self, client):
        create = client.post("/api/v1/iac/baselines?name=cross-org&org_id=orgA")
        snap_id = create.json()["id"]
        r = client.get(f"/api/v1/iac/baselines/{snap_id}/snapshot?org_id=orgB")
        assert r.status_code == 404

    def test_snapshot_has_severity_and_provider_counts(self, client):
        create = client.post("/api/v1/iac/baselines?name=sev-test&org_id=org1")
        snap_id = create.json()["id"]
        r = client.get(f"/api/v1/iac/baselines/{snap_id}/snapshot?org_id=org1")
        data = r.json()
        assert "severity_counts" in data
        assert "provider_counts" in data
        assert "created_at" in data
