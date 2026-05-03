"""Router-level HTTP tests for Checkov IaC scanner capability API.

Covers /api/v1/checkov/* via FastAPI TestClient with a fresh tmp_path-backed
engine per test (no singleton bleed). NO MOCKS — real CheckovScanEngine,
real SQLite, real Pydantic round-trips. Falls back to record-only when the
checkov binary is not installed (status="unavailable").

Tests:
  1. GET /                                empty (no scans yet)
  2. GET /                                ok (after scan queued)
  3. GET /frameworks                      14-framework catalog
  4. POST /scan                           queues + persists, status="unavailable" w/o binary
  5. POST /scan                           bad framework -> 422
  6. GET /scan/{scan_id}                  returns full record
  7. GET /scan/{unknown}                  -> 404
  8. Engine + DB round-trip
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

for _p in ["suite-core", "suite-api"]:
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

from core.checkov_scan_engine import (  # noqa: E402
    ALL_FRAMEWORKS,
    SEVERITY_LEVELS,
    CheckovScanEngine,
)
import apps.api.checkov_router as _router_mod  # noqa: E402
from apps.api.checkov_router import router  # noqa: E402


@pytest.fixture
def engine(tmp_path):
    # Use a binary name guaranteed not to exist so is_available() = False
    # and the scan path takes the "unavailable" branch deterministically.
    return CheckovScanEngine(
        db_path=str(tmp_path / "checkov_test.db"),
        checkov_binary="checkov_does_not_exist_zzz",
    )


@pytest.fixture
def client(engine, monkeypatch):
    monkeypatch.setattr(_router_mod, "_engine", lambda: engine)

    app = FastAPI()
    app.include_router(router)

    try:
        from apps.api.auth_deps import api_key_auth as _auth
        app.dependency_overrides[_auth] = lambda: None
    except ImportError:
        pass

    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# 1. GET / — empty
# ---------------------------------------------------------------------------

def test_capability_summary_empty(client):
    resp = client.get("/api/v1/checkov/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Checkov"
    assert body["status"] == "empty"
    assert body["scan_count"] == 0
    assert body["framework_count"] == 14
    assert body["framework_count"] == len(ALL_FRAMEWORKS)
    assert body["severity_levels"] == ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    for fw in [
        "terraform", "kubernetes", "helm", "cloudformation", "dockerfile",
        "github_actions", "arm", "bicep", "gitlab_ci", "circleci_pipelines",
        "argo_workflows", "openapi", "sca_image", "secrets",
    ]:
        assert fw in body["frameworks"]
    # binary_available should be False since we forced a non-existent binary
    assert body["binary_available"] is False


# ---------------------------------------------------------------------------
# 2. GET / — ok after scan
# ---------------------------------------------------------------------------

def test_capability_summary_ok_after_scan(client):
    queued = client.post(
        "/api/v1/checkov/scan",
        json={"target_path": "/tmp/some/iac"},
    )
    assert queued.status_code == 202

    resp = client.get("/api/v1/checkov/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["scan_count"] == 1


# ---------------------------------------------------------------------------
# 3. GET /frameworks — full 14-framework catalog
# ---------------------------------------------------------------------------

def test_list_frameworks_returns_full_catalog(client):
    resp = client.get("/api/v1/checkov/frameworks")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 14
    names = [f["framework"] for f in body["frameworks"]]
    assert sorted(names) == sorted(ALL_FRAMEWORKS)
    for entry in body["frameworks"]:
        assert set(entry.keys()) >= {"framework", "description"}
        assert isinstance(entry["description"], str)
        assert len(entry["description"]) > 5


# ---------------------------------------------------------------------------
# 4. POST /scan — queues, persists, marked unavailable when binary missing
# ---------------------------------------------------------------------------

def test_post_scan_queues_and_persists(client, engine):
    resp = client.post(
        "/api/v1/checkov/scan",
        json={
            "target_path": "/repos/aldeci/iac",
            "frameworks": ["terraform", "kubernetes"],
            "skip_checks": ["CKV_AWS_8"],
            "soft_fail": True,
        },
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["target_path"] == "/repos/aldeci/iac"
    assert body["frameworks"] == ["terraform", "kubernetes"]
    assert "scan_id" in body
    assert "queued_at" in body

    # Persisted in SQLite — and since the binary is fake, status is unavailable.
    persisted = engine.get_scan(body["scan_id"])
    assert persisted is not None
    assert persisted["target_path"] == "/repos/aldeci/iac"
    assert persisted["status"] == "unavailable"
    assert persisted["findings"] == []
    assert persisted["error"] is not None
    assert "checkov binary not found" in persisted["error"].lower()


# ---------------------------------------------------------------------------
# 5. POST /scan — bad framework -> 422
# ---------------------------------------------------------------------------

def test_post_scan_invalid_framework_returns_422(client):
    resp = client.post(
        "/api/v1/checkov/scan",
        json={
            "target_path": "/tmp/x",
            "frameworks": ["totally_made_up_framework"],
        },
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert "totally_made_up_framework" in detail or "Unknown framework" in detail


# ---------------------------------------------------------------------------
# 6. GET /scan/{scan_id} — round trip
# ---------------------------------------------------------------------------

def test_get_scan_round_trip(client):
    queued = client.post(
        "/api/v1/checkov/scan",
        json={"target_path": "/tmp/roundtrip", "frameworks": ["dockerfile"]},
    )
    assert queued.status_code == 202
    scan_id = queued.json()["scan_id"]

    detail = client.get(f"/api/v1/checkov/scan/{scan_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["scan_id"] == scan_id
    assert body["target_path"] == "/tmp/roundtrip"
    assert body["frameworks"] == ["dockerfile"]
    assert body["status"] == "unavailable"  # binary stub absent
    # all 5 severities normalized
    assert set(body["severity_counts"].keys()) == set(SEVERITY_LEVELS)
    for level in SEVERITY_LEVELS:
        assert body["severity_counts"][level] == 0
    assert body["findings"] == []


# ---------------------------------------------------------------------------
# 7. GET /scan/{unknown} -> 404
# ---------------------------------------------------------------------------

def test_get_scan_unknown_returns_404(client):
    resp = client.get("/api/v1/checkov/scan/no-such-scan-id")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 8. Engine + DB round-trip (no HTTP)
# ---------------------------------------------------------------------------

def test_engine_round_trip(engine):
    assert engine.count_scans() == 0
    s = engine.queue_scan(
        target_path="/some/iac/path",
        frameworks=["helm", "terraform"],
        soft_fail=False,
    )
    assert "scan_id" in s
    assert engine.count_scans() == 1

    rows = engine.list_scans(limit=10)
    assert len(rows) == 1
    assert rows[0]["scan_id"] == s["scan_id"]

    detail = engine.get_scan(s["scan_id"])
    assert detail["status"] == "unavailable"
    assert detail["frameworks"] == ["helm", "terraform"]
    assert detail["findings"] == []
    assert detail["severity_counts"] == {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    # Capability reflects state
    cap = engine.capability()
    assert cap["service"] == "Checkov"
    assert cap["scan_count"] == 1
    assert cap["status"] == "ok"
    assert cap["framework_count"] == 14
    assert cap["binary_available"] is False
