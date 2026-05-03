"""Router-level HTTP tests for Semgrep SAST capability API.

Covers /api/v1/semgrep/* via FastAPI TestClient with a fresh tmp_path-backed
engine per test (no singleton bleed). NO MOCKS — real SemgrepScanEngine,
real SQLite, real Pydantic round-trips.

When the semgrep CLI is absent (the common CI case), the engine records
scans with status="unavailable" rather than fabricating findings — these
tests assert exactly that contract.
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

from core.semgrep_scan_engine import (  # noqa: E402
    ALL_RULE_PACK_IDS,
    SEVERITY_LEVELS,
    SemgrepScanEngine,
)
import apps.api.semgrep_scan_router as _router_mod  # noqa: E402
from apps.api.semgrep_scan_router import router  # noqa: E402


@pytest.fixture
def engine(tmp_path):
    return SemgrepScanEngine(db_path=str(tmp_path / "semgrep_test.db"))


@pytest.fixture
def client(engine, monkeypatch):
    monkeypatch.setattr(_router_mod, "_get_engine", lambda: engine)

    app = FastAPI()
    app.include_router(router)

    # Override auth so 401s don't fire in unit context
    try:
        from apps.api.auth_deps import api_key_auth as _auth
        app.dependency_overrides[_auth] = lambda: None
    except ImportError:
        pass

    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# 1. GET /  — empty / unavailable capability summary
# ---------------------------------------------------------------------------

def test_capability_summary_initial(client, engine):
    resp = client.get("/api/v1/semgrep/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Semgrep"
    assert body["severity_levels"] == ["INFO", "WARNING", "ERROR"]
    assert body["scan_count"] == 0
    # Either "unavailable" (no semgrep CLI) or "empty" (CLI present, no scans).
    assert body["status"] in ("unavailable", "empty")
    assert body["binary_present"] is engine.is_semgrep_available()
    # All required rule packs present
    for required in (
        "r2c-security-audit",
        "owasp-top-10",
        "ci-rules",
        "python",
        "javascript",
        "typescript",
    ):
        assert required in body["rule_packs"]


# ---------------------------------------------------------------------------
# 2. GET /rule-packs — full catalog
# ---------------------------------------------------------------------------

def test_list_rule_packs_returns_full_catalog(client):
    resp = client.get("/api/v1/semgrep/rule-packs")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == len(ALL_RULE_PACK_IDS)
    assert body["count"] >= 6
    ids = [p["id"] for p in body["rule_packs"]]
    for required in (
        "r2c-security-audit",
        "owasp-top-10",
        "ci-rules",
        "python",
        "javascript",
        "typescript",
    ):
        assert required in ids
    for pack in body["rule_packs"]:
        assert set(pack.keys()) >= {"id", "name", "description"}
        assert pack["description"]


# ---------------------------------------------------------------------------
# 3. POST /scan — queues + persists, returns 202 with envelope
# ---------------------------------------------------------------------------

def test_post_scan_queues_and_persists(client, engine, tmp_path):
    target = str(tmp_path / "src")
    Path(target).mkdir(parents=True, exist_ok=True)
    resp = client.post(
        "/api/v1/semgrep/scan",
        json={
            "target_path": target,
            "rule_packs": ["python", "javascript"],
            "severity_threshold": "WARNING",
        },
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["target_path"] == target
    assert body["rule_packs"] == ["python", "javascript"]
    assert "scan_id" in body and body["scan_id"]
    assert "queued_at" in body and body["queued_at"]

    # Persisted in SQLite
    persisted = engine.get_scan(body["scan_id"])
    assert persisted is not None
    assert persisted["target_path"] == target
    # status will be "completed" (CLI ran), "unavailable" (CLI missing) or
    # "failed" (CLI exited non-zero); never "queued" because we run inline.
    assert persisted["status"] in ("completed", "unavailable", "failed")
    assert persisted["rule_packs"] == ["python", "javascript"]
    # severity_counts always has all three keys regardless of run outcome
    assert set(persisted["severity_counts"].keys()) >= set(SEVERITY_LEVELS)
    # findings is always a list (no fake findings on unavailable)
    assert isinstance(persisted["findings"], list)


# ---------------------------------------------------------------------------
# 4. POST /scan — bad severity_threshold → 422
# ---------------------------------------------------------------------------

def test_post_scan_invalid_severity_returns_422(client, tmp_path):
    target = str(tmp_path / "x")
    Path(target).mkdir(parents=True, exist_ok=True)
    resp = client.post(
        "/api/v1/semgrep/scan",
        json={
            "target_path": target,
            "severity_threshold": "CRITICAL",  # not in catalog
        },
    )
    assert resp.status_code == 422
    assert "severity" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 5. POST /scan — missing target_path → 422
# ---------------------------------------------------------------------------

def test_post_scan_empty_target_returns_422(client):
    resp = client.post(
        "/api/v1/semgrep/scan",
        json={"target_path": "   "},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 6. GET /scan/{scan_id} — fetch existing record
# ---------------------------------------------------------------------------

def test_get_scan_returns_record(client, engine, tmp_path):
    target = str(tmp_path / "fetch_me")
    Path(target).mkdir(parents=True, exist_ok=True)
    queued = client.post(
        "/api/v1/semgrep/scan",
        json={"target_path": target, "rule_packs": ["python"]},
    )
    assert queued.status_code == 202
    scan_id = queued.json()["scan_id"]

    fetched = client.get(f"/api/v1/semgrep/scan/{scan_id}")
    assert fetched.status_code == 200
    body = fetched.json()
    assert body["scan_id"] == scan_id
    assert body["target_path"] == target
    assert body["rule_packs"] == ["python"]
    assert body["status"] in ("completed", "unavailable", "failed")
    # severity_counts always populated with INFO/WARNING/ERROR
    assert set(body["severity_counts"].keys()) >= set(SEVERITY_LEVELS)
    # findings is always a list
    assert isinstance(body["findings"], list)


# ---------------------------------------------------------------------------
# 7. GET /scan/{scan_id} — unknown id → 404
# ---------------------------------------------------------------------------

def test_get_scan_unknown_returns_404(client):
    resp = client.get("/api/v1/semgrep/scan/does-not-exist")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 8. Capability summary flips to "ok" or "unavailable" after a scan
# ---------------------------------------------------------------------------

def test_capability_summary_after_scan(client, engine, tmp_path):
    target = str(tmp_path / "after")
    Path(target).mkdir(parents=True, exist_ok=True)
    queued = client.post(
        "/api/v1/semgrep/scan",
        json={"target_path": target},
    )
    assert queued.status_code == 202

    resp = client.get("/api/v1/semgrep/")
    assert resp.status_code == 200
    body = resp.json()
    # scan_count incremented
    assert body["scan_count"] == 1
    # status: ok if binary present, unavailable otherwise
    if body["binary_present"]:
        assert body["status"] == "ok"
    else:
        assert body["status"] == "unavailable"


# ---------------------------------------------------------------------------
# 9. Engine round-trip (no HTTP) — schema + record persistence
# ---------------------------------------------------------------------------

def test_engine_round_trip(engine, tmp_path):
    assert engine.count_scans() == 0
    target = str(tmp_path / "engine_test")
    Path(target).mkdir(parents=True, exist_ok=True)

    queued = engine.queue_scan(
        target_path=target,
        rule_packs=["typescript", "owasp-top-10"],
        severity_threshold="ERROR",
    )
    assert queued["target_path"] == target
    assert queued["rule_packs"] == ["typescript", "owasp-top-10"]
    assert queued["scan_id"]

    assert engine.count_scans() == 1

    record = engine.get_scan(queued["scan_id"])
    assert record is not None
    assert record["status"] in ("completed", "unavailable", "failed")
    # rule pack catalog lookup still works
    rp = engine.get_rule_pack("python")
    assert rp is not None and rp["id"] == "python"
    # case-insensitive
    rp2 = engine.get_rule_pack("PYTHON")
    assert rp2 is not None and rp2["id"] == "python"
    # unknown returns None
    assert engine.get_rule_pack("does-not-exist") is None
