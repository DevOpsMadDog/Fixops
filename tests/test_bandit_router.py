"""
Router-level HTTP tests for Bandit SAST capability API.

Covers /api/v1/bandit/* via FastAPI TestClient with a fresh tmp_path-backed
engine per test (no singleton bleed). NO MOCKS — real BanditScanEngine,
real SQLite, real Pydantic round-trips.

8 tests:
  1.  GET /          empty (no scans queued)
  2.  GET /          ok (after a scan is queued)
  3.  GET /rules     full catalog
  4.  GET /rules/B602 known-rule detail
  5.  GET /rules/B999 unknown-rule -> 404
  6.  POST /scan     queues + persists
  7.  POST /scan     bad severity_threshold -> 400
  8.  Engine + DB    schema and row round-trip
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

from core.bandit_scan_engine import (
    ALL_RULE_IDS,
    BanditScanEngine,
    SEVERITY_LEVELS,
)
import apps.api.bandit_router as _router_mod
from apps.api.bandit_router import router


@pytest.fixture
def engine(tmp_path):
    return BanditScanEngine(db_path=str(tmp_path / "bandit_test.db"))


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
# 1. GET /  — no scans yet, status=empty
# ---------------------------------------------------------------------------

def test_capability_summary_empty(client):
    resp = client.get("/api/v1/bandit/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Bandit"
    assert body["status"] == "empty"
    assert body["scan_count"] == 0
    assert body["rule_count"] == len(ALL_RULE_IDS)
    assert "B101" in body["rule_ids"]
    assert "B602" in body["rule_ids"]
    assert "B701" in body["rule_ids"]
    assert body["confidence_levels"] == ["LOW", "MEDIUM", "HIGH"]
    assert body["severity_levels"] == ["LOW", "MEDIUM", "HIGH"]


# ---------------------------------------------------------------------------
# 2. GET /  — after queueing, status=ok
# ---------------------------------------------------------------------------

def test_capability_summary_ok_after_scan(client):
    queued = client.post(
        "/api/v1/bandit/scan",
        json={"target_path": "/tmp/some/repo"},
    )
    assert queued.status_code == 202

    resp = client.get("/api/v1/bandit/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["scan_count"] == 1


# ---------------------------------------------------------------------------
# 3. GET /rules — full catalog
# ---------------------------------------------------------------------------

def test_list_rules_returns_full_catalog(client):
    resp = client.get("/api/v1/bandit/rules")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == len(ALL_RULE_IDS)
    assert body["count"] >= 30
    ids = [r["rule_id"] for r in body["rules"]]
    assert "B101" in ids and "B303" in ids and "B602" in ids and "B701" in ids
    # every entry must have full schema
    for rule in body["rules"]:
        assert set(rule.keys()) >= {
            "rule_id", "name", "severity", "confidence", "description"
        }
        assert rule["severity"] in SEVERITY_LEVELS
        assert rule["confidence"] in SEVERITY_LEVELS


# ---------------------------------------------------------------------------
# 4. GET /rules/{rule_id} — known rule
# ---------------------------------------------------------------------------

def test_get_rule_known(client):
    resp = client.get("/api/v1/bandit/rules/B602")
    assert resp.status_code == 200
    body = resp.json()
    assert body["rule_id"] == "B602"
    assert body["name"] == "subprocess_popen_with_shell_equals_true"
    assert body["severity"] == "HIGH"

    # case-insensitive lookup
    resp_lc = client.get("/api/v1/bandit/rules/b602")
    assert resp_lc.status_code == 200
    assert resp_lc.json()["rule_id"] == "B602"


# ---------------------------------------------------------------------------
# 5. GET /rules/{rule_id} — unknown rule
# ---------------------------------------------------------------------------

def test_get_rule_unknown_returns_404(client):
    resp = client.get("/api/v1/bandit/rules/B999")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 6. POST /scan — queues and persists
# ---------------------------------------------------------------------------

def test_post_scan_queues_and_persists(client, engine):
    resp = client.post(
        "/api/v1/bandit/scan",
        json={
            "target_path": "/repos/aldeci",
            "rule_ids": ["B101", "B602"],
            "severity_threshold": "MEDIUM",
        },
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "queued"
    assert body["target"] == "/repos/aldeci"
    assert body["rule_ids"] == ["B101", "B602"]
    assert body["severity_threshold"] == "MEDIUM"
    assert "scan_id" in body
    assert "started_at" in body

    # Persisted in SQLite
    persisted = engine.get_scan(body["scan_id"])
    assert persisted is not None
    assert persisted["target_path"] == "/repos/aldeci"
    assert persisted["status"] == "queued"
    assert persisted["findings"] == []


# ---------------------------------------------------------------------------
# 7. POST /scan — bad severity_threshold
# ---------------------------------------------------------------------------

def test_post_scan_invalid_severity_returns_400(client):
    resp = client.post(
        "/api/v1/bandit/scan",
        json={
            "target_path": "/tmp/x",
            "severity_threshold": "CRITICAL",  # not in catalog
        },
    )
    assert resp.status_code == 400
    assert "severity" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 8. Engine + DB round-trip (no HTTP)
# ---------------------------------------------------------------------------

def test_engine_round_trip(engine):
    assert engine.count_scans() == 0
    s = engine.queue_scan(
        target_path="/some/path",
        rule_ids=["B324"],
        severity_threshold="HIGH",
    )
    assert s["status"] == "queued"
    assert engine.count_scans() == 1

    # listing returns the queued scan
    rows = engine.list_scans(limit=10)
    assert len(rows) == 1
    assert rows[0]["scan_id"] == s["scan_id"]
    assert rows[0]["status"] == "queued"
    assert rows[0]["severity_counts"] == {"LOW": 0, "MEDIUM": 0, "HIGH": 0}

    # rule lookup still works
    rule = engine.get_rule("B324")
    assert rule is not None
    assert rule["name"] == "hashlib_insecure_functions"
