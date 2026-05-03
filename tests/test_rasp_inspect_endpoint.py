"""
Tests for the two new RASP router endpoints:
  POST /api/v1/rasp/inspect
  POST /api/v1/rasp/threats/{event_id}/false-positive

Run:
    python -m pytest tests/test_rasp_inspect_endpoint.py -v --timeout=10 --no-cov
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.rasp_engine import RaspConfig, RaspEngine, RaspMode


# ---------------------------------------------------------------------------
# Shared fixture: one isolated engine + auth-free TestClient per test
# ---------------------------------------------------------------------------


@pytest.fixture()
def client_engine(tmp_path):
    """Isolated RaspEngine + TestClient with auth stripped via dependency_overrides."""
    import apps.api.rasp_router as rasp_mod

    engine = RaspEngine(
        config=RaspConfig(mode=RaspMode.BLOCK),
        db_path=str(tmp_path / "rasp.db"),
    )

    # Patch the module-level getter so the router uses our isolated engine
    original_get = rasp_mod._get_engine
    rasp_mod._get_engine = lambda: engine

    app = FastAPI()
    app.include_router(rasp_mod.router)

    # Strip auth: override every dependency with a no-op lambda
    try:
        from apps.api.auth_deps import api_key_auth
        app.dependency_overrides[api_key_auth] = lambda: None
    except (ImportError, AttributeError):
        pass

    with TestClient(app, raise_server_exceptions=True) as c:
        yield c, engine

    rasp_mod._get_engine = original_get


# ---------------------------------------------------------------------------
# Test 1: clean request — 200, not blocked, zero threats
# ---------------------------------------------------------------------------


def test_inspect_clean_request(client_engine):
    client, engine = client_engine
    resp = client.post("/api/v1/rasp/inspect", json={
        "client_ip": "10.0.0.1",
        "method": "GET",
        "path": "/api/v1/assets",
        "query_params": {"page": "1", "limit": "20"},
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["blocked"] is False
    assert data["threat_count"] == 0
    assert data["threats"] == []


# ---------------------------------------------------------------------------
# Test 2: SQLi in query param — detected and blocked (mode=BLOCK)
# ---------------------------------------------------------------------------


def test_inspect_sqli_detected_and_blocked(client_engine):
    client, engine = client_engine
    resp = client.post("/api/v1/rasp/inspect", json={
        "client_ip": "1.2.3.4",
        "method": "GET",
        "path": "/api/v1/users",
        "query_params": {"id": "1 UNION SELECT * FROM users--"},
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["blocked"] is True
    assert data["threat_count"] >= 1
    threat = data["threats"][0]
    assert threat["category"] == "sqli"
    assert threat["client_ip"] == "1.2.3.4"
    assert "rule_id" in threat


# ---------------------------------------------------------------------------
# Test 3: XSS in request body — detected, correct category
# ---------------------------------------------------------------------------


def test_inspect_xss_in_body(client_engine):
    client, engine = client_engine
    resp = client.post("/api/v1/rasp/inspect", json={
        "client_ip": "5.6.7.8",
        "method": "POST",
        "path": "/api/v1/comments",
        "body_text": '<script>alert("xss")</script>',
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["threat_count"] >= 1
    categories = {t["category"] for t in data["threats"]}
    assert "xss" in categories
    severities = {t["severity"] for t in data["threats"]}
    assert severities.issubset({"low", "medium", "high", "critical"})


# ---------------------------------------------------------------------------
# Test 4: false-positive accepted for a real persisted event_id
# ---------------------------------------------------------------------------


def test_false_positive_accepted(client_engine):
    client, engine = client_engine

    # Generate a threat event first
    inspect_resp = client.post("/api/v1/rasp/inspect", json={
        "client_ip": "9.9.9.9",
        "method": "GET",
        "path": "/search",
        "query_params": {"q": "1 UNION SELECT password FROM users--"},
    })
    assert inspect_resp.status_code == 200
    threats = inspect_resp.json()["threats"]
    assert len(threats) >= 1
    event_id = threats[0]["event_id"]

    # Mark it as a false positive
    fp_resp = client.post(
        f"/api/v1/rasp/threats/{event_id}/false-positive",
        json={"reporter": "analyst@acme.com"},
    )
    assert fp_resp.status_code == 200
    fp_data = fp_resp.json()
    assert fp_data["event_id"] == event_id
    assert fp_data["accepted"] is True

    # Confirm FP rate is now non-zero in status endpoint
    status_resp = client.get("/api/v1/rasp/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["false_positive_rate"] > 0.0


# ---------------------------------------------------------------------------
# Test 5: false-positive for unknown event_id returns 404
# ---------------------------------------------------------------------------


def test_false_positive_unknown_event_404(client_engine):
    client, engine = client_engine
    resp = client.post(
        "/api/v1/rasp/threats/nonexistent-uuid-deadbeef/false-positive",
        json={"reporter": "tester"},
    )
    assert resp.status_code == 404
