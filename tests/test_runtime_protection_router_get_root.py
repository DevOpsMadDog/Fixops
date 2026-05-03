"""Tests for runtime_protection_router GET / root endpoint and core EDR endpoints.

Covers:
  GET  /api/v1/runtime/          — service index
  POST /api/v1/runtime/events    — event ingest
  GET  /api/v1/runtime/policies  — policy list (includes built-ins)
  POST /api/v1/runtime/events/evaluate + GET /api/v1/runtime/alerts — alert flow
  GET  /api/v1/runtime/stats     — aggregate stats

Usage:
    pytest tests/test_runtime_protection_router_get_root.py -v --timeout=10
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

import apps.api.runtime_protection_router as rpr_mod
from core.runtime_protection import HostRuntimeEngine


@pytest.fixture()
def client(tmp_path):
    """Isolated HostRuntimeEngine + auth-free TestClient."""
    engine = HostRuntimeEngine(db_path=str(tmp_path / "edr.db"))

    original_get = rpr_mod._get_engine
    rpr_mod._engine = engine

    app = FastAPI()
    app.include_router(rpr_mod.router)

    try:
        from apps.api.auth_deps import api_key_auth
        app.dependency_overrides[api_key_auth] = lambda: None
    except (ImportError, AttributeError):
        pass

    with TestClient(app, raise_server_exceptions=True) as c:
        yield c

    rpr_mod._engine = None


# ---------------------------------------------------------------------------
# 1. GET / — service index
# ---------------------------------------------------------------------------

def test_root_status_ok(client):
    resp = client.get("/api/v1/runtime/")
    assert resp.status_code == 200


def test_root_has_required_keys(client):
    data = client.get("/api/v1/runtime/").json()
    assert data["service"] == "eks-runtime-protection"
    assert data["status"] == "operational"
    assert isinstance(data["endpoints"], list)
    assert len(data["endpoints"]) >= 11


def test_root_capabilities_present(client):
    data = client.get("/api/v1/runtime/").json()
    caps = data["capabilities"]
    assert "process-exec-monitoring" in caps
    assert "container-escape-detection" in caps
    assert "anomaly-detection" in caps


def test_root_layers(client):
    data = client.get("/api/v1/runtime/").json()
    assert "host-edr" in data["layers"]
    assert "rasp" in data["layers"]


# ---------------------------------------------------------------------------
# 2. POST /events — ingest returns 201 + event_id
# ---------------------------------------------------------------------------

def test_ingest_event_returns_201(client):
    resp = client.post("/api/v1/runtime/events", json={
        "event_type": "process_exec",
        "source_host": "eks-node-01",
        "process_name": "bash",
        "user": "root",
        "details": {"pid": 1234, "cmdline": "bash -i"},
        "threat_level": "high",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert "event_id" in data
    assert data["status"] == "ingested"


# ---------------------------------------------------------------------------
# 3. GET /policies — built-in policies seeded on engine init
# ---------------------------------------------------------------------------

def test_policy_list_includes_builtins(client):
    resp = client.get("/api/v1/runtime/policies")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 5  # 5 built-in policies
    names = [p["name"] for p in data["policies"]]
    assert any("Crypto Mining" in n for n in names)
    assert any("Container Escape" in n for n in names)


# ---------------------------------------------------------------------------
# 4. POST /events/evaluate — triggers alert on crypto-mining process
# ---------------------------------------------------------------------------

def test_evaluate_crypto_mining_generates_alert(client):
    resp = client.post("/api/v1/runtime/events/evaluate", json={
        "event_type": "process_exec",
        "source_host": "eks-node-02",
        "process_name": "xmrig",
        "user": "nobody",
        "details": {"cmdline": "--pool stratum+tcp://pool.minexmr.com:4444"},
        "threat_level": "critical",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["alerts_generated"] >= 1
    alert = data["alerts"][0]
    assert alert["threat_level"] == "critical"
    assert "policy_id" in alert


def test_alerts_endpoint_shows_active(client):
    # Ingest + evaluate a threat first
    client.post("/api/v1/runtime/events/evaluate", json={
        "event_type": "process_exec",
        "source_host": "eks-node-03",
        "process_name": "xmrig",
        "user": "daemon",
        "details": {"cmdline": "--pool stratum+ssl://xmr.pool.minergate.com"},
        "threat_level": "critical",
    })
    resp = client.get("/api/v1/runtime/alerts")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert all(not a["acknowledged"] for a in data["alerts"])


# ---------------------------------------------------------------------------
# 5. GET /stats — aggregate stats reflect ingested events
# ---------------------------------------------------------------------------

def test_stats_counts_ingested_events(client):
    client.post("/api/v1/runtime/events", json={
        "event_type": "file_access",
        "source_host": "eks-node-04",
        "process_name": "cat",
        "user": "www-data",
        "details": {"path": "/etc/passwd"},
        "threat_level": "medium",
    })
    resp = client.get("/api/v1/runtime/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["events_total"] >= 1
    assert "events_by_type" in data
    assert "top_hosts" in data
