"""Router-level HTTP tests for Network Anomaly / IDS-IPS API.

Covers /api/v1/network-anomaly/* via FastAPI TestClient with
a temp-DB-backed engine (no singleton bleed between tests).

6 tests: POST /samples, POST /baselines/update, POST /detect,
PUT /anomalies/{id}/resolve, GET /summary, GET /baselines.
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

from core.network_anomaly_engine import NetworkAnomalyEngine
import apps.api.network_anomaly_router as _router_mod
from apps.api.network_anomaly_router import router

ORG = "org-ids-test"
SEG = "dmz"
PROTO = "TCP"
DIR = "inbound"


@pytest.fixture
def client(tmp_path, monkeypatch):
    fresh = NetworkAnomalyEngine(db_path=str(tmp_path / "na_router_test.db"))
    monkeypatch.setattr(_router_mod, "_get_engine", lambda: fresh)

    app = FastAPI()
    app.include_router(router)

    # Override any auth dependencies to a no-op so 401s don't fire
    try:
        from apps.api.auth_deps import api_key_auth as _auth
        app.dependency_overrides[_auth] = lambda: None
    except ImportError:
        pass

    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# 1. POST /samples
# ---------------------------------------------------------------------------

def test_record_sample_201_shape(client):
    resp = client.post(
        "/api/v1/network-anomaly/samples",
        json={
            "org_id": ORG,
            "segment": SEG,
            "protocol": PROTO,
            "direction": DIR,
            "bytes_per_min": 1200.0,
            "packets_per_min": 60.0,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["org_id"] == ORG
    assert body["segment"] == SEG
    assert body["bytes_per_min"] == 1200.0
    assert "id" in body
    assert "sampled_at" in body


# ---------------------------------------------------------------------------
# 2. POST /baselines/update
# ---------------------------------------------------------------------------

def test_update_baseline_after_sample(client):
    client.post(
        "/api/v1/network-anomaly/samples",
        json={"org_id": ORG, "segment": SEG, "protocol": PROTO,
              "direction": DIR, "bytes_per_min": 1000.0, "packets_per_min": 50.0},
    )
    resp = client.post(
        "/api/v1/network-anomaly/baselines/update",
        json={"org_id": ORG, "segment": SEG, "protocol": PROTO, "direction": DIR},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert abs(body["avg_bytes_per_min"] - 1000.0) < 0.01
    assert body["sample_count"] == 1


# ---------------------------------------------------------------------------
# 3. POST /detect — spike detected
# ---------------------------------------------------------------------------

def test_detect_spike_above_threshold(client):
    # seed one sample and build baseline at 1000 bytes/min
    client.post(
        "/api/v1/network-anomaly/samples",
        json={"org_id": ORG, "segment": SEG, "protocol": PROTO,
              "direction": DIR, "bytes_per_min": 1000.0, "packets_per_min": 50.0},
    )
    client.post(
        "/api/v1/network-anomaly/baselines/update",
        json={"org_id": ORG, "segment": SEG, "protocol": PROTO, "direction": DIR},
    )
    # 3500 = 250% above baseline → critical spike
    resp = client.post(
        "/api/v1/network-anomaly/detect",
        json={"org_id": ORG, "segment": SEG, "protocol": PROTO,
              "direction": DIR, "bytes_per_min": 3500.0, "packets_per_min": 50.0},
    )
    assert resp.status_code == 200
    anomalies = resp.json()
    assert len(anomalies) == 1
    assert anomalies[0]["anomaly_type"] == "spike"
    assert anomalies[0]["severity"] == "critical"
    assert anomalies[0]["status"] == "active"


# ---------------------------------------------------------------------------
# 4. PUT /anomalies/{id}/resolve
# ---------------------------------------------------------------------------

def test_resolve_anomaly(client):
    client.post(
        "/api/v1/network-anomaly/samples",
        json={"org_id": ORG, "segment": SEG, "protocol": PROTO,
              "direction": DIR, "bytes_per_min": 1000.0, "packets_per_min": 50.0},
    )
    client.post(
        "/api/v1/network-anomaly/baselines/update",
        json={"org_id": ORG, "segment": SEG, "protocol": PROTO, "direction": DIR},
    )
    detect_resp = client.post(
        "/api/v1/network-anomaly/detect",
        json={"org_id": ORG, "segment": SEG, "protocol": PROTO,
              "direction": DIR, "bytes_per_min": 3500.0, "packets_per_min": 50.0},
    )
    anomaly_id = detect_resp.json()[0]["id"]

    resp = client.put(
        f"/api/v1/network-anomaly/anomalies/{anomaly_id}/resolve",
        params={"org_id": ORG},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "resolved"
    assert body["resolved_at"] is not None


# ---------------------------------------------------------------------------
# 5. GET /summary
# ---------------------------------------------------------------------------

def test_summary_reflects_detections(client):
    client.post(
        "/api/v1/network-anomaly/samples",
        json={"org_id": ORG, "segment": SEG, "protocol": PROTO,
              "direction": DIR, "bytes_per_min": 1000.0, "packets_per_min": 50.0},
    )
    client.post(
        "/api/v1/network-anomaly/baselines/update",
        json={"org_id": ORG, "segment": SEG, "protocol": PROTO, "direction": DIR},
    )
    client.post(
        "/api/v1/network-anomaly/detect",
        json={"org_id": ORG, "segment": SEG, "protocol": PROTO,
              "direction": DIR, "bytes_per_min": 3500.0, "packets_per_min": 50.0},
    )

    resp = client.get("/api/v1/network-anomaly/summary", params={"org_id": ORG})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] >= 1
    assert body["active"] >= 1
    assert SEG in body["by_segment"]


# ---------------------------------------------------------------------------
# 6. GET /baselines
# ---------------------------------------------------------------------------

def test_baselines_health_endpoint(client):
    client.post(
        "/api/v1/network-anomaly/samples",
        json={"org_id": ORG, "segment": SEG, "protocol": PROTO,
              "direction": DIR, "bytes_per_min": 800.0, "packets_per_min": 40.0},
    )
    client.post(
        "/api/v1/network-anomaly/baselines/update",
        json={"org_id": ORG, "segment": SEG, "protocol": PROTO, "direction": DIR},
    )

    resp = client.get("/api/v1/network-anomaly/baselines", params={"org_id": ORG})
    assert resp.status_code == 200
    baselines = resp.json()
    assert len(baselines) == 1
    assert baselines[0]["segment"] == SEG
    assert baselines[0]["sample_count"] == 1
