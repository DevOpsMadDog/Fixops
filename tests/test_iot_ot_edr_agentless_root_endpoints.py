"""Tests for IoT/OT/EDR/Agentless GET / root endpoints (BUG-1 fix).

Adds GET / capability-summary handlers to:
  - GET /api/v1/iot-security/
  - GET /api/v1/ot-security/
  - GET /api/v1/edr/
  - GET /api/v1/agentless-snapshot/
"""
from __future__ import annotations

import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Must be set BEFORE any app/router import so auth_deps picks it up.
_TEST_TOKEN = "test-iot-ot-edr-root-key"
os.environ["FIXOPS_API_TOKEN"] = _TEST_TOKEN

_HEADERS = {"X-API-Key": _TEST_TOKEN}
_ACCEPTABLE = {200, 201, 307, 308}


def _make_client(router) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# IoT Security GET /
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def iot_client():
    from apps.api.iot_security_router import router
    return _make_client(router)


def test_iot_root_status_ok(iot_client):
    r = iot_client.get("/api/v1/iot-security/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE, r.text


def test_iot_root_service_field(iot_client):
    r = iot_client.get("/api/v1/iot-security/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE
    assert r.json()["service"] == "iot-security"


def test_iot_root_operational(iot_client):
    r = iot_client.get("/api/v1/iot-security/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE
    assert r.json()["status"] == "operational"


def test_iot_root_capabilities_present(iot_client):
    r = iot_client.get("/api/v1/iot-security/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE
    caps = r.json()["capabilities"]
    assert "device_registration" in caps
    assert "anomaly_detection" in caps


def test_iot_root_stats_present(iot_client):
    r = iot_client.get("/api/v1/iot-security/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE
    assert "stats" in r.json()


# ---------------------------------------------------------------------------
# OT Security GET /
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def ot_client():
    from apps.api.ot_security_router import router
    return _make_client(router)


def test_ot_root_status_ok(ot_client):
    r = ot_client.get("/api/v1/ot-security/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE, r.text


def test_ot_root_service_field(ot_client):
    r = ot_client.get("/api/v1/ot-security/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE
    assert r.json()["service"] == "ot-security"


def test_ot_root_operational(ot_client):
    r = ot_client.get("/api/v1/ot-security/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE
    assert r.json()["status"] == "operational"


def test_ot_root_capabilities_present(ot_client):
    r = ot_client.get("/api/v1/ot-security/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE
    caps = r.json()["capabilities"]
    assert "asset_registry" in caps
    assert "ics_scada_monitoring" in caps


def test_ot_root_stats_present(ot_client):
    r = ot_client.get("/api/v1/ot-security/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE
    assert "stats" in r.json()


# ---------------------------------------------------------------------------
# EDR GET /
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def edr_client():
    from apps.api.edr_router import router
    return _make_client(router)


def test_edr_root_status_ok(edr_client):
    r = edr_client.get("/api/v1/edr/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE, r.text


def test_edr_root_service_field(edr_client):
    r = edr_client.get("/api/v1/edr/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE
    assert r.json()["service"] == "edr"


def test_edr_root_operational(edr_client):
    r = edr_client.get("/api/v1/edr/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE
    assert r.json()["status"] == "operational"


def test_edr_root_capabilities_present(edr_client):
    r = edr_client.get("/api/v1/edr/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE
    caps = r.json()["capabilities"]
    assert "endpoint_isolation" in caps
    assert "threat_detection" in caps


def test_edr_root_stats_present(edr_client):
    r = edr_client.get("/api/v1/edr/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE
    assert "stats" in r.json()


# ---------------------------------------------------------------------------
# Agentless Snapshot Scan GET /
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def agentless_client():
    from apps.api.agentless_snapshot_router import router
    return _make_client(router)


def test_agentless_root_status_ok(agentless_client):
    r = agentless_client.get("/api/v1/agentless-snapshot/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE, r.text


def test_agentless_root_service_field(agentless_client):
    r = agentless_client.get("/api/v1/agentless-snapshot/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE
    assert r.json()["service"] == "agentless-snapshot-scan"


def test_agentless_root_operational(agentless_client):
    r = agentless_client.get("/api/v1/agentless-snapshot/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE
    assert r.json()["status"] == "operational"


def test_agentless_root_capabilities_present(agentless_client):
    r = agentless_client.get("/api/v1/agentless-snapshot/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE
    caps = r.json()["capabilities"]
    assert "snapshot_enqueue" in caps
    assert "vulnerability_scanning" in caps


def test_agentless_root_stats_present(agentless_client):
    r = agentless_client.get("/api/v1/agentless-snapshot/", headers=_HEADERS)
    assert r.status_code in _ACCEPTABLE
    assert "stats" in r.json()
