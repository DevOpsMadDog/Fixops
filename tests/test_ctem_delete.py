"""Tests for CTEM cycle DELETE endpoint wiring."""
import os, sys
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-core")
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-api")

os.environ["FIXOPS_API_TOKEN"] = "test-key-123"
os.environ["ALDECI_API_KEY"] = "test-key-123"

import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI

from apps.api.ctem_engine_router import router
from core.ctem_engine import CTEMEngine
import core.ctem_engine as _ctem_mod

app = FastAPI()
app.include_router(router)

HDR = {"X-API-Key": "test-key-123"}


@pytest.fixture(autouse=True)
def fresh_engine(tmp_path, monkeypatch):
    eng = CTEMEngine(db_path=str(tmp_path / "ctem_test.db"))
    monkeypatch.setattr(_ctem_mod, "_engine", eng)
    yield eng


def test_delete_existing_cycle():
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post("/api/v1/ctem/cycles", json={"name": "TestCycle", "org_id": "default"}, headers=HDR)
    assert r.status_code == 200, r.text
    cycle_id = r.json()["id"]

    r = client.delete(f"/api/v1/ctem/cycles/{cycle_id}", headers=HDR)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["deleted"] is True
    assert body["cycle_id"] == cycle_id


def test_delete_nonexistent_cycle():
    client = TestClient(app, raise_server_exceptions=False)
    r = client.delete("/api/v1/ctem/cycles/no-such-id", headers=HDR)
    assert r.status_code == 404, r.text


def test_delete_removes_from_list():
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post("/api/v1/ctem/cycles", json={"name": "ToDelete", "org_id": "default"}, headers=HDR)
    assert r.status_code == 200, r.text
    cycle_id = r.json()["id"]

    client.delete(f"/api/v1/ctem/cycles/{cycle_id}", headers=HDR)

    r = client.get("/api/v1/ctem/cycles?org_id=default", headers=HDR)
    ids = [c["id"] for c in r.json()["cycles"]]
    assert cycle_id not in ids


def test_delete_cycle_db_method_directly(fresh_engine):
    cycle = fresh_engine.start_cycle("Direct", org_id="org1")
    fresh_engine.delete_cycle(cycle.id)
    cycles = fresh_engine.list_cycles("org1")
    assert all(c.id != cycle.id for c in cycles)


def test_delete_cycle_missing_raises(fresh_engine):
    with pytest.raises(ValueError, match="not found"):
        fresh_engine.delete_cycle("ghost-id")
