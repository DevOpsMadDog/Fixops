"""Tests for saved-hunt endpoints wired to ThreatHuntingEngine (threat_hunting_engine.py).

Covers the new endpoints added to threat_hunting_router.py:
    GET  /api/v1/hunting              -- root overview
    POST /api/v1/hunting/hunts        -- create saved hunt
    GET  /api/v1/hunting/hunts        -- list saved hunts
    GET  /api/v1/hunting/hunts/{id}   -- get by ID
    POST /api/v1/hunting/hunts/{id}/run      -- execute hunt
    GET  /api/v1/hunting/hunts/{id}/results  -- results history
    POST /api/v1/hunting/hunts/{id}/schedule -- schedule hunt
    DELETE /api/v1/hunting/hunts/{id}        -- delete hunt

Run with:
    python -m pytest tests/test_threat_hunting_router_saved_hunts.py -x --tb=short --timeout=10 -q --no-cov
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Force-set the test token BEFORE any auth_deps import so _load_api_tokens()
# returns it on every per-request call.
os.environ["FIXOPS_API_TOKEN"] = "test-token-hunt"
os.environ.setdefault("FIXOPS_MODE", "dev")

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from unittest.mock import patch

_HEADERS = {"X-API-Key": "test-token-hunt"}


# ---------------------------------------------------------------------------
# App fixture — mount only the router under test with a real engine + tmp DB
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("hunt_router_db")
    db_path = str(tmp / "test_hunt.db")

    from core.threat_hunting_engine import ThreatHuntingEngine

    real_engine = ThreatHuntingEngine(db_path=db_path)

    test_app = FastAPI()

    with patch("apps.api.threat_hunting_router._get_hunt_engine", return_value=real_engine):
        with patch(
            "apps.api.threat_hunting_router._get_engine",
            return_value=real_engine,
        ):
            from apps.api.threat_hunting_router import router
            test_app.include_router(router)
            with TestClient(test_app) as c:
                yield c, real_engine


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRootOverview:
    def test_get_overview_returns_200(self, client):
        c, engine = client
        with patch("apps.api.threat_hunting_router._get_hunt_engine", return_value=engine):
            resp = c.get("/api/v1/hunting", headers=_HEADERS)
        assert resp.status_code == 200

    def test_overview_has_capabilities(self, client):
        c, engine = client
        with patch("apps.api.threat_hunting_router._get_hunt_engine", return_value=engine):
            data = c.get("/api/v1/hunting", headers=_HEADERS).json()
        assert "capabilities" in data
        assert "hunt_types" in data["capabilities"]
        assert "ioc_match" in data["capabilities"]["hunt_types"]

    def test_overview_has_saved_hunts_section(self, client):
        c, engine = client
        with patch("apps.api.threat_hunting_router._get_hunt_engine", return_value=engine):
            data = c.get("/api/v1/hunting", headers=_HEADERS).json()
        assert "saved_hunts" in data
        assert "total" in data["saved_hunts"]


class TestCreateHunt:
    def test_create_ioc_match_hunt_returns_201(self, client):
        c, engine = client
        with patch("apps.api.threat_hunting_router._get_hunt_engine", return_value=engine):
            resp = c.post(
                "/api/v1/hunting/hunts",
                json={
                    "name": "Suspicious IP Hunt",
                    "hunt_type": "ioc_match",
                    "query": {"ioc_value": "185.220.101.47", "ioc_type": "ip"},
                    "description": "Hunt for known TOR exit node",
                    "org_id": "test-org",
                },
                headers=_HEADERS,
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Suspicious IP Hunt"
        assert data["hunt_type"] == "ioc_match"
        assert data["state"] == "ready"

    def test_create_invalid_hunt_type_returns_400(self, client):
        c, engine = client
        with patch("apps.api.threat_hunting_router._get_hunt_engine", return_value=engine):
            resp = c.post(
                "/api/v1/hunting/hunts",
                json={
                    "name": "Bad Type Hunt",
                    "hunt_type": "not_a_real_type",
                    "query": {},
                    "org_id": "test-org",
                },
                headers=_HEADERS,
            )
        assert resp.status_code == 400


class TestListAndGetHunts:
    def test_list_hunts_returns_200_and_list(self, client):
        c, engine = client
        with patch("apps.api.threat_hunting_router._get_hunt_engine", return_value=engine):
            resp = c.get("/api/v1/hunting/hunts", headers=_HEADERS)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_hunt_by_id(self, client):
        c, engine = client
        with patch("apps.api.threat_hunting_router._get_hunt_engine", return_value=engine):
            created = c.post(
                "/api/v1/hunting/hunts",
                json={
                    "name": "Lateral Movement Detect",
                    "hunt_type": "lateral_movement",
                    "query": {"source_asset": "workstation-42", "hop_count": 2},
                    "org_id": "test-org",
                },
                headers=_HEADERS,
            ).json()
            hunt_id = created["hunt_id"]
            resp = c.get(f"/api/v1/hunting/hunts/{hunt_id}", headers=_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["hunt_id"] == hunt_id

    def test_get_nonexistent_hunt_returns_404(self, client):
        c, engine = client
        with patch("apps.api.threat_hunting_router._get_hunt_engine", return_value=engine):
            resp = c.get(
                "/api/v1/hunting/hunts/00000000-0000-0000-0000-000000000000",
                headers=_HEADERS,
            )
        assert resp.status_code == 404


class TestRunHunt:
    def test_run_hunt_returns_result_structure(self, client):
        c, engine = client
        with patch("apps.api.threat_hunting_router._get_hunt_engine", return_value=engine):
            created = c.post(
                "/api/v1/hunting/hunts",
                json={
                    "name": "Persistence Check",
                    "hunt_type": "persistence",
                    "query": {"technique_ids": ["T1547"]},
                    "org_id": "test-org",
                },
                headers=_HEADERS,
            ).json()
            hunt_id = created["hunt_id"]
            resp = c.post(f"/api/v1/hunting/hunts/{hunt_id}/run", headers=_HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert "hunt_id" in data
        assert "state" in data
        assert data["state"] in ("completed", "failed")
        assert "hit_count" in data
        assert "duration_ms" in data

    def test_run_nonexistent_hunt_returns_404(self, client):
        c, engine = client
        with patch("apps.api.threat_hunting_router._get_hunt_engine", return_value=engine):
            resp = c.post(
                "/api/v1/hunting/hunts/00000000-0000-0000-0000-000000000099/run",
                headers=_HEADERS,
            )
        assert resp.status_code == 404


class TestResultsAndSchedule:
    def test_results_endpoint_returns_list(self, client):
        c, engine = client
        with patch("apps.api.threat_hunting_router._get_hunt_engine", return_value=engine):
            created = c.post(
                "/api/v1/hunting/hunts",
                json={
                    "name": "Exfil Check",
                    "hunt_type": "exfiltration",
                    "query": {"destination_cidrs": ["0.0.0.0/0"], "min_bytes": 1024},
                    "org_id": "test-org",
                },
                headers=_HEADERS,
            ).json()
            hunt_id = created["hunt_id"]
            c.post(f"/api/v1/hunting/hunts/{hunt_id}/run", headers=_HEADERS)
            resp = c.get(f"/api/v1/hunting/hunts/{hunt_id}/results", headers=_HEADERS)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_schedule_hunt_returns_schedule_record(self, client):
        c, engine = client
        with patch("apps.api.threat_hunting_router._get_hunt_engine", return_value=engine):
            created = c.post(
                "/api/v1/hunting/hunts",
                json={
                    "name": "Daily Anomaly Hunt",
                    "hunt_type": "anomaly_correlation",
                    "query": {"severity_threshold": "high", "min_events": 3},
                    "org_id": "test-org",
                },
                headers=_HEADERS,
            ).json()
            hunt_id = created["hunt_id"]
            resp = c.post(
                f"/api/v1/hunting/hunts/{hunt_id}/schedule",
                json={"interval_hours": 12},
                headers=_HEADERS,
            )
        assert resp.status_code == 201
        data = resp.json()
        assert "schedule_id" in data
        assert data["hunt_id"] == hunt_id
        assert data["interval_hours"] == 12
        assert "next_run_at" in data


class TestDeleteHunt:
    def test_delete_hunt_returns_204(self, client):
        c, engine = client
        with patch("apps.api.threat_hunting_router._get_hunt_engine", return_value=engine):
            created = c.post(
                "/api/v1/hunting/hunts",
                json={
                    "name": "Temp Hunt to Delete",
                    "hunt_type": "behavior_pattern",
                    "query": {"pattern": "*.exe spawns cmd.exe", "timewindow_minutes": 30},
                    "org_id": "test-org",
                },
                headers=_HEADERS,
            ).json()
            hunt_id = created["hunt_id"]
            resp = c.delete(f"/api/v1/hunting/hunts/{hunt_id}", headers=_HEADERS)
        assert resp.status_code == 204

    def test_delete_nonexistent_hunt_returns_404(self, client):
        c, engine = client
        with patch("apps.api.threat_hunting_router._get_hunt_engine", return_value=engine):
            resp = c.delete(
                "/api/v1/hunting/hunts/00000000-0000-0000-0000-000000000404",
                headers=_HEADERS,
            )
        assert resp.status_code == 404
