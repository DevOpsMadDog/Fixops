"""Router-level tests for Backup & Disaster Recovery API (/api/v1/backup-dr).

Covers key HTTP endpoints via FastAPI TestClient with a temp-backed engine.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure suite-core and suite-api are importable
for p in ["suite-core", "suite-api"]:
    abs_p = str(Path(__file__).parent.parent / p)
    if abs_p not in sys.path:
        sys.path.insert(0, abs_p)

from core.backup_validator import BackupValidator
from apps.api.backup_validator_router import router


# ---------------------------------------------------------------------------
# App fixture: fresh validator + TestClient per test
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    """TestClient wired to a fresh temp-DB validator."""
    import apps.api.backup_validator_router as _mod

    fresh_val = BackupValidator(db_path=str(tmp_path / "bv_router_test.db"))
    monkeypatch.setattr(_mod, "_val", lambda: fresh_val)

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBackupJobRouterEndpoints:
    def test_register_job_returns_201_shape(self, client):
        payload = {
            "name": "nightly-postgres",
            "system_name": "postgres-primary",
            "backup_type": "full",
            "source_path": "/var/lib/postgresql/data",
            "destination": "s3://backups/pg/",
            "schedule_cron": "0 2 * * *",
            "retention_days": 30,
            "encryption": "aes256",
            "status": "active",
            "org_id": "org-router-test",
        }
        resp = client.post("/api/v1/backup-dr/jobs", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "nightly-postgres"
        assert data["system_name"] == "postgres-primary"
        assert "id" in data

    def test_list_jobs_empty_org(self, client):
        resp = client.get("/api/v1/backup-dr/jobs", params={"org_id": "empty-org"})
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_jobs_returns_registered(self, client):
        payload = {
            "name": "job-a",
            "system_name": "sys-a",
            "backup_type": "incremental",
            "source_path": "/data/sys-a",
            "destination": "s3://backups/sys-a/",
            "schedule_cron": "0 3 * * *",
            "retention_days": 7,
            "encryption": "aes256",
            "status": "active",
            "org_id": "org-router-test",
        }
        client.post("/api/v1/backup-dr/jobs", json=payload)
        resp = client.get("/api/v1/backup-dr/jobs", params={"org_id": "org-router-test"})
        assert resp.status_code == 200
        jobs = resp.json()
        assert len(jobs) == 1
        assert jobs[0]["name"] == "job-a"


class TestRPORouterEndpoints:
    def test_set_rpo_config(self, client):
        payload = {
            "system_name": "postgres-primary",
            "rpo_target_minutes": 60,
            "rto_target_minutes": 120,
            "rpo_actual_minutes": 30,
            "rto_actual_minutes": 90,
            "org_id": "org-router-test",
        }
        resp = client.post("/api/v1/backup-dr/rpo", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["system_name"] == "postgres-primary"
        assert data["rpo_compliant"] is True  # 30 <= 60

    def test_list_rpo_configs_empty(self, client):
        resp = client.get("/api/v1/backup-dr/rpo", params={"org_id": "no-such-org"})
        assert resp.status_code == 200
        assert resp.json() == []


class TestDRPlanRouterEndpoints:
    def test_register_dr_plan(self, client):
        payload = {
            "name": "DB Failover",
            "system_name": "postgres-primary",
            "priority_order": 1,
            "rto_minutes": 60,
            "rpo_minutes": 30,
            "org_id": "org-router-test",
        }
        resp = client.post("/api/v1/backup-dr/dr-plans", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "DB Failover"
        assert "id" in data

    def test_list_dr_plans(self, client):
        payload = {
            "name": "App Recovery",
            "system_name": "app-server",
            "priority_order": 2,
            "rto_minutes": 120,
            "rpo_minutes": 60,
            "org_id": "org-router-test",
        }
        client.post("/api/v1/backup-dr/dr-plans", json=payload)
        resp = client.get("/api/v1/backup-dr/dr-plans", params={"org_id": "org-router-test"})
        assert resp.status_code == 200
        plans = resp.json()
        assert len(plans) == 1
        assert plans[0]["system_name"] == "app-server"


class TestBCScoreRouterEndpoint:
    def test_bc_score_empty_org_returns_zero(self, client):
        resp = client.get("/api/v1/backup-dr/bc-score", params={"org_id": "empty-org"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["score"] == 0.0
        assert data["grade"] == "F"
        assert data["org_id"] == "empty-org"

    def test_bc_score_improves_with_active_job(self, client):
        # Register one active encrypted job
        client.post("/api/v1/backup-dr/jobs", json={
            "name": "nightly-db",
            "system_name": "db",
            "backup_type": "full",
            "source_path": "/var/db",
            "destination": "s3://bk/db/",
            "schedule_cron": "0 1 * * *",
            "retention_days": 30,
            "encryption": "aes256",
            "status": "active",
            "org_id": "org-score-test",
        })
        resp = client.get("/api/v1/backup-dr/bc-score", params={"org_id": "org-score-test"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["score"] > 0.0
        assert data["backup_coverage_pct"] == 100.0
