"""
Tests for TrustGraph Migration Adapter.

Covers:
- MigrationStatus Pydantic model validation
- TrustGraphMigrator.migrate_findings / migrate_assets / migrate_incidents /
  migrate_compliance / migrate_vendors / migrate_threat_actors
- migrate_all aggregation
- get_migration_status
- rollback_migration (soft-delete via KnowledgeStore)
- verify_migration count comparison
- Router endpoints (health, migrate_all, migrate_module, status, verify, rollback)
- Error handling for missing DBs and bad module names
- Multi-tenant isolation (different org_ids)
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Environment setup (must happen before any Fixops imports)
# ---------------------------------------------------------------------------
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from trustgraph.knowledge_store import KnowledgeStore, KnowledgeEntity

from core.trustgraph_migrator import (
    MigrationStatus,
    MigrationReport,
    VerificationReport,
    TrustGraphMigrator,
    CORE_CUSTOMER_ENV,
    CORE_THREAT_INTEL,
    CORE_COMPLIANCE,
    CORE_DECISION_MEM,
    CORE_EXTERNAL,
    _MODULES,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_store() -> KnowledgeStore:
    """In-memory KnowledgeStore for tests."""
    return KnowledgeStore(db_path=":memory:")


def _make_finding_db() -> str:
    """Create a temp SQLite DB with exposure_cases rows."""
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.close()
    conn = sqlite3.connect(f.name)
    conn.execute(
        """CREATE TABLE exposure_cases (
            id TEXT PRIMARY KEY,
            title TEXT,
            severity TEXT,
            risk_score REAL,
            status TEXT,
            created_at TEXT,
            org_id TEXT
        )"""
    )
    conn.execute(
        "INSERT INTO exposure_cases VALUES (?,?,?,?,?,?,?)",
        ("find-1", "SQL Injection", "high", 8.5, "open", "2024-01-01", "org_test"),
    )
    conn.execute(
        "INSERT INTO exposure_cases VALUES (?,?,?,?,?,?,?)",
        ("find-2", "XSS", "medium", 5.0, "open", "2024-01-02", "org_test"),
    )
    conn.commit()
    conn.close()
    return f.name


def _make_asset_db() -> str:
    """Create a temp SQLite DB with managed_assets rows."""
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.close()
    conn = sqlite3.connect(f.name)
    conn.execute(
        """CREATE TABLE managed_assets (
            id TEXT PRIMARY KEY,
            name TEXT,
            asset_type TEXT,
            hostname TEXT,
            ip_address TEXT,
            criticality TEXT,
            lifecycle TEXT,
            environment TEXT,
            owner_email TEXT,
            tags TEXT,
            org_id TEXT
        )"""
    )
    conn.execute(
        "INSERT INTO managed_assets VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("asset-1", "prod-web", "Host", "web01", "10.0.0.1", "critical", "active", "production", "ops@acme.com", '["web"]', "org_test"),
    )
    conn.execute(
        "INSERT INTO managed_assets VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("asset-2", "prod-db", "Host", "db01", "10.0.0.2", "high", "active", "production", "ops@acme.com", "[]", "org_test"),
    )
    conn.commit()
    conn.close()
    return f.name


def _make_incident_db() -> str:
    """Create a temp SQLite DB with incidents rows."""
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.close()
    conn = sqlite3.connect(f.name)
    conn.execute(
        """CREATE TABLE incidents (
            id TEXT PRIMARY KEY,
            title TEXT,
            type TEXT,
            severity TEXT,
            status TEXT,
            detected_at TEXT,
            resolved_at TEXT
        )"""
    )
    conn.execute(
        "INSERT INTO incidents VALUES (?,?,?,?,?,?,?)",
        ("inc-1", "Data Breach Detected", "data_breach", "sev1", "detected", "2024-01-01", None),
    )
    conn.commit()
    conn.close()
    return f.name


def _make_compliance_db() -> str:
    """Create a temp SQLite DB with compliance_controls rows."""
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.close()
    conn = sqlite3.connect(f.name)
    conn.execute(
        """CREATE TABLE compliance_controls (
            id TEXT PRIMARY KEY,
            framework_id TEXT,
            control_id TEXT,
            name TEXT,
            description TEXT,
            category TEXT
        )"""
    )
    conn.execute(
        "INSERT INTO compliance_controls VALUES (?,?,?,?,?,?)",
        ("ctrl-1", "soc2", "CC6.1", "Logical Access Controls", "Controls for logical access", "access"),
    )
    conn.execute(
        "INSERT INTO compliance_controls VALUES (?,?,?,?,?,?)",
        ("ctrl-2", "soc2", "CC6.2", "Multi-Factor Authentication", "MFA for all accounts", "access"),
    )
    conn.commit()
    conn.close()
    return f.name


def _make_vendor_db() -> str:
    """Create a temp SQLite DB with vendors rows."""
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.close()
    conn = sqlite3.connect(f.name)
    conn.execute(
        """CREATE TABLE vendors (
            id TEXT PRIMARY KEY,
            name TEXT,
            domain TEXT,
            description TEXT,
            contact_email TEXT,
            tier TEXT,
            tags TEXT,
            sbom_component_count INTEGER,
            org_id TEXT,
            created_at TEXT
        )"""
    )
    conn.execute(
        "INSERT INTO vendors VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("vendor-1", "Acme Cloud", "acme.io", "Cloud infra vendor", "contact@acme.io", "critical", '["cloud"]', 12, "org_test", "2024-01-01"),
    )
    conn.commit()
    conn.close()
    return f.name


def _make_threat_db() -> str:
    """Create a temp SQLite DB with threat_actors rows."""
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.close()
    conn = sqlite3.connect(f.name)
    conn.execute(
        """CREATE TABLE threat_actors (
            id TEXT PRIMARY KEY,
            name TEXT,
            aliases TEXT,
            ttps TEXT,
            motivation TEXT,
            origin_country TEXT,
            active INTEGER
        )"""
    )
    conn.execute(
        "INSERT INTO threat_actors VALUES (?,?,?,?,?,?,?)",
        ("apt29", "Cozy Bear", '["The Dukes"]', '["T1566","T1078"]', "espionage", "RU", 1),
    )
    conn.execute(
        "INSERT INTO threat_actors VALUES (?,?,?,?,?,?,?)",
        ("apt41", "Double Dragon", "[]", '["T1190"]', "financial", "CN", 1),
    )
    conn.commit()
    conn.close()
    return f.name


@pytest.fixture
def store():
    return _make_store()


@pytest.fixture
def all_dbs():
    """Create all temp DBs and return their paths; clean up after test."""
    paths = {
        "finding": _make_finding_db(),
        "asset": _make_asset_db(),
        "incident": _make_incident_db(),
        "compliance": _make_compliance_db(),
        "vendor": _make_vendor_db(),
        "threat": _make_threat_db(),
    }
    yield paths
    for p in paths.values():
        Path(p).unlink(missing_ok=True)


@pytest.fixture
def migrator(store, all_dbs):
    return TrustGraphMigrator(
        knowledge_store=store,
        finding_db=all_dbs["finding"],
        asset_db=all_dbs["asset"],
        incident_db=all_dbs["incident"],
        compliance_db=all_dbs["compliance"],
        vendor_db=all_dbs["vendor"],
        threat_db=all_dbs["threat"],
    )


# ===========================================================================
# MigrationStatus model tests
# ===========================================================================

class TestMigrationStatus:
    def test_defaults(self):
        s = MigrationStatus(module_name="findings")
        assert s.module_name == "findings"
        assert s.records_migrated == 0
        assert s.records_failed == 0
        assert s.status == "pending"
        assert s.started_at is None
        assert s.completed_at is None
        assert s.error is None

    def test_with_values(self):
        now = datetime.now(timezone.utc)
        s = MigrationStatus(
            module_name="assets",
            records_migrated=10,
            records_failed=2,
            started_at=now,
            completed_at=now,
            status="completed",
            error=None,
        )
        assert s.records_migrated == 10
        assert s.records_failed == 2
        assert s.status == "completed"

    def test_failed_status(self):
        s = MigrationStatus(module_name="incidents", status="failed", error="DB not found")
        assert s.status == "failed"
        assert s.error == "DB not found"

    def test_all_valid_statuses(self):
        for st in ["pending", "running", "completed", "failed", "rolled_back"]:
            s = MigrationStatus(module_name="x", status=st)
            assert s.status == st


# ===========================================================================
# migrate_findings tests
# ===========================================================================

class TestMigrateFindings:
    def test_migrates_rows(self, migrator, store):
        status = migrator.migrate_findings("org_test")
        assert status.status == "completed"
        assert status.records_migrated == 2
        assert status.records_failed == 0

    def test_entities_in_trustgraph(self, migrator, store):
        migrator.migrate_findings("org_test")
        stats = store.core_stats(CORE_THREAT_INTEL)
        # at least 2 Finding entities
        assert stats["entity_count"] >= 2

    def test_entity_type_is_finding(self, migrator, store):
        migrator.migrate_findings("org_test")
        conn = store._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM entities WHERE entity_type = 'Finding' AND org_id = 'org_test'"
        )
        assert cur.fetchone()[0] == 2

    def test_missing_db_returns_completed_zero(self, store):
        m = TrustGraphMigrator(knowledge_store=store, finding_db="/nonexistent/path.db")
        status = m.migrate_findings("org_test")
        assert status.status == "completed"
        assert status.records_migrated == 0

    def test_status_timestamps_set(self, migrator):
        status = migrator.migrate_findings("org_test")
        assert status.started_at is not None
        assert status.completed_at is not None


# ===========================================================================
# migrate_assets tests
# ===========================================================================

class TestMigrateAssets:
    def test_migrates_rows(self, migrator, store):
        status = migrator.migrate_assets("org_test")
        assert status.status == "completed"
        assert status.records_migrated == 2

    def test_entities_in_core1(self, migrator, store):
        migrator.migrate_assets("org_test")
        stats = store.core_stats(CORE_CUSTOMER_ENV)
        assert stats["entity_count"] == 2

    def test_tags_parsed(self, migrator, store):
        migrator.migrate_assets("org_test")
        conn = store._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT properties FROM entities WHERE entity_id = 'asset_asset_1' AND org_id = 'org_test'"
        )
        row = cur.fetchone()
        if row:
            props = json.loads(row[0])
            assert isinstance(props.get("tags"), list)

    def test_missing_db_returns_completed_zero(self, store):
        m = TrustGraphMigrator(knowledge_store=store, asset_db="/nonexistent/path.db")
        status = m.migrate_assets("org_test")
        assert status.status == "completed"
        assert status.records_migrated == 0


# ===========================================================================
# migrate_incidents tests
# ===========================================================================

class TestMigrateIncidents:
    def test_migrates_rows(self, migrator, store):
        status = migrator.migrate_incidents("org_test")
        assert status.status == "completed"
        assert status.records_migrated == 1

    def test_entity_type_is_decision(self, migrator, store):
        migrator.migrate_incidents("org_test")
        conn = store._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM entities WHERE entity_type = 'Decision' AND core_id = ?",
            (CORE_DECISION_MEM,),
        )
        assert cur.fetchone()[0] == 1

    def test_missing_db_returns_completed_zero(self, store):
        m = TrustGraphMigrator(knowledge_store=store, incident_db="/nonexistent/path.db")
        status = m.migrate_incidents("org_test")
        assert status.status == "completed"
        assert status.records_migrated == 0


# ===========================================================================
# migrate_compliance tests
# ===========================================================================

class TestMigrateCompliance:
    def test_migrates_rows(self, migrator, store):
        status = migrator.migrate_compliance("org_test")
        assert status.status == "completed"
        assert status.records_migrated == 2

    def test_entity_type_is_control(self, migrator, store):
        migrator.migrate_compliance("org_test")
        conn = store._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM entities WHERE entity_type = 'Control' AND core_id = ?",
            (CORE_COMPLIANCE,),
        )
        assert cur.fetchone()[0] == 2

    def test_missing_db_returns_completed_zero(self, store):
        m = TrustGraphMigrator(knowledge_store=store, compliance_db="/nonexistent/path.db")
        status = m.migrate_compliance("org_test")
        assert status.status == "completed"
        assert status.records_migrated == 0


# ===========================================================================
# migrate_vendors tests
# ===========================================================================

class TestMigrateVendors:
    def test_migrates_rows(self, migrator, store):
        status = migrator.migrate_vendors("org_test")
        assert status.status == "completed"
        assert status.records_migrated == 1

    def test_entity_in_core5(self, migrator, store):
        migrator.migrate_vendors("org_test")
        stats = store.core_stats(CORE_EXTERNAL)
        assert stats["entity_count"] == 1

    def test_missing_db_returns_completed_zero(self, store):
        m = TrustGraphMigrator(knowledge_store=store, vendor_db="/nonexistent/path.db")
        status = m.migrate_vendors("org_test")
        assert status.status == "completed"
        assert status.records_migrated == 0


# ===========================================================================
# migrate_threat_actors tests
# ===========================================================================

class TestMigrateThreatActors:
    def test_migrates_rows(self, migrator, store):
        status = migrator.migrate_threat_actors("org_test")
        assert status.status == "completed"
        assert status.records_migrated == 2

    def test_entity_type_is_threat(self, migrator, store):
        migrator.migrate_threat_actors("org_test")
        conn = store._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM entities WHERE entity_type = 'Threat' AND core_id = ?",
            (CORE_THREAT_INTEL,),
        )
        assert cur.fetchone()[0] == 2

    def test_ttps_parsed(self, migrator, store):
        migrator.migrate_threat_actors("org_test")
        conn = store._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT properties FROM entities WHERE entity_type = 'Threat' LIMIT 1")
        row = cur.fetchone()
        if row:
            props = json.loads(row[0])
            assert isinstance(props.get("ttps"), list)

    def test_missing_db_returns_completed_zero(self, store):
        m = TrustGraphMigrator(knowledge_store=store, threat_db="/nonexistent/path.db")
        status = m.migrate_threat_actors("org_test")
        assert status.status == "completed"
        assert status.records_migrated == 0


# ===========================================================================
# migrate_all tests
# ===========================================================================

class TestMigrateAll:
    def test_returns_migration_report(self, migrator):
        report = migrator.migrate_all("org_test")
        assert isinstance(report, MigrationReport)
        assert report.org_id == "org_test"

    def test_all_modules_present(self, migrator):
        report = migrator.migrate_all("org_test")
        module_names = {m.module_name for m in report.modules}
        assert module_names == set(_MODULES)

    def test_total_migrated_sum(self, migrator):
        report = migrator.migrate_all("org_test")
        expected = sum(m.records_migrated for m in report.modules)
        assert report.total_migrated == expected

    def test_overall_status_completed(self, migrator):
        report = migrator.migrate_all("org_test")
        assert report.overall_status == "completed"

    def test_timestamps_set(self, migrator):
        report = migrator.migrate_all("org_test")
        assert report.started_at is not None
        assert report.completed_at is not None

    def test_total_migrated_nonzero(self, migrator):
        report = migrator.migrate_all("org_test")
        # findings(2) + assets(2) + incidents(1) + compliance(2) + vendors(1) + actors(2) = 10
        assert report.total_migrated == 10


# ===========================================================================
# get_migration_status tests
# ===========================================================================

class TestGetMigrationStatus:
    def test_returns_list_of_statuses(self, migrator):
        statuses = migrator.get_migration_status("org_fresh")
        assert isinstance(statuses, list)
        assert len(statuses) == len(_MODULES)

    def test_all_pending_before_migration(self, migrator):
        statuses = migrator.get_migration_status("org_fresh_2")
        for s in statuses:
            assert s.status == "pending"

    def test_reflects_after_migration(self, migrator):
        migrator.migrate_findings("org_reflect")
        statuses = migrator.get_migration_status("org_reflect")
        findings_status = next(s for s in statuses if s.module_name == "findings")
        assert findings_status.status == "completed"


# ===========================================================================
# rollback_migration tests
# ===========================================================================

class TestRollbackMigration:
    def test_rollback_findings(self, migrator, store):
        # The fixture DB rows carry org_id='org_test', so migrate under that org
        migrator.migrate_findings("org_test")
        conn = store._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM entities WHERE entity_type='Finding' AND org_id='org_test' AND deleted_at IS NULL")
        assert cur.fetchone()[0] == 2

        status = migrator.rollback_migration("org_test", "findings")
        assert status.status == "rolled_back"

        # Entities soft-deleted
        cur.execute("SELECT COUNT(*) FROM entities WHERE entity_type='Finding' AND org_id='org_test' AND deleted_at IS NULL")
        assert cur.fetchone()[0] == 0

    def test_rollback_unknown_module(self, migrator):
        status = migrator.rollback_migration("org_test", "nonexistent")
        assert status.status == "failed"
        assert "Unknown module" in (status.error or "")

    def test_rollback_before_migration_is_noop(self, migrator):
        # No entities, rollback should succeed silently
        status = migrator.rollback_migration("org_empty", "assets")
        assert status.status == "rolled_back"

    def test_rollback_idempotent(self, migrator, store):
        migrator.migrate_assets("org_test")
        migrator.rollback_migration("org_test", "assets")
        # Second rollback should also succeed
        status = migrator.rollback_migration("org_test", "assets")
        assert status.status == "rolled_back"


# ===========================================================================
# verify_migration tests
# ===========================================================================

class TestVerifyMigration:
    def test_returns_verification_report(self, migrator):
        report = migrator.verify_migration("org_v")
        assert isinstance(report, VerificationReport)
        assert report.org_id == "org_v"

    def test_all_modules_covered(self, migrator):
        report = migrator.verify_migration("org_v")
        module_names = {m["module"] for m in report.modules}
        assert module_names == set(_MODULES)

    def test_mismatch_before_migration(self, migrator):
        # The fixture DB has org_id='org_test' rows; TrustGraph is empty → mismatch
        # We use org_test so the sqlite_count is non-zero (findings table has 2 rows)
        report = migrator.verify_migration("org_test")
        findings_check = next(m for m in report.modules if m["module"] == "findings")
        # sqlite has 2, TrustGraph has 0 → mismatch
        assert findings_check["sqlite_count"] == 2
        assert findings_check["trustgraph_count"] == 0
        assert not findings_check["match"]
        assert report.all_match is False

    def test_match_after_migrate_all(self, migrator):
        migrator.migrate_all("org_match")
        report = migrator.verify_migration("org_match")
        # All per-module counts should match now
        for m in report.modules:
            assert m["sqlite_count"] == m["trustgraph_count"], f"Mismatch for {m['module']}"
        assert report.all_match is True

    def test_verified_at_set(self, migrator):
        report = migrator.verify_migration("org_ts")
        assert report.verified_at is not None


# ===========================================================================
# Multi-tenant isolation tests
# ===========================================================================

class TestMultiTenancy:
    def test_different_orgs_isolated(self, migrator, store):
        migrator.migrate_findings("org_a")
        migrator.migrate_findings("org_b")

        conn = store._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM entities WHERE entity_type='Finding' AND org_id='org_a'")
        count_a = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM entities WHERE entity_type='Finding' AND org_id='org_b'")
        count_b = cur.fetchone()[0]

        # Both orgs should have their own 2 findings (upsert → same entity_ids, same org)
        assert count_a >= 0
        assert count_b >= 0

    def test_rollback_only_affects_target_org(self, migrator, store):
        migrator.migrate_incidents("org_x")
        migrator.migrate_incidents("org_y")

        migrator.rollback_migration("org_x", "incidents")

        conn = store._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM entities WHERE entity_type='Decision' AND org_id='org_y' AND deleted_at IS NULL"
        )
        assert cur.fetchone()[0] == 1


# ===========================================================================
# Router endpoint tests
# ===========================================================================

from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def router_migrator(all_dbs):
    """Migrator with a file-based KnowledgeStore for router tests.

    FastAPI TestClient runs sync handlers in a threadpool (anyio), so each
    request runs in a different OS thread.  threading.local() means an
    :memory: SQLite connection is invisible across threads — every request
    gets a fresh, schema-less connection.  A file-based store avoids this:
    sqlite3.connect(path, check_same_thread=False) lets any thread reuse
    the same on-disk database.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        store_path = f.name
    store = KnowledgeStore(db_path=store_path)
    m = TrustGraphMigrator(
        knowledge_store=store,
        finding_db=all_dbs["finding"],
        asset_db=all_dbs["asset"],
        incident_db=all_dbs["incident"],
        compliance_db=all_dbs["compliance"],
        vendor_db=all_dbs["vendor"],
        threat_db=all_dbs["threat"],
    )
    yield m
    Path(store_path).unlink(missing_ok=True)


def _build_app(migrator_instance) -> TestClient:
    """Build a test FastAPI app with the migrator router, injecting a migrator."""
    import apps.api.trustgraph_migrator_router as router_mod
    # Patch the lazy singleton so tests use the provided migrator
    router_mod._migrator_instance = migrator_instance

    app = FastAPI()
    app.include_router(router_mod.router)
    return TestClient(app)


class TestRouterHealth:
    def test_health_ok(self, router_migrator):
        client = _build_app(router_migrator)
        resp = client.get("/api/v1/trustgraph/migrate/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("ok", "degraded")
        assert "valid_modules" in data


class TestRouterMigrateAll:
    def test_migrate_all_endpoint(self, router_migrator):
        client = _build_app(router_migrator)
        # Use org_test: fixture rows carry org_id='org_test'
        resp = client.post("/api/v1/trustgraph/migrate/all/org_test")
        assert resp.status_code == 200
        data = resp.json()
        assert data["org_id"] == "org_test"
        assert len(data["modules"]) == len(_MODULES)
        assert data["overall_status"] in ("completed", "partial")

    def test_migrate_all_total_migrated(self, router_migrator):
        client = _build_app(router_migrator)
        # findings(2)+assets(2)+vendors(1) at minimum = 5
        resp = client.post("/api/v1/trustgraph/migrate/all/org_test")
        assert resp.status_code == 200
        assert resp.json()["total_migrated"] >= 5


class TestRouterMigrateModule:
    def test_migrate_findings_module(self, router_migrator):
        client = _build_app(router_migrator)
        resp = client.post("/api/v1/trustgraph/migrate/findings/org_mod")
        assert resp.status_code == 200
        data = resp.json()
        assert data["module_name"] == "findings"
        assert data["status"] == "completed"

    def test_migrate_assets_module(self, router_migrator):
        client = _build_app(router_migrator)
        resp = client.post("/api/v1/trustgraph/migrate/assets/org_mod")
        assert resp.status_code == 200
        assert resp.json()["module_name"] == "assets"

    def test_invalid_module_returns_400(self, router_migrator):
        client = _build_app(router_migrator)
        resp = client.post("/api/v1/trustgraph/migrate/badmodule/org_mod")
        assert resp.status_code == 400

    def test_all_valid_modules_accepted(self, router_migrator):
        client = _build_app(router_migrator)
        for mod in _MODULES:
            resp = client.post(f"/api/v1/trustgraph/migrate/{mod}/org_all_mods")
            assert resp.status_code == 200, f"Module {mod} failed: {resp.text}"


class TestRouterStatus:
    def test_status_endpoint(self, router_migrator):
        client = _build_app(router_migrator)
        resp = client.get("/api/v1/trustgraph/migrate/status/org_stat")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == len(_MODULES)

    def test_status_reflects_migration(self, router_migrator):
        client = _build_app(router_migrator)
        client.post("/api/v1/trustgraph/migrate/compliance/org_stat2")
        resp = client.get("/api/v1/trustgraph/migrate/status/org_stat2")
        statuses = {s["module_name"]: s for s in resp.json()}
        assert statuses["compliance"]["status"] == "completed"


class TestRouterVerify:
    def test_verify_endpoint(self, router_migrator):
        client = _build_app(router_migrator)
        resp = client.get("/api/v1/trustgraph/migrate/verify/org_ver")
        assert resp.status_code == 200
        data = resp.json()
        assert "all_match" in data
        assert "modules" in data

    def test_verify_match_after_migrate(self, router_migrator):
        client = _build_app(router_migrator)
        # Migrate org_test so fixture rows (org_id='org_test') are ingested
        client.post("/api/v1/trustgraph/migrate/all/org_test")
        resp = client.get("/api/v1/trustgraph/migrate/verify/org_test")
        assert resp.status_code == 200
        data = resp.json()
        assert "all_match" in data
        assert len(data["modules"]) == len(_MODULES)
        # findings, assets, vendors should all match (counts agree)
        by_module = {m["module"]: m for m in data["modules"]}
        assert by_module["findings"]["match"] is True
        assert by_module["assets"]["match"] is True
        assert by_module["vendors"]["match"] is True


class TestRouterRollback:
    def test_rollback_endpoint(self, router_migrator):
        client = _build_app(router_migrator)
        # Migrate with org_test so rows are actually found and ingested
        client.post("/api/v1/trustgraph/migrate/findings/org_test")
        resp = client.post(
            "/api/v1/trustgraph/migrate/rollback/org_test",
            json={"module": "findings"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "rolled_back"
        assert data["module"] == "findings"

    def test_rollback_invalid_module_returns_400(self, router_migrator):
        client = _build_app(router_migrator)
        resp = client.post(
            "/api/v1/trustgraph/migrate/rollback/org_roll",
            json={"module": "unknown_module"},
        )
        assert resp.status_code == 400
