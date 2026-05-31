"""
tests/test_brain_node_isolation.py

Covers the tenant-isolation fix applied to brain_router.get_node /
brain_router.delete_node (FIX-K, 2026-06-01).

Test matrix:
  1. Tenant A can read its own node.
  2. Tenant B cannot read Tenant A's node (404).
  3. Any tenant can read a system/global node (shared threat knowledge).
  4. Non-admin tenant cannot DELETE a system node (403).
  5. Admin-scoped caller CAN delete a system node (200).
  6. Tenant A can delete its own node.
  7. Tenant B cannot delete Tenant A's node (404).
  8. Legacy NULL-org nodes are migrated to 'system' on DB startup.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Minimal stubs so the router can be imported without the full app stack.
# ---------------------------------------------------------------------------

# Stub event bus so the router's bus.emit() doesn't explode.
import core.event_bus as _eb_mod

_orig_get_event_bus = _eb_mod.get_event_bus

class _StubBus:
    async def emit(self, *a, **kw):  # noqa: D102
        return None

def _stub_get_event_bus():
    return _StubBus()

_eb_mod.get_event_bus = _stub_get_event_bus  # monkeypatch before router import


# ---------------------------------------------------------------------------
# Import the router AFTER the event-bus stub is in place.
# ---------------------------------------------------------------------------
import sys as _sys
import importlib as _il

# suite-core/api is not a package — add it directly to sys.path so the module
# can be imported as a flat name.
_brain_router_dir = str(Path(__file__).parent.parent / "suite-core" / "api")
if _brain_router_dir not in _sys.path:
    _sys.path.insert(0, _brain_router_dir)

import brain_router as _brain_router_mod  # noqa: E402
brain_router_router = _brain_router_mod.router

from core.knowledge_brain import KnowledgeBrain, get_brain, GraphNode, EntityType  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SYSTEM_ORG = KnowledgeBrain.SYSTEM_ORG  # "system"
_ORG_A = "org-tenant-a"
_ORG_B = "org-tenant-b"


def _make_app(caller_org: str, caller_scopes: Optional[list] = None) -> FastAPI:
    """Build a throwaway FastAPI app wired to *brain_router*.

    The org-id and scopes are injected via request.state so the router's
    Depends(get_org_id) and request.state.user_scopes work without JWT.
    """
    app = FastAPI()

    @app.middleware("http")
    async def _inject_auth(request, call_next):
        request.state.user_scopes = caller_scopes or []
        # Also set the contextvar so get_org_id() picks it up.
        from apps.api.org_middleware import _org_id_var
        token = _org_id_var.set(caller_org)
        response = await call_next(request)
        _org_id_var.reset(token)
        return response

    app.include_router(brain_router_router)
    return app


def _client(caller_org: str, caller_scopes: Optional[list] = None, brain: Optional[KnowledgeBrain] = None) -> TestClient:
    """Return a TestClient for the given org/scope combination."""
    app = _make_app(caller_org, caller_scopes)
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_brain(tmp_path, monkeypatch):
    """Each test gets its own fresh KnowledgeBrain so state doesn't leak."""
    db_path = tmp_path / "test_brain.db"
    # Reset the singleton so the next get_brain() call creates a fresh one.
    KnowledgeBrain.reset_instance()
    monkeypatch.setenv("FIXOPS_BRAIN_DB_PATH", str(db_path))
    brain = get_brain(db_path=str(db_path))
    yield brain
    # Teardown: reset singleton so subsequent tests start clean.
    KnowledgeBrain.reset_instance()


def _insert_node(brain: KnowledgeBrain, node_id: str, org_id: Optional[str]) -> None:
    """Directly insert a node into brain_nodes, bypassing GraphNode validation."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    with brain._conn_lock:
        brain._conn.execute(
            "INSERT OR REPLACE INTO brain_nodes "
            "(node_id, node_type, org_id, properties, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (node_id, "finding", org_id, "{}", now, now),
        )
        brain._conn.commit()


# ===========================================================================
# Tests
# ===========================================================================

class TestGetNodeIsolation:
    """GET /api/v1/brain/nodes/{node_id}"""

    def test_tenant_can_read_own_node(self, isolated_brain):
        """Tenant A reads its own node → 200."""
        _insert_node(isolated_brain, "node-own", _ORG_A)
        client = _client(_ORG_A)
        resp = client.get("/api/v1/brain/nodes/node-own")
        assert resp.status_code == 200
        assert resp.json()["org_id"] == _ORG_A

    def test_tenant_b_cannot_read_tenant_a_node(self, isolated_brain):
        """Tenant B tries to read Tenant A's node → 404."""
        _insert_node(isolated_brain, "node-a-private", _ORG_A)
        client = _client(_ORG_B)
        resp = client.get("/api/v1/brain/nodes/node-a-private")
        assert resp.status_code == 404

    def test_any_tenant_can_read_system_node(self, isolated_brain):
        """System node is readable by any tenant."""
        _insert_node(isolated_brain, "cve:CVE-2024-0001", _SYSTEM_ORG)
        for org in (_ORG_A, _ORG_B, "org-random-c"):
            client = _client(org)
            resp = client.get("/api/v1/brain/nodes/cve:CVE-2024-0001")
            assert resp.status_code == 200, f"Expected 200 for org={org}, got {resp.status_code}"
            assert resp.json()["org_id"] == _SYSTEM_ORG

    def test_missing_node_returns_404(self, isolated_brain):
        """Non-existent node → 404."""
        client = _client(_ORG_A)
        resp = client.get("/api/v1/brain/nodes/does-not-exist")
        assert resp.status_code == 404


class TestDeleteNodeIsolation:
    """DELETE /api/v1/brain/nodes/{node_id}"""

    def test_tenant_can_delete_own_node(self, isolated_brain):
        """Tenant A deletes its own node → 200."""
        _insert_node(isolated_brain, "node-to-delete", _ORG_A)
        client = _client(_ORG_A)
        resp = client.delete("/api/v1/brain/nodes/node-to-delete")
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True

    def test_tenant_b_cannot_delete_tenant_a_node(self, isolated_brain):
        """Tenant B tries to delete Tenant A's node → 404."""
        _insert_node(isolated_brain, "node-a-priv", _ORG_A)
        client = _client(_ORG_B)
        resp = client.delete("/api/v1/brain/nodes/node-a-priv")
        assert resp.status_code == 404

    def test_non_admin_cannot_delete_system_node(self, isolated_brain):
        """Regular tenant tries to delete a system node → 403."""
        _insert_node(isolated_brain, "cve:CVE-2024-0002", _SYSTEM_ORG)
        client = _client(_ORG_A, caller_scopes=[])
        resp = client.delete("/api/v1/brain/nodes/cve:CVE-2024-0002")
        assert resp.status_code == 403
        assert "admin:all" in resp.json()["detail"]

    def test_admin_can_delete_system_node(self, isolated_brain):
        """Admin-scoped caller deletes a system node → 200."""
        _insert_node(isolated_brain, "cve:CVE-2024-0003", _SYSTEM_ORG)
        client = _client(_ORG_A, caller_scopes=["admin:all"])
        resp = client.delete("/api/v1/brain/nodes/cve:CVE-2024-0003")
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True

    def test_delete_missing_node_returns_404(self, isolated_brain):
        """Deleting a non-existent node → 404."""
        client = _client(_ORG_A)
        resp = client.delete("/api/v1/brain/nodes/ghost-node")
        assert resp.status_code == 404


class TestNullOrgMigration:
    """Verify that the startup migration backfills NULL org_id → 'system'."""

    def test_null_org_nodes_migrated_to_system(self, tmp_path, monkeypatch):
        """Nodes with org_id=NULL before startup are migrated to 'system'."""
        db_path = tmp_path / "migration_test.db"
        # Create a fresh brain, insert a NULL-org node directly, then reset and
        # re-initialise to trigger the migration a second time (simulates restart).
        KnowledgeBrain.reset_instance()
        monkeypatch.setenv("FIXOPS_BRAIN_DB_PATH", str(db_path))
        brain1 = get_brain(db_path=str(db_path))
        # Insert a node with org_id=NULL bypassing the dataclass default.
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        with brain1._conn_lock:
            brain1._conn.execute(
                "INSERT OR REPLACE INTO brain_nodes "
                "(node_id, node_type, org_id, properties, created_at, updated_at) "
                "VALUES ('legacy-null-node', 'cve', NULL, '{}', ?, ?)",
                (now, now),
            )
            brain1._conn.commit()
        # Confirm it's NULL before migration.
        with brain1._conn_lock:
            row = brain1._conn.execute(
                "SELECT org_id FROM brain_nodes WHERE node_id = 'legacy-null-node'"
            ).fetchone()
        assert row[0] is None, "Pre-migration: expected NULL org_id"

        # Simulate restart by resetting singleton and getting a new instance.
        KnowledgeBrain.reset_instance()
        brain2 = get_brain(db_path=str(db_path))
        with brain2._conn_lock:
            row = brain2._conn.execute(
                "SELECT org_id FROM brain_nodes WHERE node_id = 'legacy-null-node'"
            ).fetchone()
        assert row[0] == _SYSTEM_ORG, (
            f"Post-migration: expected org_id='{_SYSTEM_ORG}', got {row[0]!r}"
        )
        KnowledgeBrain.reset_instance()

    def test_migrated_null_node_readable_by_all_tenants(self, tmp_path, monkeypatch):
        """After migration, former NULL-org node is readable by any tenant via the API."""
        db_path = tmp_path / "api_migration_test.db"
        KnowledgeBrain.reset_instance()
        monkeypatch.setenv("FIXOPS_BRAIN_DB_PATH", str(db_path))
        brain = get_brain(db_path=str(db_path))
        # Insert a NULL-org node (legacy data).
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        with brain._conn_lock:
            brain._conn.execute(
                "INSERT OR REPLACE INTO brain_nodes "
                "(node_id, node_type, org_id, properties, created_at, updated_at) "
                "VALUES ('legacy-cve', 'cve', NULL, '{}', ?, ?)",
                (now, now),
            )
            brain._conn.commit()
        # Run the migration explicitly (simulates what __init__ does on restart).
        brain._migrate_legacy_null_nodes()

        # Now the node should be readable by any tenant.
        for org in (_ORG_A, _ORG_B):
            client = _client(org)
            resp = client.get("/api/v1/brain/nodes/legacy-cve")
            assert resp.status_code == 200, (
                f"Expected 200 for org={org} after migration, got {resp.status_code}"
            )
            assert resp.json()["org_id"] == _SYSTEM_ORG
        KnowledgeBrain.reset_instance()
