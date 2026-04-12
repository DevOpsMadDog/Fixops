"""Tests for multi-tenancy isolation — TenantContext, DB paths, access validation.

Covers:
- TenantContext: set/get/clear, thread isolation
- tenant_scoped_db: correct path generation
- ensure_tenant_directory: creates org directory
- validate_tenant_access: same org passes, different org raises TenantIsolationError
- list_tenants: returns org directories
- delete_tenant_data: removes directory, raises on missing
- get_tenant_stats: returns correct stats dict
- TenantAwareConnection: org_id injection in queries
- OrgIdMiddleware integration: sets/clears TenantContext

Run with:
    python -m pytest tests/test_tenant_isolation.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import sqlite3
import sys
import threading
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure suite-core is on the path (mirrors other test files)
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.exceptions import TenantIsolationError
from core.tenant_isolation import (
    TenantAwareConnection,
    TenantContext,
    clear_tenant,
    delete_tenant_data,
    ensure_tenant_directory,
    get_tenant,
    get_tenant_stats,
    list_tenants,
    set_tenant,
    tenant_scoped_db,
    validate_tenant_access,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clear_tenant_context():
    """Ensure TenantContext is clean before and after each test."""
    TenantContext.clear()
    yield
    TenantContext.clear()


@pytest.fixture()
def data_root(tmp_path, monkeypatch):
    """Point ALDECI_DATA_ROOT to a temp directory for isolation."""
    monkeypatch.setenv("ALDECI_DATA_ROOT", str(tmp_path))
    return tmp_path


# ---------------------------------------------------------------------------
# TenantContext — set / get / clear
# ---------------------------------------------------------------------------


class TestTenantContext:
    def test_set_and_get(self):
        TenantContext.set("acme-corp")
        assert TenantContext.get() == "acme-corp"

    def test_clear_returns_none(self):
        TenantContext.set("acme-corp")
        TenantContext.clear()
        assert TenantContext.get() is None

    def test_get_before_set_returns_none(self):
        assert TenantContext.get() is None

    def test_overwrite_org_id(self):
        TenantContext.set("org-a")
        TenantContext.set("org-b")
        assert TenantContext.get() == "org-b"

    def test_thread_isolation(self):
        """Each thread should see its own tenant context independently."""
        results = {}

        def thread_fn(org_id, key):
            TenantContext.set(org_id)
            import time
            time.sleep(0.01)  # yield to let other thread run
            results[key] = TenantContext.get()

        t1 = threading.Thread(target=thread_fn, args=("thread-org-1", "t1"))
        t2 = threading.Thread(target=thread_fn, args=("thread-org-2", "t2"))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert results["t1"] == "thread-org-1"
        assert results["t2"] == "thread-org-2"

    def test_main_thread_unaffected_by_child_thread(self):
        """Setting TenantContext in a child thread must not affect the main thread."""
        TenantContext.set("main-org")

        def set_other():
            TenantContext.set("child-org")

        t = threading.Thread(target=set_other)
        t.start()
        t.join()

        assert TenantContext.get() == "main-org"


# ---------------------------------------------------------------------------
# Module-level set_tenant / get_tenant / clear_tenant
# ---------------------------------------------------------------------------


class TestModuleFunctions:
    def test_set_tenant_sets_context(self):
        set_tenant("widget-co")
        assert get_tenant() == "widget-co"

    def test_clear_tenant_clears_context(self):
        set_tenant("widget-co")
        clear_tenant()
        assert get_tenant() is None

    def test_set_tenant_strips_whitespace(self):
        set_tenant("  trimmed  ")
        assert get_tenant() == "trimmed"

    def test_set_tenant_empty_raises(self):
        with pytest.raises(ValueError):
            set_tenant("")

    def test_set_tenant_whitespace_only_raises(self):
        with pytest.raises(ValueError):
            set_tenant("   ")


# ---------------------------------------------------------------------------
# tenant_scoped_db
# ---------------------------------------------------------------------------


class TestTenantScopedDb:
    def test_returns_correct_path(self, data_root):
        path = tenant_scoped_db("findings", "acme-corp")
        assert path == data_root / "acme-corp" / "findings.db"

    def test_path_suffix_is_db(self, data_root):
        path = tenant_scoped_db("audit", "org-x")
        assert path.suffix == ".db"

    def test_empty_db_name_raises(self, data_root):
        with pytest.raises(ValueError):
            tenant_scoped_db("", "acme-corp")

    def test_empty_org_id_raises(self, data_root):
        with pytest.raises(ValueError):
            tenant_scoped_db("findings", "")

    def test_different_orgs_produce_different_paths(self, data_root):
        p1 = tenant_scoped_db("findings", "org-a")
        p2 = tenant_scoped_db("findings", "org-b")
        assert p1 != p2

    def test_different_dbs_same_org(self, data_root):
        p1 = tenant_scoped_db("findings", "org-a")
        p2 = tenant_scoped_db("audit", "org-a")
        assert p1 != p2
        assert p1.parent == p2.parent


# ---------------------------------------------------------------------------
# ensure_tenant_directory
# ---------------------------------------------------------------------------


class TestEnsureTenantDirectory:
    def test_creates_directory(self, data_root):
        result = ensure_tenant_directory("new-org")
        assert result.exists()
        assert result.is_dir()

    def test_idempotent(self, data_root):
        ensure_tenant_directory("idempotent-org")
        ensure_tenant_directory("idempotent-org")  # should not raise
        assert (data_root / "idempotent-org").exists()

    def test_returns_path(self, data_root):
        result = ensure_tenant_directory("path-org")
        assert result == data_root / "path-org"

    def test_empty_org_id_raises(self, data_root):
        with pytest.raises(ValueError):
            ensure_tenant_directory("")


# ---------------------------------------------------------------------------
# validate_tenant_access
# ---------------------------------------------------------------------------


class TestValidateTenantAccess:
    def test_same_org_passes(self):
        # Should not raise
        validate_tenant_access("acme-corp", "acme-corp")

    def test_different_org_raises_isolation_error(self):
        with pytest.raises(TenantIsolationError):
            validate_tenant_access("org-a", "org-b")

    def test_empty_request_org_raises_value_error(self):
        with pytest.raises(ValueError):
            validate_tenant_access("", "org-b")

    def test_empty_resource_org_raises_value_error(self):
        with pytest.raises(ValueError):
            validate_tenant_access("org-a", "")

    def test_error_message_contains_org_ids(self):
        with pytest.raises(TenantIsolationError, match="org-a"):
            validate_tenant_access("org-a", "org-b")


# ---------------------------------------------------------------------------
# list_tenants
# ---------------------------------------------------------------------------


class TestListTenants:
    def test_empty_data_root_returns_empty_list(self, data_root):
        result = list_tenants()
        assert result == []

    def test_lists_created_org_directories(self, data_root):
        ensure_tenant_directory("zebra-corp")
        ensure_tenant_directory("alpha-inc")
        result = list_tenants()
        assert "zebra-corp" in result
        assert "alpha-inc" in result

    def test_returns_sorted_list(self, data_root):
        ensure_tenant_directory("c-org")
        ensure_tenant_directory("a-org")
        ensure_tenant_directory("b-org")
        result = list_tenants()
        assert result == sorted(result)

    def test_missing_data_root_returns_empty_list(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ALDECI_DATA_ROOT", str(tmp_path / "nonexistent"))
        result = list_tenants()
        assert result == []


# ---------------------------------------------------------------------------
# delete_tenant_data
# ---------------------------------------------------------------------------


class TestDeleteTenantData:
    def test_deletes_directory(self, data_root):
        ensure_tenant_directory("to-delete")
        delete_tenant_data("to-delete")
        assert not (data_root / "to-delete").exists()

    def test_missing_tenant_raises_file_not_found(self, data_root):
        with pytest.raises(FileNotFoundError):
            delete_tenant_data("nonexistent-org")

    def test_empty_org_id_raises_value_error(self, data_root):
        with pytest.raises(ValueError):
            delete_tenant_data("")

    def test_also_deletes_db_files(self, data_root):
        tenant_dir = ensure_tenant_directory("rich-org")
        db_path = tenant_dir / "findings.db"
        db_path.write_text("dummy")
        delete_tenant_data("rich-org")
        assert not db_path.exists()
        assert not tenant_dir.exists()


# ---------------------------------------------------------------------------
# get_tenant_stats
# ---------------------------------------------------------------------------


class TestGetTenantStats:
    def test_missing_org_returns_exists_false(self, data_root):
        stats = get_tenant_stats("ghost-org")
        assert stats["exists"] is False
        assert stats["org_id"] == "ghost-org"
        assert stats["database_count"] == 0

    def test_existing_org_returns_exists_true(self, data_root):
        ensure_tenant_directory("stats-org")
        stats = get_tenant_stats("stats-org")
        assert stats["exists"] is True

    def test_database_count_correct(self, data_root):
        tenant_dir = ensure_tenant_directory("db-org")
        (tenant_dir / "findings.db").write_bytes(b"x" * 100)
        (tenant_dir / "audit.db").write_bytes(b"y" * 200)
        (tenant_dir / "notes.txt").write_bytes(b"z" * 50)
        stats = get_tenant_stats("db-org")
        assert stats["database_count"] == 2

    def test_total_size_bytes(self, data_root):
        tenant_dir = ensure_tenant_directory("size-org")
        (tenant_dir / "a.db").write_bytes(b"a" * 512)
        (tenant_dir / "b.db").write_bytes(b"b" * 256)
        stats = get_tenant_stats("size-org")
        assert stats["total_size_bytes"] == 768

    def test_databases_dict_maps_filename_to_size(self, data_root):
        tenant_dir = ensure_tenant_directory("map-org")
        (tenant_dir / "findings.db").write_bytes(b"f" * 128)
        stats = get_tenant_stats("map-org")
        assert "findings.db" in stats["databases"]
        assert stats["databases"]["findings.db"] == 128

    def test_empty_org_id_raises(self, data_root):
        with pytest.raises(ValueError):
            get_tenant_stats("")


# ---------------------------------------------------------------------------
# TenantAwareConnection
# ---------------------------------------------------------------------------


class TestTenantAwareConnection:
    @pytest.fixture()
    def shared_db(self, tmp_path):
        """Create a shared findings table with org_id column."""
        db_path = tmp_path / "shared.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "CREATE TABLE findings (id INTEGER PRIMARY KEY, title TEXT, org_id TEXT)"
        )
        conn.execute("INSERT INTO findings (title, org_id) VALUES (?, ?)", ("Finding A", "org-a"))
        conn.execute("INSERT INTO findings (title, org_id) VALUES (?, ?)", ("Finding B", "org-b"))
        conn.execute("INSERT INTO findings (title, org_id) VALUES (?, ?)", ("Finding C", "org-a"))
        conn.commit()
        conn.close()
        return db_path

    def test_select_filters_by_org(self, shared_db):
        with TenantAwareConnection(shared_db, "org-a") as conn:
            rows = conn.execute("SELECT * FROM findings").fetchall()
        assert len(rows) == 2

    def test_select_with_where_appends_org(self, shared_db):
        with TenantAwareConnection(shared_db, "org-b") as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE title = ?", ("Finding B",)
            ).fetchall()
        assert len(rows) == 1

    def test_empty_org_id_raises(self, tmp_path):
        with pytest.raises(ValueError):
            TenantAwareConnection(tmp_path / "x.db", "")

    def test_context_manager_commits_and_closes(self, shared_db):
        # Verify no exception on normal exit
        with TenantAwareConnection(shared_db, "org-a") as conn:
            _ = conn.execute("SELECT COUNT(*) FROM findings").fetchone()


# ---------------------------------------------------------------------------
# Middleware integration — OrgIdMiddleware sets/clears TenantContext
# ---------------------------------------------------------------------------


class TestOrgIdMiddlewareIntegration:
    """Verify that OrgIdMiddleware correctly sets and clears TenantContext."""

    @pytest.mark.asyncio
    async def test_middleware_sets_tenant_context(self):
        """OrgIdMiddleware.dispatch should call TenantContext.set with the resolved org_id."""
        from apps.api.org_middleware import OrgIdMiddleware

        # Build a minimal fake app
        async def mock_app(scope, receive, send):
            pass

        middleware = OrgIdMiddleware(mock_app)

        # Mock request with X-Org-ID header
        mock_request = MagicMock()
        mock_request.headers = {"X-Org-ID": "middleware-org"}
        mock_request.query_params = {}
        mock_request.state = MagicMock(spec=[])  # empty state namespace

        captured = {}

        async def call_next(req):
            captured["org_id"] = TenantContext.get()
            response = MagicMock()
            response.headers = {}
            return response

        with patch(
            "apps.api.org_middleware._extract_org_id", return_value="middleware-org"
        ):
            await middleware.dispatch(mock_request, call_next)

        assert captured["org_id"] == "middleware-org"

    @pytest.mark.asyncio
    async def test_middleware_clears_tenant_context_after_response(self):
        """TenantContext should be cleared after dispatch completes."""
        from apps.api.org_middleware import OrgIdMiddleware

        async def mock_app(scope, receive, send):
            pass

        middleware = OrgIdMiddleware(mock_app)

        mock_request = MagicMock()
        mock_request.headers = {}
        mock_request.query_params = {}
        mock_request.state = MagicMock(spec=[])

        async def call_next(req):
            response = MagicMock()
            response.headers = {}
            return response

        TenantContext.set("before-org")
        with patch(
            "apps.api.org_middleware._extract_org_id", return_value="transient-org"
        ):
            await middleware.dispatch(mock_request, call_next)

        # After dispatch the TenantContext should be cleared (not "transient-org")
        assert TenantContext.get() is None
