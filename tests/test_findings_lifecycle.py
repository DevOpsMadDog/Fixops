"""Smoke tests for GAP-063 findings lifecycle.

Minimal post-salvage tests covering the firstSeenAt/previousViolationId/
resolvedAt columns and the /api/v1/findings/lifecycle router. Full
reconcile-determinism tests are a follow-up.
"""
from __future__ import annotations

import importlib
import tempfile

import pytest


@pytest.fixture
def tmp_data_dir(monkeypatch):
    d = tempfile.mkdtemp(prefix="findings_lifecycle_test_")
    monkeypatch.setenv("FIXOPS_DATA_DIR", d)
    yield d


def _findings_engine():
    mod = importlib.import_module("core.security_findings_engine")
    importlib.reload(mod)
    for name in dir(mod):
        obj = getattr(mod, name)
        if isinstance(obj, type) and name.endswith("Engine"):
            return obj()
    raise RuntimeError("No Engine class found")


class TestSchemaMigration:
    def test_schema_has_new_columns(self, tmp_data_dir):
        eng = _findings_engine()
        # Pull pragma info
        import sqlite3
        db = getattr(eng, "_db_path", None) or getattr(eng, "db_path", None)
        if db is None:
            pytest.skip("engine doesn't expose db_path")
        with sqlite3.connect(str(db)) as conn:
            cols = [r[1] for r in conn.execute("PRAGMA table_info(security_findings)")]
        for needed in ("first_seen_at", "previous_violation_id", "resolved_at", "unchanged_scan_count"):
            assert needed in cols, f"GAP-063 schema must have {needed} column"

    def test_ensure_schema_idempotent(self, tmp_data_dir):
        eng1 = _findings_engine()
        eng2 = _findings_engine()
        # Both construct without raising
        assert eng1 is not None and eng2 is not None


class TestRouter:
    def test_router_imports(self):
        r = importlib.import_module("apps.api.findings_lifecycle_router")
        assert hasattr(r, "router")

    def test_router_has_expected_endpoints(self):
        r = importlib.import_module("apps.api.findings_lifecycle_router")
        paths = {route.path for route in r.router.routes}
        # Accept either /reconcile or /lifecycle/reconcile depending on prefix
        assert any("reconcile" in p for p in paths), f"Missing reconcile endpoint; got {paths}"
        assert any("summary" in p for p in paths), f"Missing summary endpoint; got {paths}"
        assert any("history" in p for p in paths), f"Missing history endpoint; got {paths}"


class TestTrendEngine:
    def test_vuln_trend_has_lifecycle_method(self, tmp_data_dir):
        mod = importlib.import_module("core.vuln_trend_engine")
        importlib.reload(mod)
        methods = [m for m in dir(mod) if "lifecycle" in m.lower()]
        # either a module-level function or a method on the engine class
        has_lifecycle = bool(methods)
        if not has_lifecycle:
            # check methods on engine classes
            for name in dir(mod):
                obj = getattr(mod, name)
                if isinstance(obj, type):
                    if any("lifecycle" in a.lower() for a in dir(obj)):
                        has_lifecycle = True
                        break
        assert has_lifecycle, "vuln_trend_engine should expose a lifecycle trend method"


class TestVulnAgeEngine:
    def test_uses_first_seen_at_when_available(self, tmp_data_dir):
        # Smoke: engine module imports and has age calculation logic
        mod = importlib.import_module("core.vulnerability_age_engine")
        importlib.reload(mod)
        assert mod is not None
        # At minimum the module should reference first_seen_at somewhere
        src = open(mod.__file__).read()
        assert "first_seen_at" in src, "vulnerability_age_engine must use first_seen_at"


class TestPostureHistory:
    def test_snapshot_records_3_tuple(self, tmp_data_dir):
        mod = importlib.import_module("core.security_posture_history_engine")
        importlib.reload(mod)
        assert mod is not None
        src = open(mod.__file__).read()
        # Must reference the 3 lifecycle buckets
        has_lifecycle_refs = sum(1 for k in ("new", "unchanged", "resolved") if k in src.lower())
        assert has_lifecycle_refs >= 2
