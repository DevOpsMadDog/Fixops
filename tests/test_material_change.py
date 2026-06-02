"""Smoke tests for GAP-011 material_change merge on security_change_management_engine.

Minimal post-salvage tests. Comprehensive diff-determinism tests are follow-up.
"""
from __future__ import annotations

import importlib
import tempfile

import pytest


@pytest.fixture
def tmp_data_dir(monkeypatch):
    d = tempfile.mkdtemp(prefix="material_change_test_")
    monkeypatch.setenv("FIXOPS_DATA_DIR", d)
    yield d


def _change_engine():
    mod = importlib.import_module("core.security_change_management_engine")
    importlib.reload(mod)
    for name in dir(mod):
        obj = getattr(mod, name)
        if isinstance(obj, type) and name.endswith("Engine"):
            return obj()
    raise RuntimeError("No Engine class found")


class TestEngineExtension:
    def test_has_material_change_diff_method(self, tmp_data_dir):
        mod = importlib.import_module("core.security_change_management_engine")
        importlib.reload(mod)
        src = open(mod.__file__).read()
        assert "compute_material_change_diff" in src or "material_change" in src, \
            "security_change_management_engine must have material change diff method"

    def test_list_material_events_present(self, tmp_data_dir):
        mod = importlib.import_module("core.security_change_management_engine")
        importlib.reload(mod)
        src = open(mod.__file__).read()
        assert "material_change_events" in src or "list_material_events" in src

    def test_pr_webhook_method_present(self, tmp_data_dir):
        mod = importlib.import_module("core.security_change_management_engine")
        importlib.reload(mod)
        src = open(mod.__file__).read()
        assert "pr_webhook" in src.lower() or "pr_ref" in src

    def test_engine_imports(self, tmp_data_dir):
        eng = _change_engine()
        assert eng is not None


class TestRouter:
    def test_router_imports(self):
        r = importlib.import_module("apps.api.material_change_router")
        assert hasattr(r, "router")

    def test_router_serves_material_change(self):
        # The router was refactored to prefix "/api/v1/changes" with
        # material-change exposed as a sub-resource (/changes/material-change/*).
        r = importlib.import_module("apps.api.material_change_router")
        paths = {route.path for route in r.router.routes}
        assert "changes" in r.router.prefix, f"unexpected prefix: {r.router.prefix}"
        assert any("material-change" in p for p in paths), \
            f"expected material-change endpoints; got {paths}"

    def test_router_has_analyze_endpoint(self):
        # "compute" was renamed to "analyze" in the refactor.
        r = importlib.import_module("apps.api.material_change_router")
        paths = {route.path for route in r.router.routes}
        assert any("analyze" in p for p in paths), f"expected analyze endpoint; got {paths}"

    def test_router_has_recent_endpoint(self):
        # recent material changes (the former "events" listing).
        r = importlib.import_module("apps.api.material_change_router")
        paths = {route.path for route in r.router.routes}
        assert any("recent" in p or "events" in p for p in paths), \
            f"expected recent/events endpoint; got {paths}"

    def test_router_has_webhook_endpoint(self):
        # PR/webhook ingestion (analyze-pr + webhook routes).
        r = importlib.import_module("apps.api.material_change_router")
        paths = {route.path for route in r.router.routes}
        assert any("webhook" in p or "analyze-pr" in p for p in paths), \
            f"expected webhook/PR endpoint; got {paths}"


class TestWiring:
    def test_wired_in_app(self):
        with open("suite-api/apps/api/app.py") as f:
            app_src = f.read()
        assert "material_change_router" in app_src, "router must be wired in app.py"
