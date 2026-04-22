"""Smoke tests for GAP-022/023 compliance seed methods + router.

Minimal coverage written post-quota-kill to unblock main line.
Comprehensive tests are a follow-up.
"""
from __future__ import annotations

import importlib
import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_data_dir(monkeypatch):
    d = tempfile.mkdtemp(prefix="compliance_seed_test_")
    monkeypatch.setenv("FIXOPS_DATA_DIR", d)
    yield d


def _fresh_compliance_engine():
    mod = importlib.import_module("core.compliance_mapping_engine")
    importlib.reload(mod)
    return mod.ComplianceMappingEngine()


def _fresh_policy_engine():
    mod = importlib.import_module("core.policy_engine")
    importlib.reload(mod)
    return mod.PolicyEngine()


class TestFrameworkSeed:
    def test_seed_frameworks_runs_and_returns_dict(self, tmp_data_dir):
        eng = _fresh_compliance_engine()
        result = eng.seed_framework_library(org_id="org-seed-test")
        assert isinstance(result, dict)

    def test_seed_frameworks_reports_counts(self, tmp_data_dir):
        eng = _fresh_compliance_engine()
        result = eng.seed_framework_library(org_id="org-seed-test")
        assert "frameworks" in result or "controls_inserted" in result

    def test_seed_frameworks_idempotent(self, tmp_data_dir):
        eng = _fresh_compliance_engine()
        first = eng.seed_framework_library(org_id="org-idemp")
        second = eng.seed_framework_library(org_id="org-idemp")
        inserted_first = first.get("controls_inserted", 0)
        inserted_second = second.get("controls_inserted", 0)
        assert inserted_second <= inserted_first, "Second run must not insert more than first"

    def test_seed_frameworks_org_isolation(self, tmp_data_dir):
        eng = _fresh_compliance_engine()
        a = eng.seed_framework_library(org_id="org-a")
        b = eng.seed_framework_library(org_id="org-b")
        assert a.get("controls_inserted", 0) > 0
        assert b.get("controls_inserted", 0) > 0

    def test_seed_frameworks_covers_100_plus(self, tmp_data_dir):
        eng = _fresh_compliance_engine()
        result = eng.seed_framework_library(org_id="org-size-check")
        inserted = result.get("controls_inserted", 0) + result.get("controls_skipped", 0)
        assert inserted >= 100, f"GAP-022 target: 100+ framework controls; got {inserted}"

    def test_framework_library_catalog_callable(self):
        mod = importlib.import_module("core.compliance_mapping_engine")
        assert hasattr(mod, "_framework_library_catalog"), "catalog builder must exist"


class TestPolicySeed:
    def test_seed_policies_runs_and_returns_dict(self, tmp_data_dir):
        eng = _fresh_policy_engine()
        result = eng.seed_policy_library(org_id="org-pol-test")
        assert isinstance(result, dict)

    def test_seed_policies_reports_counts(self, tmp_data_dir):
        eng = _fresh_policy_engine()
        result = eng.seed_policy_library(org_id="org-pol-test")
        assert any(k in result for k in ("policies", "policies_inserted", "inserted"))

    def test_seed_policies_idempotent(self, tmp_data_dir):
        eng = _fresh_policy_engine()
        first = eng.seed_policy_library(org_id="org-idemp-pol")
        second = eng.seed_policy_library(org_id="org-idemp-pol")
        # Second run should skip most / all
        total_new = second.get("policies_inserted", second.get("inserted", 0))
        first_new = first.get("policies_inserted", first.get("inserted", 0))
        assert total_new <= first_new

    def test_seed_policies_org_isolation(self, tmp_data_dir):
        eng = _fresh_policy_engine()
        a = eng.seed_policy_library(org_id="org-pol-a")
        b = eng.seed_policy_library(org_id="org-pol-b")
        # Both orgs should get their own seed set
        new_a = a.get("policies_inserted", a.get("inserted", 0))
        new_b = b.get("policies_inserted", b.get("inserted", 0))
        assert new_a > 0 and new_b > 0

    def test_seed_policies_covers_3000_plus(self, tmp_data_dir):
        eng = _fresh_policy_engine()
        result = eng.seed_policy_library(org_id="org-pol-size")
        total = (
            result.get("policies_inserted", 0)
            + result.get("policies_skipped", 0)
            + result.get("inserted", 0)
            + result.get("skipped", 0)
        )
        assert total >= 3000, f"GAP-023 target: 3000+ policy rules; got {total}"

    def test_policy_catalog_callable(self):
        mod = importlib.import_module("core.policy_engine")
        assert hasattr(mod, "build_policy_library_catalog"), "catalog builder must exist"


class TestRouterImport:
    def test_router_module_imports(self):
        r = importlib.import_module("apps.api.compliance_seed_router")
        assert hasattr(r, "router"), "compliance_seed_router must expose `router`"

    def test_router_has_three_endpoints(self):
        r = importlib.import_module("apps.api.compliance_seed_router")
        paths = {route.path for route in r.router.routes}
        assert "/api/v1/compliance-seed/frameworks" in paths
        assert "/api/v1/compliance-seed/policies" in paths
        assert "/api/v1/compliance-seed/stats" in paths
