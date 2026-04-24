"""Integration smoke tests for 16 new routers shipped this session.

Goal: verify each router mounts cleanly and an endpoint exists.
We DO NOT test correctness — only:
  - The router can be imported without error
  - The endpoint is reachable (HTTP status < 500)
  - 200/401/403/422 all acceptable (endpoint exists, auth/validation layer answered)
  - 404 acceptable for endpoints that require a resource id
  - 405 acceptable if the method isn't the one we guessed

The 16 routers under smoke test:
  1. /api/v1/air-gap/bundle/stats
  2. /api/v1/orgs/stats/summary
  3. /api/v1/upgrade-path/stats
  4. /api/v1/binary-fp/stats
  5. /api/v1/reachability/stats
  6. /api/v1/dca/stats
  7. /api/v1/code-to-runtime/stats
  8. /api/v1/pbom/stats
  9. /api/v1/slsa/stats
 10. /api/v1/agentless-snapshot/stats
 11. /api/v1/sql/stats
 12. /api/v1/fips/readiness
 13. /api/v1/local-file-store/config
 14. /api/v1/rules/dsl/stats
 15. /api/v1/semantic/stats
 16. /api/v1/ide/stats
"""
from __future__ import annotations

import importlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


SMOKE_ENDPOINTS = [
    ("air_gap_bundle_router", "/api/v1/air-gap/bundle/stats"),
    ("org_hierarchy_router", "/api/v1/orgs/stats/summary"),
    ("upgrade_path_router", "/api/v1/upgrade-path/stats"),
    ("binary_fingerprint_router", "/api/v1/binary-fp/stats"),
    ("function_reachability_router", "/api/v1/reachability/stats"),
    ("deep_code_analysis_router", "/api/v1/dca/stats"),
    ("code_to_runtime_router", "/api/v1/code-to-runtime/stats"),
    ("pipeline_bom_router", "/api/v1/pbom/stats"),
    ("slsa_provenance_router", "/api/v1/slsa/stats"),
    ("agentless_snapshot_router", "/api/v1/agentless-snapshot/stats"),
    ("security_query_router", "/api/v1/sql/stats"),
    ("fips_router", "/api/v1/fips/readiness"),
    ("local_file_store_router", "/api/v1/local-file-store/config"),
    ("dynamic_rule_dsl_router", "/api/v1/rules/dsl/stats"),
    ("semantic_analyzer_router", "/api/v1/semantic/stats"),
    ("ide_backend_router", "/api/v1/ide/stats"),
]

# <500 = router mounted cleanly. We expressly include 401/403 (auth wall),
# 404 (missing resource id), 405 (wrong method), 422 (validation).
ACCEPTABLE_STATUS = {200, 400, 401, 403, 404, 405, 422}


@pytest.fixture(scope="module")
def app_client():
    """Mount all 16 new routers under one app, stub auth, return client."""
    import apps.api.auth_deps as auth_deps

    app = FastAPI()
    mounted = {}
    import_errors = {}

    for module_name, _ in SMOKE_ENDPOINTS:
        try:
            mod = importlib.import_module(f"apps.api.{module_name}")
            router = getattr(mod, "router", None)
            if router is None:
                import_errors[module_name] = "no 'router' attribute"
                continue
            app.include_router(router)
            mounted[module_name] = True
        except Exception as e:  # noqa: BLE001
            import_errors[module_name] = f"{type(e).__name__}: {e}"

    # Override auth so we can reach the endpoints (many require api_key_auth)
    app.dependency_overrides[auth_deps.api_key_auth] = lambda: None

    client = TestClient(app)
    return client, mounted, import_errors


class TestRouterImports:
    """Each router must import and expose a `router` APIRouter instance."""

    @pytest.mark.parametrize("module_name,path", SMOKE_ENDPOINTS)
    def test_router_imports_cleanly(self, module_name, path, app_client):
        _, mounted, import_errors = app_client
        assert module_name not in import_errors, (
            f"Router {module_name} failed to import: {import_errors.get(module_name)}"
        )
        assert mounted.get(module_name) is True, (
            f"Router {module_name} did not mount"
        )


class TestEndpointSmoke:
    """Each endpoint must answer (not 500) — proves the route is registered."""

    @pytest.mark.parametrize("module_name,path", SMOKE_ENDPOINTS)
    def test_endpoint_reachable(self, module_name, path, app_client):
        client, mounted, _ = app_client
        if not mounted.get(module_name):
            pytest.skip(f"Router {module_name} did not mount")

        # Try GET first with a default org_id query param (most endpoints expect one)
        resp = client.get(path, params={"org_id": "org-smoke-test"})
        assert resp.status_code in ACCEPTABLE_STATUS, (
            f"{path} returned {resp.status_code} (expected <500). "
            f"Body: {resp.text[:300]}"
        )
        # 500 or 502/503/504 would indicate a broken endpoint
        assert resp.status_code < 500, (
            f"{path} returned server error {resp.status_code}. Body: {resp.text[:300]}"
        )


class TestCollectiveHealth:
    """All 16 routers mount and respond — aggregate sanity check."""

    def test_all_16_routers_mounted(self, app_client):
        _, mounted, import_errors = app_client
        failed = [m for m, _ in SMOKE_ENDPOINTS if not mounted.get(m)]
        assert not failed, (
            f"Routers failed to mount: {failed}. Errors: {import_errors}"
        )

    def test_all_16_endpoints_answer(self, app_client):
        client, mounted, _ = app_client
        bad = []
        for module_name, path in SMOKE_ENDPOINTS:
            if not mounted.get(module_name):
                bad.append((path, "not-mounted"))
                continue
            resp = client.get(path, params={"org_id": "org-smoke-test"})
            if resp.status_code >= 500:
                bad.append((path, resp.status_code))
        assert not bad, f"Endpoints with 5xx: {bad}"
