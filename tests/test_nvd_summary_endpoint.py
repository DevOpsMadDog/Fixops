"""Tests for GET /api/v1/nvd/ summary endpoint (nvd_cve_router)."""
import importlib.util
import sys
import types

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Stub apps.api.auth_deps before loading the router module
# ---------------------------------------------------------------------------
_auth_mod = types.ModuleType("apps.api.auth_deps")


async def _api_key_auth():
    return True


_auth_mod.api_key_auth = _api_key_auth
sys.modules.setdefault("apps", types.ModuleType("apps"))
sys.modules.setdefault("apps.api", types.ModuleType("apps.api"))
sys.modules["apps.api.auth_deps"] = _auth_mod

# Load the router module directly by file path to avoid collision with the
# already-registered stub `apps.api` namespace.
_ROUTER_PATH = (
    "/Users/devops.ai/fixops/Fixops/suite-api/apps/api/nvd_cve_router.py"
)
_spec = importlib.util.spec_from_file_location("nvd_cve_router", _ROUTER_PATH)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

class _FakeImporter:
    def __init__(self, counts=None, raise_exc=None):
        self._counts = counts or {
            "CRITICAL": 12, "HIGH": 55, "MEDIUM": 120, "LOW": 30
        }
        self._raise = raise_exc

    def list_cves(self, severity=None, page=1, page_size=50, **_kw):
        if self._raise:
            raise self._raise
        total = self._counts.get((severity or "").upper(), 0)
        return {"total": total, "items": []}


def _make_client(importer, raise_server_exceptions=True):
    original = mod._get_importer
    mod._get_importer = lambda: importer
    app = FastAPI()
    app.include_router(mod.router)
    client = TestClient(app, raise_server_exceptions=raise_server_exceptions)
    return client, original


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_nvd_summary_200():
    """GET / returns 200 with correct totals and breakdown."""
    client, orig = _make_client(_FakeImporter())
    try:
        resp = client.get("/api/v1/nvd/")
        assert resp.status_code == 200
        body = resp.json()
        assert body["router"] == "nvd-cve"
        assert body["total_cves"] == 217  # 12+55+120+30
        assert body["severity_breakdown"]["critical"] == 12
        assert body["severity_breakdown"]["high"] == 55
        assert body["severity_breakdown"]["medium"] == 120
        assert body["severity_breakdown"]["low"] == 30
    finally:
        mod._get_importer = orig


def test_nvd_summary_required_keys():
    """Response must contain router, total_cves, severity_breakdown."""
    client, orig = _make_client(_FakeImporter())
    try:
        body = client.get("/api/v1/nvd/").json()
        for key in ("router", "total_cves", "severity_breakdown"):
            assert key in body, f"Missing key: {key}"
    finally:
        mod._get_importer = orig


def test_nvd_summary_all_severity_tiers():
    """severity_breakdown must include all four CVSS tiers."""
    client, orig = _make_client(_FakeImporter())
    try:
        bd = client.get("/api/v1/nvd/").json()["severity_breakdown"]
        for sev in ("critical", "high", "medium", "low"):
            assert sev in bd, f"Missing severity tier: {sev}"
    finally:
        mod._get_importer = orig


def test_nvd_summary_engine_error_returns_500():
    """When the importer raises, GET / must return 500."""
    client, orig = _make_client(
        _FakeImporter(raise_exc=RuntimeError("db locked")),
        raise_server_exceptions=False,
    )
    try:
        resp = client.get("/api/v1/nvd/")
        assert resp.status_code == 500
    finally:
        mod._get_importer = orig
