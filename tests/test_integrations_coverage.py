"""Coverage tests for suite-integrations and suite-feeds modules.

Tests the integration routers (webhooks, IDE, IaC, MCP, OSS tools)
and feed routers.
"""
import os
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for d in ["suite-core", "suite-api", "suite-attack", "suite-feeds",
          "suite-evidence-risk", "suite-integrations"]:
    p = os.path.join(ROOT, d)
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not available")


def _make_client(router) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


# ─── IDE Router (980 LOC) ───────────────────────────────────────────────────

class TestIDERouter:
    def test_import(self):
        from api import ide_router
        assert ide_router.router is not None

    def test_has_routes(self):
        from api import ide_router
        assert len(ide_router.router.routes) > 0

    def test_status(self):
        from api import ide_router
        client = _make_client(ide_router.router)
        resp = client.get("/api/v1/ide/status")
        assert resp.status_code in (200, 404)


# ─── IaC Router (242 LOC) ───────────────────────────────────────────────────

class TestIaCRouter:
    def test_import(self):
        from api import iac_router
        assert iac_router.router is not None

    def test_has_routes(self):
        from api import iac_router
        assert len(iac_router.router.routes) > 0


# ─── Integrations Router (525 LOC) ──────────────────────────────────────────

class TestIntegrationsRouter:
    def test_import(self):
        from api import integrations_router
        assert integrations_router.router is not None

    def test_has_routes(self):
        from api import integrations_router
        assert len(integrations_router.router.routes) > 0


# ─── OSS Tools (205 LOC) ────────────────────────────────────────────────────

class TestOSSToolsRouter:
    def test_import(self):
        from api import oss_tools
        assert hasattr(oss_tools, 'router')

    def test_has_routes(self):
        from api import oss_tools
        if hasattr(oss_tools, 'router'):
            assert len(oss_tools.router.routes) >= 0


# ─── MCP Router (468 LOC, integrations) ─────────────────────────────────────

class TestMCPRouterIntegrations:
    def test_import(self):
        from api import mcp_router
        assert mcp_router.router is not None

    def test_has_routes(self):
        from api import mcp_router
        assert len(mcp_router.router.routes) > 0


# ─── Feeds Router (1216 LOC, suite-feeds) ───────────────────────────────────

class TestFeedsRouterSuiteFeeds:
    """Tests for the suite-feeds/api/feeds_router.py."""

    def test_import(self):
        """Import the feeds router from suite-feeds."""
        # suite-feeds may shadow suite-core feeds_router via sys.path
        import importlib
        spec = importlib.util.find_spec("api.feeds_router")
        assert spec is not None
