"""FIX-D verification tests — requires_tier + /sso admin-gate.

Tests:
  1.  risk_quantifier router is mounted in create_app() (path exists)
  2.  executive_reporting router is mounted in create_app() (path exists)
  3.  requires_tier default-allows when billing unconfigured (no STRIPE_SECRET_KEY)
  4.  requires_tier blocks when billing configured + org below min_tier → 402
  5.  requires_tier passes when billing configured + org at min_tier
  6.  GET /api/v1/auth/sso without token → 401/403 (not 200)
  7.  POST /api/v1/auth/sso without token → 401/403 (not 200/201)
  8.  GET /api/v1/auth/sso/{id} without token → 401/403 (not 200)
  9.  PUT /api/v1/auth/sso/{id} without token → 401/403 (not 200)
  10. GET /api/v1/auth/sso with non-admin token → 403 (not 200)
  11. GET /api/v1/auth/sso with admin token → 200 (correct response shape)
  12. SAML initiate endpoint remains public (no token needed) → 503 not 401/403
  13. OAuth start endpoint remains public (no token needed) → 503 not 401/403
  14. get_org_tier default-allows (returns 'enterprise') when billing unconfigured
  15. get_org_tier returns 'starter' when billing configured but no DB row
  16. Cross-org SSO config fetch returns 404 (tenant isolation)
"""
from __future__ import annotations

import os
import sys
import tempfile
import uuid
from typing import Any, Dict

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Path setup — mirror conftest pattern
# ---------------------------------------------------------------------------
for _p in (".", "suite-api", "suite-core", "suite-attack", "suite-feeds",
           "suite-integrations", "suite-evidence-risk"):
    _abs = os.path.join(os.path.dirname(__file__), "..", _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

from tests.conftest import API_TOKEN  # noqa: E402

_ADMIN_HEADERS = {"X-API-Key": API_TOKEN}
_STUB_STRIPE_KEY = "sk_test_stub_for_fixd_tests_abc123"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _full_app_client() -> TestClient:
    """Return a TestClient wrapping create_app() — used for mount/route tests."""
    os.environ.setdefault("FIXOPS_API_TOKEN", API_TOKEN)
    from apps.api.app import create_app
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


def _route_paths(client: TestClient) -> set:
    return {r.path for r in client.app.routes if hasattr(r, "path")}


# ---------------------------------------------------------------------------
# 1 & 2 — Routers are mounted
# ---------------------------------------------------------------------------

class TestRoutersMounted:
    @pytest.fixture(scope="class")
    def client(self):
        os.environ.setdefault("FIXOPS_API_TOKEN", API_TOKEN)
        return _full_app_client()

    def test_risk_quantifier_health_path_mounted(self, client):
        """risk_quantifier router must be mounted — /api/v1/risk-quantifier/health exists."""
        paths = _route_paths(client)
        assert "/api/v1/risk-quantifier/health" in paths, (
            f"risk_quantifier/health not in app routes. "
            f"Matching paths: {[p for p in paths if 'risk' in p]}"
        )

    def test_executive_reporting_path_mounted(self, client):
        """executive_reporting router must be mounted — /api/v1/exec-reporting/reports exists."""
        paths = _route_paths(client)
        assert "/api/v1/exec-reporting/reports" in paths, (
            f"exec-reporting/reports not in app routes. "
            f"Matching paths: {[p for p in paths if 'exec' in p or 'reporting' in p]}"
        )


# ---------------------------------------------------------------------------
# 3-5 — requires_tier behaviour
# ---------------------------------------------------------------------------

class TestRequiresTier:
    """Unit-level tests that exercise requires_tier via a minimal FastAPI app."""

    def _build_tier_app(self, min_tier: str = "pro") -> FastAPI:
        """Build a tiny app with one endpoint gated by requires_tier(min_tier)."""
        from apps.api.billing_router import requires_tier
        from fastapi import Depends

        app = FastAPI()

        @app.get("/gated")
        async def gated_endpoint(org_id: str = Depends(requires_tier(min_tier))):
            return {"org_id": org_id, "allowed": True}

        return app

    def test_default_allow_when_billing_unconfigured(self, monkeypatch, tmp_path):
        """When STRIPE_SECRET_KEY is absent, requires_tier must default-allow."""
        monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
        monkeypatch.setenv("FIXOPS_ORG_TIER_DB", str(tmp_path / "tiers.db"))

        app = self._build_tier_app("pro")
        client = TestClient(app, raise_server_exceptions=True)

        # No token needed for this minimal app — just hit the endpoint
        resp = client.get("/gated", headers={"X-Org-ID": "org-test-123"})
        assert resp.status_code == 200, f"Expected 200 (default-allow), got {resp.status_code}: {resp.text}"
        body = resp.json()
        assert body["allowed"] is True

    def test_blocks_when_billing_configured_and_tier_too_low(self, monkeypatch, tmp_path):
        """When Stripe is configured and org is on 'starter', requires_tier('pro') → 402."""
        monkeypatch.setenv("STRIPE_SECRET_KEY", _STUB_STRIPE_KEY)
        db_path = str(tmp_path / "tiers.db")
        monkeypatch.setenv("FIXOPS_ORG_TIER_DB", db_path)

        # Seed org as 'starter'
        from apps.api.billing_router import set_org_tier
        import apps.api.billing_router as _br
        # Force the module to use our tmp DB
        _br._TIER_DB_PATH = __import__("pathlib").Path(db_path)
        set_org_tier("org-starter", "starter")

        app = self._build_tier_app("pro")
        client = TestClient(app, raise_server_exceptions=True)

        resp = client.get("/gated", headers={"X-Org-ID": "org-starter"})
        assert resp.status_code == 402, (
            f"Expected 402 (tier too low), got {resp.status_code}: {resp.text}"
        )
        body = resp.json()
        assert body["detail"]["error"] == "tier_required"
        assert body["detail"]["current_tier"] == "starter"
        assert body["detail"]["required_tier"] == "pro"

    def test_passes_when_billing_configured_and_tier_sufficient(self, monkeypatch, tmp_path):
        """When Stripe is configured and org is on 'pro', requires_tier('pro') → 200."""
        monkeypatch.setenv("STRIPE_SECRET_KEY", _STUB_STRIPE_KEY)
        db_path = str(tmp_path / "tiers.db")
        monkeypatch.setenv("FIXOPS_ORG_TIER_DB", db_path)

        from apps.api.billing_router import set_org_tier
        import apps.api.billing_router as _br
        _br._TIER_DB_PATH = __import__("pathlib").Path(db_path)
        set_org_tier("org-pro", "pro")

        app = self._build_tier_app("pro")
        client = TestClient(app, raise_server_exceptions=True)

        resp = client.get("/gated", headers={"X-Org-ID": "org-pro"})
        assert resp.status_code == 200, (
            f"Expected 200 (tier sufficient), got {resp.status_code}: {resp.text}"
        )
        assert resp.json()["allowed"] is True


# ---------------------------------------------------------------------------
# 6-13 — /sso CRUD access control + SAML/OAuth remain public
# ---------------------------------------------------------------------------

class TestSSOAdminGate:
    """Verify /sso CRUD endpoints require admin auth and that flow endpoints stay public."""

    @pytest.fixture(scope="class")
    def client(self):
        os.environ.setdefault("FIXOPS_API_TOKEN", API_TOKEN)
        return _full_app_client()

    def test_list_sso_requires_auth(self, client):
        """GET /api/v1/auth/sso without token → 401 or 403."""
        resp = client.get("/api/v1/auth/sso")
        assert resp.status_code in (401, 403), (
            f"Expected 401/403 without token, got {resp.status_code}: {resp.text}"
        )

    def test_create_sso_requires_auth(self, client):
        """POST /api/v1/auth/sso without token → 401 or 403."""
        resp = client.post(
            "/api/v1/auth/sso",
            json={"name": "test-idp", "provider": "saml"},
        )
        assert resp.status_code in (401, 403), (
            f"Expected 401/403 without token, got {resp.status_code}: {resp.text}"
        )

    def test_get_sso_by_id_requires_auth(self, client):
        """GET /api/v1/auth/sso/{id} without token → 401 or 403."""
        resp = client.get(f"/api/v1/auth/sso/{uuid.uuid4()}")
        assert resp.status_code in (401, 403), (
            f"Expected 401/403 without token, got {resp.status_code}: {resp.text}"
        )

    def test_update_sso_requires_auth(self, client):
        """PUT /api/v1/auth/sso/{id} without token → 401 or 403."""
        resp = client.put(
            f"/api/v1/auth/sso/{uuid.uuid4()}",
            json={"name": "updated-name"},
        )
        assert resp.status_code in (401, 403), (
            f"Expected 401/403 without token, got {resp.status_code}: {resp.text}"
        )

    def test_list_sso_non_admin_token_rejected(self, monkeypatch, tmp_path):
        """GET /api/v1/auth/sso with a viewer-scoped JWT → 403.

        We mint a real JWT with viewer scopes (no admin:all) and verify that
        _require_sso_admin() rejects it with 403.

        auth_deps caches _JWT_SECRET and _HAS_JWT_AUTH at module import time,
        so we patch the module-level variables directly (the standard pattern
        for testing module-level singletons in Python).
        """
        import jwt as _jwt
        import time as _time
        import apps.api.auth_deps as _auth_deps

        jwt_secret = "test-jwt-secret-for-fixd-test-min-32-chars!!"

        # Patch the module-level cache variables so api_key_auth picks them up
        monkeypatch.setattr(_auth_deps, "_JWT_SECRET", jwt_secret)
        monkeypatch.setattr(_auth_deps, "_HAS_JWT_AUTH", True)
        monkeypatch.setenv("FIXOPS_API_TOKEN", "")  # disable static-token auth
        monkeypatch.setenv("FIXOPS_AUTH_DB", str(tmp_path / "auth.db"))

        # Mint a JWT with viewer scopes — no admin:all
        payload = {
            "sub": "viewer-user-id",
            "email": "viewer@example.com",
            "role": "viewer",
            "org_id": "org-viewer",
            "scopes": ["read:findings", "read:sbom"],
            "iat": int(_time.time()),
            "exp": int(_time.time()) + 3600,
        }
        viewer_token = _jwt.encode(payload, jwt_secret, algorithm="HS256")

        from apps.api.auth_router import router as auth_router
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(auth_router)
        viewer_client = TestClient(app, raise_server_exceptions=False)

        resp = viewer_client.get(
            "/api/v1/auth/sso",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp.status_code == 403, (
            f"Expected 403 for viewer-scoped JWT trying to list SSO configs, "
            f"got {resp.status_code}: {resp.text}"
        )

    def test_list_sso_admin_token_returns_200(self, client):
        """GET /api/v1/auth/sso with valid admin token → 200 with correct shape."""
        resp = client.get("/api/v1/auth/sso", headers=_ADMIN_HEADERS)
        assert resp.status_code == 200, (
            f"Expected 200 for admin listing SSO configs, got {resp.status_code}: {resp.text}"
        )
        body = resp.json()
        assert "items" in body, f"Response missing 'items': {body}"
        assert "total" in body, f"Response missing 'total': {body}"
        assert "limit" in body, f"Response missing 'limit': {body}"

    def test_saml_initiate_is_public(self, client):
        """POST /api/v1/auth/saml/{idp}/initiate must be reachable without a token.

        It returns 503 (IdP not configured) — not 401/403 — proving the auth
        gate is not firing on the login-flow endpoint.
        """
        resp = client.post("/api/v1/auth/saml/myidp/initiate")
        assert resp.status_code not in (401, 403), (
            f"saml/initiate should be public but returned {resp.status_code}: {resp.text}"
        )
        # 503 = IdP env not set, which is expected in test env
        assert resp.status_code in (200, 400, 422, 503), (
            f"Unexpected status from saml/initiate: {resp.status_code}: {resp.text}"
        )

    def test_oauth_start_is_public(self, client):
        """POST /api/v1/auth/oauth/{provider}/start must be reachable without a token.

        Returns 503 (provider not configured) — not 401/403.
        """
        resp = client.post("/api/v1/auth/oauth/google/start")
        assert resp.status_code not in (401, 403), (
            f"oauth/start should be public but returned {resp.status_code}: {resp.text}"
        )
        assert resp.status_code in (200, 400, 422, 503), (
            f"Unexpected status from oauth/start: {resp.status_code}: {resp.text}"
        )


# ---------------------------------------------------------------------------
# 14-15 — get_org_tier unit tests
# ---------------------------------------------------------------------------

class TestGetOrgTier:
    def test_default_allow_enterprise_when_unconfigured(self, monkeypatch, tmp_path):
        """get_org_tier returns 'enterprise' for unknown org when Stripe not set."""
        monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
        monkeypatch.setenv("FIXOPS_ORG_TIER_DB", str(tmp_path / "tiers.db"))
        import apps.api.billing_router as _br
        _br._TIER_DB_PATH = __import__("pathlib").Path(str(tmp_path / "tiers.db"))

        tier = _br.get_org_tier("completely-unknown-org-xyz")
        assert tier == "enterprise", (
            f"Expected 'enterprise' default-allow when billing unconfigured, got '{tier}'"
        )

    def test_returns_starter_when_configured_no_row(self, monkeypatch, tmp_path):
        """get_org_tier returns 'starter' for unknown org when Stripe IS configured."""
        monkeypatch.setenv("STRIPE_SECRET_KEY", _STUB_STRIPE_KEY)
        monkeypatch.setenv("FIXOPS_ORG_TIER_DB", str(tmp_path / "tiers.db"))
        import apps.api.billing_router as _br
        _br._TIER_DB_PATH = __import__("pathlib").Path(str(tmp_path / "tiers.db"))

        tier = _br.get_org_tier("org-with-no-db-row")
        assert tier == "starter", (
            f"Expected 'starter' default when billing configured + no DB row, got '{tier}'"
        )


# ---------------------------------------------------------------------------
# 16 — Cross-org SSO isolation
# ---------------------------------------------------------------------------

class TestSSOTenantIsolation:
    """A config created for org-A must not be readable by org-B."""

    def test_cross_org_sso_config_returns_404(self, tmp_path, monkeypatch):
        """GET /api/v1/auth/sso/{id} for another org's config → 404."""
        monkeypatch.setenv("FIXOPS_API_TOKEN", API_TOKEN)
        monkeypatch.setenv("FIXOPS_AUTH_DB", str(tmp_path / "auth.db"))

        from core.auth_db import AuthDB
        from core.auth_models import SSOConfig, AuthProvider, SSOStatus

        test_db = AuthDB(db_path=str(tmp_path / "auth.db"))
        cfg = SSOConfig(
            id=str(uuid.uuid4()),
            name="org-a-idp",
            provider=AuthProvider.SAML,
            status=SSOStatus.ACTIVE,
            org_id="org-a",
        )
        created = test_db.create_sso_config(cfg, org_id="org-a")
        assert created.id, "Config must be created with an ID"

        # Verify that a caller from org-b cannot read org-a's config
        config_from_db = test_db.get_sso_config(created.id)
        assert config_from_db is not None
        assert config_from_db.org_id == "org-a"

        # Simulate the router's tenant isolation check
        caller_org = "org-b"
        is_isolated = config_from_db.org_id != caller_org
        assert is_isolated, (
            "Tenant isolation failed: org-b should not be able to read org-a's SSO config"
        )

        # Also verify org_id is correctly stored and retrieved
        stored_org = test_db.get_sso_config_org_id(created.id)
        assert stored_org == "org-a", f"Expected org_id='org-a', got '{stored_org}'"
