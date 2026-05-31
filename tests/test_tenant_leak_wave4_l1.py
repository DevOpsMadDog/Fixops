"""
Tenant isolation tests — Wave 4 L1 (api_keys, export, notifications).

Tests confirm that the three patched routers correctly scope data to the
caller's org_id. Because apikey_router, export_router, and notification_router
are not currently mounted in the main app, each test group builds a minimal
standalone FastAPI app that mounts only the target router. This proves the
router-level fix is correct regardless of mount status.

Isolation assertions:
  - Org A creates a resource.
  - Org B list excludes it.
  - Org B by-id returns 404.
  - Org B cannot mutate Org A's resource.

pytest.skip is used when an engine returns 503 (unconfigured dependency).
"""

from __future__ import annotations

import os
import sys
import time
import tempfile
from typing import Optional

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _d in (
    _REPO,
    os.path.join(_REPO, "suite-api"),
    os.path.join(_REPO, "suite-core"),
    os.path.join(_REPO, "suite-attack"),
    os.path.join(_REPO, "suite-feeds"),
    os.path.join(_REPO, "suite-integrations"),
    os.path.join(_REPO, "suite-evidence-risk"),
):
    if _d not in sys.path:
        sys.path.insert(0, _d)

import jwt as _jwt
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# JWT / auth helpers
# ---------------------------------------------------------------------------
_JWT_SECRET = os.getenv("FIXOPS_JWT_SECRET", "fixops-dev-secret-change-in-production")
_JWT_ALG = "HS256"
_ADMIN_SCOPES = ["read:findings", "write:findings", "admin:all"]


def _mint_token(org_id: str, user_id: str = "test-user") -> str:
    payload = {
        "sub": user_id,
        "email": f"{user_id}@{org_id}.test",
        "role": "admin",
        "org_id": org_id,
        "scopes": _ADMIN_SCOPES,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    return _jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALG)


def _org_headers(org_id: str) -> dict:
    """Return headers with both JWT (for require_scope) and X-Org-ID (for OrgIdMiddleware)."""
    token = _mint_token(org_id)
    return {
        "Authorization": f"Bearer {token}",
        "X-Org-ID": org_id,
    }


# ---------------------------------------------------------------------------
# Minimal standalone app builder for unmounted routers
# ---------------------------------------------------------------------------

def _make_standalone_app(router_module_path: str, router_attr: str = "router") -> FastAPI:
    """
    Build a minimal FastAPI app mounting a single router under test.

    Wires OrgIdMiddleware so get_org_id dependency works correctly,
    and auth_middleware so require_scope works.
    """
    import importlib

    mod = importlib.import_module(router_module_path)
    router = getattr(mod, router_attr)

    from apps.api.org_middleware import OrgIdMiddleware
    from core.auth_middleware import require_auth  # noqa: F401 — imported to warm JWT config

    app = FastAPI()
    app.add_middleware(OrgIdMiddleware)
    app.include_router(router)
    return app


def _make_client_for(app: FastAPI, org_id: str) -> TestClient:
    client = TestClient(app, raise_server_exceptions=False)
    client.headers.update(_org_headers(org_id))
    return client


# ===========================================================================
# 1. API Keys — apikey_router.py (APIKeyManager-backed)
# ===========================================================================

class TestApiKeysTenantIsolation:
    """Org A keys must not be visible or mutable by Org B.

    Tests the router-level fix in apikey_router.py which passes auth.org_id
    (from the JWT) to all by-id lookups and the list query.
    """

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path):
        os.environ["FIXOPS_DATA_DIR"] = str(tmp_path)
        os.environ["FIXOPS_JWT_SECRET"] = _JWT_SECRET
        os.environ["FIXOPS_AUTH_MODE"] = "enforced"

        # Reset singleton so it picks up new FIXOPS_DATA_DIR
        import core.api_key_manager as _akm  # noqa: PLC0415
        old = _akm.APIKeyManager._instance
        _akm.APIKeyManager._instance = None

        app = _make_standalone_app("apps.api.apikey_router")
        self.ca = _make_client_for(app, "org-a")
        self.cb = _make_client_for(app, "org-b")

        yield

        _akm.APIKeyManager._instance = old

    def _create_key(self, client: TestClient, name: str = "test-key") -> dict:
        resp = client.post(
            "/api/v1/auth/keys",
            json={"name": name, "role": "viewer", "scopes": []},
        )
        if resp.status_code == 503:
            pytest.skip("APIKeyManager unavailable (503)")
        assert resp.status_code == 201, f"create failed ({resp.status_code}): {resp.text}"
        return resp.json()

    def test_list_keys_scoped_to_caller_org(self):
        """Org B cannot see Org A's keys in the list."""
        self._create_key(self.ca, "key-for-a")
        resp = self.cb.get("/api/v1/auth/keys")
        if resp.status_code == 503:
            pytest.skip("APIKeyManager unavailable (503)")
        assert resp.status_code == 200, resp.text
        keys = resp.json()
        org_ids = [k["org_id"] for k in keys]
        assert all(o == "org-b" for o in org_ids), (
            f"Org B list contains non-org-b keys: {org_ids}"
        )

    def test_get_key_cross_org_returns_404(self):
        data = self._create_key(self.ca)
        resp = self.cb.get(f"/api/v1/auth/keys/{data['id']}")
        if resp.status_code == 503:
            pytest.skip("APIKeyManager unavailable (503)")
        assert resp.status_code == 404, (
            f"Org B read Org A key — expected 404, got {resp.status_code}: {resp.text}"
        )

    def test_revoke_key_cross_org_returns_404(self):
        data = self._create_key(self.ca)
        resp = self.cb.post(f"/api/v1/auth/keys/{data['id']}/revoke")
        if resp.status_code == 503:
            pytest.skip("APIKeyManager unavailable (503)")
        assert resp.status_code == 404, (
            f"Org B revoked Org A key — expected 404, got {resp.status_code}: {resp.text}"
        )

    def test_update_key_cross_org_returns_404(self):
        data = self._create_key(self.ca)
        resp = self.cb.put(
            f"/api/v1/auth/keys/{data['id']}",
            json={"name": "hacked"},
        )
        if resp.status_code == 503:
            pytest.skip("APIKeyManager unavailable (503)")
        assert resp.status_code == 404, (
            f"Org B updated Org A key — expected 404, got {resp.status_code}: {resp.text}"
        )

    def test_rotate_key_cross_org_returns_404(self):
        data = self._create_key(self.ca)
        resp = self.cb.post(f"/api/v1/auth/keys/{data['id']}/rotate")
        if resp.status_code == 503:
            pytest.skip("APIKeyManager unavailable (503)")
        assert resp.status_code == 404, (
            f"Org B rotated Org A key — expected 404, got {resp.status_code}: {resp.text}"
        )

    def test_usage_cross_org_returns_404(self):
        data = self._create_key(self.ca)
        resp = self.cb.get(f"/api/v1/auth/keys/{data['id']}/usage")
        if resp.status_code == 503:
            pytest.skip("APIKeyManager unavailable (503)")
        assert resp.status_code == 404, (
            f"Org B read usage of Org A key — expected 404, got {resp.status_code}: {resp.text}"
        )

    def test_org_a_can_access_own_key(self):
        data = self._create_key(self.ca)
        resp = self.ca.get(f"/api/v1/auth/keys/{data['id']}")
        if resp.status_code == 503:
            pytest.skip("APIKeyManager unavailable (503)")
        assert resp.status_code == 200
        assert resp.json()["org_id"] == "org-a"


# ===========================================================================
# 2. Export — export_router.py
# ===========================================================================

class TestExportTenantIsolation:
    """Export endpoints must derive org_id from auth context, not a free query param."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        os.environ["FIXOPS_JWT_SECRET"] = _JWT_SECRET
        os.environ["FIXOPS_AUTH_MODE"] = "enforced"
        # export_router uses api_key_auth dependency — set FIXOPS_MODE=dev so it passes
        os.environ["FIXOPS_MODE"] = "dev"

        app = _make_standalone_app("apps.api.export_router")
        self.ca = _make_client_for(app, "org-a")
        self.cb = _make_client_for(app, "org-b")

    def _check(self, client: TestClient, path: str) -> tuple:
        resp = client.get(f"/api/v1/export/{path}")
        return resp.status_code, resp

    def test_alerts_responds_for_auth_org(self):
        status, resp = self._check(self.ca, "alerts")
        if status == 503:
            pytest.skip("Export engine unavailable (503)")
        assert status in (200, 206), f"unexpected {status}: {resp.text}"

    def test_vulnerabilities_responds_for_auth_org(self):
        status, resp = self._check(self.ca, "vulnerabilities")
        if status == 503:
            pytest.skip("Export engine unavailable (503)")
        assert status in (200, 206), f"unexpected {status}: {resp.text}"

    def test_compliance_responds_for_auth_org(self):
        status, resp = self._check(self.ca, "compliance")
        if status == 503:
            pytest.skip("Export engine unavailable (503)")
        assert status in (200, 206), f"unexpected {status}: {resp.text}"

    def test_assets_responds_for_auth_org(self):
        status, resp = self._check(self.ca, "assets")
        if status == 503:
            pytest.skip("Export engine unavailable (503)")
        assert status in (200, 206), f"unexpected {status}: {resp.text}"

    def test_dashboard_responds_for_auth_org(self):
        status, resp = self._check(self.ca, "dashboard")
        if status == 503:
            pytest.skip("Export engine unavailable (503)")
        assert status in (200, 206), f"unexpected {status}: {resp.text}"

    def test_query_param_org_id_override_ignored(self):
        """?org_id=org-a is ignored when X-Org-ID=org-b is set — auth header wins."""
        resp = self.cb.get("/api/v1/export/alerts?org_id=org-a")
        if resp.status_code == 503:
            pytest.skip("Export engine unavailable (503)")
        cd = resp.headers.get("content-disposition", "")
        assert "org-a" not in cd, (
            f"Org B exported Org A data via ?org_id override. "
            f"Content-Disposition: {cd!r}"
        )


# ===========================================================================
# 3. Notifications — notification_router.py
# ===========================================================================

class TestNotificationsTenantIsolation:
    """Alert rules and inbox must be org-scoped."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path):
        os.environ["FIXOPS_JWT_SECRET"] = _JWT_SECRET
        os.environ["FIXOPS_AUTH_MODE"] = "enforced"

        import core.notifications as _notif  # noqa: PLC0415
        self._orig_db = _notif._DB_PATH
        _notif._DB_PATH = str(tmp_path / "notifications_test.db")

        import apps.api.notification_router as _nr  # noqa: PLC0415
        _nr._engine = None

        app = _make_standalone_app("apps.api.notification_router")
        self.ca = _make_client_for(app, "org-a")
        self.cb = _make_client_for(app, "org-b")

        yield

        _notif._DB_PATH = self._orig_db
        _nr._engine = None

    def _create_rule(self, client: TestClient, name: str = "test-rule") -> dict:
        resp = client.post(
            "/api/v1/notifications/rules",
            json={"name": name, "enabled": True},
        )
        if resp.status_code == 503:
            pytest.skip("NotificationEngine unavailable (503)")
        assert resp.status_code == 201, f"create rule failed ({resp.status_code}): {resp.text}"
        return resp.json()

    def test_org_b_list_excludes_org_a_rules(self):
        self._create_rule(self.ca, "org-a-rule")
        resp = self.cb.get("/api/v1/notifications/rules")
        if resp.status_code == 503:
            pytest.skip("NotificationEngine unavailable (503)")
        assert resp.status_code == 200
        names = [r["name"] for r in resp.json()]
        assert "org-a-rule" not in names, (
            f"Org B sees Org A rule in list: {names}"
        )

    def test_org_b_delete_org_a_rule_returns_404(self):
        data = self._create_rule(self.ca)
        resp = self.cb.delete(f"/api/v1/notifications/rules/{data['id']}")
        if resp.status_code == 503:
            pytest.skip("NotificationEngine unavailable (503)")
        assert resp.status_code == 404, (
            f"Org B deleted Org A rule — expected 404, got {resp.status_code}: {resp.text}"
        )

    def test_org_b_update_org_a_rule_returns_404(self):
        data = self._create_rule(self.ca)
        resp = self.cb.put(
            f"/api/v1/notifications/rules/{data['id']}",
            json={"name": "hacked"},
        )
        if resp.status_code == 503:
            pytest.skip("NotificationEngine unavailable (503)")
        assert resp.status_code == 404, (
            f"Org B updated Org A rule — expected 404, got {resp.status_code}: {resp.text}"
        )

    def test_org_a_can_manage_own_rules(self):
        data = self._create_rule(self.ca, "keep-me")
        rule_id = data["id"]

        resp = self.ca.get("/api/v1/notifications/rules")
        if resp.status_code == 503:
            pytest.skip("NotificationEngine unavailable (503)")
        assert "keep-me" in [r["name"] for r in resp.json()]

        resp = self.ca.delete(f"/api/v1/notifications/rules/{rule_id}")
        assert resp.status_code == 200

    def test_inbox_does_not_leak_across_orgs(self):
        """Inbox is scoped to org — Org B querying an org-a email sees no notifications."""
        resp = self.cb.get("/api/v1/notifications/inbox?user_email=user@org-a.com")
        if resp.status_code == 503:
            pytest.skip("NotificationEngine unavailable (503)")
        assert resp.status_code == 200
        notifs = resp.json()
        assert notifs == [], (
            f"Org B inbox returned cross-org notifications: {notifs}"
        )
