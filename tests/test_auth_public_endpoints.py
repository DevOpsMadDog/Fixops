"""
Tests proving that public auth endpoints are reachable without a token AND
that protected auth endpoints still require authentication.

Bug fixed: auth_router was mounted with
  dependencies=[Depends(_verify_api_key), Depends(_require_scope("admin:all"))]
in platform_app.py, making login/signup/forgot-password/reset-password
unreachable for new customers who have no token yet.

Fix: mount auth_router with no router-level dependencies; per-endpoint
Depends(api_key_auth) on /keys/*, /disposable-token*, /role-view* still fires.
"""
import os
import sys

import pytest

# Ensure all suite paths are importable
for _p in (".", "suite-api", "suite-core", "suite-attack", "suite-feeds",
           "suite-integrations", "suite-evidence-risk"):
    _abs = os.path.join(os.path.dirname(__file__), "..", _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from apps.api.app import create_app
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ---------------------------------------------------------------------------
# PUBLIC endpoints — must be reachable (no token) — expect NOT 403
# ---------------------------------------------------------------------------

class TestPublicAuthEndpoints:
    """Public auth endpoints must return something other than 403/401 scope-denied."""

    def test_login_reachable_without_token(self, client):
        """POST /api/v1/auth/login with bad creds → 401 invalid credentials, NOT 403."""
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@example.com", "password": "wrongpassword"},
        )
        # Must reach the endpoint (401 = invalid creds is correct)
        # 403 would mean the scope gate is still firing
        assert resp.status_code != 403, (
            f"login returned 403 — scope gate is still blocking unauthenticated users. "
            f"Body: {resp.text}"
        )
        assert resp.status_code in (400, 401, 422, 429), (
            f"Unexpected status {resp.status_code} from login endpoint. Body: {resp.text}"
        )

    def test_signup_reachable_without_token(self, client):
        """POST /api/v1/auth/signup must be reachable (201, 400, 409, 422, or 429)."""
        resp = client.post(
            "/api/v1/auth/signup",
            json={
                "email": "test_signup_probe@example.com",
                "password": "TestPassword123!",
                "name": "Test User",
                "org_name": "Test Org",
            },
        )
        assert resp.status_code != 403, (
            f"signup returned 403 — scope gate is still blocking unauthenticated users. "
            f"Body: {resp.text}"
        )
        assert resp.status_code in (201, 400, 409, 422, 429, 500), (
            f"Unexpected status {resp.status_code} from signup endpoint. Body: {resp.text}"
        )

    def test_forgot_password_reachable_without_token(self, client):
        """POST /api/v1/auth/forgot-password must be reachable without a token."""
        resp = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "nobody@example.com"},
        )
        assert resp.status_code != 403, (
            f"forgot-password returned 403 — scope gate still active. Body: {resp.text}"
        )
        assert resp.status_code in (200, 202, 400, 404, 422, 429, 500), (
            f"Unexpected status {resp.status_code}. Body: {resp.text}"
        )

    def test_reset_password_reachable_without_token(self, client):
        """POST /api/v1/auth/reset-password must be reachable without a token."""
        resp = client.post(
            "/api/v1/auth/reset-password",
            json={"token": "fake-reset-token", "new_password": "NewPassword123!"},
        )
        assert resp.status_code != 403, (
            f"reset-password returned 403 — scope gate still active. Body: {resp.text}"
        )
        assert resp.status_code in (200, 400, 404, 422, 429, 500), (
            f"Unexpected status {resp.status_code}. Body: {resp.text}"
        )

    def test_verify_email_reachable_without_token(self, client):
        """GET /api/v1/auth/verify-email must be reachable without a token."""
        resp = client.get("/api/v1/auth/verify-email", params={"token": "fake-token"})
        assert resp.status_code != 403, (
            f"verify-email returned 403 — scope gate still active. Body: {resp.text}"
        )
        assert resp.status_code in (200, 400, 404, 422, 429, 500), (
            f"Unexpected status {resp.status_code}. Body: {resp.text}"
        )

    def test_refresh_reachable_without_token(self, client):
        """POST /api/v1/auth/refresh with invalid refresh token → 400/401/422, not 403."""
        resp = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "fake-refresh-token"},
        )
        assert resp.status_code != 403, (
            f"refresh returned 403 — scope gate still active. Body: {resp.text}"
        )
        assert resp.status_code in (200, 400, 401, 422, 429, 500), (
            f"Unexpected status {resp.status_code}. Body: {resp.text}"
        )

    def test_refresh_is_rate_limited(self, client, monkeypatch):
        """Regression (2026-06-03): /refresh mints access tokens and is exempt from the
        global limiter, so it MUST have its own IP rate limit (auth:refresh, 30/min).
        Hammering well past the limit must yield at least one 429 — otherwise refresh
        tokens can be ground unbounded. (conftest disables rate-limiting globally; this
        test re-enables it like test_rate_limiting.py does.)"""
        monkeypatch.delenv("FIXOPS_DISABLE_RATE_LIMIT", raising=False)
        from apps.api import endpoint_rate_limit as _erl
        _erl._buckets.clear()  # clean rolling window for a deterministic count
        statuses = [
            client.post("/api/v1/auth/refresh",
                        json={"refresh_token": "grind-me"}).status_code
            for _ in range(45)
        ]
        assert 429 in statuses, (
            "No 429 after 45 rapid /refresh calls — the auth:refresh rate limit is "
            f"missing or not enforced. Statuses seen: {sorted(set(statuses))}"
        )


# ---------------------------------------------------------------------------
# PROTECTED endpoints — must still require auth
# ---------------------------------------------------------------------------

class TestProtectedAuthEndpoints:
    """Protected auth endpoints must still reject requests with no token."""

    def test_create_api_key_requires_auth(self, client):
        """POST /api/v1/auth/keys requires api_key_auth — returns 401/403 without token."""
        resp = client.post(
            "/api/v1/auth/keys",
            json={"name": "test-key", "user_id": "u1", "role": "viewer"},
        )
        assert resp.status_code in (401, 403), (
            f"Expected 401/403 for unauthenticated /auth/keys POST, got {resp.status_code}. "
            f"Body: {resp.text}"
        )

    def test_list_api_keys_requires_auth(self, client):
        """GET /api/v1/auth/keys requires api_key_auth — returns 401/403 without token."""
        resp = client.get("/api/v1/auth/keys")
        assert resp.status_code in (401, 403), (
            f"Expected 401/403 for unauthenticated /auth/keys GET, got {resp.status_code}. "
            f"Body: {resp.text}"
        )

    def test_mint_disposable_token_requires_auth(self, client):
        """POST /api/v1/auth/disposable-token requires api_key_auth."""
        resp = client.post(
            "/api/v1/auth/disposable-token",
            json={"user_id": "u1", "scopes": ["read:findings"], "ttl_seconds": 300},
        )
        assert resp.status_code in (401, 403), (
            f"Expected 401/403 for unauthenticated /auth/disposable-token POST, "
            f"got {resp.status_code}. Body: {resp.text}"
        )

    def test_role_view_requires_auth(self, client):
        """POST /api/v1/auth/role-view requires api_key_auth."""
        resp = client.post(
            "/api/v1/auth/role-view",
            json={"target_role": "admin"},
        )
        assert resp.status_code in (401, 403), (
            f"Expected 401/403 for unauthenticated /auth/role-view POST, "
            f"got {resp.status_code}. Body: {resp.text}"
        )

    def test_list_disposable_tokens_requires_auth(self, client):
        """GET /api/v1/auth/disposable-tokens requires api_key_auth."""
        resp = client.get("/api/v1/auth/disposable-tokens")
        assert resp.status_code in (401, 403), (
            f"Expected 401/403 for unauthenticated /auth/disposable-tokens GET, "
            f"got {resp.status_code}. Body: {resp.text}"
        )
