"""Tests for RBAC enforcement via require_role dependency.

Uses a minimal FastAPI test app (not create_app) to avoid optional-dependency
import failures. Mirrors the pattern in test_api_auth.py.

Verifies that:
  - Admin API key (user_role='admin') passes admin-only routes.
  - JWT with viewer role is blocked (403) on admin-only routes.
  - JWT with analyst role is allowed on analyst-only routes.
  - JWT with viewer role is blocked (403) on analyst-only routes.
  - Missing credentials return 401 (auth fires before role check).
  - 403 response body contains 'not permitted' detail.
  - security_engineer is allowed on analyst-only routes.
  - org_admin is allowed on admin-only routes.
"""
from __future__ import annotations

import os
import sys

# sitecustomize.py handles path setup at Python startup, but add fallback for
# environments where it hasn't run (e.g. isolated test runs).
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _d in ("suite-api", "suite-core"):
    _p = os.path.join(_ROOT, _d)
    if _p not in sys.path:
        sys.path.insert(0, _p)

import pytest

# ── optional dependency guards (same pattern as test_api_auth.py) ─────────
try:
    import jwt as _pyjwt
    _JWT_OK = True
except Exception:
    _JWT_OK = False

try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    _FASTAPI_OK = True
except Exception:
    _FASTAPI_OK = False

try:
    from apps.api.auth_deps import api_key_auth, require_role
    _AUTH_DEPS_OK = True
except Exception:
    _AUTH_DEPS_OK = False

_DEPS_OK = _JWT_OK and _FASTAPI_OK and _AUTH_DEPS_OK

_SKIP = pytest.mark.skipif(not _DEPS_OK, reason="FastAPI/JWT/auth_deps not available")

# ── test constants ────────────────────────────────────────────────────────
_API_TOKEN = "rbac-test-token-xyz"
_JWT_SECRET = "test-jwt-secret-long-enough-32chars-ok"  # >= 32 chars


def _make_jwt(role: str) -> str:
    """Mint a minimal valid JWT with the given role claim."""
    import time
    now = int(time.time())
    return _pyjwt.encode(
        {"sub": f"u-{role}", "iat": now, "exp": now + 3600, "role": role, "scopes": []},
        _JWT_SECRET,
        algorithm="HS256",
    )


def _make_test_app():
    """Build a minimal FastAPI app with two guarded routes for testing require_role."""
    from fastapi import FastAPI

    app = FastAPI()

    _ADMIN = ("admin", "org_admin", "super_admin")
    _ANALYST = ("admin", "super_admin", "org_admin", "security_engineer", "analyst")

    @app.get("/admin-only", dependencies=[require_role(*_ADMIN)])
    def admin_only():
        return {"ok": True}

    @app.get("/analyst-only", dependencies=[require_role(*_ANALYST)])
    def analyst_only():
        return {"ok": True}

    return app


# ── fixture ───────────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def client():
    if not _DEPS_OK:
        pytest.skip("deps not available")

    monkeypatch_env = {
        "FIXOPS_API_TOKEN": _API_TOKEN,
        "FIXOPS_JWT_SECRET": _JWT_SECRET,
        "FIXOPS_MODE": "",
    }
    orig = {k: os.environ.get(k) for k in monkeypatch_env}
    for k, v in monkeypatch_env.items():
        os.environ[k] = v

    # Force auth_deps to reload its module-level cached config
    import importlib
    import apps.api.auth_deps as _auth_mod
    importlib.reload(_auth_mod)

    app = _make_test_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c

    for k, v in orig.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


# ── Test 1: Admin API key passes admin-only route ─────────────────────────
@_SKIP
def test_admin_key_allowed_on_admin_route(client):
    """API key → user_role='admin' → must pass require_role on admin routes."""
    resp = client.get("/admin-only", headers={"X-API-Key": _API_TOKEN})
    assert resp.status_code == 200, f"Admin API key blocked: {resp.status_code} {resp.text}"


# ── Test 2: Viewer JWT blocked on admin-only route → 403 ──────────────────
@_SKIP
def test_viewer_jwt_blocked_on_admin_route(client):
    """viewer role must be denied on admin routes with 403."""
    resp = client.get("/admin-only", headers={"Authorization": f"Bearer {_make_jwt('viewer')}"})
    assert resp.status_code == 403, f"Expected 403 for viewer on admin, got {resp.status_code}: {resp.text}"


# ── Test 3: Analyst JWT allowed on analyst-only route ─────────────────────
@_SKIP
def test_analyst_jwt_allowed_on_analyst_route(client):
    """analyst role must pass require_role on analyst-only routes."""
    resp = client.get("/analyst-only", headers={"Authorization": f"Bearer {_make_jwt('analyst')}"})
    assert resp.status_code == 200, f"Analyst blocked: {resp.status_code} {resp.text}"


# ── Test 4: Viewer JWT blocked on analyst-only route → 403 ────────────────
@_SKIP
def test_viewer_jwt_blocked_on_analyst_route(client):
    """viewer role must be denied on analyst-only routes with 403."""
    resp = client.get("/analyst-only", headers={"Authorization": f"Bearer {_make_jwt('viewer')}"})
    assert resp.status_code == 403, f"Expected 403 for viewer on analyst, got {resp.status_code}: {resp.text}"


# ── Test 5: 403 detail contains 'not permitted' ────────────────────────────
@_SKIP
def test_403_detail_is_human_readable(client):
    """403 response must include 'not permitted' in detail."""
    resp = client.get("/admin-only", headers={"Authorization": f"Bearer {_make_jwt('viewer')}"})
    assert resp.status_code == 403
    body = resp.json()
    assert "detail" in body
    assert "not permitted" in body["detail"].lower(), f"Got: {body['detail']!r}"


# ── Test 6: Missing credentials → 401 not 403 ────────────────────────────
@_SKIP
def test_missing_credentials_returns_401(client):
    """No credentials → 401 (auth fires before role check)."""
    resp = client.get("/admin-only")
    assert resp.status_code == 401, f"Expected 401 for no creds, got {resp.status_code}: {resp.text}"


# ── Test 7: security_engineer allowed on analyst-only route ───────────────
@_SKIP
def test_security_engineer_allowed_on_analyst_route(client):
    """security_engineer must pass on analyst-only routes."""
    resp = client.get("/analyst-only", headers={"Authorization": f"Bearer {_make_jwt('security_engineer')}"})
    assert resp.status_code == 200, f"security_engineer blocked: {resp.status_code} {resp.text}"


# ── Test 8: org_admin allowed on admin-only route ────────────────────────
@_SKIP
def test_org_admin_allowed_on_admin_route(client):
    """org_admin role must pass on admin-only routes."""
    resp = client.get("/admin-only", headers={"Authorization": f"Bearer {_make_jwt('org_admin')}"})
    assert resp.status_code == 200, f"org_admin blocked: {resp.status_code} {resp.text}"
