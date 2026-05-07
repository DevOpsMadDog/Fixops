"""
Smoke tests for Multica #4112 — Social OAuth2 endpoints.

Tests:
  1. POST /api/v1/auth/oauth/google/start  → 200, redirect_url contains accounts.google.com, state present
  2. GET  /api/v1/auth/oauth/github/callback → exchanges code, returns JWT pair (httpx mocked)

Run:
    python -m pytest tests/test_oauth_social_login.py -v --timeout=15
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure suite paths are on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

# ---------------------------------------------------------------------------
# Env vars — set before any import so modules see them
# ---------------------------------------------------------------------------
os.environ.setdefault("FIXOPS_OAUTH_GOOGLE_CLIENT_ID", "test-google-client-id")
os.environ.setdefault("FIXOPS_OAUTH_GOOGLE_CLIENT_SECRET", "test-google-client-secret")
os.environ.setdefault("FIXOPS_OAUTH_GITHUB_CLIENT_ID", "test-github-client-id")
os.environ.setdefault("FIXOPS_OAUTH_GITHUB_CLIENT_SECRET", "test-github-client-secret")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-for-oauth-smoke-tests-min32chars!!")
os.environ.setdefault("FIXOPS_MODE", "dev")

from fastapi.testclient import TestClient
from fastapi import FastAPI

# Import only the auth_router (not full create_app to keep test fast)
from apps.api.auth_router import router as auth_router

_app = FastAPI()
_app.include_router(auth_router)

_client = TestClient(_app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode_state(state: str) -> dict:
    """Decode the HMAC-signed state token produced by oauth_start."""
    padded = state + "=" * (-len(state) % 4)
    raw = base64.urlsafe_b64decode(padded).decode()
    parts = raw.split(":")
    assert len(parts) == 4, f"Unexpected state format: {raw!r}"
    provider, ts_str, nonce, sig = parts
    return {"provider": provider, "ts": int(ts_str), "nonce": nonce, "sig": sig}


def _make_valid_state(provider: str) -> str:
    """Construct a valid HMAC state for callback tests."""
    from apps.api.auth_router import _generate_state  # type: ignore[attr-defined]
    return _generate_state(provider)


# ---------------------------------------------------------------------------
# Test 1 — oauth/start returns redirect_url with correct provider URL + state
# ---------------------------------------------------------------------------

class TestOAuthStart:
    def test_google_start_returns_redirect_url(self):
        resp = _client.post("/api/v1/auth/oauth/google/start")
        assert resp.status_code == 200, resp.text
        body = resp.json()

        assert "redirect_url" in body
        assert "state" in body
        assert body["provider"] == "google"

        # Must point at Google's OAuth endpoint
        assert "accounts.google.com" in body["redirect_url"], (
            f"Expected Google auth URL, got: {body['redirect_url']}"
        )
        assert "client_id=test-google-client-id" in body["redirect_url"]
        assert "response_type=code" in body["redirect_url"]

        # State must be a valid HMAC token
        decoded = _decode_state(body["state"])
        assert decoded["provider"] == "google"
        assert abs(time.time() - decoded["ts"]) < 30, "State timestamp too far from now"

    def test_unsupported_provider_returns_400(self):
        resp = _client.post("/api/v1/auth/oauth/okta/start")
        assert resp.status_code == 400
        assert "unsupported provider" in resp.json()["detail"].lower()

    def test_unconfigured_provider_returns_503(self):
        # Remove env var temporarily
        backup = os.environ.pop("FIXOPS_OAUTH_GOOGLE_CLIENT_ID", None)
        try:
            resp = _client.post("/api/v1/auth/oauth/google/start")
            assert resp.status_code == 503
        finally:
            if backup is not None:
                os.environ["FIXOPS_OAUTH_GOOGLE_CLIENT_ID"] = backup


# ---------------------------------------------------------------------------
# Test 2 — oauth/callback exchanges code → returns JWT pair (httpx mocked)
# ---------------------------------------------------------------------------

class TestOAuthCallback:
    """Mock httpx.AsyncClient to avoid real network calls."""

    def _mock_httpx(self, provider: str, email: str = "alice@example.com") -> Any:
        """Build a context-manager-compatible httpx mock."""
        if provider == "github":
            userinfo = {"login": "alice", "email": email, "name": "Alice"}
            token_response = {"access_token": "gha_fake_token", "token_type": "bearer"}
        else:  # google
            userinfo = {"sub": "12345", "email": email, "name": "Alice"}
            token_response = {"access_token": "ya29.fake", "token_type": "bearer"}

        def _make_response(data: dict, status: int = 200):
            r = MagicMock()
            r.status_code = status
            r.json.return_value = data
            r.raise_for_status = MagicMock()
            return r

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=_make_response(token_response))
        mock_client.get = AsyncMock(return_value=_make_response(userinfo))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        return mock_client

    def _mock_user_db(self, email: str):
        """Minimal UserDB mock: always returns a fresh user object."""
        user = MagicMock()
        user.id = "user-oauth-001"
        user.email = email
        user.org_id = "default"
        user.role = MagicMock()
        user.role.value = "viewer"
        from core.user_models import UserStatus
        user.status = UserStatus.ACTIVE
        return user

    def test_github_callback_returns_jwt_pair(self):
        import jwt as pyjwt

        email = "alice@github.example.com"
        secret = os.environ["FIXOPS_JWT_SECRET"]

        # Build state token
        state = _make_valid_state("github")
        mock_client = self._mock_httpx("github", email=email)
        mock_user = self._mock_user_db(email)

        # _mint_token reads FIXOPS_JWT_SECRET via _get_login_jwt_secret().
        # Patch that function to always return our test secret so the
        # module-level import-time caching in auth_deps doesn't interfere.
        def _fake_get_login_jwt_secret():
            return secret

        with (
            patch("apps.api.auth_router._httpx.AsyncClient", return_value=mock_client),
            patch("apps.api.auth_router._user_db") as mock_db,
            patch("apps.api.auth_router._get_login_jwt_secret", _fake_get_login_jwt_secret),
        ):
            mock_db.get_user_by_email.return_value = mock_user

            resp = _client.get(
                "/api/v1/auth/oauth/github/callback",
                params={"code": "fake-github-code", "state": state},
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()

        assert "access_token" in body, f"Missing access_token: {body}"
        assert "refresh_token" in body, f"Missing refresh_token: {body}"
        assert body["token_type"] == "bearer"
        assert body["provider"] == "github"
        assert body["email"] == email
        assert body["expires_in"] > 0

        # Verify the access_token is a parseable JWT with correct claims
        claims = pyjwt.decode(
            body["access_token"],
            secret,
            algorithms=["HS256"],
            options={"require": ["exp", "iat", "sub"]},
        )
        assert claims["sub"] == "user-oauth-001"
        assert claims["email"] == email
        assert claims["oauth_provider"] == "github"
        assert claims["token_type"] == "access"

    def test_invalid_state_returns_400(self):
        resp = _client.get(
            "/api/v1/auth/oauth/google/callback",
            params={"code": "any-code", "state": "totally-invalid-state"},
        )
        assert resp.status_code == 400
        assert "state" in resp.json()["detail"].lower()
