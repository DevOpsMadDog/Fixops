"""Tests for OAuth2 client credentials token endpoint.

POST /api/v1/oauth2/token

Covers:
  1. Valid client_id + client_secret → 200 with JWT
  2. Wrong client_secret → 401 invalid_client
  3. Mismatched client_id (valid secret, wrong id) → 401 invalid_client
  4. Unsupported grant_type → 400 unsupported_grant_type
  5. JWT is accepted by api_key_auth (Bearer round-trip)
"""
from __future__ import annotations

import os
import tempfile
import time

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ── Fixtures ────────────────────────────────────────────────────────────────

JWT_SECRET = "test-secret-at-least-32-characters-long!!"


@pytest.fixture(autouse=True)
def _set_env(monkeypatch, tmp_path):
    """Inject required env vars and isolate DB to a temp dir."""
    monkeypatch.setenv("FIXOPS_JWT_SECRET", JWT_SECRET)
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FIXOPS_MODE", "")  # disable dev-mode pass-through


@pytest.fixture()
def app_client(_set_env):
    """Build a minimal FastAPI app with just the OAuth2 router mounted."""
    from apps.api.oauth2_router import router as oauth2_router
    from apps.api.auth_deps import api_key_auth
    from fastapi import Depends

    application = FastAPI()
    application.include_router(oauth2_router)

    # Protected probe endpoint to verify JWT round-trip (test 5)
    @application.get("/probe", dependencies=[Depends(api_key_auth)])
    def probe():
        return {"ok": True}

    return TestClient(application, raise_server_exceptions=True)


@pytest.fixture()
def client_credentials(tmp_path, monkeypatch):
    """Create a real API key and return (client_id, client_secret)."""
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))

    # Import after env is set so the manager picks up the correct DB path
    from core.api_key_manager import APIKeyManager, get_api_key_manager
    from core.rbac import RBACRole

    # Force fresh instance for this test's temp dir
    mgr = APIKeyManager(db_path=str(tmp_path / "api_keys.db"))
    key_record, raw_key = mgr.create_key(
        name="ci-test",
        org_id="test-org",
        role=RBACRole.ADMIN,
        scopes=["read:findings", "write:findings"],
    )
    return key_record.id, raw_key, mgr


# ── Tests ────────────────────────────────────────────────────────────────────


def test_valid_credentials_returns_jwt(app_client, client_credentials, monkeypatch, tmp_path):
    """Test 1: valid client_id + client_secret → 200 with signed JWT."""
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))

    client_id, client_secret, mgr = client_credentials

    # Patch the router's APIKeyManager to use the test DB instance
    import apps.api.oauth2_router as oauth2_mod
    monkeypatch.setattr(oauth2_mod, "APIKeyManager", lambda: mgr)

    resp = app_client.post(
        "/api/v1/oauth2/token",
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 1800
    assert "access_token" in body

    # Verify JWT structure
    claims = jwt.decode(body["access_token"], JWT_SECRET, algorithms=["HS256"])
    assert claims["sub"] == client_id
    assert claims["iss"] == "aldeci/oauth2"
    assert claims["org_id"] == "test-org"
    assert claims["role"] == "admin"
    assert "read:findings" in claims["scopes"]
    # Expiry is ~30 min from now
    assert claims["exp"] - claims["iat"] == 1800


def test_wrong_client_secret_returns_401(app_client, client_credentials, monkeypatch, tmp_path):
    """Test 2: wrong client_secret → 401 invalid_client."""
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    client_id, _correct_secret, mgr = client_credentials

    import apps.api.oauth2_router as oauth2_mod
    monkeypatch.setattr(oauth2_mod, "APIKeyManager", lambda: mgr)

    resp = app_client.post(
        "/api/v1/oauth2/token",
        data={
            "client_id": client_id,
            "client_secret": "aldeci_definitely_wrong_secret_000000",
            "grant_type": "client_credentials",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid_client"


def test_mismatched_client_id_returns_401(app_client, client_credentials, monkeypatch, tmp_path):
    """Test 3: valid secret but wrong client_id → 401 invalid_client."""
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    _correct_id, client_secret, mgr = client_credentials

    import apps.api.oauth2_router as oauth2_mod
    monkeypatch.setattr(oauth2_mod, "APIKeyManager", lambda: mgr)

    resp = app_client.post(
        "/api/v1/oauth2/token",
        data={
            "client_id": "ak_wrongidwrongid",
            "client_secret": client_secret,
            "grant_type": "client_credentials",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid_client"


def test_unsupported_grant_type_returns_400(app_client, client_credentials, monkeypatch, tmp_path):
    """Test 4: grant_type=password → 400 unsupported_grant_type."""
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    client_id, client_secret, mgr = client_credentials

    import apps.api.oauth2_router as oauth2_mod
    monkeypatch.setattr(oauth2_mod, "APIKeyManager", lambda: mgr)

    resp = app_client.post(
        "/api/v1/oauth2/token",
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "password",
        },
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "unsupported_grant_type"


def test_jwt_accepted_by_auth_middleware(app_client, client_credentials, monkeypatch, tmp_path):
    """Test 5: JWT from /token is accepted as Bearer by api_key_auth."""
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    # Also set FIXOPS_JWT_SECRET so auth_deps picks it up (already set by autouse fixture)
    client_id, client_secret, mgr = client_credentials

    import apps.api.oauth2_router as oauth2_mod
    monkeypatch.setattr(oauth2_mod, "APIKeyManager", lambda: mgr)

    # Get token
    token_resp = app_client.post(
        "/api/v1/oauth2/token",
        data={
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )
    assert token_resp.status_code == 200
    access_token = token_resp.json()["access_token"]

    # Use it on the protected probe endpoint
    probe_resp = app_client.get(
        "/probe",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert probe_resp.status_code == 200
    assert probe_resp.json() == {"ok": True}
