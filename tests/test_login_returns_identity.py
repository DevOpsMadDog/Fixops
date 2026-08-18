"""Signing in must tell the client who it signed in as.

Two defects, one shape — the client was left to guess its own identity, and
guessed differently from what the API enforces.

1. ``POST /api/v1/auth/login`` returned only tokens. The UI does
   ``const userData = data.user as AuthUser`` immediately afterwards, so it got
   ``undefined``: ``persistUser(undefined)`` CLEARS the stored user, while
   ``isAuthenticated = user !== null`` stays true. You were logged in, and
   ``hasRole()`` / ``hasScope()`` answered false for everything — every
   role-gated screen rendered empty with no error anywhere.

2. The API-key path never asked at all. It probed ``/api/v1/orgs`` for liveness
   and then hardcoded ``role: "admin"``. A viewer-scoped key rendered the full
   admin surface, and every privileged control on it 403'd on use.

Both are the recurring defect class: each side correct on its own, and the join
between them a lie. The fix is that the server answers, and the answer matches
the token the server will enforce.
"""

from __future__ import annotations

import uuid

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

TOKEN = "identity-test-token"
JWT_SECRET = "identity-test-jwt-secret-long-enough-for-validation-0123456789"


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("FIXOPS_API_TOKEN", TOKEN)
    monkeypatch.setenv("FIXOPS_JWT_SECRET", JWT_SECRET)
    monkeypatch.setenv("FIXOPS_MODE", "enterprise")

    from apps.api.auth_router import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


@pytest.fixture()
def account(client):
    """A real account, created through the real signup endpoint."""
    email = f"identity-{uuid.uuid4().hex[:12]}@probe.example"
    password = "IdentityProbe123"
    resp = client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": password, "first_name": "Iden", "last_name": "Tity"},
    )
    assert resp.status_code in (200, 201), resp.text
    return {"email": email, "password": password, "signup": resp.json()}


def test_login_returns_the_user_it_signed_in(client, account) -> None:
    """The whole first defect in one assertion."""
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": account["email"], "password": account["password"]},
    )
    assert resp.status_code == 200, resp.text
    user = resp.json().get("user")

    assert user, "login returned no user — the UI logs into an empty product"
    assert user.get("role"), "no role — hasRole()/hasScope() answer false for everything"
    assert user.get("email") == account["email"]


def test_ui_identity_matches_the_token_the_api_enforces(client, account) -> None:
    """A second, drifting copy of the role is worse than none."""
    body = client.post(
        "/api/v1/auth/login",
        json={"email": account["email"], "password": account["password"]},
    ).json()

    claims = jwt.decode(body["access_token"], options={"verify_signature": False})

    assert claims["role"] == body["user"]["role"], "UI would gate on a different role than the API enforces"
    assert claims["scopes"] == body["user"]["scopes"], "scope drift between token and UI"


def test_whoami_answers_for_an_api_key(client) -> None:
    """The API-key path needs a server-supplied identity, not a hardcoded one."""
    resp = client.get("/api/v1/auth/me", headers={"X-API-Key": TOKEN})
    assert resp.status_code == 200, resp.text

    me = resp.json()
    assert me["role"], "no role — the client would have to invent one again"
    assert me["scopes"], "no scopes"


def test_whoami_does_not_dress_a_service_credential_up_as_a_person(client) -> None:
    """Absence is a fact worth stating. A token is not a user."""
    me = client.get("/api/v1/auth/me", headers={"X-API-Key": TOKEN}).json()

    assert me["id"] == "service-credential"
    assert me["email"] == "", "a service credential must not be given an invented email"


def test_whoami_leaks_nothing_without_a_credential(client) -> None:
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code in (401, 403), f"identity endpoint answered {resp.status_code} unauthenticated"


def test_whoami_reports_the_logged_in_user_for_a_jwt(client, account) -> None:
    """The same endpoint has to serve both credential kinds, or the UI forks."""
    token = client.post(
        "/api/v1/auth/login",
        json={"email": account["email"], "password": account["password"]},
    ).json()["access_token"]

    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["email"] == account["email"]
