"""Which tenant you land in must not depend on which credential you used.

Signup derives a per-user org (``org-<user_id>``) and mints an org-scoped API
key against it. The users table had no ``org_id`` column, so that org existed
only on the key. Login read ``getattr(user, "org_id", "default")``, got
"default" every time, and issued a JWT for the shared default tenant.

The same account therefore resolved to two different tenants:
  * by API key   -> org-<user_id>   (its own data)
  * by password  -> default         (the shared tenant's data)

``list_users(org_id=...)`` made it worse. It checked for the column, logged
"org_id column missing", and then returned every user in every org — the caller
asked to be scoped and silently got the lot. Defensive code that degrades into
the exact failure it is defending against.
"""

from __future__ import annotations

import uuid

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

JWT_SECRET = "org-isolation-test-secret-long-enough-for-validation-0123456789"


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("FIXOPS_API_TOKEN", "org-isolation-token")
    monkeypatch.setenv("FIXOPS_JWT_SECRET", JWT_SECRET)
    monkeypatch.setenv("FIXOPS_MODE", "enterprise")

    from apps.api.auth_router import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _account(client):
    email = f"orgiso-{uuid.uuid4().hex[:12]}@probe.example"
    password = "OrgIsolation123"
    signup = client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": password, "first_name": "Org", "last_name": "Iso"},
    )
    assert signup.status_code in (200, 201), signup.text
    login = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200, login.text
    return email, signup.json(), login.json()


def test_password_login_lands_in_the_org_signup_created(client) -> None:
    """The whole defect in one assertion."""
    _, signup, login = _account(client)
    claims = jwt.decode(login["access_token"], options={"verify_signature": False})

    assert claims["org_id"] == signup["org_id"], (
        "password login issued a token for a different tenant than signup created"
    )


def test_the_org_reaches_the_ui_identity_too(client) -> None:
    _, signup, login = _account(client)
    assert login["user"]["org_id"] == signup["org_id"]


def test_two_signups_are_not_the_same_tenant(client) -> None:
    _, signup_a, _ = _account(client)
    _, signup_b, _ = _account(client)
    assert signup_a["org_id"] != signup_b["org_id"]


def test_listing_users_for_one_org_does_not_return_another_orgs_users(client) -> None:
    email_a, signup_a, _ = _account(client)
    email_b, _, _ = _account(client)

    from core.user_db import UserDB

    listed = {u.email for u in UserDB().list_users(org_id=signup_a["org_id"])}

    assert email_a in listed
    assert email_b not in listed, "cross-tenant user leak"


def test_a_scoped_query_never_silently_returns_every_tenant(monkeypatch, tmp_path) -> None:
    """Fail closed. The old code logged a warning and returned everything."""
    import sqlite3

    from core.user_db import UserDB

    db_path = tmp_path / "legacy_users.db"
    conn = sqlite3.connect(db_path)
    # A pre-tenancy schema: no org_id column, and no migration will run because
    # we bypass _init_tables by pointing at an already-created table.
    conn.executescript(
        """
        CREATE TABLE users (
            id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            first_name TEXT NOT NULL, last_name TEXT NOT NULL, role TEXT NOT NULL,
            status TEXT NOT NULL, department TEXT, created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL, last_login_at TEXT
        );
        """
    )
    conn.commit()
    conn.close()

    db = UserDB.__new__(UserDB)          # skip __init__ so the migration cannot run
    db.db_path = str(db_path)

    with pytest.raises(RuntimeError, match="org_id"):
        db.list_users(org_id="some-org")

    with pytest.raises(RuntimeError, match="org_id"):
        db.count_users(org_id="some-org")


def test_an_unscoped_list_is_still_allowed(client) -> None:
    """Fail-closed applies to SCOPED queries; admin-wide listing is legitimate."""
    from core.user_db import UserDB

    assert isinstance(UserDB().list_users(), list)
