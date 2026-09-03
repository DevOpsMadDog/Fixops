"""Org administration was addressed entirely by URL, not by credential.

Nine handlers took the org from the path. Measured against the real app with a
key pinned to "acme", a victim user seeded into "victim-corp":

  PRE   GET    /api/v1/orgs/victim-corp/users        -> 200, victim's users listed
        DELETE /api/v1/orgs/victim-corp/users/{uid}  -> 200, USER ACTUALLY DELETED
        DELETE /api/v1/orgs/victim-corp              -> targeted victim-corp

  POST  list   -> 200, org "acme", zero victim users
        delete -> 404, victim user still present
        delete org -> targets "acme"

The user endpoints were worse than a path leak. list_org_users called
UserDB.list_users() with NO org filter and returned every user in the shared
database — its own docstring said so ("org_id used as namespace tag; returns
all users"). The filter existed and failed closed; the router never passed it.
The role-update and remove handlers looked users up by id GLOBALLY, so the org
in the path was decoration: echoed into the response, never checked against the
user being modified or deleted.

And invite_org_user never persisted the org at all — it echoed it in the
response while creating the user with the dataclass default. Every invited user
landed in "default", which once list_users is org-filtered makes them invisible
to the org that invited them.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    import os

    os.environ["FIXOPS_DATA_DIR"] = str(tmp_path_factory.mktemp("orgrt"))
    os.environ["FIXOPS_BODY_TENANT_GUARD"] = "off"

    from core.key_manager import KeyManager
    from core.user_db import UserDB
    from core.user_models import User, UserRole, UserStatus
    from apps.api.app import create_app

    suffix = uuid.uuid4().hex[:8]
    udb = UserDB()
    victim = udb.create_user(
        User(id="", email=f"victim-{suffix}@victim-corp.test",
             password_hash=udb.hash_password("x"), first_name="V", last_name="I",
             role=UserRole.VIEWER, status=UserStatus.ACTIVE, department=None,
             org_id="victim-corp")
    )
    _, raw = KeyManager().create_key(
        user_id="u", name=f"acme-{suffix}", role="admin", org_id="acme"
    )
    return TestClient(create_app()), {"X-API-Key": raw}, victim, udb


def test_listing_users_is_scoped_to_the_credentials_org(env) -> None:
    client, headers, victim, _ = env
    response = client.get("/api/v1/orgs/victim-corp/users", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["org_id"] == "acme"
    emails = [u.get("email", "") for u in body.get("items", [])]
    assert victim.email not in emails, "another tenant's users were listed"


def test_a_user_in_another_tenant_cannot_be_deleted(env) -> None:
    """The destructive one. Pre-fix this returned 200 and the user was gone."""
    client, headers, victim, udb = env
    response = client.delete(
        f"/api/v1/orgs/victim-corp/users/{victim.id}", headers=headers
    )
    assert response.status_code == 404, response.text[:200]
    assert udb.get_user(victim.id) is not None, "another tenant's user was deleted"


def test_a_user_in_another_tenant_cannot_be_promoted(env) -> None:
    client, headers, victim, udb = env
    response = client.put(
        f"/api/v1/orgs/victim-corp/users/{victim.id}",
        headers=headers, json={"role": "admin"},
    )
    assert response.status_code == 404
    assert udb.get_user(victim.id).role.value != "admin"


def test_an_invited_user_is_created_in_the_credentials_org(env) -> None:
    """The org was echoed in the response and never stored, so invited users
    landed in "default" — invisible to the org that invited them."""
    client, headers, _victim, udb = env
    # NOT a .test domain: EmailStr rejects special-use TLDs, and a 422 here
    # would look like a tenancy failure when it is only a bad fixture.
    email = f"invitee-{uuid.uuid4().hex[:8]}@example.com"
    response = client.post(
        "/api/v1/orgs/victim-corp/users", headers=headers,
        json={"email": email, "first_name": "A", "last_name": "B", "role": "viewer"},
    )
    assert response.status_code == 201, response.text[:250]
    assert response.json()["org_id"] == "acme"
    created = udb.get_user_by_email(email)
    assert created is not None
    assert getattr(created, "org_id", None) == "acme", (
        "the invited user was not persisted into the credential's org"
    )


def test_every_handler_taking_a_credential_actually_resolves_it() -> None:
    """Three handlers received the credential parameter but never called
    resolve_tenant — including delete_org, the most destructive one. A
    signature change that looks like a fix is not a fix."""
    import pathlib
    import re

    src = (
        pathlib.Path(__file__).resolve().parents[1]
        / "suite-api" / "apps" / "api" / "org_router.py"
    ).read_text()
    unresolved = [
        m.group(1)
        for block in re.split(r"(?m)^@router\.", src)[1:]
        if (m := re.search(r"def (\w+)\(", block))
        and "credential_org" in block
        and "resolve_tenant" not in block
    ]
    assert not unresolved, f"handlers take a credential but ignore it: {unresolved}"
