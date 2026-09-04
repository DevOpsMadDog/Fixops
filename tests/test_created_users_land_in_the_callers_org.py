"""A user you create must belong to your org, and be visible to you.

POST /api/v1/users built the User record without an org_id, so it fell to the
dataclass default of "default". list_users IS correctly org-scoped, so the
account a tenant admin had just created was invisible to them. Measured:

    CREATE                 201  (reported as success)
    stored org_id          "default"
    caller's org           org-368f45e1-3ded-4fa8-b1c8-5f4786a35ddb
    visible in GET /users  False

A broken feature and cross-tenant pollution at once — every tenant's
mis-assigned users piling into one shared org — and the API said 201 throughout.
Same omission as invite_org_user in org_router.
"""

from __future__ import annotations

import base64
import json
import uuid

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def tenant(tmp_path_factory):
    import os

    os.environ["FIXOPS_DATA_DIR"] = str(tmp_path_factory.mktemp("usersrt"))
    os.environ["FIXOPS_BODY_TENANT_GUARD"] = "off"

    from apps.api.app import create_app

    client = TestClient(create_app())
    suffix = uuid.uuid4().hex[:8]
    email, password = f"ur-{suffix}@example.com", "Aldeci-Demo-2026!x"
    client.post("/api/v1/auth/signup", json={
        "email": email, "password": password, "first_name": "U", "last_name": "R"})
    token = client.post("/api/v1/auth/login", json={
        "email": email, "password": password}).json().get("access_token", "")
    assert token
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "==="))
    return client, {"Authorization": f"Bearer {token}"}, claims["org_id"], suffix


def test_a_created_user_is_stored_in_the_callers_org(tenant) -> None:
    client, headers, org, suffix = tenant
    from core.user_db import UserDB

    email = f"created-{suffix}@example.com"
    response = client.post("/api/v1/users", headers=headers, json={
        "email": email, "first_name": "New", "last_name": "User",
        "password": "Aldeci-Demo-2026!x", "role": "viewer"})
    assert response.status_code == 201, response.text[:200]

    stored = UserDB().get_user_by_email(email)
    assert stored is not None
    assert getattr(stored, "org_id", None) == org, (
        f"created in {getattr(stored, 'org_id', None)!r}, caller is in {org!r}"
    )


def test_the_created_user_is_visible_to_its_creator(tenant) -> None:
    """The symptom a customer actually hits: 201, then the person is not there.

    Asserts the OUTCOME rather than the stored column — a fix that set org_id
    but broke the listing would pass the previous test alone.
    """
    client, headers, _org, suffix = tenant
    email = f"visible-{suffix}@example.com"
    client.post("/api/v1/users", headers=headers, json={
        "email": email, "first_name": "Vis", "last_name": "Ible",
        "password": "Aldeci-Demo-2026!x", "role": "viewer"})

    body = client.get("/api/v1/users", headers=headers).json()
    items = body.get("users") or body.get("items") or []
    assert email in [u.get("email") for u in items], (
        "the user was created successfully and does not appear in the org's list"
    )
