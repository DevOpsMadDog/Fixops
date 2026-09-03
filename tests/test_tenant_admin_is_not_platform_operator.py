"""A tenant admin is not a platform operator, and the guard read the wrong org.

Two defects compounding:

1. Self-service signup makes the first user of an org an admin so they can
   administer THEIR org — and that role carries `admin:all`, a globally-scoped
   permission. Measured on a freshly-signed-up account: scopes ['admin:all'].
   Every guard reading admin:all inherited a cross-tenant bypass from an
   org-scoped role.

2. The guards resolved the caller's org from get_current_org_id(), a contextvar
   set by OrgIdMiddleware — which runs BEFORE the auth dependency that reads the
   JWT. Measured inside the guard, on a request from org-1bfc06f2…:

       get_current_org_id() -> 'default'
       request.state.org_id -> 'org-1bfc06f2-5026-4a10-8868-fd4cb8156c5c'

   So every JWT caller looked like the unpinned operator, and the "own org"
   comparison was matching 'default' against a real org id and never succeeding.
   The admin:all bypass was the only reason those endpoints answered at all.

Measured end to end, signed-up user against another tenant:

    PRE   GET    /api/v1/tenants/victim-corp/stats -> 200 (data dir returned)
          DELETE /api/v1/tenants/victim-corp       -> authorisation passed
    POST  both -> 403, own tenant still 200
"""

from __future__ import annotations

import base64
import json
import uuid

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def signed_up(tmp_path_factory):
    import os

    os.environ["FIXOPS_DATA_DIR"] = str(tmp_path_factory.mktemp("tenantadmin"))
    os.environ["FIXOPS_BODY_TENANT_GUARD"] = "off"

    from apps.api.app import create_app

    client = TestClient(create_app())
    suffix = uuid.uuid4().hex[:8]
    email, password = f"ta-{suffix}@example.com", "Aldeci-Demo-2026!x"
    client.post("/api/v1/auth/signup", json={
        "email": email, "password": password, "first_name": "T", "last_name": "A"})
    token = client.post("/api/v1/auth/login", json={
        "email": email, "password": password}).json().get("access_token", "")
    assert token
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "==="))
    return client, {"Authorization": f"Bearer {token}"}, claims


def test_signup_still_grants_admin_all(signed_up) -> None:
    """Pinning the PREMISE, not endorsing it.

    If signup ever stops issuing admin:all this test fails loudly, and whoever
    changed it should re-read the guards that assume a tenant admin holds it.
    """
    _client, _headers, claims = signed_up
    assert "admin:all" in (claims.get("scopes") or [])


def test_a_tenant_admin_cannot_read_another_tenant(signed_up) -> None:
    client, headers, _claims = signed_up
    response = client.get("/api/v1/tenants/victim-corp/stats", headers=headers)
    assert response.status_code == 403, (
        f"a tenant admin read another tenant's stats (HTTP {response.status_code})"
    )


def test_a_tenant_admin_cannot_delete_another_tenant(signed_up) -> None:
    """The irreversible one."""
    client, headers, _claims = signed_up
    response = client.request("DELETE", "/api/v1/tenants/victim-corp", headers=headers)
    assert response.status_code == 403


def test_a_tenant_admin_can_still_reach_its_own_org(signed_up) -> None:
    """The fix must not lock a customer out of their own tenant — the "own org"
    branch was broken too, comparing 'default' against a real org id."""
    client, headers, claims = signed_up
    own = claims.get("org_id")
    response = client.get(f"/api/v1/tenants/{own}/stats", headers=headers)
    assert response.status_code == 200, (
        f"a tenant admin lost access to its OWN org (HTTP {response.status_code})"
    )
