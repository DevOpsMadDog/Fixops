"""RBAC is the one place a cross-tenant write is unrecoverable.

Every handler here took org_id from the caller while also taking a credential.
Measured against the real app with a key pinned to "acme":

    POST /api/v1/rbac/assign  {"org_id": "victim-corp", "role": "org_admin"}
      -> 200, assignment stored in org "victim-corp"
    GET  /api/v1/rbac/org/victim-corp/users
      -> 200, victim-corp's role table returned

So one tenant could grant itself org_admin inside another tenant and then read
back who else holds power there. Not a data-exposure bug — a privilege one.

The list endpoint is the interesting shape: the org arrives as a PATH parameter,
which is the same trust problem as a body field wearing different clothes.
resolve_tenant is fed the path value the same way, so the credential wins
wherever the caller put it.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client_and_key(tmp_path_factory):
    import os

    os.environ["FIXOPS_DATA_DIR"] = str(tmp_path_factory.mktemp("rbac"))
    os.environ["FIXOPS_BODY_TENANT_GUARD"] = "off"  # the router must stand alone

    from core.key_manager import KeyManager
    from apps.api.app import create_app

    _, raw = KeyManager().create_key(
        user_id="u", name="acme", role="admin", org_id="acme"
    )
    return TestClient(create_app()), {"X-API-Key": raw}


def test_a_role_cannot_be_granted_into_another_tenant(client_and_key) -> None:
    client, headers = client_and_key
    response = client.post(
        "/api/v1/rbac/assign",
        headers=headers,
        json={"user_id": "u1", "role": "org_admin",
              "org_id": "victim-corp", "assigned_by": "x"},
    )
    assert response.status_code == 200, response.text[:300]
    assert response.json().get("org_id") == "acme", (
        "a role was granted inside the tenant the BODY named"
    )


def test_a_permission_check_is_answered_for_the_credentials_tenant(client_and_key) -> None:
    """Answering for another org leaks whether that org's user holds a scope."""
    client, headers = client_and_key
    response = client.post(
        "/api/v1/rbac/check",
        headers=headers,
        json={"user_id": "u1", "org_id": "victim-corp", "scope": "admin:all"},
    )
    assert response.status_code == 200
    assert response.json()["org_id"] == "acme"


def test_the_path_parameter_cannot_name_another_tenant(client_and_key) -> None:
    """The org in the URL is still a caller-supplied value."""
    client, headers = client_and_key
    response = client.get("/api/v1/rbac/org/victim-corp/users", headers=headers)
    assert response.status_code == 200
    assert response.json()["org_id"] == "acme", (
        "another tenant's role table was returned via the path parameter"
    )


def test_the_response_reports_the_tenant_actually_acted_on() -> None:
    """Echoing the REQUESTED org tells the caller a write happened somewhere it
    did not — and the audit log had the same flaw."""
    import pathlib

    src = (
        pathlib.Path(__file__).resolve().parents[1]
        / "suite-api" / "apps" / "api" / "rbac_router.py"
    ).read_text()
    assert "body.org_id" not in src, (
        "a handler still reports the caller-supplied org rather than the "
        "effective one"
    )
    assert "resolve_tenant" in src
