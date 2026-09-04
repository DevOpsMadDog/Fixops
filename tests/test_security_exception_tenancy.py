"""A security exception is a signed-off waiver of a control.

All nine handlers took the org from the path with only api_key_auth —
authentication, not authorisation. Measured against the real app with a JWT from
a freshly-signed-up tenant, after seeding an exception titled
"victim-secret-exception" into "victim-corp":

    GET /api/v1/security-exceptions/victim-corp
      PRE   -> 200, response CONTAINS victim-secret-exception
      POST  -> 200, does not

Reading them is a map of which controls another company has knowingly waived and
why. Worse are the writes: /review approves a waiver in someone else's tenant
and /revoke cancels one. Both were reachable by any authenticated caller.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

VICTIM = "victim-corp"
SECRET = "victim-secret-exception"


@pytest.fixture(scope="module")
def client_and_token(tmp_path_factory):
    import os

    os.environ["FIXOPS_DATA_DIR"] = str(tmp_path_factory.mktemp("secexc"))
    os.environ["FIXOPS_BODY_TENANT_GUARD"] = "off"
    os.environ["FIXOPS_DISABLE_RATE_LIMIT"] = "1"

    from apps.api.security_exception_router import _get_engine
    from apps.api.app import create_app

    _get_engine().request_exception(VICTIM, {
        "title": SECRET, "description": "waiver", "requestor": "victim",
        "exception_type": "vulnerability", "risk_level": "high",
        "business_justification": "legacy system",
    })

    client = TestClient(create_app(), raise_server_exceptions=False)
    suffix = uuid.uuid4().hex[:8]
    email, password = f"se-{suffix}@example.com", "Aldeci-Demo-2026!x"
    client.post("/api/v1/auth/signup", json={
        "email": email, "password": password, "first_name": "S", "last_name": "E"})
    token = client.post("/api/v1/auth/login", json={
        "email": email, "password": password}).json().get("access_token", "")
    assert token
    return client, {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize("path", [
    f"/api/v1/security-exceptions/{VICTIM}",
    f"/api/v1/security-exceptions/{VICTIM}/stats",
    f"/api/v1/security-exceptions/{VICTIM}/expiring",
])
def test_no_endpoint_returns_another_tenants_waivers(path, client_and_token) -> None:
    client, headers = client_and_token
    response = client.get(path, headers=headers)
    assert SECRET not in response.text, f"{path} leaked another tenant's exceptions"


def test_every_handler_resolves_the_tenant() -> None:
    """api_key_auth authenticates; it does not authorise. Nine handlers had
    only that, so any valid credential reached any org."""
    import pathlib
    import re

    src = (
        pathlib.Path(__file__).resolve().parents[1]
        / "suite-api" / "apps" / "api" / "security_exception_router.py"
    ).read_text()
    unresolved = [
        m.group(1)
        for block in re.split(r"(?m)^@router\.", src)[1:]
        if (m := re.search(r"(?m)^(?:async )?def (\w+)\(", block))
        and re.search(r"org_id: str(?!\s*=\s*Depends)", block)
        and "resolve_tenant" not in block
    ]
    assert not unresolved, f"handlers take an org but never resolve it: {unresolved}"
