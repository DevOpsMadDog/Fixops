"""Compliance controls were addressed by URL, not by credential.

Ten handlers took the org from the path. Measured against the real app with a
JWT belonging to a freshly-created tenant, after seeding a control named
"victim-secret-control" into "victim-corp":

    GET /api/v1/ccm/orgs/victim-corp/controls
      PRE   -> 200, response CONTAINS victim-secret-control
      POST  -> 200, does not

The test asserts the leaked CONTENT, not the status code: these endpoints return
200 either way, so a status check would have passed against the vulnerable
build. That is the same trap as "root returns 200" standing in for a UI check.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

VICTIM = "victim-corp"
SECRET = "victim-secret-control"


@pytest.fixture(scope="module")
def client_and_token(tmp_path_factory):
    import os

    os.environ["FIXOPS_DATA_DIR"] = str(tmp_path_factory.mktemp("ccm"))
    os.environ["FIXOPS_BODY_TENANT_GUARD"] = "off"

    from apps.api.ccm_router import get_engine
    from apps.api.app import create_app

    get_engine().register_control(VICTIM, {
        "control_id": "VICTIM-AC-1", "control_name": SECRET, "name": SECRET,
        "framework": "SOC2", "owner": "victim", "control_type": "detective",
        "frequency": "monthly",
    })

    client = TestClient(create_app())
    suffix = uuid.uuid4().hex[:8]
    email, password = f"ccm-{suffix}@example.com", "Aldeci-Demo-2026!x"
    client.post("/api/v1/auth/signup", json={
        "email": email, "password": password, "first_name": "C", "last_name": "M"})
    token = client.post("/api/v1/auth/login", json={
        "email": email, "password": password}).json().get("access_token", "")
    assert token, "login did not return a token"
    return client, {"Authorization": f"Bearer {token}"}


def test_another_tenants_controls_are_not_returned(client_and_token) -> None:
    client, headers = client_and_token
    response = client.get(f"/api/v1/ccm/orgs/{VICTIM}/controls", headers=headers)
    assert response.status_code == 200
    assert SECRET not in response.text, (
        "another tenant's compliance controls were returned"
    )


def test_coverage_and_stats_do_not_leak_either(client_and_token) -> None:
    client, headers = client_and_token
    for path in (f"/api/v1/ccm/orgs/{VICTIM}/coverage",
                 f"/api/v1/ccm/orgs/{VICTIM}/stats"):
        response = client.get(path, headers=headers)
        assert SECRET not in response.text, f"{path} leaked another tenant's data"


def test_every_handler_with_an_org_resolves_it() -> None:
    """Four handlers were missed on the first pass because their signatures
    spanned several lines and did not match the shape I patched."""
    import pathlib
    import re

    src = (
        pathlib.Path(__file__).resolve().parents[1]
        / "suite-api" / "apps" / "api" / "ccm_router.py"
    ).read_text()
    unresolved = [
        m.group(1)
        for block in re.split(r"(?m)^@router\.", src)[1:]
        if (m := re.search(r"def (\w+)\(", block))
        and "org_id" in block
        and "resolve_tenant" not in block
    ]
    assert not unresolved, f"handlers take an org but never resolve it: {unresolved}"
