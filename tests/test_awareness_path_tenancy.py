"""Employee records are PII, and they were addressed by URL.

Nine handlers took the org from the path. Measured against the real app with a
JWT belonging to a freshly-signed-up tenant, after seeding an employee named
"victim-secret-employee" (Finance, controller) into "victim-corp":

    GET /api/v1/awareness-score/orgs/victim-corp/employees
      PRE   -> 200, response CONTAINS the victim's name, department and role
      POST  -> 200, does not

Names, departments, roles and phishing-test results for another company's staff.
A phishing-susceptibility score is also a targeting list: it says which employee
to send the next lure to.

Asserted on CONTENT, not status — these return 200 either way.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

VICTIM = "victim-corp"
SECRET = "victim-secret-employee"


@pytest.fixture(scope="module")
def client_and_token(tmp_path_factory):
    import os

    os.environ["FIXOPS_DATA_DIR"] = str(tmp_path_factory.mktemp("aware"))
    os.environ["FIXOPS_BODY_TENANT_GUARD"] = "off"

    from apps.api.awareness_score_router import get_engine
    from apps.api.app import create_app

    get_engine().register_employee(VICTIM, {
        "employee_id": "VIC-1", "name": SECRET, "department": "Finance",
        "role": "controller", "email": "vic@example.com",
    })

    client = TestClient(create_app())
    suffix = uuid.uuid4().hex[:8]
    email, password = f"aware-{suffix}@example.com", "Aldeci-Demo-2026!x"
    client.post("/api/v1/auth/signup", json={
        "email": email, "password": password, "first_name": "A", "last_name": "W"})
    token = client.post("/api/v1/auth/login", json={
        "email": email, "password": password}).json().get("access_token", "")
    assert token
    return client, {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize("path", [
    f"/api/v1/awareness-score/orgs/{VICTIM}/employees",
    f"/api/v1/awareness-score/orgs/{VICTIM}/scores",
    f"/api/v1/awareness-score/orgs/{VICTIM}/department-summary",
    f"/api/v1/awareness-score/orgs/{VICTIM}/stats",
    f"/api/v1/awareness-score/orgs/{VICTIM}/risk-trend",
])
def test_no_endpoint_returns_another_tenants_employee_data(path, client_and_token) -> None:
    client, headers = client_and_token
    response = client.get(path, headers=headers)
    assert SECRET not in response.text, f"{path} leaked another tenant's PII"


def test_every_handler_with_an_org_resolves_it() -> None:
    """get_risk_trend was missed on the first pass — its signature did not match
    the shape the other eight shared. The scan is the guard, not the patch."""
    import pathlib
    import re

    src = (
        pathlib.Path(__file__).resolve().parents[1]
        / "suite-api" / "apps" / "api" / "awareness_score_router.py"
    ).read_text()
    unresolved = [
        m.group(1)
        for block in re.split(r"(?m)^@router\.", src)[1:]
        if (m := re.search(r"def (\w+)\(", block))
        and "org_id" in block
        and "resolve_tenant" not in block
    ]
    assert not unresolved, f"handlers take an org but never resolve it: {unresolved}"
