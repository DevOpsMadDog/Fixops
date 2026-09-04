"""Five admin endpoints raised AttributeError after doing their work.

Every call site used `_audit.log_admin_action(...)`, a method AuditLogger has
never had — its API is `log(AuditEvent)`. So POST /api/v1/admin/users created
the user, then crashed logging it, and returned 500. The operator sees a
failure; the account exists. Role changes and deletions had the same shape.

An audit trail that crashes the action it audits is worse than no audit trail:
it makes the operator believe nothing happened.

Also fixed here: admin_create_user built the User with no org_id, so it fell to
the model's "default" — the identical omission proven in users_router (201
returned, stored org "default", invisible to the creator).
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

    os.environ["FIXOPS_DATA_DIR"] = str(tmp_path_factory.mktemp("adminrt"))
    os.environ["FIXOPS_BODY_TENANT_GUARD"] = "off"

    from apps.api.app import create_app

    client = TestClient(create_app())
    suffix = uuid.uuid4().hex[:8]
    email, password = f"adm-{suffix}@example.com", "Aldeci-Demo-2026!x"
    client.post("/api/v1/auth/signup", json={
        "email": email, "password": password, "first_name": "A", "last_name": "D"})
    token = client.post("/api/v1/auth/login", json={
        "email": email, "password": password}).json().get("access_token", "")
    assert token
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "==="))
    return client, {"Authorization": f"Bearer {token}"}, claims["org_id"], suffix


def test_admin_create_user_does_not_500(tenant) -> None:
    """It returned 201 only after the audit call was corrected."""
    client, headers, _org, suffix = tenant
    response = client.post("/api/v1/admin/users", headers=headers, json={
        "email": f"adm-created-{suffix}@example.com", "first_name": "A",
        "last_name": "U", "password": "Aldeci-Demo-2026!x", "role": "viewer"})
    assert response.status_code == 201, response.text[:200]


def test_the_created_user_belongs_to_the_callers_org(tenant) -> None:
    client, headers, org, suffix = tenant
    from core.user_db import UserDB

    email = f"adm-org-{suffix}@example.com"
    client.post("/api/v1/admin/users", headers=headers, json={
        "email": email, "first_name": "A", "last_name": "U",
        "password": "Aldeci-Demo-2026!x", "role": "viewer"})
    stored = UserDB().get_user_by_email(email)
    assert stored is not None
    assert getattr(stored, "org_id", None) == org


def test_an_audit_failure_never_breaks_the_action() -> None:
    """The whole point. Logging must not be able to fail the operation it
    records — and the swallow path itself must not raise, which it would have:
    my first version referenced a logger name that does not exist in the module.
    """
    import apps.api.admin_router as admin_router

    class Broken:
        def log(self, *args, **kwargs):
            raise RuntimeError("audit backend down")

    real = admin_router._audit
    admin_router._audit = Broken()
    try:
        admin_router._log_admin_action(action="probe", resource="user:1")
    finally:
        admin_router._audit = real


def test_no_call_site_uses_the_method_that_never_existed() -> None:
    import pathlib

    src = (
        pathlib.Path(__file__).resolve().parents[1]
        / "suite-api" / "apps" / "api" / "admin_router.py"
    ).read_text()
    assert "_audit.log_admin_action(" not in src
