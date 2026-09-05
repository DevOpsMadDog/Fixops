"""Only the owner may edit a trust page — but anyone may read the public one.

The Trust Center is deliberately half-public. Its own module docstring lists
two PUBLIC routes (/{org_id}/public and /{org_id}/report) and eleven ADMIN
ones. The admin routes carried `dependencies=[Depends(api_key_auth)]`, which
authenticates the caller but binds no tenant, and then took the org straight
from the URL.

Measured against the running app with two real signed-up tenants, before:

    B POST /trust/{A}/badges  {"framework": "SOC2", "status": "certified",
                               "auditor": "TOTALLY-REAL-AUDITOR"}      -> 200
    GET  /trust/{A}/public    (no credential at all)  -> serves the forgery

A forged SOC2 attestation, published on another company's public compliance
page. B could also read A's config and list A's badges.

The two public routes are untouched: a trust page nobody can read is not a
trust page.
"""

from __future__ import annotations

import base64
import json
import uuid

import pytest
from fastapi.testclient import TestClient

TRUST = "/api/v1/trust"


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    import os

    os.environ["FIXOPS_DATA_DIR"] = str(tmp_path_factory.mktemp("trust"))
    os.environ["FIXOPS_DISABLE_RATE_LIMIT"] = "1"
    from apps.api.app import create_app

    return TestClient(create_app(), raise_server_exceptions=False)


def _tenant(client: TestClient, tag: str):
    suffix = uuid.uuid4().hex[:8]
    email, password = f"{tag}-{suffix}@example.com", "Aldeci-Demo-2026!x"
    client.post("/api/v1/auth/signup", json={
        "email": email, "password": password, "first_name": tag, "last_name": "T",
    })
    token = client.post("/api/v1/auth/login", json={
        "email": email, "password": password,
    }).json()["access_token"]
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return ({"Authorization": f"Bearer {token}"},
            json.loads(base64.urlsafe_b64decode(payload))["org_id"])


@pytest.fixture(scope="module")
def owner(client):
    """A configured trust page with one genuine badge.

    Seeded through the API, because an unseeded page answers 404 to
    everything and a "denied" that is really "not configured" proves nothing.
    """
    headers, org = _tenant(client, "brandowner")
    configured = client.post(f"{TRUST}/configure", headers=headers, json={
        "org_name": "VictimCorp", "custom_message": "we are secure",
    })
    assert configured.status_code == 200, configured.text
    badge = client.post(f"{TRUST}/{org}/badges", headers=headers, json={
        "framework": "SOC2", "status": "certified", "auditor": "RealAuditorLLP",
    })
    assert badge.status_code == 200, badge.text
    return headers, org


def test_another_tenant_cannot_publish_a_forged_badge(client, owner) -> None:
    """The headline defect: forged compliance on someone else's public page."""
    _, victim_org = owner
    attacker, _ = _tenant(client, "defacer")

    forged = client.post(f"{TRUST}/{victim_org}/badges", headers=attacker, json={
        "framework": "SOC2", "status": "certified",
        "auditor": "TOTALLY-REAL-AUDITOR",
    })
    assert forged.status_code == 404

    public = client.get(f"{TRUST}/{victim_org}/public")
    assert public.status_code == 200
    assert "TOTALLY-REAL-AUDITOR" not in public.text


def test_another_tenant_cannot_read_the_admin_views(client, owner) -> None:
    _, victim_org = owner
    attacker, _ = _tenant(client, "snooper")

    assert client.get(f"{TRUST}/{victim_org}/config", headers=attacker).status_code == 404
    assert client.get(f"{TRUST}/{victim_org}/badges", headers=attacker).status_code == 404


def test_the_public_page_stays_public(client, owner) -> None:
    """A trust page nobody can read is not a trust page.

    This is the half of the router that must NOT be locked down, and the
    reason the fix was applied per-handler rather than swept across the file.
    """
    _, victim_org = owner

    page = client.get(f"{TRUST}/{victim_org}/public")
    assert page.status_code == 200, "no credential was sent, and none is required"
    assert "RealAuditorLLP" in page.text, "the owner's genuine badge must publish"


def test_the_owner_still_administers_their_own_page(client, owner) -> None:
    headers, org = owner
    badges = client.get(f"{TRUST}/{org}/badges", headers=headers)
    assert badges.status_code == 200 and len(badges.json()) >= 1
    assert client.get(f"{TRUST}/{org}/config",
                      headers=headers).json()["org_name"] == "VictimCorp"


def test_every_admin_handler_resolves_the_tenant_and_no_public_one_does() -> None:
    """Structural backstop, both directions.

    A new admin route that skips resolve_tenant is a leak; a public route that
    gains it would silently break the public page, which is the feature.
    """
    import ast
    import pathlib

    source = (pathlib.Path(__file__).resolve().parents[1] / "suite-api" /
              "apps" / "api" / "trust_center_router.py").read_text(encoding="utf-8")

    public_routes = {"get_public_page", "get_security_report"}
    unscoped_admin, scoped_public = [], []

    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        routes = [d for d in node.decorator_list
                  if isinstance(d, ast.Call)
                  and getattr(d.func, "attr", "") in
                  ("get", "post", "put", "patch", "delete")]
        if not routes:
            continue
        path = (routes[0].args[0].value
                if routes[0].args and isinstance(routes[0].args[0], ast.Constant)
                else "")

        # The rule applies to the org in the URL. configure_trust_page posts to
        # /configure and takes org_id from Depends(get_org_id) — the credential
        # is already the only source, so there is nothing to resolve against.
        if "{org_id}" not in path:
            continue

        body = ast.unparse(node)
        resolves = "resolve_tenant(" in body
        if node.name in public_routes:
            if resolves:
                scoped_public.append(node.name)
        elif not resolves:
            unscoped_admin.append(node.name)

    assert not unscoped_admin, (
        f"admin routes take org_id from the URL without resolving it: {unscoped_admin}"
    )
    assert not scoped_public, (
        f"a documented PUBLIC route now resolves a tenant and will stop serving "
        f"anonymous readers: {scoped_public}"
    )
