"""A customer credential must not be able to name another tenant.

Reproduces the P0 in docs/SECURITY_FINDING_cross_tenant_org_id.md. Before the
fix, a key minted by real self-service signup read AND wrote another tenant's
data simply by putting that tenant's id in a query string:

    GET /api/v1/identity-governance/entitlements?org_id=acme-secret
        -H "X-API-Key: fixops_…"      # a DIFFERENT tenant's customer key
     -> [{"org_id": "acme-secret", …}]

Four layers were involved, and each hid the one below it:
  1. ManagedKey had no org_id field — the key was "org-scoped" only because the
     org appeared as a substring of its display name.
  2. The managed-key branch of api_key_auth never set request.state.org_id;
     only the JWT branch did.
  3. So _extract_org_id's otherwise-correct precedence chain fell through to the
     client-supplied X-Org-ID header / ?org_id= query param.
  4. 33 handlers skipped the dependency entirely with a bare ``org_id: str``,
     which FastAPI exposes as a plain query parameter.

These tests exercise the seam end to end — two real accounts created through the
real signup endpoint — because that is the only level at which all four layers
are in play at once.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("FIXOPS_API_TOKEN", "cross-tenant-operator-token")
    monkeypatch.setenv("FIXOPS_JWT_SECRET", "cross-tenant-test-secret-long-enough-0123456789abcdef")
    monkeypatch.setenv("FIXOPS_MODE", "enterprise")

    from apps.api.auth_router import router as auth_router
    from apps.api.identity_governance_router import router as iga_router

    app = FastAPI()
    app.include_router(auth_router)
    app.include_router(iga_router)
    return TestClient(app)


def _tenant(client):
    """A real account with a real org-scoped key, via the real signup flow."""
    email = f"xt-{uuid.uuid4().hex[:12]}@probe.example"
    resp = client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "CrossTenant123", "first_name": "X", "last_name": "T"},
    )
    assert resp.status_code in (200, 201), resp.text
    body = resp.json()
    assert body.get("api_key"), "signup issued no key"
    return {"key": body["api_key"], "org": body["org_id"]}


def _rows(resp):
    body = resp.json()
    return body if isinstance(body, list) else body.get("items", [])


def test_a_signup_key_carries_its_own_tenant(client) -> None:
    """Layer 1: the credential must have an org at all."""
    t = _tenant(client)
    me = client.get("/api/v1/auth/me", headers={"X-API-Key": t["key"]})
    assert me.status_code == 200, me.text
    assert me.json()["org_id"] == t["org"], "the key does not carry the org signup promised it"


def test_writes_land_in_the_credentials_tenant_not_default(client) -> None:
    """Layer 2/3: auth must pin the org, or everything lands in "default"."""
    t = _tenant(client)
    resp = client.post(
        "/api/v1/identity-governance/entitlements",
        headers={"X-API-Key": t["key"]},
        json={"identity_id": "own-user", "resource": "own-db", "access_level": "admin"},
    )
    assert resp.status_code in (200, 201), resp.text
    assert resp.json().get("org_id") == t["org"]


def test_one_tenant_cannot_read_another_by_naming_it(client) -> None:
    """The breach itself."""
    a, b = _tenant(client), _tenant(client)

    client.post(
        "/api/v1/identity-governance/entitlements",
        headers={"X-API-Key": a["key"]},
        json={"identity_id": "alpha-secret", "resource": "alpha-db", "access_level": "admin"},
    )

    leaked = client.get(
        f"/api/v1/identity-governance/entitlements?org_id={a['org']}",
        headers={"X-API-Key": b["key"]},
    )
    ids = {r.get("identity_id") for r in _rows(leaked) if isinstance(r, dict)}
    assert "alpha-secret" not in ids, "cross-tenant READ: B reached A by naming A's org"


def test_one_tenant_cannot_write_into_another_by_naming_it(client) -> None:
    a, b = _tenant(client), _tenant(client)

    client.post(
        f"/api/v1/identity-governance/entitlements?org_id={a['org']}",
        headers={"X-API-Key": b["key"]},
        json={"identity_id": "planted-by-b", "resource": "x", "access_level": "admin"},
    )

    seen = client.get("/api/v1/identity-governance/entitlements", headers={"X-API-Key": a["key"]})
    ids = {r.get("identity_id") for r in _rows(seen) if isinstance(r, dict)}
    assert "planted-by-b" not in ids, "cross-tenant WRITE: B planted a row in A's org"


def test_the_x_org_id_header_cannot_override_the_credential_either(client) -> None:
    """The query param is not the only client-supplied channel."""
    a, b = _tenant(client), _tenant(client)

    client.post(
        "/api/v1/identity-governance/entitlements",
        headers={"X-API-Key": a["key"]},
        json={"identity_id": "alpha-header-secret", "resource": "alpha-db", "access_level": "admin"},
    )

    leaked = client.get(
        "/api/v1/identity-governance/entitlements",
        headers={"X-API-Key": b["key"], "X-Org-ID": a["org"]},
    )
    ids = {r.get("identity_id") for r in _rows(leaked) if isinstance(r, dict)}
    assert "alpha-header-secret" not in ids, "cross-tenant READ via X-Org-ID header"


def test_a_tenant_still_reads_its_own_data(client) -> None:
    """Sealing the breach must not seal the product."""
    a = _tenant(client)
    client.post(
        "/api/v1/identity-governance/entitlements",
        headers={"X-API-Key": a["key"]},
        json={"identity_id": "mine", "resource": "my-db", "access_level": "admin"},
    )
    seen = client.get("/api/v1/identity-governance/entitlements", headers={"X-API-Key": a["key"]})
    ids = {r.get("identity_id") for r in _rows(seen) if isinstance(r, dict)}
    assert "mine" in ids, "isolation broke the tenant's own access"
