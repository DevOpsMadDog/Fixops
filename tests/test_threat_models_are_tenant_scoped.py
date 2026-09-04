"""A threat model belongs to the org that created it, whatever the URL says.

All eleven routes take the tenant from the PATH — /threat-model-gen/{org_id}/...
— and guarded it with Depends(api_key_auth), which authenticates the caller
but binds no tenant. Any valid credential could therefore name any org in the
URL.

Measured against the running app with two real signed-up tenants, before:

    B GET  /threat-model-gen/{A}/models            200, "VICTIM-CROWN-JEWELS"
    B GET  /threat-model-gen/{A}/models/{id}       200, full contents
    B POST /threat-model-gen/{A}/models/{id}/auto-generate
                                                   200 — wrote 8 threats in
    B GET  /threat-model-gen/{A}/stats             200, total_threats=8

A threat model is a customer's STRIDE analysis of their own architecture —
trust boundaries, components, and every weakness they know about. The victim
model in that run described a payment core with an HSM and a card vault.
"""

from __future__ import annotations

import base64
import json
import uuid

import pytest
from fastapi.testclient import TestClient

BASE = "/api/v1/threat-model-gen"


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    import os

    os.environ["FIXOPS_DATA_DIR"] = str(tmp_path_factory.mktemp("tmg"))
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
def victim(client):
    headers, org = _tenant(client, "victim")
    created = client.post(f"{BASE}/{org}/models", headers=headers, json={
        "name": "VICTIM-CROWN-JEWELS",
        "description": "payment core",
        "components": ["hsm", "card-vault"],
    })
    assert created.status_code == 200, created.text
    return headers, org, created.json()["model_id"]


def test_the_model_is_stamped_with_the_creating_org(client, victim) -> None:
    headers, org, model_id = victim
    body = client.get(f"{BASE}/{org}/models/{model_id}", headers=headers).json()
    assert body["org_id"] == org


def test_another_tenant_naming_the_victim_org_in_the_url_gets_nothing(client, victim) -> None:
    _, victim_org, model_id = victim
    attacker, _ = _tenant(client, "attacker")

    listing = client.get(f"{BASE}/{victim_org}/models", headers=attacker)
    assert listing.status_code == 200
    assert "VICTIM-CROWN-JEWELS" not in listing.text
    assert listing.json() == []

    assert client.get(f"{BASE}/{victim_org}/models/{model_id}",
                      headers=attacker).status_code == 404


def test_another_tenant_cannot_write_into_the_victims_model(client, victim) -> None:
    """The write was the worse half: auto-generate injected 8 STRIDE threats
    into a model belonging to someone else."""
    _, victim_org, model_id = victim
    attacker, _ = _tenant(client, "attacker2")

    assert client.post(f"{BASE}/{victim_org}/models/{model_id}/auto-generate",
                       headers=attacker).status_code == 404
    assert client.post(f"{BASE}/{victim_org}/models/{model_id}/threats",
                       headers=attacker,
                       json={"stride_category": "Spoofing", "title": "x"},
                       ).status_code in (404, 422)


def test_stats_report_the_callers_own_org_not_the_url(client, victim) -> None:
    """Aggregates leak too, and are easy to forget — the count is the data."""
    victim_headers, victim_org, _ = victim
    attacker, _ = _tenant(client, "attacker3")

    theirs = client.get(f"{BASE}/{victim_org}/stats", headers=attacker)
    assert theirs.status_code == 200
    assert theirs.json()["total_models"] == 0

    mine = client.get(f"{BASE}/{victim_org}/stats", headers=victim_headers)
    assert mine.json()["total_models"] >= 1


def test_the_owner_is_unaffected(client, victim) -> None:
    """A tenancy fix that also locks out the owner is not a fix."""
    headers, org, model_id = victim
    assert client.get(f"{BASE}/{org}/models", headers=headers).json()
    body = client.get(f"{BASE}/{org}/models/{model_id}", headers=headers)
    assert body.status_code == 200
    assert body.json()["name"] == "VICTIM-CROWN-JEWELS"


def test_every_path_org_handler_resolves_the_tenant() -> None:
    """Structural backstop: a new route here must not skip resolve_tenant.

    Three handlers in org_router once took the credential parameter and never
    called resolve_tenant — the signature looked fixed and the body was not.
    """
    import ast
    import pathlib

    source = (pathlib.Path(__file__).resolve().parents[1]
              / "suite-api" / "apps" / "api"
              / "threat_model_generator_router.py").read_text(encoding="utf-8")

    missing = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(isinstance(d, ast.Call)
                   and getattr(d.func, "attr", "") in
                   ("get", "post", "put", "patch", "delete")
                   for d in node.decorator_list):
            continue
        if not any(a.arg == "org_id" for a in node.args.args + node.args.kwonlyargs):
            continue
        body = ast.unparse(node)
        if "resolve_tenant(" not in body or "credential_org" not in body:
            missing.append(node.name)

    assert not missing, (
        "handlers take org_id from the path without resolving it against the "
        f"credential: {missing}"
    )
