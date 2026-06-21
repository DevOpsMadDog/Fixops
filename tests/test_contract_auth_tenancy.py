"""SPEC-033 C10 — contract: API-key auth is enforced (fail-closed) on data routes.

Pins the cross-cutting auth contract so a router can't silently ship unauthenticated
(the auth-gap class, feedback_router_auth_gap_pattern): a protected data endpoint
returns 401 with no key and 200 with a valid key. Additive, no API change.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FIXOPS_API_TOKEN", "ci-test-token")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

_TOKEN = os.environ.get("FIXOPS_API_TOKEN", "ci-test-token")


@pytest.fixture(scope="module")
def client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import apps.api.security_findings_router as m

    app = FastAPI()
    app.include_router(m.router)
    return TestClient(app, raise_server_exceptions=False)


def test_no_key_is_401(client):
    resp = client.get("/api/v1/security-findings/?org_id=c10-org")
    assert resp.status_code == 401, f"unauthenticated request must be 401, got {resp.status_code}"


def test_valid_key_is_200(client):
    resp = client.get(
        "/api/v1/security-findings/?org_id=c10-org",
        headers={"X-API-Key": _TOKEN, "X-Org-ID": "c10-org"},
    )
    assert resp.status_code == 200, f"valid key must be 200, got {resp.status_code}: {resp.text[:150]}"


def test_bad_key_is_401(client):
    resp = client.get(
        "/api/v1/security-findings/?org_id=c10-org",
        headers={"X-API-Key": "totally-wrong-token", "X-Org-ID": "c10-org"},
    )
    assert resp.status_code in (401, 403), f"invalid key must be fail-closed 401/403, got {resp.status_code}"
