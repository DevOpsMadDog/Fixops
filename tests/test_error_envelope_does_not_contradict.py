"""A 404 the handler raised on purpose must not be relabelled "endpoint not found".

A 404 means two different things in this API:

* the ROUTER raises it, with Starlette's default detail "Not Found", when no
  route matches — the routing hint is exactly right;
* a HANDLER raises it, with its own detail, to say the resource has no data yet:
  "No RBAC analysis available. POST /api/v1/k8s/scan first."

The envelope attached the routing hint to both, so the second kind of response
contradicted itself — the detail told the caller to run a scan while the hint
told them to verify the URL because the endpoint does not exist. A customer
reads the hint and concludes the feature is missing, when they are one POST
away from data. Several screens looked dead for exactly this reason.
"""

from __future__ import annotations

import pytest
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.testclient import TestClient


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("FIXOPS_API_TOKEN", "envelope-test-token")
    monkeypatch.setenv("FIXOPS_MODE", "enterprise")

    from apps.api.app import create_app

    # A real endpoint, not a probe route. Anything registered after create_app()
    # lands BEHIND the SPA catch-all and is never reached — which is itself a
    # trap worth remembering.
    return TestClient(create_app(), raise_server_exceptions=False)


def test_a_handlers_own_404_message_is_not_overridden(client) -> None:
    """GET /k8s/rbac before any scan: a real "no data yet" 404 with real guidance."""
    resp = client.get("/api/v1/k8s/rbac", headers={"X-API-Key": "envelope-test-token"})
    assert resp.status_code == 404, f"expected the no-data 404, got {resp.status_code}"

    body = resp.json()
    assert "scan" in body["detail"].lower(), "the handler's guidance was lost"
    assert body.get("hint") != "Endpoint not found", (
        "the envelope contradicted the handler: detail says run a scan, hint says the URL is wrong"
    )


def test_a_genuinely_missing_route_is_still_reported_as_missing(client) -> None:
    """Don't throw away the "this URL is wrong" signal where it genuinely applies.

    An unmatched /api/v1/... path is handled by the API catch-all rather than the
    HTTPException envelope, so it carries the framework detail and the path it
    could not resolve — which is the honest answer for a wrong URL.
    """
    resp = client.get("/api/v1/this-route-does-not-exist-anywhere", headers={"X-API-Key": "envelope-test-token"})
    assert resp.status_code == 404

    body = resp.json()
    assert body["detail"] == "Not Found"
    assert "this-route-does-not-exist-anywhere" in body.get("path", ""), (
        "a wrong URL should say which URL it could not resolve"
    )


def test_401_and_403_hints_are_untouched(client) -> None:
    """Only the 404 case is ambiguous; the others must keep their guidance."""
    resp = client.get("/api/v1/orgs")
    assert resp.status_code in (401, 403)
    assert resp.json().get("hint"), "auth hints were lost"
