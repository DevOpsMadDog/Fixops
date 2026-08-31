"""The body-tenant guard must catch cross-tenant bodies without breaking POSTs.

206 routers take the credential and then read ``body.org_id`` anyway. A codemod
across them has broken this build three times, so the remainder gets one guard.
That trade is only acceptable if the guard demonstrably cannot break a request,
which is what most of this file is about.

The dangerous part is reading the body. Whatever consumes the ASGI receive
channel must put it back, or the route handler gets an empty body and the
request hangs. So the first tests here are not about tenancy at all — they check
that ordinary POSTs still arrive intact, that multipart uploads are untouched,
and that a malformed body still produces the route's own 422 rather than a
confusing 403 from the middleware.
"""

from __future__ import annotations

import io
import json

import pytest
from fastapi import FastAPI, UploadFile, File
from fastapi.testclient import TestClient
from pydantic import BaseModel

from apps.api.body_tenant_guard import BodyTenantGuard


class Payload(BaseModel):
    org_id: str = "default"
    value: str = ""


def _app(credential_org: str | None) -> FastAPI:
    app = FastAPI()

    @app.post("/echo")
    def echo(body: Payload) -> dict:
        return {"org_id": body.org_id, "value": body.value}

    @app.post("/upload")
    async def upload(file: UploadFile = File(...)) -> dict:
        content = await file.read()
        return {"bytes": len(content), "name": file.filename}

    # ORDER MATTERS, and it is the opposite of what it looks like:
    # add_middleware PREPENDS, so the LAST added is the OUTERMOST and runs
    # FIRST. The guard must therefore be added BEFORE the credential
    # middleware, so that the credential middleware ends up outside it and has
    # already populated scope["state"] by the time the guard runs.
    app.add_middleware(BodyTenantGuard)

    @app.middleware("http")
    async def seed_credential(request, call_next):
        # Stands in for OrgIdMiddleware.
        if credential_org is not None:
            request.state.org_id = credential_org
        return await call_next(request)

    return app


# --- the guard must not break anything -------------------------------------


def test_a_normal_post_still_arrives_intact(monkeypatch) -> None:
    """The body is buffered and replayed. If the replay is wrong, this hangs or
    returns an empty body — which is why it is the first test."""
    monkeypatch.setenv("FIXOPS_BODY_TENANT_GUARD", "enforce")
    client = TestClient(_app("acme"))

    response = client.post("/echo", json={"org_id": "acme", "value": "hello"})
    assert response.status_code == 200
    assert response.json() == {"org_id": "acme", "value": "hello"}


def test_a_multipart_upload_is_never_inspected(monkeypatch) -> None:
    """Scanner output arrives as multipart. Buffering a scan file on every
    request to look for a field it cannot contain would be real cost for no
    benefit — and the upload must still work byte-for-byte."""
    monkeypatch.setenv("FIXOPS_BODY_TENANT_GUARD", "enforce")
    client = TestClient(_app("acme"))

    blob = b"x" * 5000
    response = client.post("/upload", files={"file": ("scan.json", io.BytesIO(blob), "application/json")})
    assert response.status_code == 200
    assert response.json() == {"bytes": len(blob), "name": "scan.json"}


def test_a_malformed_body_still_gets_the_routes_own_error(monkeypatch) -> None:
    """A parse failure is the route's to report. Turning it into a 403 here
    would replace a clear 422 with a confusing one."""
    monkeypatch.setenv("FIXOPS_BODY_TENANT_GUARD", "enforce")
    client = TestClient(_app("acme"))

    response = client.post(
        "/echo", content=b"{not json", headers={"content-type": "application/json"}
    )
    assert response.status_code == 422


def test_off_is_the_default(monkeypatch) -> None:
    """New request-path enforcement must not switch itself on."""
    monkeypatch.delenv("FIXOPS_BODY_TENANT_GUARD", raising=False)
    client = TestClient(_app("acme"))

    response = client.post("/echo", json={"org_id": "someone-else", "value": "v"})
    assert response.status_code == 200, "the guard enabled itself"


# --- and it must actually catch the thing -----------------------------------


def test_enforce_refuses_a_body_naming_another_tenant(monkeypatch) -> None:
    monkeypatch.setenv("FIXOPS_BODY_TENANT_GUARD", "enforce")
    client = TestClient(_app("acme"))

    response = client.post("/echo", json={"org_id": "victim-corp", "value": "v"})
    assert response.status_code == 403
    body = response.json()
    assert body["credential_org"] == "acme"
    assert body["requested_org"] == "victim-corp"


def test_warn_logs_but_allows(monkeypatch, caplog) -> None:
    """Run warn first in a real deployment: the log tells you whether honest
    clients send a mismatched org before you start refusing them."""
    monkeypatch.setenv("FIXOPS_BODY_TENANT_GUARD", "warn")
    client = TestClient(_app("acme"))

    with caplog.at_level("WARNING"):
        response = client.post("/echo", json={"org_id": "victim-corp", "value": "v"})
    assert response.status_code == 200
    assert any("body-tenant-guard" in r.message for r in caplog.records)


def test_a_matching_org_passes(monkeypatch) -> None:
    monkeypatch.setenv("FIXOPS_BODY_TENANT_GUARD", "enforce")
    client = TestClient(_app("acme"))
    assert client.post("/echo", json={"org_id": "acme", "value": "v"}).status_code == 200


def test_a_body_saying_default_is_not_a_conflict(monkeypatch) -> None:
    """"default" is what a client that never set the field sends. Refusing it
    would reject honest traffic — the overwhelmingly common case."""
    monkeypatch.setenv("FIXOPS_BODY_TENANT_GUARD", "enforce")
    client = TestClient(_app("acme"))
    assert client.post("/echo", json={"org_id": "default", "value": "v"}).status_code == 200


def test_an_unpinned_credential_may_name_any_org(monkeypatch) -> None:
    """FIXOPS_API_TOKEN is the operator credential; targeting a named org with
    it is legitimate administration, and resolve_tenant allows it too."""
    monkeypatch.setenv("FIXOPS_BODY_TENANT_GUARD", "enforce")
    client = TestClient(_app("default"))
    assert client.post("/echo", json={"org_id": "acme", "value": "v"}).status_code == 200


def test_the_guard_reads_scope_state_as_a_dict(monkeypatch) -> None:
    """scope["state"] is a plain dict; Request.state is only a wrapper over it.

    Reading it with getattr() returns nothing, which would make this guard a
    silent no-op that looks installed. This test fails if that regresses,
    because a credential of "acme" would stop being seen and the conflicting
    body would sail through.
    """
    monkeypatch.setenv("FIXOPS_BODY_TENANT_GUARD", "enforce")
    client = TestClient(_app("acme"))
    assert client.post("/echo", json={"org_id": "other", "value": "v"}).status_code == 403
