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


def test_warn_is_the_default_and_never_refuses(monkeypatch, caplog) -> None:
    """A control nobody enables is not a control — but the default must not
    reject traffic either.

    warn logs the conflict and allows the request, which is the evidence you
    need before moving to enforce. Measured cost, alternating runs after
    warm-up on a 20 KB JSON body: +0.060 ms against a 1.058 ms baseline.
    """
    monkeypatch.delenv("FIXOPS_BODY_TENANT_GUARD", raising=False)
    from apps.api.body_tenant_guard import guard_mode

    assert guard_mode() == "warn"

    client = TestClient(_app("acme"))
    with caplog.at_level("WARNING"):
        response = client.post("/echo", json={"org_id": "someone-else", "value": "v"})
    assert response.status_code == 200, "the default refused a request"
    assert any("body-tenant-guard" in r.message for r in caplog.records)


def test_an_unrecognised_mode_falls_back_to_warn(monkeypatch) -> None:
    """A typo in the environment must not silently disable the control."""
    monkeypatch.setenv("FIXOPS_BODY_TENANT_GUARD", "enforcing")
    from apps.api.body_tenant_guard import guard_mode

    assert guard_mode() == "warn"


def test_off_still_disables_it_completely(monkeypatch) -> None:
    monkeypatch.setenv("FIXOPS_BODY_TENANT_GUARD", "off")
    client = TestClient(_app("acme"))
    assert client.post(
        "/echo", json={"org_id": "someone-else", "value": "v"}
    ).status_code == 200


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


# --- the credential must come from the TOKEN, not from request state --------
#
# The guard shipped as a no-op for the only credential that matters, and only
# an end-to-end test with a real key exposed it. An API key's tenant is bound in
# _verify_api_key, a route DEPENDENCY, which runs AFTER all middleware. At guard
# time scope["state"] holds whatever OrgIdMiddleware derived, and with no
# X-Org-ID header that is "default" — so the guard returned early.
#
# Measured against the real app with a key genuinely pinned to "acme":
#     no X-Org-ID header   -> guard never reached the comparison   (422)
#     X-Org-ID: acme       -> 403
#
# It protected the honest client who volunteers the header and was silent for
# the attacker who omits it.


import apps.api.body_tenant_guard as guard_module


class _Record:
    def __init__(self, org_id):
        self.org_id = org_id


@pytest.fixture(autouse=True)
def _clear_token_cache():
    guard_module._TOKEN_ORG_CACHE.clear()
    yield
    guard_module._TOKEN_ORG_CACHE.clear()


def _with_key(monkeypatch, org: str | None):
    class _KM:
        def validate_key(self, token):
            return _Record(org) if org else None

    import core.key_manager as km
    monkeypatch.setattr(km, "KeyManager", lambda *a, **k: _KM())


def test_the_tenant_is_resolved_from_the_token_without_any_header(monkeypatch) -> None:
    """The case that was broken. No X-Org-ID anywhere."""
    monkeypatch.setenv("FIXOPS_BODY_TENANT_GUARD", "enforce")
    _with_key(monkeypatch, "acme")

    app = _app(None)  # nothing pins state.org_id — exactly like a real API key
    client = TestClient(app)
    response = client.post(
        "/echo",
        json={"org_id": "victim-corp", "value": "v"},
        headers={"X-API-Key": "fixops_live_abc"},
    )
    assert response.status_code == 403
    assert response.json()["credential_org"] == "acme"


def test_a_bearer_token_is_read_too(monkeypatch) -> None:
    monkeypatch.setenv("FIXOPS_BODY_TENANT_GUARD", "enforce")
    _with_key(monkeypatch, "acme")
    client = TestClient(_app(None))
    response = client.post(
        "/echo",
        json={"org_id": "victim-corp", "value": "v"},
        headers={"Authorization": "Bearer fixops_live_abc"},
    )
    assert response.status_code == 403


def test_the_operator_token_is_not_a_managed_key(monkeypatch) -> None:
    """FIXOPS_API_TOKEN does not start with fixops_ and pins no tenant.

    Naming an org with it is legitimate administration, and resolve_tenant
    allows it too — so no DB lookup should even be attempted.
    """
    monkeypatch.setenv("FIXOPS_BODY_TENANT_GUARD", "enforce")

    def _explode(*a, **k):
        raise AssertionError("looked up a non-managed token")

    import core.key_manager as km
    monkeypatch.setattr(km, "KeyManager", _explode)

    client = TestClient(_app(None))
    response = client.post(
        "/echo", json={"org_id": "acme", "value": "v"},
        headers={"X-API-Key": "operator-token-not-managed"},
    )
    assert response.status_code == 200


def test_a_lookup_failure_never_rejects_traffic(monkeypatch) -> None:
    """A control that failed closed on its own database error would take the
    API down on a hiccup. Unknown credential means fall through, not reject."""
    monkeypatch.setenv("FIXOPS_BODY_TENANT_GUARD", "enforce")

    class _Broken:
        def validate_key(self, token):
            raise RuntimeError("key database unavailable")

    import core.key_manager as km
    monkeypatch.setattr(km, "KeyManager", lambda *a, **k: _Broken())

    client = TestClient(_app(None))
    response = client.post(
        "/echo", json={"org_id": "victim-corp", "value": "v"},
        headers={"X-API-Key": "fixops_live_abc"},
    )
    assert response.status_code == 200


def test_an_unknown_key_is_not_treated_as_a_tenant(monkeypatch) -> None:
    monkeypatch.setenv("FIXOPS_BODY_TENANT_GUARD", "enforce")
    _with_key(monkeypatch, None)
    client = TestClient(_app(None))
    response = client.post(
        "/echo", json={"org_id": "victim-corp", "value": "v"},
        headers={"X-API-Key": "fixops_unknown"},
    )
    assert response.status_code == 200


def test_state_still_wins_when_auth_did_pin_a_tenant(monkeypatch) -> None:
    """A JWT binds org_id in middleware, before the guard. That must keep
    working, and must not trigger a redundant key lookup."""
    monkeypatch.setenv("FIXOPS_BODY_TENANT_GUARD", "enforce")

    def _explode(*a, **k):
        raise AssertionError("looked up a token when state already pinned one")

    import core.key_manager as km
    monkeypatch.setattr(km, "KeyManager", _explode)

    client = TestClient(_app("acme"))
    response = client.post(
        "/echo", json={"org_id": "victim-corp", "value": "v"},
        headers={"X-API-Key": "fixops_live_abc"},
    )
    assert response.status_code == 403


def test_the_token_lookup_is_cached(monkeypatch) -> None:
    """One DB read per key, not one per request."""
    monkeypatch.setenv("FIXOPS_BODY_TENANT_GUARD", "enforce")
    calls = {"n": 0}

    class _Counting:
        def validate_key(self, token):
            calls["n"] += 1
            return _Record("acme")

    import core.key_manager as km
    monkeypatch.setattr(km, "KeyManager", lambda *a, **k: _Counting())

    client = TestClient(_app(None))
    for _ in range(4):
        client.post("/echo", json={"org_id": "victim-corp", "value": "v"},
                    headers={"X-API-Key": "fixops_live_abc"})
    assert calls["n"] == 1
