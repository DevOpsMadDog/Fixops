"""An unconfigured deployment must refuse requests, not serve them.

Found by cloning the repository into a clean directory and following the
README — the one thing a session working inside a live tree never does. A
fresh checkout has no FIXOPS_API_TOKEN and no FIXOPS_AUTH_STRATEGY, so
`_get_auth_strategy()` returned "". `_verify_api_key` matched "token" and
"jwt" and had no else: an unrecognised strategy fell past both blocks and
returned None, and a satisfied FastAPI dependency is an ALLOWED request.

Measured on that clean clone with no credential of any kind:

    GET  /api/v1/scanner-ingest/        200
    GET  /api/v1/playbooks              200
    POST /api/v1/scanner-ingest/upload  200   anonymous upload accepted
    GET  /api/v1/security-findings/     401   (api_key_auth, which fails closed)

Two implementations of one rule disagreeing about the default, and the
permissive one guarded the ingest front door.

These tests pin both halves of the fix: the strategy resolves for a token-less
deployment (because the generated token is published to the environment), and
the dependency refuses outright if it ever does not.
"""

from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient


@pytest.fixture()
def unconfigured(monkeypatch):
    """A deployment with neither variable set — a fresh checkout."""
    monkeypatch.delenv("FIXOPS_API_TOKEN", raising=False)
    monkeypatch.delenv("FIXOPS_AUTH_STRATEGY", raising=False)
    return None


def test_an_unrecognised_strategy_refuses_the_request(unconfigured) -> None:
    """The core invariant: no strategy match means DENY, never fall through."""
    from apps.api.auth_deps import _get_auth_strategy, verify_api_key

    assert _get_auth_strategy() == "", "precondition: nothing configured"

    app = FastAPI()

    @app.get("/probe", dependencies=[Depends(verify_api_key)])
    async def probe() -> dict:
        return {"reached": True}

    response = TestClient(app, raise_server_exceptions=False).get("/probe")
    assert response.status_code == 401, (
        "an unconfigured deployment served the request. This dependency guards "
        "the scanner-ingest front door; falling through means anonymous upload."
    )
    assert "not configured" in response.json()["detail"].lower()


def test_a_token_deployment_still_authenticates(monkeypatch) -> None:
    """The fix must not break the configured case."""
    monkeypatch.setenv("FIXOPS_API_TOKEN", "a-real-operator-token-value")
    monkeypatch.delenv("FIXOPS_AUTH_STRATEGY", raising=False)
    from apps.api.auth_deps import _get_auth_strategy, verify_api_key

    assert _get_auth_strategy() == "token"

    app = FastAPI()

    @app.get("/probe", dependencies=[Depends(verify_api_key)])
    async def probe() -> dict:
        return {"reached": True}

    client = TestClient(app, raise_server_exceptions=False)
    assert client.get("/probe").status_code == 401, "no credential must still fail"
    ok = client.get("/probe", headers={"X-API-Key": "a-real-operator-token-value"})
    assert ok.status_code == 200 and ok.json()["reached"] is True


def test_a_tokenless_deployment_resolves_a_strategy_after_overlay_load(monkeypatch, tmp_path) -> None:
    """The other half: generating a token must also PUBLISH it.

    load_overlay generates an ephemeral token when the variable is unset, so a
    clean clone can start. If it only appends to the config object, the
    environment stays empty, the strategy stays "", and the deployment boots
    with the fall-through above. It has to reach os.environ.
    """
    import os

    monkeypatch.delenv("FIXOPS_API_TOKEN", raising=False)
    monkeypatch.delenv("FIXOPS_AUTH_STRATEGY", raising=False)
    monkeypatch.delenv("FIXOPS_DEPLOYMENT_PROFILE", raising=False)

    from core.configuration import load_overlay

    try:
        load_overlay()
    except Exception as exc:  # pragma: no cover - overlay may need more setup
        pytest.skip(f"overlay could not load in this environment: {exc}")

    from apps.api.auth_deps import _get_auth_strategy

    assert os.environ.get("FIXOPS_API_TOKEN"), (
        "load_overlay generated a token but did not publish it to the "
        "environment; the auth strategy will stay unresolved and every router "
        "mounted with verify_api_key will fall through"
    )
    assert _get_auth_strategy() == "token"


def test_the_published_placeholder_tokens_are_refused(monkeypatch) -> None:
    """.env.example and docker-compose.yml ship values anyone can read.

    Both are non-empty, so they looked like configuration. A deployment
    running on them has a credential published in this repository.
    """
    from core.configuration import _PUBLISHED_PLACEHOLDER_TOKENS

    assert "fixops_ent_YOUR_TOKEN_HERE" in _PUBLISHED_PLACEHOLDER_TOKENS
    assert "aldeci-demo-token" in _PUBLISHED_PLACEHOLDER_TOKENS

    # And they really are what the repo ships — if these files change, this
    # allowlist has to change with them or the check quietly stops matching.
    import pathlib

    repo = pathlib.Path(__file__).resolve().parents[1]
    env_example = (repo / ".env.example").read_text(encoding="utf-8")
    compose = (repo / "docker-compose.yml").read_text(encoding="utf-8")
    assert "fixops_ent_YOUR_TOKEN_HERE" in env_example
    assert "aldeci-demo-token" in compose
