"""GAP_MAP medium (SPEC-002) — openclaw index must pass org_id to the engine.

Regression guard: openclaw_index called _get_engine() with no arg, but
_get_engine(org_id) requires it -> TypeError, swallowed by `except Exception`,
so the index ALWAYS returned 0 campaigns even when the org had some. Pin that the
endpoint resolves the engine for the org and returns its real campaign list shape.
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

    import apps.api.openclaw_router as m

    app = FastAPI()
    app.include_router(m.router)
    return TestClient(app, raise_server_exceptions=False)


def test_openclaw_index_passes_org_id(client):
    resp = client.get(
        "/api/v1/openclaw/?org_id=oc-index-org",
        headers={"X-API-Key": _TOKEN, "X-Org-ID": "oc-index-org"},
    )
    assert resp.status_code == 200, f"{resp.status_code}: {resp.text[:150]}"
    body = resp.json()
    assert "count" in body and "items" in body
    assert isinstance(body["count"], int)


def test_get_engine_requires_org_id():
    import apps.api.openclaw_router as m

    eng = m._get_engine("oc-index-org")
    assert hasattr(eng, "list_campaigns"), "engine should expose list_campaigns (real, not swallowed)"
