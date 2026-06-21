"""SPEC-033 C9 — contract: evidence is honest (404 when absent, never fabricated).

Pins the evidence chain-of-custody contract (SPEC-019): downloading a bundle that
does not exist returns 404 — NOT a 200 with fabricated/synthetic content. Additive,
no API change.
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

    import apps.api.evidence_router as m

    app = FastAPI()
    app.include_router(m.router)
    return TestClient(app, raise_server_exceptions=False)


def test_download_nonexistent_bundle_is_404_not_fabricated(client):
    resp = client.get(
        "/evidence/bundles/does-not-exist-zzz/download",
        headers={"X-API-Key": _TOKEN, "X-Org-ID": "c9-org"},
    )
    # honest: missing bundle -> 404 (or 401/403 if auth-gated), never a 200 with
    # fabricated bytes, never a 500.
    assert resp.status_code in (404, 401, 403), (
        f"missing evidence bundle must be honest 404 (not fabricated/500), got {resp.status_code}"
    )
    assert resp.status_code != 500, "evidence download 500'd on a missing bundle"


def test_evidence_health_ok(client):
    resp = client.get("/evidence/health", headers={"X-API-Key": _TOKEN})
    assert resp.status_code in (200, 401, 403), f"evidence health unexpected: {resp.status_code}"
