"""SPEC-033 C5 — UI↔API contract: analytics triage-funnel (monotonic, no drift).

This endpoint silently regressed before (tick213: exposure_cases counted raw
findings -> funnel non-monotonic, ~0% reduction shown instead of the real ~99%).
Pins the response shape AND the monotonic invariant raw>=dedup>=correlation>=
exposure so the noise-reduction moat can't misreport again. Additive, no API change.
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

    import apps.api.analytics_router as m

    app = FastAPI()
    app.include_router(m.router)
    return TestClient(app, raise_server_exceptions=False)


def test_triage_funnel_shape_and_monotonic(client):
    # fresh org -> honest-empty, but the contract (shape + monotonic) must hold.
    resp = client.get(
        "/api/v1/analytics/triage-funnel?org_id=contract-funnel-org",
        headers={"X-API-Key": _TOKEN, "X-Org-ID": "contract-funnel-org"},
    )
    assert resp.status_code == 200, f"{resp.status_code}: {resp.text[:200]}"
    body = resp.json()
    assert "funnel" in body, f"missing funnel: {sorted(body)}"
    f = body["funnel"]
    for k in ("raw_findings", "after_dedup", "after_correlation", "exposure_cases"):
        assert k in f and isinstance(f[k], int), f"funnel.{k} missing/not int: {f}"
    # the core invariant — the funnel must never widen as it narrows
    assert f["raw_findings"] >= f["after_dedup"] >= f["after_correlation"] >= f["exposure_cases"], (
        f"triage funnel is NOT monotonic (the tick213 regression class): {f}"
    )
    assert "reduction_percentage" in body and isinstance(body["reduction_percentage"], (int, float))
    assert 0.0 <= float(body["reduction_percentage"]) <= 100.0
    assert "fail_distribution" in body and set(body["fail_distribution"]) >= {
        "critical", "high", "medium", "low", "info"
    }
    # honest-empty: a fresh org reports data_available False, all zeros
    assert body.get("data_available") is False
    assert f["raw_findings"] == 0
