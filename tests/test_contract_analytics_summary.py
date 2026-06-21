"""SPEC-033 C4 — UI↔API contract: analytics dashboard summary (shape + invariants).

Pins /api/v1/analytics/dashboard/summary — the KPI source for the exec/dev
dashboards — so the shape and numeric invariants can't drift, and a fresh org
stays honest-empty (SPEC-029). Additive contract test, no API change.
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


def test_dashboard_summary_shape_and_invariants(client):
    org = "contract-summary-org"
    resp = client.get(
        f"/api/v1/analytics/dashboard/summary?org_id={org}",
        headers={"X-API-Key": _TOKEN, "X-Org-ID": org},
    )
    assert resp.status_code == 200, f"{resp.status_code}: {resp.text[:200]}"
    b = resp.json()
    for k in ("total_findings", "open_findings", "resolved_findings", "severity", "risk_score"):
        assert k in b, f"summary missing '{k}': {sorted(b)}"
    for k in ("total_findings", "open_findings", "resolved_findings"):
        assert isinstance(b[k], int) and b[k] >= 0, f"{k} not a non-negative int: {b[k]}"
    # numeric invariants
    assert b["open_findings"] <= b["total_findings"], f"open>total: {b}"
    assert b["resolved_findings"] <= b["total_findings"], f"resolved>total: {b}"
    assert 0 <= float(b["risk_score"]) <= 100, f"risk_score out of range: {b['risk_score']}"
    sev = b["severity"]
    assert set(sev) >= {"critical", "high", "medium", "low", "info"}
    assert sum(int(v) for v in sev.values()) <= b["total_findings"], f"severity sum > total: {b}"


def test_dashboard_summary_honest_empty_for_fresh_org(client):
    org = "contract-summary-FRESH-zzz"
    resp = client.get(
        f"/api/v1/analytics/dashboard/summary?org_id={org}",
        headers={"X-API-Key": _TOKEN, "X-Org-ID": org},
    )
    assert resp.status_code == 200
    b = resp.json()
    # SPEC-029: un-ingested org reports zeros, not fabricated KPIs
    assert b["total_findings"] == 0 and b["open_findings"] == 0
    assert float(b["risk_score"]) == 0
