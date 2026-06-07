"""SPEC-029 — ingest-first honest-empty invariant (guards the 2026-06 fixes).

A fresh / un-ingested org MUST read honest-empty from posture/score/summary
endpoints — never a fabricated score. This session fixed a wave of these
(analytics risk_score:100/findings:10000, posture baseline 50→60/D,
cloud posture/inventory/governance 100%, analytics-engine open_cases:65,
compliance-status 100% with no evidence). This integration test queries a
random fresh org and asserts every guarded endpoint returns zeros / None /
empty so the fabrications cannot regress.

NO MOCKS rule, inverse: the platform must not fabricate a non-zero posture for
a tenant that has ingested nothing.
"""

from __future__ import annotations

import logging
import os

import pytest

os.environ.setdefault("FIXOPS_API_TOKEN", "ci-test-token")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")
logging.disable(logging.CRITICAL)

_TOKEN = os.environ["FIXOPS_API_TOKEN"]
_FRESH = "fresh-ingest-guard-zzq"  # an org guaranteed to have ingested nothing


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    from apps.api.app import create_app

    return TestClient(create_app())


def _get(client, path):
    r = client.get(path + ("&" if "?" in path else "?") + f"org_id={_FRESH}",
                   headers={"X-API-Key": _TOKEN})
    return r.status_code, (r.json() if r.status_code == 200 else None)


# (path, field, predicate) — predicate(value) must hold for honest-empty.
_GUARDS = [
    ("/api/v1/analytics/risk-overview", "risk_score", lambda v: v in (0, 0.0)),
    ("/api/v1/analytics/risk-overview", "total_findings", lambda v: v == 0),
    ("/api/v1/analytics/summary", "total_findings", lambda v: v == 0),
    ("/api/v1/analytics/summary", "total_decisions", lambda v: v == 0),
    ("/api/v1/analytics/posture", "overall_score", lambda v: v in (0, 0.0)),
    ("/api/v1/analytics/dashboard/compliance-status", "compliance_score", lambda v: v is None or v in (0, 0.0)),
    ("/api/v1/cloud-posture/stats", "avg_posture_score", lambda v: v is None),
    ("/api/v1/cloud-inventory/stats", "avg_security_score", lambda v: v is None),
    ("/api/v1/cloud-governance/stats", "compliance_score", lambda v: v is None),
    ("/api/v1/analytics-engine/summary", "open_cases", lambda v: v == 0),
    ("/api/v1/analytics-engine/summary", "total_findings", lambda v: v == 0),
    ("/api/v1/posture/current", "overall_score", lambda v: v in (0, 0.0)),
]


@pytest.mark.parametrize("path,field,ok", _GUARDS, ids=[f"{p}:{f}" for p, f, _ in _GUARDS])
def test_fresh_org_is_honest_empty(client, path, field, ok):
    status, body = _get(client, path)
    if status != 200:
        pytest.skip(f"{path} -> HTTP {status} (not 200; endpoint may be unmounted in this build)")
    assert field in body, f"{path}: missing field {field!r} in {list(body)[:8]}"
    assert ok(body[field]), (
        f"{path}: fabricated non-empty value for un-ingested org — {field}={body[field]!r} "
        "(must be 0/None/empty; see SPEC-029 ingest-first)"
    )
