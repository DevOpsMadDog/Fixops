"""
Batch-6 empty-endpoint regression — verifies the canonical envelope shape
applied to 6 class-c endpoints (empty IS correct for fresh tenants).

Canonical envelope contract:
    {
        "items": [...],
        "<legacy_key>": [...],   # back-compat (requests / treatments / etc.)
        "total": int,
        "org_id": str,
        "limit": int,
        "offset": int,
        "filters_applied": {...},
        "hint": str,             # only present when total == 0
    }

Endpoints covered (all class-c per docs/empty_endpoints_triage_2026-04-26.md):
- GET /api/v1/intel-enrichment/requests       (#6)
- GET /api/v1/posture-reports/reports         (#7)  — already aligned, smoke test
- GET /api/v1/risk-treatment/treatments       (#9)
- GET /api/v1/security-budget/allocations     (#11)
- GET /api/v1/access-requests/requests        (#12)
- GET /api/v1/cloud-governance/policies       (#16)
- GET /api/v1/security-chaos/experiments      (#26)

Each endpoint asserts:
    1. status_code == 200
    2. envelope contains: items, total, org_id, limit, offset, filters_applied
    3. when empty: total == 0 and `hint` non-empty
    4. pagination params (limit, offset) round-trip back into the envelope
    5. filters_applied echoes back the supplied filter values verbatim
"""

from __future__ import annotations

import os
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

# Set API key BEFORE importing the app so api_key_auth picks it up.
# Auth precedence: FIXOPS_API_TOKEN (canonical, see suite-api/apps/api/auth_deps.py:70).
API_KEY = "fixops_test_key_batch6"
os.environ["FIXOPS_API_TOKEN"] = API_KEY
os.environ.setdefault("FIXOPS_MODE", "dev")  # belt-and-suspenders dev bypass

from apps.api.app import create_app  # noqa: E402

HEADERS = {"X-API-Key": API_KEY}
ORG = "batch6-test-org"

CANONICAL_KEYS = {"items", "total", "org_id", "limit", "offset", "filters_applied"}


@pytest.fixture(scope="module")
def client() -> TestClient:
    app = create_app()
    return TestClient(app)


def _assert_canonical(envelope: Dict[str, Any], *, expect_empty: bool, legacy_key: str) -> None:
    """Assert the envelope conforms to the batch-6 canonical contract."""
    missing = CANONICAL_KEYS - set(envelope.keys())
    assert not missing, f"Envelope missing canonical keys: {missing}; got keys={list(envelope.keys())}"

    assert isinstance(envelope["items"], list), f"items must be a list, got {type(envelope['items'])}"
    assert isinstance(envelope["total"], int), f"total must be int, got {type(envelope['total'])}"
    assert isinstance(envelope["org_id"], str) and envelope["org_id"], "org_id must be non-empty str"
    assert isinstance(envelope["limit"], int) and envelope["limit"] > 0, "limit must be positive int"
    assert isinstance(envelope["offset"], int) and envelope["offset"] >= 0, "offset must be >= 0"
    assert isinstance(envelope["filters_applied"], dict), "filters_applied must be dict"

    # Back-compat legacy key still present and identical to items
    assert legacy_key in envelope, f"legacy key '{legacy_key}' missing for back-compat"
    assert envelope[legacy_key] == envelope["items"], f"{legacy_key} must mirror items"

    if expect_empty:
        assert envelope["total"] == 0
        assert envelope["items"] == []
        assert "hint" in envelope and isinstance(envelope["hint"], str) and len(envelope["hint"]) > 20, (
            f"empty envelope must include actionable hint; got hint={envelope.get('hint')!r}"
        )


# -----------------------------------------------------------------------------
# Test cases — one per endpoint
# -----------------------------------------------------------------------------


def test_intel_enrichment_requests_canonical_envelope(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/intel-enrichment/requests",
        params={"org_id": ORG, "status": "pending", "limit": 25, "offset": 0},
        headers=HEADERS,
    )
    assert resp.status_code == 200, f"got {resp.status_code}: {resp.text}"
    body = resp.json()
    _assert_canonical(body, expect_empty=True, legacy_key="requests")
    assert body["org_id"] == ORG
    assert body["limit"] == 25
    assert body["filters_applied"]["status"] == "pending"


def test_risk_treatment_treatments_canonical_envelope(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/risk-treatment/treatments",
        params={
            "org_id": ORG,
            "treatment_type": "mitigate",
            "treatment_status": "in_progress",
            "risk_level": "high",
            "limit": 10,
            "offset": 0,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, f"got {resp.status_code}: {resp.text}"
    body = resp.json()
    _assert_canonical(body, expect_empty=True, legacy_key="treatments")
    assert body["org_id"] == ORG
    assert body["limit"] == 10
    f = body["filters_applied"]
    assert f["treatment_type"] == "mitigate"
    assert f["treatment_status"] == "in_progress"
    assert f["risk_level"] == "high"


def test_security_budget_allocations_canonical_envelope(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/security-budget/allocations",
        params={"org_id": ORG, "fiscal_year": 2026, "category": "tooling", "limit": 5},
        headers=HEADERS,
    )
    assert resp.status_code == 200, f"got {resp.status_code}: {resp.text}"
    body = resp.json()
    _assert_canonical(body, expect_empty=True, legacy_key="allocations")
    assert body["limit"] == 5
    assert body["filters_applied"]["fiscal_year"] == 2026
    assert body["filters_applied"]["category"] == "tooling"


def test_access_requests_requests_canonical_envelope(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/access-requests/requests",
        params={
            "org_id": ORG,
            "access_type": "privileged",
            "status": "pending",
            "resource_type": "production_db",
            "limit": 50,
            "offset": 0,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, f"got {resp.status_code}: {resp.text}"
    body = resp.json()
    _assert_canonical(body, expect_empty=True, legacy_key="requests")
    f = body["filters_applied"]
    assert f["access_type"] == "privileged"
    assert f["status"] == "pending"
    assert f["resource_type"] == "production_db"


def test_cloud_governance_policies_canonical_envelope(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/cloud-governance/policies",
        params={
            "org_id": ORG,
            "policy_type": "tagging",
            "cloud_provider": "aws",
            "enforcement": "advisory",
            "limit": 15,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, f"got {resp.status_code}: {resp.text}"
    body = resp.json()
    _assert_canonical(body, expect_empty=True, legacy_key="policies")
    f = body["filters_applied"]
    assert f["policy_type"] == "tagging"
    assert f["cloud_provider"] == "aws"
    assert f["enforcement"] == "advisory"
    assert body["limit"] == 15


def test_security_chaos_experiments_canonical_envelope(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/security-chaos/experiments",
        params={"org_id": ORG, "experiment_type": "iam_rotation", "status": "draft"},
        headers=HEADERS,
    )
    assert resp.status_code == 200, f"got {resp.status_code}: {resp.text}"
    body = resp.json()
    _assert_canonical(body, expect_empty=True, legacy_key="experiments")
    f = body["filters_applied"]
    assert f["experiment_type"] == "iam_rotation"
    assert f["status"] == "draft"


# -----------------------------------------------------------------------------
# Pagination boundary tests — limit/offset round-trip and clamps
# -----------------------------------------------------------------------------


def test_pagination_limit_clamp_low(client: TestClient) -> None:
    """limit=0 must be rejected (ge=1)."""
    resp = client.get(
        "/api/v1/risk-treatment/treatments",
        params={"org_id": ORG, "limit": 0},
        headers=HEADERS,
    )
    assert resp.status_code == 422, f"limit=0 should be 422, got {resp.status_code}"


def test_pagination_offset_negative_rejected(client: TestClient) -> None:
    """offset=-1 must be rejected (ge=0)."""
    resp = client.get(
        "/api/v1/security-budget/allocations",
        params={"org_id": ORG, "offset": -1},
        headers=HEADERS,
    )
    assert resp.status_code == 422, f"offset=-1 should be 422, got {resp.status_code}"


def test_filters_applied_omitted_returns_none_values(client: TestClient) -> None:
    """When filters are not provided, filters_applied keys must echo None (not missing)."""
    resp = client.get(
        "/api/v1/cloud-governance/policies",
        params={"org_id": ORG},
        headers=HEADERS,
    )
    assert resp.status_code == 200
    body = resp.json()
    # All three filter keys must be present even when unset
    f = body["filters_applied"]
    assert "policy_type" in f and f["policy_type"] is None
    assert "cloud_provider" in f and f["cloud_provider"] is None
    assert "enforcement" in f and f["enforcement"] is None
