"""
Batch-7 empty-endpoint regression — verifies the canonical envelope shape
applied to 7 class-c endpoints (empty IS correct for fresh tenants).

Canonical envelope contract (mirrors batch-6, ref docs/empty_endpoints_triage_2026-04-26.md):
    {
        "items": [...],
        "<legacy_key>": [...],   # back-compat (reports / incidents / captures / etc.)
        "total": int,
        "org_id": str,
        "limit": int,
        "offset": int,
        "filters_applied": {...},
        "hint": str,             # only present when total == 0
    }

Endpoints covered (all class-c per docs/empty_endpoints_triage_2026-04-26.md):
- GET /api/v1/posture-reports/reports         (#7)
- GET /api/v1/cloud-ir/incidents              (#17)
- GET /api/v1/network-forensics/captures      (#21)
- GET /api/v1/network-segmentation/segments   (#22)
- GET /api/v1/microsegmentation/segments      (#23)
- GET /api/v1/awareness-gamification/challenges (#29)
- GET /api/v1/gdpr/activities                 (#30)

Each endpoint asserts:
    1. status_code == 200
    2. envelope contains: items, total, org_id, limit, offset, filters_applied
    3. when empty: total == 0 and `hint` non-empty
    4. pagination params (limit, offset) round-trip back into the envelope
    5. filters_applied echoes back the supplied filter values verbatim
    6. boundary tests: limit=0 → 422, offset=-1 → 422, omitted-filter echoes None
"""

from __future__ import annotations

import os
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

# Set API key BEFORE importing the app so api_key_auth picks it up.
API_KEY = "fixops_test_key_batch7"
os.environ["FIXOPS_API_TOKEN"] = API_KEY
os.environ.setdefault("FIXOPS_MODE", "dev")

from apps.api.app import create_app  # noqa: E402

HEADERS = {"X-API-Key": API_KEY}
ORG = "batch7-test-org"

CANONICAL_KEYS = {"items", "total", "org_id", "limit", "offset", "filters_applied"}


@pytest.fixture(scope="module")
def client() -> TestClient:
    app = create_app()
    return TestClient(app)


def _assert_canonical(envelope: Dict[str, Any], *, expect_empty: bool, legacy_key: str) -> None:
    """Assert the envelope conforms to the batch-7 canonical contract."""
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


def test_posture_reports_reports_canonical_envelope(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/posture-reports/reports",
        params={"org_id": ORG, "report_type": "executive", "limit": 25, "offset": 0},
        headers=HEADERS,
    )
    assert resp.status_code == 200, f"got {resp.status_code}: {resp.text}"
    body = resp.json()
    _assert_canonical(body, expect_empty=True, legacy_key="reports")
    assert body["org_id"] == ORG
    assert body["limit"] == 25
    assert body["filters_applied"]["report_type"] == "executive"
    # Status was not supplied → must echo as None
    assert body["filters_applied"]["status"] is None


def test_cloud_ir_incidents_canonical_envelope(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/cloud-ir/incidents",
        params={
            "org_id": ORG,
            "status": "open",
            "cloud_provider": "aws",
            "limit": 10,
            "offset": 0,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, f"got {resp.status_code}: {resp.text}"
    body = resp.json()
    _assert_canonical(body, expect_empty=True, legacy_key="incidents")
    assert body["org_id"] == ORG
    assert body["limit"] == 10
    assert body["filters_applied"]["status"] == "open"
    assert body["filters_applied"]["cloud_provider"] == "aws"


def test_network_forensics_captures_canonical_envelope(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/network-forensics/captures",
        params={"org_id": ORG, "status": "in_progress", "limit": 50, "offset": 0},
        headers=HEADERS,
    )
    assert resp.status_code == 200, f"got {resp.status_code}: {resp.text}"
    body = resp.json()
    _assert_canonical(body, expect_empty=True, legacy_key="captures")
    assert body["org_id"] == ORG
    assert body["limit"] == 50
    assert body["filters_applied"]["status"] == "in_progress"


def test_network_segmentation_segments_canonical_envelope(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/network-segmentation/segments",
        params={"org_id": ORG, "segment_type": "dmz", "limit": 100, "offset": 0},
        headers=HEADERS,
    )
    assert resp.status_code == 200, f"got {resp.status_code}: {resp.text}"
    body = resp.json()
    _assert_canonical(body, expect_empty=True, legacy_key="segments")
    assert body["org_id"] == ORG
    assert body["limit"] == 100
    assert body["filters_applied"]["segment_type"] == "dmz"


def test_microsegmentation_segments_canonical_envelope(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/microsegmentation/segments",
        params={
            "org_id": ORG,
            "segment_type": "workload",
            "enforcement_mode": "monitoring",
            "limit": 30,
            "offset": 0,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, f"got {resp.status_code}: {resp.text}"
    body = resp.json()
    _assert_canonical(body, expect_empty=True, legacy_key="segments")
    assert body["org_id"] == ORG
    assert body["limit"] == 30
    assert body["filters_applied"]["segment_type"] == "workload"
    assert body["filters_applied"]["enforcement_mode"] == "monitoring"


def test_awareness_gamification_challenges_canonical_envelope(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/awareness-gamification/challenges",
        params={
            "org_id": ORG,
            "challenge_type": "quiz",
            "difficulty": "medium",
            "limit": 20,
            "offset": 0,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, f"got {resp.status_code}: {resp.text}"
    body = resp.json()
    _assert_canonical(body, expect_empty=True, legacy_key="challenges")
    assert body["org_id"] == ORG
    assert body["limit"] == 20
    assert body["filters_applied"]["challenge_type"] == "quiz"
    assert body["filters_applied"]["difficulty"] == "medium"


def test_gdpr_activities_canonical_envelope(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/gdpr/activities",
        params={
            "org_id": ORG,
            "lawful_basis": "consent",
            "status": "active",
            "limit": 40,
            "offset": 0,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, f"got {resp.status_code}: {resp.text}"
    body = resp.json()
    _assert_canonical(body, expect_empty=True, legacy_key="activities")
    assert body["org_id"] == ORG
    assert body["limit"] == 40
    assert body["filters_applied"]["lawful_basis"] == "consent"
    assert body["filters_applied"]["status"] == "active"


# -----------------------------------------------------------------------------
# Boundary tests — pagination + filter-echo behaviour
# -----------------------------------------------------------------------------


def test_batch7_limit_zero_rejected(client: TestClient) -> None:
    """limit=0 must be rejected (422) — ge=1 constraint."""
    resp = client.get(
        "/api/v1/posture-reports/reports",
        params={"org_id": ORG, "limit": 0, "offset": 0},
        headers=HEADERS,
    )
    assert resp.status_code == 422, f"limit=0 should 422, got {resp.status_code}: {resp.text}"


def test_batch7_offset_negative_rejected(client: TestClient) -> None:
    """offset=-1 must be rejected (422) — ge=0 constraint."""
    resp = client.get(
        "/api/v1/cloud-ir/incidents",
        params={"org_id": ORG, "limit": 50, "offset": -1},
        headers=HEADERS,
    )
    assert resp.status_code == 422, f"offset=-1 should 422, got {resp.status_code}: {resp.text}"


def test_batch7_omitted_filters_echo_none(client: TestClient) -> None:
    """Every filter param defaults to None and MUST be echoed as None in filters_applied."""
    resp = client.get(
        "/api/v1/microsegmentation/segments",
        params={"org_id": ORG},  # no filter params at all
        headers=HEADERS,
    )
    assert resp.status_code == 200, f"got {resp.status_code}: {resp.text}"
    body = resp.json()
    fa = body["filters_applied"]
    # Both filters must be present in the dict (echoed as None) — no missing keys
    assert "segment_type" in fa, "segment_type missing from filters_applied"
    assert "enforcement_mode" in fa, "enforcement_mode missing from filters_applied"
    assert fa["segment_type"] is None
    assert fa["enforcement_mode"] is None
    # Default pagination must be applied
    assert body["limit"] == 50
    assert body["offset"] == 0


def test_batch7_limit_too_high_rejected(client: TestClient) -> None:
    """limit=501 must be rejected (422) — le=500 constraint."""
    resp = client.get(
        "/api/v1/network-forensics/captures",
        params={"org_id": ORG, "limit": 501, "offset": 0},
        headers=HEADERS,
    )
    assert resp.status_code == 422, f"limit=501 should 422, got {resp.status_code}: {resp.text}"
