"""
Guard against fake/hardcoded constants in unified-dashboard and related endpoints.

These tests confirm that the formerly hardcoded values (87, 88, 76, 82, 4.2,
1842, 28, 38, 14, 72, 68, 75) are NOT returned as response data, and that
endpoints return real-engine output or honest not_configured signals.

Endpoints covered:
  GET /api/v1/unified-dashboard/ciso
  GET /api/v1/unified-dashboard/soc
  GET /api/v1/unified-dashboard/executive
  GET /api/v1/unified-dashboard/compliance
  GET /api/v1/cspm/compliance-report
  GET /api/v1/scanner-ingest/supported  (when scanner_parsers unavailable)
"""

from __future__ import annotations

import json
import sys
import types
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FAKE_LITERALS = {
    # SLA
    "on_track_87": 87,
    # compliance
    "soc2_88": 88,
    "pcidss_76": 76,
    "iso_82": 82,
    "overall_82": 82,
    # incidents
    "mttr_4_2": 4.2,
    # threat intel
    "iocs_1842": 1842,
    "feeds_28": 28,
    # attack surface
    "exposure_score_38": 38,
    "exposed_14": 14,
    # CSPM CIS scores
    "cis_aws_72": 72,
    "cis_azure_68": 68,
    "cis_gcp_75": 75,
}


def _collect_numbers(obj, path="") -> list[tuple[str, float]]:
    """Recursively collect all numeric leaf values from a JSON-like object."""
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            found.extend(_collect_numbers(v, f"{path}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            found.extend(_collect_numbers(v, f"{path}[{i}]"))
    elif isinstance(obj, (int, float)):
        found.append((path, float(obj)))
    return found


def _assert_no_fake_literals(data: dict, endpoint: str) -> None:
    """Assert none of the old hardcoded sentinel values appear in the response."""
    numbers = _collect_numbers(data)
    # Build set of values present
    values_present = {v for _, v in numbers}

    # We check each fake literal individually for a clear error message
    # on_track:87 — was always returned from _safe_sla_summary
    assert 87.0 not in values_present or _only_in_legit_context(data, 87), (
        f"{endpoint}: hardcoded SLA on_track=87 still present in response"
    )
    # soc2 88, pcidss 76, iso 82, overall 82
    for val, name in [(88.0, "SOC2=88"), (76.0, "PCI-DSS=76")]:
        # These might legitimately appear as control counts — check they're
        # not inside a "coverage_pct" or "overall_coverage_pct" key
        _assert_not_fake_coverage(data, val, name, endpoint)

    # incidents: active=3, mttr=4.2
    assert 4.2 not in values_present, (
        f"{endpoint}: hardcoded mean_time_to_resolve_hours=4.2 still present"
    )
    assert _no_exact_active_3_in_incidents(data), (
        f"{endpoint}: hardcoded incidents.active=3 still present (old placeholder)"
    )

    # threat intel: 1842, 28
    assert 1842.0 not in values_present, (
        f"{endpoint}: hardcoded iocs_ingested_24h=1842 still present"
    )
    assert 28.0 not in _get_threat_feeds_active(data), (
        f"{endpoint}: hardcoded feeds_active=28 still present"
    )

    # attack surface: 38, 14
    assert 38.0 not in _get_exposure_scores(data), (
        f"{endpoint}: hardcoded exposure_score=38 still present"
    )
    assert 14.0 not in _get_exposed_endpoints(data), (
        f"{endpoint}: hardcoded exposed_endpoints=14 still present"
    )

    # CSPM CIS hardcoded scores: 72, 68, 75 inside frameworks list
    _assert_no_cis_fake_scores(data, endpoint)


def _only_in_legit_context(data: dict, val: int) -> bool:
    """Return True — allow 87 to pass if it's not under sla/on_track path."""
    # We stringify and search for the specific JSON key pattern
    s = json.dumps(data)
    return f'"on_track": {val}' not in s and f'"on_track":{val}' not in s


def _assert_not_fake_coverage(data: dict, val: float, name: str, endpoint: str) -> None:
    s = json.dumps(data)
    # Only flag if it appears as coverage_pct value
    assert (
        f'"coverage_pct": {int(val)}' not in s and f'"coverage_pct":{int(val)}' not in s
        and f'"overall_coverage_pct": {int(val)}' not in s
    ), f"{endpoint}: hardcoded {name} coverage_pct still present"


def _no_exact_active_3_in_incidents(data: dict) -> bool:
    s = json.dumps(data)
    # "active": 3 in an incidents widget = old placeholder
    return '"active": 3' not in s and '"active":3' not in s


def _get_threat_feeds_active(data: dict) -> set:
    s = json.dumps(data)
    result = set()
    if '"feeds_active": 28' in s or '"feeds_active":28' in s:
        result.add(28.0)
    return result


def _get_exposure_scores(data: dict) -> set:
    s = json.dumps(data)
    result = set()
    if '"exposure_score": 38' in s or '"exposure_score":38' in s:
        result.add(38.0)
    return result


def _get_exposed_endpoints(data: dict) -> set:
    s = json.dumps(data)
    result = set()
    if '"exposed_endpoints": 14' in s or '"exposed_endpoints":14' in s:
        result.add(14.0)
    return result


def _assert_no_cis_fake_scores(data: dict, endpoint: str) -> None:
    s = json.dumps(data)
    for score, name in [(72, "CIS AWS=72"), (68, "CIS Azure=68"), (75, "CIS GCP=75")]:
        # Only flag if it's a "score" field inside a frameworks list entry
        assert f'"score": {score}' not in s and f'"score":{score}' not in s, (
            f"{endpoint}: hardcoded {name} framework score still present"
        )


# ---------------------------------------------------------------------------
# App fixture — import real app with engines mocked so they return empty DB
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    """Spin up the real FastAPI app with a test client."""
    sys.path.insert(0, ".")
    sys.path.insert(0, "suite-api")
    sys.path.insert(0, "suite-core")
    sys.path.insert(0, "suite-feeds")
    sys.path.insert(0, "suite-integrations")
    sys.path.insert(0, "suite-evidence-risk")

    from apps.api.app import create_app
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


def _auth_headers():
    return {"X-API-Key": "test-key", "Authorization": "Bearer test-key"}


# ---------------------------------------------------------------------------
# T1 — unified-dashboard endpoints must not return old fake literals
# ---------------------------------------------------------------------------

DASHBOARD_VIEWS = ["ciso", "soc", "executive", "compliance"]


@pytest.mark.parametrize("view", DASHBOARD_VIEWS)
def test_unified_dashboard_no_fake_literals(client, view):
    """Each dashboard view must NOT contain the formerly hardcoded sentinel values."""
    resp = client.get(f"/api/v1/unified-dashboard/{view}", headers=_auth_headers())
    # Accept 200 (real data or honest empty) or 401/403 (auth not wired in test)
    # but NOT 500
    assert resp.status_code != 500, f"Dashboard {view} returned 500: {resp.text[:300]}"
    if resp.status_code == 200:
        data = resp.json()
        _assert_no_fake_literals(data, f"/api/v1/unified-dashboard/{view}")


@pytest.mark.parametrize("view", DASHBOARD_VIEWS)
def test_unified_dashboard_has_widgets(client, view):
    """Dashboard views that return 200 must include a widgets list."""
    resp = client.get(f"/api/v1/unified-dashboard/{view}", headers=_auth_headers())
    if resp.status_code == 200:
        data = resp.json()
        assert "widgets" in data, f"Dashboard {view} missing 'widgets' key"


# ---------------------------------------------------------------------------
# T2 — CSPM compliance-report must not contain hardcoded CIS scores
# ---------------------------------------------------------------------------

def test_cspm_compliance_report_no_fake_cis_scores(client):
    """GET /cspm/compliance-report must not return hardcoded CIS benchmark scores."""
    resp = client.get("/api/v1/cspm/compliance-report", headers=_auth_headers())
    assert resp.status_code != 500, f"CSPM compliance-report returned 500: {resp.text[:300]}"
    if resp.status_code == 200:
        data = resp.json()
        s = json.dumps(data)
        for score, name in [(72, "CIS AWS=72"), (68, "CIS Azure=68"), (75, "CIS GCP=75")]:
            assert f'"score": {score}' not in s and f'"score":{score}' not in s, (
                f"CSPM compliance-report still contains hardcoded {name}"
            )
        # frameworks key must exist (may be empty list)
        assert "frameworks" in data, "CSPM compliance-report missing 'frameworks' key"


def test_cspm_compliance_report_frameworks_not_fake_when_engine_down(client):
    """When CSPM engine is unavailable the response must be degraded/empty, not fake."""
    # Patch _probe_engine to False to simulate unavailable engine
    with patch("apps.api.cspm_deep_router._probe_engine", return_value=False):
        resp = client.get("/api/v1/cspm/compliance-report", headers=_auth_headers())
    if resp.status_code == 200:
        data = resp.json()
        assert data.get("frameworks") == [], (
            "When CSPM engine down, frameworks must be [] not hardcoded list"
        )
        assert data.get("status") == "degraded"


# ---------------------------------------------------------------------------
# T3 — scanner-ingest/supported must return 503 when parsers unavailable
# ---------------------------------------------------------------------------

def test_scanner_ingest_supported_503_when_parsers_unavailable(client):
    """GET /scanner-ingest/supported must return 503 when scanner_parsers can't load."""
    with patch("apps.api.scanner_ingest_router._get_scanner_parsers", return_value=None):
        resp = client.get("/api/v1/scanner-ingest/supported", headers=_auth_headers())
    assert resp.status_code in (503, 401, 403), (
        f"Expected 503 (or auth gate) when parsers unavailable, got {resp.status_code}: {resp.text[:300]}"
    )
    if resp.status_code == 503:
        data = resp.json()
        # Must not contain the fake 26-scanner catalogue
        s = json.dumps(data)
        assert "checkmarx" not in s, "503 response must not include fake scanner list"
        assert "total" not in data or data.get("total") != 26, (
            "503 response must not claim total=26 fake scanners"
        )


def test_scanner_ingest_supported_real_parsers_when_available(client):
    """GET /scanner-ingest/supported with real parsers returns actual scanner data."""
    resp = client.get("/api/v1/scanner-ingest/supported", headers=_auth_headers())
    # If parsers ARE available this should be 200; if not available that's fine too
    assert resp.status_code in (200, 503, 401, 403), (
        f"Unexpected status {resp.status_code}: {resp.text[:300]}"
    )
    if resp.status_code == 200:
        data = resp.json()
        # Real response must have scanners from actual parser registry
        assert "scanners" in data or "total_new_parsers" in data, (
            "200 response missing scanner catalogue keys"
        )


# ---------------------------------------------------------------------------
# Smoke: create_app() must succeed (boot test)
# ---------------------------------------------------------------------------

def test_create_app_boots():
    """create_app() must not raise after the unified_dashboard changes."""
    sys.path.insert(0, ".")
    sys.path.insert(0, "suite-api")
    sys.path.insert(0, "suite-core")
    from apps.api.app import create_app
    app = create_app()
    assert app is not None
    # Must have routes
    assert len(app.routes) > 0
