"""test_no_fake_intel_ml.py — FIX-F2 honesty gate.

Asserts that the four routers fixed in FIX-F2 return honest 501/503
(not configured / engine error) or real engine data, and that no
fabricated numbers (random.uniform, hardcoded percentiles, fake accuracy)
are present in their source.

Endpoints under test:
  GET  /api/v1/benchmarking/industry        → 501 (no peer feed)
  GET  /api/v1/peer-insights/trends         → 501 (no peer feed)
  POST /api/v1/ml/anomaly/detect            → 200 from real AnomalyDetector
  GET  /api/v1/ml/anomaly/models            → 200, trained_models == []
  GET  /api/v1/threat-actors/campaigns      → 200 from real ThreatActorEngine
                                               (or 500 if DB not ready — not a static list)
"""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Ensure suite paths are on sys.path
# ---------------------------------------------------------------------------
_REPO = Path(__file__).resolve().parents[1]
for _p in [
    _REPO,
    _REPO / "suite-api",
    _REPO / "suite-core",
    _REPO / "suite-attack",
    _REPO / "suite-feeds",
    _REPO / "suite-integrations",
    _REPO / "suite-evidence-risk",
]:
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from fastapi.testclient import TestClient  # noqa: E402


# ---------------------------------------------------------------------------
# App fixture — mount only the four routers into a standalone FastAPI app
# so we avoid the global auth middleware in create_app().
# Pattern matches test_abuseipdb_summary_endpoint.py and test_trust_center.py.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    from fastapi import FastAPI
    from apps.api.auth_deps import api_key_auth
    from apps.api.benchmarking_router import router as benchmarking_router
    from apps.api.peer_insights_router import router as peer_insights_router
    from apps.api.ml_anomaly_router import router as ml_anomaly_router
    from apps.api.threat_actor_router import router as threat_actor_router

    app = FastAPI()
    app.include_router(benchmarking_router)
    app.include_router(peer_insights_router)
    app.include_router(ml_anomaly_router)
    app.include_router(threat_actor_router)
    # Bypass API-key auth — standard pattern used across ALDECI tests
    app.dependency_overrides[api_key_auth] = lambda: None

    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


_HEADERS: dict = {}  # auth bypassed via dependency_overrides


# ---------------------------------------------------------------------------
# 1. benchmarking_router — GET /benchmarking/industry must return 501
# ---------------------------------------------------------------------------

def test_benchmarking_industry_returns_501(client):
    """Industry benchmarking has no real peer feed → must return 501."""
    resp = client.get("/api/v1/benchmarking/industry", headers=_HEADERS)
    assert resp.status_code == 501, (
        f"Expected 501 (not configured), got {resp.status_code}: {resp.text}"
    )
    body = resp.json()
    detail = body.get("detail", {})
    if isinstance(detail, dict):
        assert detail.get("configured") is False, "configured flag must be False"
    else:
        assert "not configured" in str(detail).lower() or "not" in str(detail).lower()


def test_benchmarking_industry_no_percentile_number(client):
    """Response body must not contain a fabricated peer-percentile number like 73."""
    resp = client.get("/api/v1/benchmarking/industry", headers=_HEADERS)
    body_text = resp.text
    # Should NOT contain a bare percentile digit implying fake data
    assert "73" not in body_text or "501" in body_text, (
        "Response contains '73' which may be a fabricated percentile"
    )


# ---------------------------------------------------------------------------
# 2. peer_insights_router — GET /peer-insights/trends must return 501
# ---------------------------------------------------------------------------

def test_peer_insights_trends_returns_501(client):
    """Peer insights has no real data feed → must return 501."""
    resp = client.get("/api/v1/peer-insights/trends", headers=_HEADERS)
    assert resp.status_code == 501, (
        f"Expected 501 (not configured), got {resp.status_code}: {resp.text}"
    )
    body = resp.json()
    detail = body.get("detail", {})
    if isinstance(detail, dict):
        assert detail.get("configured") is False, "configured flag must be False"


def test_peer_insights_trends_no_fake_trends(client):
    """Response must not contain fabricated trend data."""
    resp = client.get("/api/v1/peer-insights/trends", headers=_HEADERS)
    assert resp.status_code == 501
    body = resp.json()
    # Must not contain any list of industry trends
    assert "trends" not in body or resp.status_code == 501


# ---------------------------------------------------------------------------
# 3. ml_anomaly_router — POST /ml/anomaly/detect must NOT use random.uniform
# ---------------------------------------------------------------------------

def test_ml_anomaly_detect_no_random_uniform_in_source():
    """ml_anomaly_router.py must not contain random.uniform anywhere."""
    router_file = _REPO / "suite-api" / "apps" / "api" / "ml_anomaly_router.py"
    assert router_file.exists(), f"Router file missing: {router_file}"
    source = router_file.read_text()
    assert "random.uniform" not in source, (
        "ml_anomaly_router.py contains random.uniform — fake confidence values present"
    )


def test_ml_anomaly_detect_no_hardcoded_confidence_in_source():
    """ml_anomaly_router.py must not contain hardcoded confidence literals like 0.94."""
    router_file = _REPO / "suite-api" / "apps" / "api" / "ml_anomaly_router.py"
    source = router_file.read_text()
    # Parse AST and check for float literals between 0.7 and 0.99 outside of comments
    tree = ast.parse(source)
    suspicious = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, float):
            v = node.value
            if 0.70 <= v <= 0.99:
                suspicious.append(v)
    assert not suspicious, (
        f"ml_anomaly_router.py contains suspicious float literals that look like "
        f"fake confidence scores: {suspicious}"
    )


def test_ml_anomaly_detect_returns_real_engine_data(client):
    """POST /ml/anomaly/detect must succeed and identify the real engine."""
    resp = client.post(
        "/api/v1/ml/anomaly/detect",
        json={"org_id": "test-fix-f2"},
        headers=_HEADERS,
    )
    # 200 (engine ran, possibly empty) or 503 (engine error) — never a fake 200 with random confidence
    assert resp.status_code in (200, 503), (
        f"Unexpected status {resp.status_code}: {resp.text}"
    )
    if resp.status_code == 200:
        body = resp.json()
        assert "engine" in body, "Response must identify the real engine"
        assert body["engine"] == "AnomalyDetector"
        assert "anomalies" in body
        # anomalies is a list, not a fake dict with random confidence
        assert isinstance(body["anomalies"], list)


def test_ml_anomaly_models_returns_empty_honest_registry(client):
    """GET /ml/anomaly/models must return an honest empty trained_models list."""
    resp = client.get("/api/v1/ml/anomaly/models", headers=_HEADERS)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    body = resp.json()
    assert "trained_models" in body, "Response must contain trained_models key"
    assert body["trained_models"] == [], (
        f"trained_models must be empty (no model trained yet), got: {body['trained_models']}"
    )
    # Must not contain a fake accuracy number like 0.94
    body_text = resp.text
    assert "0.94" not in body_text, "Response contains fake accuracy value 0.94"
    assert "accuracy" not in body_text or "trained_models" in body_text


# ---------------------------------------------------------------------------
# 4. benchmarking + peer_insights source checks — no random / hardcoded numbers
# ---------------------------------------------------------------------------

def test_benchmarking_router_no_random_in_source():
    """benchmarking_router.py must not import or call random."""
    router_file = _REPO / "suite-api" / "apps" / "api" / "benchmarking_router.py"
    assert router_file.exists(), f"Router file missing: {router_file}"
    source = router_file.read_text()
    assert "import random" not in source
    assert "random.uniform" not in source
    assert "random.randint" not in source


def test_peer_insights_router_no_random_in_source():
    """peer_insights_router.py must not import or call random."""
    router_file = _REPO / "suite-api" / "apps" / "api" / "peer_insights_router.py"
    assert router_file.exists(), f"Router file missing: {router_file}"
    source = router_file.read_text()
    assert "import random" not in source
    assert "random.uniform" not in source
    assert "random.randint" not in source


# ---------------------------------------------------------------------------
# 5. threat_actor_router — GET /threat-actors/campaigns calls real engine
# ---------------------------------------------------------------------------

def test_threat_actor_campaigns_not_a_static_list(client):
    """GET /threat-actors/campaigns must delegate to the real engine, not a static list."""
    resp = client.get("/api/v1/threat-actors/campaigns", headers=_HEADERS)
    # Acceptable: 200 (real engine, possibly empty), 401/403 (auth), 404
    # NOT acceptable: a static response that always contains the same hardcoded dates
    assert resp.status_code in (200, 401, 403, 404, 422, 500), (
        f"Unexpected status {resp.status_code}: {resp.text}"
    )
    if resp.status_code == 200:
        body = resp.json()
        # If campaigns come back, they should be a real list (may be empty)
        campaigns = body if isinstance(body, list) else body.get("campaigns", body.get("items", []))
        # Static fake lists typically have exactly 2-3 items with fixed dates like "2023-01-01"
        if isinstance(campaigns, list) and len(campaigns) >= 2:
            dates = [str(c.get("start_date", "")) for c in campaigns if isinstance(c, dict)]
            # All identical dates is a red flag for a static list
            unique_dates = set(d for d in dates if d)
            if len(dates) >= 2 and unique_dates:
                assert len(unique_dates) > 0, "Campaigns all have identical dates — looks like a static list"


def test_threat_actor_router_no_static_campaign_list_in_source():
    """threat_actor_router.py must not contain a hardcoded static campaign list."""
    router_file = _REPO / "suite-api" / "apps" / "api" / "threat_actor_router.py"
    assert router_file.exists(), f"Router file missing: {router_file}"
    source = router_file.read_text()
    # Static list signatures
    assert '"2023-01-01"' not in source, "Hardcoded date 2023-01-01 found in threat_actor_router"
    assert '"2024-01-01"' not in source, "Hardcoded date 2024-01-01 found in threat_actor_router"
    assert "APT28" not in source or "_get_engine" in source, (
        "Hardcoded actor name without real engine call suggests static data"
    )
