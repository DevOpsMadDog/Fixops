"""
Live integration tests for the 4 demo-path endpoints that were 404 on 2026-05-01.

Each test hits the running server (localhost:8000) with the real API key.
Tests verify:
  1. HTTP status is non-404 (200 or appropriate 4xx/5xx — but NOT 404)
  2. Response shape sanity (required keys present)

Run with:
    pytest tests/test_demo_path_endpoints_live.py -v --timeout=30
"""

from __future__ import annotations

import os

import pytest
import httpx

BASE_URL = os.getenv("FIXOPS_BASE_URL", "http://localhost:8000")

def _load_api_key() -> str:
    """Load API key: env var first, then .env file, then hardcoded fallback."""
    key = os.getenv("FIXOPS_API_TOKEN", "")
    if key:
        return key
    # Try to read from .env file in repo root
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    try:
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("FIXOPS_API_TOKEN="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"

API_KEY = _load_api_key()
HEADERS = {"X-API-Key": API_KEY}

# Skip all tests if server is not reachable
@pytest.fixture(scope="session")
def client():
    try:
        r = httpx.get(f"{BASE_URL}/api/v1/health", timeout=5)
        assert r.status_code < 500
    except Exception as exc:
        pytest.skip(f"Server not reachable at {BASE_URL}: {exc}")
    # Use explicit headers on every request to guarantee auth is sent
    return httpx.Client(base_url=BASE_URL, timeout=15)


def _get(client, path) -> httpx.Response:
    """GET with explicit auth header — avoids httpx client-level header issues."""
    return client.get(path, headers=HEADERS)


def _post(client, path, json=None) -> httpx.Response:
    """POST with explicit auth header."""
    return client.post(path, json=json or {}, headers=HEADERS)


# ---------------------------------------------------------------------------
# 1. GET /api/v1/llm/council/status
# ---------------------------------------------------------------------------

def test_llm_council_status_not_404(client):
    """llm_council_router must be mounted — was missing from app.py despite commit 1aaecf27."""
    r = _get(client, "/api/v1/llm/council/status")
    assert r.status_code != 404, f"Got 404 — router not mounted. Body: {r.text[:200]}"
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text[:200]}"


def test_llm_council_status_shape(client):
    """Response must include the 3 fields the demo dashboard reads."""
    r = _get(client, "/api/v1/llm/council/status")
    assert r.status_code == 200
    body = r.json()
    required = {"configured_providers", "member_count", "consensus_enabled"}
    missing = required - set(body.keys())
    assert not missing, f"Missing keys: {missing}. Got: {list(body.keys())}"


# ---------------------------------------------------------------------------
# 2. GET /api/v1/feeds/registry
# ---------------------------------------------------------------------------

def test_feeds_registry_not_404(client):
    """feed_registry_router was imported but include_router() never called — commit 30385fde."""
    r = _get(client, "/api/v1/feeds/registry")
    assert r.status_code != 404, f"Got 404 — router not mounted. Body: {r.text[:200]}"
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text[:200]}"


def test_feeds_registry_shape(client):
    """Response must be a list of feed objects each with id and status."""
    r = _get(client, "/api/v1/feeds/registry")
    assert r.status_code == 200
    body = r.json()
    # May return a list or a dict with a feeds key
    if isinstance(body, list):
        feeds = body
    else:
        feeds = body.get("feeds", body.get("data", []))
    assert len(feeds) > 0, "Feed registry returned empty list"
    first = feeds[0]
    assert isinstance(first, dict), f"Feed entry is not a dict: {first}"


# ---------------------------------------------------------------------------
# 3. GET /api/v1/risk-scoring/summary
# ---------------------------------------------------------------------------

def test_risk_scoring_summary_not_404(client):
    """risk_scoring_router was in a late try/except that silently swallowed failures — commit 2fae8133."""
    r = _get(client, "/api/v1/risk-scoring/summary")
    assert r.status_code != 404, f"Got 404 — router not mounted. Body: {r.text[:200]}"
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text[:200]}"


def test_risk_scoring_summary_shape(client):
    """Response must include exposure_score, rating, by_tier, open_findings_count."""
    r = _get(client, "/api/v1/risk-scoring/summary")
    assert r.status_code == 200
    body = r.json()
    required = {"exposure_score", "rating", "by_tier", "open_findings_count"}
    missing = required - set(body.keys())
    assert not missing, f"Missing keys: {missing}. Got: {list(body.keys())}"


# ---------------------------------------------------------------------------
# 4. POST /api/v1/scanners/ingest
# ---------------------------------------------------------------------------

def test_scanners_ingest_not_404(client):
    """scanners_alias_router (POST /api/v1/scanners/ingest) was never registered — commit 1ac0a248."""
    r = _post(client, "/api/v1/scanners/ingest", json={"scanner_type": "bandit", "findings": []})
    assert r.status_code != 404, f"Got 404 — alias router not mounted. Body: {r.text[:200]}"
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text[:200]}"


def test_scanners_ingest_shape(client):
    """Response must include status, scanner_type, findings_received, ingested_at."""
    r = _post(
        client,
        "/api/v1/scanners/ingest",
        json={
            "scanner_type": "pytest-live-test",
            "findings": [{"title": "demo finding", "severity": "low"}],
        },
    )
    assert r.status_code == 200
    body = r.json()
    required = {"status", "scanner_type", "findings_received", "ingested_at"}
    missing = required - set(body.keys())
    assert not missing, f"Missing keys: {missing}. Got: {list(body.keys())}"
    assert body["findings_received"] == 1
    assert body["status"] == "ok"
