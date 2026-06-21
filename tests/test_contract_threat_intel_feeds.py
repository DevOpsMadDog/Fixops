"""SPEC-033 C8 — UI↔API contract: threat-intel feed status (no fabricated counts).

Pins /api/v1/threat-intel/feeds/status + /feeds/summary so the honest-empty fix
(GAP_MAP #9 — no more hardcoded 3200/8900/600/1100) can't regress, and the shape
the UI feed widgets consume stays stable. Additive contract test, no API change.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FIXOPS_API_TOKEN", "ci-test-token")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

_TOKEN = os.environ.get("FIXOPS_API_TOKEN", "ci-test-token")
_FABRICATED = {3200, 8900, 600, 1100}  # the old hardcoded magic numbers (GAP_MAP #9)


@pytest.fixture(scope="module")
def client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import apps.api.threat_intel_router as m

    app = FastAPI()
    app.include_router(m.router)
    return TestClient(app, raise_server_exceptions=False)


def test_feeds_status_shape_and_no_fabricated_counts(client):
    resp = client.get("/api/v1/threat-intel/feeds/status", headers={"X-API-Key": _TOKEN})
    assert resp.status_code == 200, f"{resp.status_code}: {resp.text[:200]}"
    body = resp.json()
    assert "feeds" in body and isinstance(body["feeds"], list) and body["feeds"]
    for feed in body["feeds"]:
        # contract: every feed exposes these fields
        for k in ("name", "source", "ioc_count", "health"):
            assert k in feed, f"feed missing '{k}': {sorted(feed)}"
        assert isinstance(feed["ioc_count"], int) and feed["ioc_count"] >= 0
        # NO-MOCKS: feeds with no API key / never fetched must not report a
        # fabricated magic count. URLhaus/ThreatFox have no fetch wired -> 0.
        if feed["source"] in ("urlhaus", "threatfox") and feed.get("health") == "degraded":
            assert feed["ioc_count"] == 0, f"{feed['source']} still fabricates a count: {feed['ioc_count']}"
    for key in ("total_feeds", "healthy_feeds", "degraded_feeds"):
        assert key in body and isinstance(body[key], int)


def test_feeds_summary_no_fabricated_magic_numbers(client):
    resp = client.get("/api/v1/threat-intel/feeds/summary", headers={"X-API-Key": _TOKEN})
    assert resp.status_code == 200, f"{resp.status_code}: {resp.text[:200]}"
    body = resp.json()
    assert "by_source" in body and "by_type" in body and "total_iocs" in body
    # urlhaus/threatfox have no live fetch wired -> must be 0 (not 3200/8900)
    assert body["by_source"].get("urlhaus", 0) == 0
    assert body["by_source"].get("threatfox", 0) == 0
    # none of the old fabricated constants should appear as a source/type total
    for v in list(body["by_source"].values()) + list(body["by_type"].values()):
        assert v not in _FABRICATED, f"fabricated magic number resurfaced: {v}"
