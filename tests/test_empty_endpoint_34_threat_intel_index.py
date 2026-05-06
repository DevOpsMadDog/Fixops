"""Test: GET /api/v1/threat-intel/ wired to ThreatIntelCorrelator.get_active_threats"""
import sys
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops")
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-core")
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-api")

from fastapi.testclient import TestClient


def _make_app():
    from fastapi import FastAPI
    from apps.api.threat_intel_router import router
    app = FastAPI()
    app.include_router(router)
    return app


def test_threat_intel_index_calls_get_active_threats():
    from core.threat_intel_correlator import ThreatActor
    fake_actor = ThreatActor(
        id="actor-1", name="APT-Test", aliases=["TestGroup"],
        ttps=["T1059"], motivation="espionage", origin_country="XX",
        active=True, associated_campaigns=[], iocs=[],
    )
    app = _make_app()
    client = TestClient(app)
    import apps.api.threat_intel_router as mod
    original = mod._correlator.get_active_threats
    mod._correlator.get_active_threats = lambda org_id: [fake_actor]
    try:
        resp = client.get("/api/v1/threat-intel/")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert data["count"] == 1, f"count={data['count']}"
        assert len(data["items"]) == 1, f"items len={len(data['items'])}"
        assert data["items"][0]["name"] == "APT-Test"
        print("PASS: items returned from real engine, not hardcoded []")
    finally:
        mod._correlator.get_active_threats = original


def test_threat_intel_index_empty_when_no_actors():
    app = _make_app()
    client = TestClient(app)
    import apps.api.threat_intel_router as mod
    original = mod._correlator.get_active_threats
    mod._correlator.get_active_threats = lambda org_id: []
    try:
        resp = client.get("/api/v1/threat-intel/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["items"] == []
        print("PASS: empty items when no actors")
    finally:
        mod._correlator.get_active_threats = original


if __name__ == "__main__":
    test_threat_intel_index_calls_get_active_threats()
    test_threat_intel_index_empty_when_no_actors()
    print("ALL TESTS PASSED")
