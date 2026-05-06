"""Test: GET /api/v1/rules/ is wired to DynamicRuleDSLEngine (Multica #4038)."""
import sys

sys.path.insert(0, "suite-api")
sys.path.insert(0, "suite-core")


def test_list_rules_returns_valid_envelope():
    """Endpoint must return dict with 'items', 'count', 'router' keys — not a 501."""
    from fastapi.testclient import TestClient
    from apps.api.wave_c_router import rules_router
    from apps.api.auth_deps import api_key_auth
    from fastapi import FastAPI

    app = FastAPI()
    # Override auth so this unit test doesn't require a real API key
    app.dependency_overrides[api_key_auth] = lambda: "test-user"
    app.include_router(rules_router)

    client = TestClient(app, raise_server_exceptions=True)
    resp = client.get("/api/v1/rules/", params={"org_id": "test-org"})
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "items" in data
    assert "count" in data
    assert data["router"] == "rules"
    assert isinstance(data["items"], list)


def test_dynamic_rule_dsl_engine_list_rules():
    """DynamicRuleDSLEngine.list_rules must return a list (was unreachable via broken import)."""
    from core.dynamic_rule_dsl_engine import DynamicRuleDSLEngine
    eng = DynamicRuleDSLEngine()
    result = eng.list_rules(org_id="default")
    assert isinstance(result, list)
