from __future__ import annotations

from typing import Dict

import pytest
from fastapi.testclient import TestClient

from src.main import create_app
from src.config.settings import get_settings


API_TOKEN = "enterprise-token"


@pytest.fixture()
def enterprise_enhanced_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("FIXOPS_API_KEY", API_TOKEN)
    monkeypatch.setenv("FIXOPS_ALLOWED_ORIGINS", "http://localhost")
    monkeypatch.setenv(
        "FIXOPS_EVIDENCE_KEY",
        "Zz6A0n4P3skS8F6edSxE2xe50Tzw9uQWGWp9JYG1ChE=",
    )
    monkeypatch.setenv("FIXOPS_JIRA_TOKEN", "jira-token")
    monkeypatch.setenv("FIXOPS_JIRA_ENDPOINT", "https://jira.example.com")
    monkeypatch.setenv("FIXOPS_CONFLUENCE_TOKEN", "confluence-token")
    monkeypatch.setenv("FIXOPS_CONFLUENCE_ENDPOINT", "https://confluence.example.com")
    monkeypatch.setenv("ENVIRONMENT", "development")
    get_settings.cache_clear()
    app = create_app()
    client = TestClient(app)
    try:
        yield client
    finally:
        client.close()
        get_settings.cache_clear()


def _auth() -> Dict[str, str]:
    return {"Authorization": f"Bearer {API_TOKEN}"}


def test_capabilities_return_signals(enterprise_enhanced_client: TestClient) -> None:
    response = enterprise_enhanced_client.get("/api/v1/enhanced/capabilities", headers=_auth())
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ready"
    assert payload.get("supported_llms")
    signals = payload.get("signals", {})
    assert signals.get("ssvc_label") in {"Track", "Attend", "Act"}


def test_analysis_endpoint_returns_consensus(enterprise_enhanced_client: TestClient) -> None:
    body = {
        "service_name": "claims-api",
        "security_findings": [
            {"id": "FND-1", "severity": "high", "message": "SQL injection"},
            {"id": "FND-2", "severity": "medium", "message": "Dependency risk"},
        ],
        "business_context": {"tier": "tier1"},
    }
    response = enterprise_enhanced_client.post(
        "/api/v1/enhanced/analysis",
        json=body,
        headers=_auth(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["final_decision"]
    assert payload["individual_analyses"]
    assert payload["signals"]["ssvc_label"] in {"Act", "Attend", "Track"}


def test_signals_allows_overrides(enterprise_enhanced_client: TestClient) -> None:
    response = enterprise_enhanced_client.get(
        "/api/v1/enhanced/signals",
        params={"verdict": "review", "confidence": 0.55},
        headers=_auth(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["ssvc_label"] == "Attend"
    assert pytest.approx(payload["confidence"], rel=1e-6) == 0.55


def test_missing_token_rejected(enterprise_enhanced_client: TestClient) -> None:
    response = enterprise_enhanced_client.get("/api/v1/enhanced/capabilities")
    assert response.status_code == 401
    response = enterprise_enhanced_client.post(
        "/api/v1/enhanced/analysis",
        json={"service_name": "claims", "security_findings": []},
    )
    assert response.status_code == 401
