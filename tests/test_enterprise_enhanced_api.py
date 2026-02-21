"""Tests for the enhanced multi-LLM decision API.

The enhanced routes inject the engine via ``request.app.state.enhanced_engine``
(see ``suite-api/apps/api/routes/enhanced.py``).  We create the app, attach
an ``EnhancedDecisionEngine`` instance to ``app.state``, and exercise the
``/api/v1/enhanced/*`` endpoints.
"""

from __future__ import annotations

from typing import Dict

import pytest
from apps.api.app import create_app
from core.enhanced_decision import EnhancedDecisionEngine
from fastapi.testclient import TestClient

API_TOKEN = "enterprise-token"


@pytest.fixture()
def enterprise_enhanced_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("FIXOPS_API_KEY", API_TOKEN)
    monkeypatch.setenv("FIXOPS_API_TOKEN", API_TOKEN)
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
    engine = EnhancedDecisionEngine()
    app = create_app()
    app.state.enhanced_engine = engine
    client = TestClient(app)
    try:
        yield client
    finally:
        client.close()


@pytest.fixture()
def enterprise_enhanced_client_missing_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> TestClient:
    monkeypatch.setenv("FIXOPS_API_KEY", API_TOKEN)
    monkeypatch.setenv("FIXOPS_API_TOKEN", API_TOKEN)
    monkeypatch.setenv("FIXOPS_ALLOWED_ORIGINS", "http://localhost")
    monkeypatch.setenv(
        "FIXOPS_EVIDENCE_KEY",
        "Zz6A0n4P3skS8F6edSxE2xe50Tzw9uQWGWp9JYG1ChE=",
    )
    monkeypatch.delenv("FIXOPS_JIRA_TOKEN", raising=False)
    monkeypatch.setenv("FIXOPS_JIRA_ENDPOINT", "https://jira.example.com")
    monkeypatch.delenv("FIXOPS_CONFLUENCE_TOKEN", raising=False)
    monkeypatch.setenv("FIXOPS_CONFLUENCE_ENDPOINT", "https://confluence.example.com")
    monkeypatch.setenv("ENVIRONMENT", "development")
    engine = EnhancedDecisionEngine()
    app = create_app()
    app.state.enhanced_engine = engine
    client = TestClient(app)
    try:
        yield client
    finally:
        client.close()


def _auth() -> Dict[str, str]:
    return {"X-API-Key": API_TOKEN}


def test_capabilities_return_signals(enterprise_enhanced_client: TestClient) -> None:
    response = enterprise_enhanced_client.get(
        "/api/v1/enhanced/capabilities", headers=_auth()
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ready"
    assert payload.get("supported_llms")
    signals = payload.get("signals", {})
    assert signals.get("ssvc_label") in {"Track", "Attend", "Act"}


def test_analysis_endpoint_returns_consensus(
    enterprise_enhanced_client: TestClient,
) -> None:
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


def test_capabilities_surface_runtime_warnings_when_tokens_missing(
    enterprise_enhanced_client_missing_tokens: TestClient,
) -> None:
    response = enterprise_enhanced_client_missing_tokens.get(
        "/api/v1/enhanced/capabilities", headers=_auth()
    )
    assert response.status_code == 200
    payload = response.json()
    warnings = payload.get("runtime_warnings")
    assert (
        warnings
    ), "runtime warnings should be surfaced when automation tokens missing"
    assert payload.get("automation_ready") is False


def test_analysis_surfaces_runtime_warnings_when_tokens_missing(
    enterprise_enhanced_client_missing_tokens: TestClient,
) -> None:
    body = {
        "service_name": "claims-api",
        "security_findings": [],
        "business_context": {},
    }
    response = enterprise_enhanced_client_missing_tokens.post(
        "/api/v1/enhanced/analysis",
        json=body,
        headers=_auth(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("runtime_warnings")
    assert payload.get("automation_ready") is False
