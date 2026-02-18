"""Regression coverage for the enhanced decision API endpoints."""

from __future__ import annotations

from typing import Dict

import pytest
from fastapi.testclient import TestClient

from apps.api.app import create_app

API_TOKEN = "test-token"


@pytest.fixture()
def enhanced_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("FIXOPS_API_TOKEN", API_TOKEN)
    monkeypatch.setenv(
        "FIXOPS_EVIDENCE_KEY",
        "Zz6A0n4P3skS8F6edSxE2xe50Tzw9uQWGWp9JYG1ChE=",
    )
    monkeypatch.setenv("FIXOPS_JIRA_TOKEN", "jira-token")
    monkeypatch.setenv("FIXOPS_JIRA_ENDPOINT", "https://jira.example.com")
    monkeypatch.setenv("FIXOPS_CONFLUENCE_TOKEN", "confluence-token")
    monkeypatch.setenv("FIXOPS_CONFLUENCE_ENDPOINT", "https://confluence.example.com")
    app = create_app()
    client = TestClient(app)
    yield client
    client.close()


def _auth_headers() -> Dict[str, str]:
    return {"X-API-Key": API_TOKEN}


def test_capabilities_exposes_supported_models(enhanced_client: TestClient) -> None:
    response = enhanced_client.get(
        "/api/v1/enhanced/capabilities", headers=_auth_headers()
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ready"
    assert "supported_llms" in payload and payload["supported_llms"]
    signals = payload.get("signals", {})
    assert "ssvc_label" in signals
    knowledge = payload.get("knowledge_graph", {})
    assert knowledge.get("nodes") >= 0


def test_enhanced_routes_require_api_key(enhanced_client: TestClient) -> None:
    response = enhanced_client.get("/api/v1/enhanced/capabilities")
    assert response.status_code == 401
    response = enhanced_client.post(
        "/api/v1/enhanced/analysis",
        json={"service_name": "customer-api", "security_findings": []},
    )
    assert response.status_code == 401


def test_analysis_returns_consensus_payload(enhanced_client: TestClient) -> None:
    body = {
        "service_name": "customer-api",
        "environment": "production",
        "security_findings": [
            {"id": "SNYK-1", "severity": "high", "message": "SQLi"},
            {"id": "SNYK-2", "severity": "medium", "message": "DoS"},
        ],
        "compliance_requirements": ["ISO27001:A.12.6.1"],
    }
    response = enhanced_client.post(
        "/api/v1/enhanced/analysis",
        json=body,
        headers=_auth_headers(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["final_decision"]
    assert payload["individual_analyses"]
    assert payload["signals"]["ssvc_label"] in {"Act", "Attend", "Track"}
    telemetry = payload.get("telemetry", {})
    assert telemetry.get("knowledge_graph", {}).get("nodes") >= 0
    modes = telemetry.get("provider_modes", [])
    assert modes and all("provider" in entry and "mode" in entry for entry in modes)


def test_compare_llms_returns_consensus_breakdown(enhanced_client: TestClient) -> None:
    body = {
        "service_name": "customer-api",
        "security_findings": [
            {"severity": "high", "id": "SNYK-1"},
            {"severity": "medium", "id": "SNYK-2"},
        ],
        "business_context": {"tier": "tier1"},
    }
    response = enhanced_client.post(
        "/api/v1/enhanced/compare-llms",
        json=body,
        headers=_auth_headers(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["service_analyzed"] == "customer-api"
    assert payload["models_compared"] >= 1
    assert payload["consensus"]["decision"]


def test_signals_endpoint_accepts_overrides(enhanced_client: TestClient) -> None:
    response = enhanced_client.get(
        "/api/v1/enhanced/signals",
        params={"verdict": "review", "confidence": 0.62},
        headers=_auth_headers(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["ssvc_label"] == "Attend"
    assert pytest.approx(payload["confidence"], rel=1e-6) == 0.62
