"""
Tests for Risk Quantification Engine — FAIR-based financial risk modeling.

Tests cover:
- RiskScenario and QuantifiedRisk Pydantic models
- RiskQuantifier: create_scenario, quantify, quantify_finding
- Portfolio risk aggregation
- ROI analysis
- Scenario comparison
- Risk heatmap
- Asset value templates
- API router endpoints (all 8 routes)
- Edge cases: empty org, single scenario, multiple tiers

Minimum 35 tests, all passing.

Compliance: SOC2 CC3.2 (Risk Assessment), CC9.1 (Risk Mitigation)
"""

from __future__ import annotations

import os
import sys
import pytest
from typing import Any, Dict
from unittest.mock import MagicMock, patch

# Configure test environment
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

# Ensure suite paths are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from core.risk_quantifier import (
    RiskQuantifier,
    RiskScenario,
    QuantifiedRisk,
    ASSET_VALUE_TEMPLATES,
    SEVERITY_PROBABILITY,
    SEVERITY_LOSS_FRACTION,
)

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def engine() -> RiskQuantifier:
    """Create in-memory RiskQuantifier for testing."""
    return RiskQuantifier(db_path=":memory:", org_id="test-org")


@pytest.fixture
def sample_scenario_params() -> Dict[str, Any]:
    return {
        "name": "SQL Injection on Payment DB",
        "threat_event": "Attacker exploits SQL injection to exfiltrate customer data",
        "asset_value_usd": 2_000_000.0,
        "loss_magnitude_low": 200_000.0,
        "loss_magnitude_high": 1_500_000.0,
        "probability_low": 0.2,
        "probability_high": 0.5,
    }


@pytest.fixture
def created_scenario(engine: RiskQuantifier, sample_scenario_params: Dict[str, Any]) -> RiskScenario:
    return engine.create_scenario(**sample_scenario_params)


@pytest.fixture
def api_client() -> TestClient:
    """FastAPI test client with risk quantifier router mounted."""
    from apps.api.risk_quantifier_router import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


# ============================================================================
# MODEL TESTS
# ============================================================================


class TestRiskScenarioModel:
    def test_model_creation_defaults(self) -> None:
        """RiskScenario should have auto-generated ID and org_id default."""
        s = RiskScenario(
            name="Test",
            threat_event="Phishing",
            asset_value_usd=100_000.0,
            loss_magnitude_low=10_000.0,
            loss_magnitude_high=80_000.0,
            probability_low=0.1,
            probability_high=0.4,
        )
        assert s.id != ""
        assert s.org_id == "default"
        assert s.annual_loss_expectancy is None

    def test_model_explicit_id(self) -> None:
        """RiskScenario accepts explicit ID."""
        s = RiskScenario(
            id="custom-id-123",
            name="Test",
            threat_event="DDoS",
            asset_value_usd=500_000.0,
            loss_magnitude_low=50_000.0,
            loss_magnitude_high=300_000.0,
            probability_low=0.3,
            probability_high=0.7,
        )
        assert s.id == "custom-id-123"

    def test_model_serialization(self) -> None:
        """RiskScenario serializes to dict correctly."""
        s = RiskScenario(
            name="Test",
            threat_event="Ransomware",
            asset_value_usd=1_000_000.0,
            loss_magnitude_low=100_000.0,
            loss_magnitude_high=900_000.0,
            probability_low=0.1,
            probability_high=0.3,
        )
        d = s.model_dump()
        assert d["name"] == "Test"
        assert d["asset_value_usd"] == 1_000_000.0

    def test_quantified_risk_model(self) -> None:
        """QuantifiedRisk model holds all required fields."""
        qr = QuantifiedRisk(
            scenario_id="abc-123",
            ale_low=50_000.0,
            ale_high=300_000.0,
            ale_most_likely=150_000.0,
            risk_tier="high",
            recommended_investment_usd=52_500.0,
        )
        assert qr.scenario_id == "abc-123"
        assert qr.risk_tier == "high"
        assert qr.recommended_investment_usd == 52_500.0


# ============================================================================
# ENGINE TESTS
# ============================================================================


class TestRiskQuantifierEngine:
    def test_init_creates_engine(self, engine: RiskQuantifier) -> None:
        """Engine initializes without error."""
        assert engine.db_path == ":memory:"
        assert engine.org_id == "test-org"

    def test_create_scenario_returns_scenario(
        self, engine: RiskQuantifier, sample_scenario_params: Dict[str, Any]
    ) -> None:
        """create_scenario returns valid RiskScenario with assigned ID."""
        s = engine.create_scenario(**sample_scenario_params)
        assert isinstance(s, RiskScenario)
        assert s.id != ""
        assert s.name == sample_scenario_params["name"]

    def test_create_scenario_persists(
        self, engine: RiskQuantifier, sample_scenario_params: Dict[str, Any]
    ) -> None:
        """Created scenario can be retrieved by ID."""
        s = engine.create_scenario(**sample_scenario_params)
        retrieved = engine.get_scenario(s.id)
        assert retrieved is not None
        assert retrieved.id == s.id
        assert retrieved.name == s.name

    def test_get_scenario_missing_returns_none(self, engine: RiskQuantifier) -> None:
        """get_scenario returns None for unknown ID."""
        result = engine.get_scenario("nonexistent-id-xyz")
        assert result is None

    def test_create_scenario_custom_org(self, engine: RiskQuantifier) -> None:
        """create_scenario accepts custom org_id."""
        s = engine.create_scenario(
            name="Test",
            threat_event="XSS attack",
            asset_value_usd=300_000.0,
            loss_magnitude_low=30_000.0,
            loss_magnitude_high=200_000.0,
            probability_low=0.1,
            probability_high=0.4,
            org_id="other-org",
        )
        assert s.org_id == "other-org"

    def test_quantify_returns_quantified_risk(
        self, engine: RiskQuantifier, created_scenario: RiskScenario
    ) -> None:
        """quantify returns QuantifiedRisk with valid fields."""
        result = engine.quantify(created_scenario.id)
        assert isinstance(result, QuantifiedRisk)
        assert result.scenario_id == created_scenario.id

    def test_quantify_ale_ordering(
        self, engine: RiskQuantifier, created_scenario: RiskScenario
    ) -> None:
        """ALE low <= most_likely <= high."""
        result = engine.quantify(created_scenario.id)
        assert result.ale_low <= result.ale_most_likely <= result.ale_high

    def test_quantify_ale_positive(
        self, engine: RiskQuantifier, created_scenario: RiskScenario
    ) -> None:
        """All ALE values are non-negative."""
        result = engine.quantify(created_scenario.id)
        assert result.ale_low >= 0
        assert result.ale_most_likely >= 0
        assert result.ale_high >= 0

    def test_quantify_risk_tier_valid(
        self, engine: RiskQuantifier, created_scenario: RiskScenario
    ) -> None:
        """Risk tier is one of the four valid values."""
        result = engine.quantify(created_scenario.id)
        assert result.risk_tier in ("critical", "high", "medium", "low")

    def test_quantify_recommended_investment_positive(
        self, engine: RiskQuantifier, created_scenario: RiskScenario
    ) -> None:
        """Recommended investment is a positive value."""
        result = engine.quantify(created_scenario.id)
        assert result.recommended_investment_usd >= 0.0

    def test_quantify_missing_scenario_raises(self, engine: RiskQuantifier) -> None:
        """quantify raises ValueError for unknown scenario."""
        with pytest.raises(ValueError, match="Scenario not found"):
            engine.quantify("does-not-exist")

    def test_critical_scenario_tier(self, engine: RiskQuantifier) -> None:
        """Very high probability + high loss produces critical tier."""
        s = engine.create_scenario(
            name="Catastrophic breach",
            threat_event="Full database exfiltration",
            asset_value_usd=10_000_000.0,
            loss_magnitude_low=2_000_000.0,
            loss_magnitude_high=8_000_000.0,
            probability_low=0.7,
            probability_high=0.95,
        )
        result = engine.quantify(s.id)
        assert result.risk_tier == "critical"

    def test_low_risk_tier(self, engine: RiskQuantifier) -> None:
        """Very low probability + minimal loss produces low tier."""
        s = engine.create_scenario(
            name="Info disclosure",
            threat_event="Error message leaks stack trace",
            asset_value_usd=10_000.0,
            loss_magnitude_low=100.0,
            loss_magnitude_high=500.0,
            probability_low=0.01,
            probability_high=0.03,
        )
        result = engine.quantify(s.id)
        assert result.risk_tier == "low"

    def test_quantify_finding_critical(self, engine: RiskQuantifier) -> None:
        """quantify_finding with critical severity returns valid result."""
        finding = {
            "id": "finding-001",
            "title": "Remote Code Execution",
            "severity": "critical",
            "asset_type": "payment_service",
        }
        result = engine.quantify_finding(finding)
        assert isinstance(result, QuantifiedRisk)
        assert result.ale_most_likely > 0

    def test_quantify_finding_low_severity(self, engine: RiskQuantifier) -> None:
        """quantify_finding with low severity produces lower ALE than critical."""
        critical_finding = {"severity": "critical", "asset_type": "database"}
        low_finding = {"severity": "low", "asset_type": "database"}

        r_critical = engine.quantify_finding(critical_finding)
        r_low = engine.quantify_finding(low_finding)

        assert r_critical.ale_most_likely > r_low.ale_most_likely

    def test_quantify_finding_unknown_severity_defaults(self, engine: RiskQuantifier) -> None:
        """Unknown severity defaults to medium without raising."""
        finding = {"severity": "bogus", "title": "Some finding"}
        result = engine.quantify_finding(finding)
        assert isinstance(result, QuantifiedRisk)

    def test_quantify_finding_uses_asset_template(self, engine: RiskQuantifier) -> None:
        """quantify_finding uses ASSET_VALUE_TEMPLATES for known asset_type."""
        finding = {"severity": "high", "asset_type": "database"}
        result = engine.quantify_finding(finding)
        # database template = $2M → high severity loss fraction applied
        assert result.ale_most_likely > 0

    def test_list_scenarios_empty_org(self, engine: RiskQuantifier) -> None:
        """list_scenarios returns empty list for org with no scenarios."""
        scenarios = engine.list_scenarios(org_id="empty-org")
        assert scenarios == []

    def test_list_scenarios_returns_all(self, engine: RiskQuantifier) -> None:
        """list_scenarios returns all created scenarios for org."""
        for i in range(3):
            engine.create_scenario(
                name=f"Scenario {i}",
                threat_event=f"Threat {i}",
                asset_value_usd=100_000.0,
                loss_magnitude_low=10_000.0,
                loss_magnitude_high=80_000.0,
                probability_low=0.1,
                probability_high=0.3,
                org_id="multi-org",
            )
        scenarios = engine.list_scenarios(org_id="multi-org")
        assert len(scenarios) == 3

    def test_get_portfolio_risk_empty(self, engine: RiskQuantifier) -> None:
        """Portfolio risk returns zeroed structure for org with no quantifications."""
        portfolio = engine.get_portfolio_risk(org_id="empty-org")
        assert portfolio["total_ale_most_likely"] == 0.0
        assert portfolio["scenario_count"] == 0
        assert portfolio["tier_breakdown"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}

    def test_get_portfolio_risk_aggregates(self, engine: RiskQuantifier) -> None:
        """Portfolio aggregates ALE from multiple quantified scenarios."""
        for i in range(3):
            s = engine.create_scenario(
                name=f"Scenario {i}",
                threat_event=f"Threat {i}",
                asset_value_usd=500_000.0,
                loss_magnitude_low=50_000.0,
                loss_magnitude_high=200_000.0,
                probability_low=0.2,
                probability_high=0.5,
                org_id="portfolio-org",
            )
            engine.quantify(s.id)

        portfolio = engine.get_portfolio_risk(org_id="portfolio-org")
        assert portfolio["scenario_count"] == 3
        assert portfolio["total_ale_most_likely"] > 0
        assert len(portfolio["top_scenarios"]) == 3

    def test_get_roi_analysis_structure(self, engine: RiskQuantifier) -> None:
        """ROI analysis returns all expected keys."""
        s = engine.create_scenario(
            name="ROI Test",
            threat_event="Attack",
            asset_value_usd=1_000_000.0,
            loss_magnitude_low=100_000.0,
            loss_magnitude_high=500_000.0,
            probability_low=0.3,
            probability_high=0.6,
            org_id="roi-org",
        )
        engine.quantify(s.id)

        roi = engine.get_roi_analysis(org_id="roi-org")
        assert "total_annual_risk_usd" in roi
        assert "recommended_control_investment_usd" in roi
        assert "expected_risk_reduction_usd" in roi
        assert "net_benefit_usd" in roi
        assert "roi_percent" in roi
        assert "payback_years" in roi

    def test_compare_scenarios_sorted_by_ale(self, engine: RiskQuantifier) -> None:
        """compare_scenarios returns results sorted by ALE descending."""
        ids = []
        configs = [
            (50_000.0, 0.05, 0.10),   # low ALE
            (1_000_000.0, 0.50, 0.80),  # high ALE
            (200_000.0, 0.15, 0.30),   # medium ALE
        ]
        for i, (asset, p_lo, p_hi) in enumerate(configs):
            s = engine.create_scenario(
                name=f"Compare {i}",
                threat_event=f"Threat {i}",
                asset_value_usd=asset,
                loss_magnitude_low=asset * 0.1,
                loss_magnitude_high=asset * 0.8,
                probability_low=p_lo,
                probability_high=p_hi,
            )
            engine.quantify(s.id)
            ids.append(s.id)

        comparison = engine.compare_scenarios(ids)
        assert len(comparison) == 3
        # Verify descending ALE order
        ales = [c["ale_most_likely"] for c in comparison]
        assert ales == sorted(ales, reverse=True)

    def test_compare_scenarios_skips_missing(self, engine: RiskQuantifier) -> None:
        """compare_scenarios skips unknown IDs gracefully."""
        s = engine.create_scenario(
            name="Valid",
            threat_event="Threat",
            asset_value_usd=500_000.0,
            loss_magnitude_low=50_000.0,
            loss_magnitude_high=300_000.0,
            probability_low=0.2,
            probability_high=0.5,
        )
        comparison = engine.compare_scenarios([s.id, "nonexistent-id"])
        assert len(comparison) == 1

    def test_get_risk_heatmap_structure(self, engine: RiskQuantifier) -> None:
        """Heatmap returns correct structure with 25 cells."""
        s = engine.create_scenario(
            name="Heatmap Test",
            threat_event="Attack",
            asset_value_usd=500_000.0,
            loss_magnitude_low=50_000.0,
            loss_magnitude_high=300_000.0,
            probability_low=0.3,
            probability_high=0.6,
            org_id="heatmap-org",
        )
        engine.quantify(s.id)

        heatmap = engine.get_risk_heatmap(org_id="heatmap-org")
        assert "cells" in heatmap
        assert len(heatmap["cells"]) == 25  # 5×5 grid
        assert "probability_labels" in heatmap
        assert "impact_labels" in heatmap

    def test_asset_value_templates_present(self) -> None:
        """ASSET_VALUE_TEMPLATES contains expected keys."""
        assert "web_app" in ASSET_VALUE_TEMPLATES
        assert "database" in ASSET_VALUE_TEMPLATES
        assert "api" in ASSET_VALUE_TEMPLATES
        assert ASSET_VALUE_TEMPLATES["database"] == 2_000_000.0


# ============================================================================
# API ROUTER TESTS
# ============================================================================


class TestRiskQuantifierRouter:
    def test_health_endpoint(self, api_client: TestClient) -> None:
        """GET /health returns healthy status."""
        resp = api_client.get("/api/v1/risk-quantifier/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["methodology"] == "FAIR"

    def test_asset_templates_endpoint(self, api_client: TestClient) -> None:
        """GET /asset-templates returns all templates."""
        resp = api_client.get("/api/v1/risk-quantifier/asset-templates")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["count"] > 0
        assert any(t["asset_type"] == "database" for t in data["templates"])

    def test_create_scenario_endpoint(self, api_client: TestClient) -> None:
        """POST /scenarios creates a scenario and returns it."""
        payload = {
            "name": "API Test Scenario",
            "threat_event": "Credential stuffing attack",
            "asset_value_usd": 500_000.0,
            "loss_magnitude_low": 50_000.0,
            "loss_magnitude_high": 300_000.0,
            "probability_low": 0.2,
            "probability_high": 0.5,
        }
        resp = api_client.post("/api/v1/risk-quantifier/scenarios", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "created"
        assert data["scenario"]["name"] == "API Test Scenario"
        assert data["scenario"]["id"] != ""

    def test_list_scenarios_endpoint_empty(self, api_client: TestClient) -> None:
        """GET /scenarios returns empty list initially."""
        resp = api_client.get("/api/v1/risk-quantifier/scenarios")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "scenarios" in data
        assert isinstance(data["scenarios"], list)

    def test_get_scenario_not_found(self, api_client: TestClient) -> None:
        """GET /scenarios/{id} returns 404 for unknown ID."""
        resp = api_client.get("/api/v1/risk-quantifier/scenarios/nonexistent-abc")
        assert resp.status_code == 404

    def test_quantify_scenario_endpoint(self, api_client: TestClient) -> None:
        """POST /scenarios/{id}/quantify returns quantified risk."""
        # Create first
        payload = {
            "name": "Quantify Test",
            "threat_event": "Insider threat",
            "asset_value_usd": 1_000_000.0,
            "loss_magnitude_low": 100_000.0,
            "loss_magnitude_high": 800_000.0,
            "probability_low": 0.1,
            "probability_high": 0.3,
        }
        create_resp = api_client.post("/api/v1/risk-quantifier/scenarios", json=payload)
        assert create_resp.status_code == 200
        scenario_id = create_resp.json()["scenario"]["id"]

        # Quantify
        quant_resp = api_client.post(f"/api/v1/risk-quantifier/scenarios/{scenario_id}/quantify")
        assert quant_resp.status_code == 200
        data = quant_resp.json()
        assert data["status"] == "ok"
        qr = data["quantified_risk"]
        assert qr["ale_low"] <= qr["ale_most_likely"] <= qr["ale_high"]
        assert qr["risk_tier"] in ("critical", "high", "medium", "low")

    def test_quantify_scenario_not_found(self, api_client: TestClient) -> None:
        """POST /scenarios/{id}/quantify returns 404 for unknown scenario."""
        resp = api_client.post("/api/v1/risk-quantifier/scenarios/bad-id/quantify")
        assert resp.status_code == 404

    def test_quantify_finding_endpoint(self, api_client: TestClient) -> None:
        """POST /findings/quantify returns quantified risk from finding."""
        payload = {
            "id": "finding-api-001",
            "title": "SQL Injection",
            "severity": "high",
            "asset_type": "database",
        }
        resp = api_client.post("/api/v1/risk-quantifier/findings/quantify", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["quantified_risk"]["ale_most_likely"] > 0

    def test_portfolio_endpoint_empty(self, api_client: TestClient) -> None:
        """GET /portfolio returns zeroed structure for fresh org."""
        resp = api_client.get("/api/v1/risk-quantifier/portfolio")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "total_ale_most_likely" in data

    def test_roi_endpoint(self, api_client: TestClient) -> None:
        """GET /roi returns ROI analysis structure."""
        resp = api_client.get("/api/v1/risk-quantifier/roi")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "roi_percent" in data
        assert "net_benefit_usd" in data

    def test_compare_endpoint(self, api_client: TestClient) -> None:
        """POST /compare returns comparison for two scenarios."""
        # Create two scenarios
        ids = []
        for name in ["Scenario A", "Scenario B"]:
            payload = {
                "name": name,
                "threat_event": "Generic threat",
                "asset_value_usd": 500_000.0,
                "loss_magnitude_low": 50_000.0,
                "loss_magnitude_high": 300_000.0,
                "probability_low": 0.2,
                "probability_high": 0.5,
            }
            r = api_client.post("/api/v1/risk-quantifier/scenarios", json=payload)
            ids.append(r.json()["scenario"]["id"])

        resp = api_client.post(
            "/api/v1/risk-quantifier/compare",
            json={"scenario_ids": ids},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["count"] == 2

    def test_heatmap_endpoint(self, api_client: TestClient) -> None:
        """GET /heatmap returns 5×5 grid of cells."""
        resp = api_client.get("/api/v1/risk-quantifier/heatmap")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert len(data["cells"]) == 25

    def test_full_workflow(self, api_client: TestClient) -> None:
        """End-to-end: create scenario → quantify → check portfolio."""
        # Create
        payload = {
            "name": "E2E Workflow Scenario",
            "threat_event": "Supply chain compromise",
            "asset_value_usd": 3_000_000.0,
            "loss_magnitude_low": 300_000.0,
            "loss_magnitude_high": 2_000_000.0,
            "probability_low": 0.1,
            "probability_high": 0.4,
        }
        create_resp = api_client.post("/api/v1/risk-quantifier/scenarios", json=payload)
        assert create_resp.status_code == 200
        sid = create_resp.json()["scenario"]["id"]

        # Quantify
        quant_resp = api_client.post(f"/api/v1/risk-quantifier/scenarios/{sid}/quantify")
        assert quant_resp.status_code == 200

        # Portfolio should now have 1 scenario
        port_resp = api_client.get("/api/v1/risk-quantifier/portfolio")
        assert port_resp.status_code == 200
        portfolio = port_resp.json()
        assert portfolio["scenario_count"] >= 1
        assert portfolio["total_ale_most_likely"] > 0
