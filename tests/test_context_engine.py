"""Smoke tests for ContextEngine — baseline coverage.

evaluate() takes (design_rows, crosswalk) where design_rows are component
metadata rows and crosswalk maps design_index → {findings, cves}.
Returns a dict with keys: summary, components, highest_context_score, etc.
"""
import pytest
from core.context_engine import ContextEngine, ComponentContext


MINIMAL_SETTINGS = {
    "fields": {
        "criticality": "customer_impact",
        "data": "data_classification",
        "exposure": "exposure",
    },
    "criticality_weights": {"mission_critical": 4, "internal": 1},
    "data_weights": {"pii": 4, "internal": 2, "public": 1},
    "exposure_weights": {"internet": 3, "internal": 1},
    "playbooks": [
        {"min_score": 70, "name": "critical_response", "steps": ["isolate", "patch"]},
        {"min_score": 40, "name": "standard_response", "steps": ["patch"]},
    ],
}

SARIF_ROW = {
    "name": "auth-service",
    "customer_impact": "mission_critical",
    "data_classification": ["pii", "internal"],
    "exposure": "internet",
}

CVE_ROW = {
    "name": "payments-api",
    "customer_impact": "mission_critical",
    "data_classification": "pii",
    "exposure": "internet",
}

LOW_ROW = {
    "name": "static-docs",
    "customer_impact": "internal",
    "data_classification": "public",
    "exposure": "internal",
}

SARIF_CROSSWALK = [
    {
        "design_index": 0,
        "findings": [{"sarifLevel": "error"}],
        "cves": [],
    }
]

CVE_CROSSWALK = [
    {
        "design_index": 0,
        "findings": [],
        "cves": [{"cveSeverity": "critical"}],
    }
]

LOW_CROSSWALK = [
    {
        "design_index": 0,
        "findings": [{"sarifLevel": "note"}],
        "cves": [],
    }
]


# ── Instantiation ─────────────────────────────────────────────────────────────

def test_instantiation_minimal():
    engine = ContextEngine(MINIMAL_SETTINGS)
    assert engine is not None


def test_instantiation_empty_settings():
    engine = ContextEngine({})
    assert engine is not None


def test_default_field_names():
    engine = ContextEngine({})
    assert engine.criticality_field == "customer_impact"
    assert engine.data_field == "data_classification"
    assert engine.exposure_field == "exposure"


# ── evaluate() ────────────────────────────────────────────────────────────────

def test_evaluate_returns_dict():
    engine = ContextEngine(MINIMAL_SETTINGS)
    result = engine.evaluate([SARIF_ROW], SARIF_CROSSWALK)
    assert isinstance(result, dict)


def test_evaluate_has_summary():
    engine = ContextEngine(MINIMAL_SETTINGS)
    result = engine.evaluate([SARIF_ROW], SARIF_CROSSWALK)
    assert "summary" in result


def test_evaluate_has_components():
    engine = ContextEngine(MINIMAL_SETTINGS)
    result = engine.evaluate([SARIF_ROW], SARIF_CROSSWALK)
    assert "components" in result
    assert isinstance(result["components"], list)


def test_evaluate_component_count():
    engine = ContextEngine(MINIMAL_SETTINGS)
    result = engine.evaluate([SARIF_ROW], SARIF_CROSSWALK)
    assert len(result["components"]) == 1


def test_evaluate_component_has_name():
    engine = ContextEngine(MINIMAL_SETTINGS)
    result = engine.evaluate([SARIF_ROW], SARIF_CROSSWALK)
    # components is a list of dicts
    assert result["components"][0]["name"] == "auth-service"


def test_evaluate_severity_from_sarif():
    engine = ContextEngine(MINIMAL_SETTINGS)
    result = engine.evaluate([SARIF_ROW], SARIF_CROSSWALK)
    assert result["components"][0]["severity"] in ("low", "medium", "high", "critical")


def test_evaluate_context_score_is_int():
    engine = ContextEngine(MINIMAL_SETTINGS)
    result = engine.evaluate([SARIF_ROW], SARIF_CROSSWALK)
    assert isinstance(result["components"][0]["context_score"], int)


def test_evaluate_high_risk_higher_than_low():
    engine = ContextEngine(MINIMAL_SETTINGS)
    high = engine.evaluate([SARIF_ROW], SARIF_CROSSWALK)
    low = engine.evaluate([LOW_ROW], LOW_CROSSWALK)
    assert high["components"][0]["context_score"] >= low["components"][0]["context_score"]


def test_evaluate_multiple_components():
    engine = ContextEngine(MINIMAL_SETTINGS)
    crosswalk = [
        {"design_index": 0, "findings": [], "cves": []},
        {"design_index": 1, "findings": [], "cves": []},
        {"design_index": 2, "findings": [], "cves": []},
    ]
    result = engine.evaluate([SARIF_ROW, LOW_ROW, CVE_ROW], crosswalk)
    assert len(result["components"]) == 3


def test_evaluate_empty_rows():
    engine = ContextEngine(MINIMAL_SETTINGS)
    result = engine.evaluate([], [])
    assert result["summary"]["components_evaluated"] == 0


def test_evaluate_component_data_classification_list():
    engine = ContextEngine(MINIMAL_SETTINGS)
    result = engine.evaluate([SARIF_ROW], SARIF_CROSSWALK)
    assert isinstance(result["components"][0]["data_classification"], list)


def test_evaluate_component_exposure_field():
    engine = ContextEngine(MINIMAL_SETTINGS)
    result = engine.evaluate([SARIF_ROW], SARIF_CROSSWALK)
    assert result["components"][0]["exposure"] == "internet"


def test_evaluate_component_signals_dict():
    engine = ContextEngine(MINIMAL_SETTINGS)
    result = engine.evaluate([SARIF_ROW], SARIF_CROSSWALK)
    assert isinstance(result["components"][0]["signals"], dict)


def test_evaluate_component_playbook_present():
    engine = ContextEngine(MINIMAL_SETTINGS)
    result = engine.evaluate([SARIF_ROW], SARIF_CROSSWALK)
    assert isinstance(result["components"][0]["playbook"], dict)


# ── _normalise_weights() ──────────────────────────────────────────────────────

def test_normalise_weights_uses_defaults():
    weights = ContextEngine._normalise_weights(
        None, default={"critical": 5, "low": 1}
    )
    assert weights["critical"] == 5
    assert weights["low"] == 1


def test_normalise_weights_overrides_defaults():
    weights = ContextEngine._normalise_weights(
        {"critical": 10}, default={"critical": 5, "low": 1}
    )
    assert weights["critical"] == 10


def test_normalise_weights_lowercases_keys():
    weights = ContextEngine._normalise_weights(
        {"CRITICAL": 8}, default={}
    )
    assert "critical" in weights


# ── criticality field ─────────────────────────────────────────────────────────

def test_criticality_field_override():
    settings = {**MINIMAL_SETTINGS, "fields": {"criticality": "impact_tier"}}
    engine = ContextEngine(settings)
    assert engine.criticality_field == "impact_tier"


# ── no playbooks configured ───────────────────────────────────────────────────

def test_evaluate_no_playbooks():
    settings = {**MINIMAL_SETTINGS, "playbooks": []}
    engine = ContextEngine(settings)
    result = engine.evaluate([SARIF_ROW], SARIF_CROSSWALK)
    assert isinstance(result["components"][0]["playbook"], dict)
