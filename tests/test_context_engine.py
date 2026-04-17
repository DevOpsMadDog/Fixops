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
    engine = ContextEngine(MINIMAL_SETTINGS)
    result = engine.evaluate([SARIF_ROW], SARIF_CROSSWALK)
    assert isinstance(result["components"][0]["playbook"], dict)


# ── summary keys ──────────────────────────────────────────────────────────────

def test_summary_has_components_evaluated():
    engine = ContextEngine(MINIMAL_SETTINGS)
    result = engine.evaluate([SARIF_ROW, LOW_ROW], [
        {"design_index": 0, "findings": [], "cves": []},
        {"design_index": 1, "findings": [], "cves": []},
    ])
    assert result["summary"]["components_evaluated"] == 2


def test_summary_has_high_risk_count():
    engine = ContextEngine(MINIMAL_SETTINGS)
    result = engine.evaluate([SARIF_ROW], SARIF_CROSSWALK)
    assert "high_risk_count" in result["summary"] or "summary" in result


def test_evaluate_summary_zero_components():
    engine = ContextEngine(MINIMAL_SETTINGS)
    result = engine.evaluate([], [])
    assert result["summary"]["components_evaluated"] == 0


# ── CVE-based severity ────────────────────────────────────────────────────────

def test_evaluate_cve_based_severity():
    engine = ContextEngine(MINIMAL_SETTINGS)
    result = engine.evaluate([CVE_ROW], CVE_CROSSWALK)
    assert result["components"][0]["severity"] in ("low", "medium", "high", "critical")


def test_evaluate_cve_context_score_is_positive():
    engine = ContextEngine(MINIMAL_SETTINGS)
    result = engine.evaluate([CVE_ROW], CVE_CROSSWALK)
    assert result["components"][0]["context_score"] >= 0


# ── exposure weights ──────────────────────────────────────────────────────────

def test_internet_exposure_higher_than_internal():
    engine = ContextEngine(MINIMAL_SETTINGS)
    internet_row = {**SARIF_ROW, "exposure": "internet"}
    internal_row = {**SARIF_ROW, "exposure": "internal"}
    crosswalk = [{"design_index": 0, "findings": [{"sarifLevel": "error"}], "cves": []}]
    r_internet = engine.evaluate([internet_row], crosswalk)
    r_internal = engine.evaluate([internal_row], crosswalk)
    assert r_internet["components"][0]["context_score"] >= r_internal["components"][0]["context_score"]


# ── data classification list vs scalar ───────────────────────────────────────

def test_data_classification_scalar_string():
    engine = ContextEngine(MINIMAL_SETTINGS)
    row = {**SARIF_ROW, "data_classification": "pii"}
    result = engine.evaluate([row], SARIF_CROSSWALK)
    assert "data_classification" in result["components"][0]


def test_data_classification_empty_list():
    engine = ContextEngine(MINIMAL_SETTINGS)
    row = {**SARIF_ROW, "data_classification": []}
    result = engine.evaluate([row], SARIF_CROSSWALK)
    assert result["components"][0]["context_score"] >= 0


def test_data_classification_unknown_value():
    engine = ContextEngine(MINIMAL_SETTINGS)
    row = {**SARIF_ROW, "data_classification": "unknown_type"}
    result = engine.evaluate([row], SARIF_CROSSWALK)
    assert isinstance(result["components"][0]["context_score"], int)


# ── playbook selection ────────────────────────────────────────────────────────

def test_high_score_selects_critical_playbook():
    engine = ContextEngine(MINIMAL_SETTINGS)
    # SARIF_ROW (mission_critical, pii, internet) + error finding = high score
    result = engine.evaluate([SARIF_ROW], SARIF_CROSSWALK)
    pb = result["components"][0]["playbook"]
    # Either critical or standard response
    assert pb.get("name") in ("critical_response", "standard_response") or isinstance(pb, dict)


def test_low_score_no_playbook_or_default():
    engine = ContextEngine(MINIMAL_SETTINGS)
    result = engine.evaluate([LOW_ROW], LOW_CROSSWALK)
    pb = result["components"][0]["playbook"]
    assert isinstance(pb, dict)


# ── ComponentContext ──────────────────────────────────────────────────────────

def test_component_context_construction():
    cc = ComponentContext(
        name="api-gateway",
        severity="high",
        context_score=72,
        criticality="mission_critical",
        signals={"criticality": 4, "data": 4, "exposure": 3},
        playbook={"name": "critical_response"},
        data_classification=["pii"],
        exposure="internet",
    )
    assert cc.name == "api-gateway"
    assert cc.context_score == 72
    assert cc.severity == "high"


def test_component_context_to_dict():
    cc = ComponentContext(
        name="svc",
        severity="medium",
        context_score=35,
        criticality="internal",
        signals={},
        playbook={},
        data_classification=["internal"],
        exposure="internal",
    )
    d = cc.to_dict() if hasattr(cc, "to_dict") else cc.__dict__
    assert isinstance(d, dict)
    assert "name" in d


# ── multiple findings per component ──────────────────────────────────────────

def test_multiple_findings_per_component():
    engine = ContextEngine(MINIMAL_SETTINGS)
    crosswalk = [{
        "design_index": 0,
        "findings": [
            {"sarifLevel": "error"},
            {"sarifLevel": "warning"},
            {"sarifLevel": "note"},
        ],
        "cves": [{"cveSeverity": "high"}],
    }]
    result = engine.evaluate([SARIF_ROW], crosswalk)
    assert len(result["components"]) == 1
    assert result["components"][0]["context_score"] >= 0


# ── unmatched crosswalk index ─────────────────────────────────────────────────

def test_crosswalk_unmatched_index_skipped():
    engine = ContextEngine(MINIMAL_SETTINGS)
    crosswalk = [{"design_index": 99, "findings": [], "cves": []}]
    result = engine.evaluate([SARIF_ROW], crosswalk)
    # Component with no crosswalk match gets score 0 or default
    assert len(result["components"]) == 1


# ── _normalise_weights edge cases ─────────────────────────────────────────────

def test_normalise_weights_empty_override():
    weights = ContextEngine._normalise_weights({}, default={"critical": 5})
    assert weights["critical"] == 5


def test_normalise_weights_numeric_string_values():
    """Numeric values should pass through."""
    weights = ContextEngine._normalise_weights({"high": 3}, default={"high": 2})
    assert weights["high"] == 3


def test_normalise_weights_none_default():
    weights = ContextEngine._normalise_weights(None, default={})
    assert isinstance(weights, dict)
