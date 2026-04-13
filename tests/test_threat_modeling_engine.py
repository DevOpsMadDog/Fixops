"""Tests for the STRIDE Threat Modeling Engine."""
import sys
import os
import tempfile
import pytest

sys.path.insert(0, "suite-core")

from core.threat_modeling_engine import ThreatModelingEngine, STRIDE_CATEGORIES, COMPONENT_TYPES

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_LIKELIHOODS = {"high", "medium", "low"}


@pytest.fixture
def engine(tmp_path):
    db_path = str(tmp_path / "test_threat_modeling.db")
    return ThreatModelingEngine(db_path=db_path)


@pytest.fixture
def model(engine):
    return engine.create_model(name="Test Model", description="A test model", scope="test")


@pytest.fixture
def model_with_components(engine, model):
    engine.add_component(model["model_id"], "WebFrontend", "web_app", trust_level="external")
    engine.add_component(model["model_id"], "MainDB", "database", data_classification="confidential")
    engine.add_component(model["model_id"], "AuthAPI", "api")
    return model


# ---------------------------------------------------------------------------
# create_model
# ---------------------------------------------------------------------------


def test_create_model_returns_dict(engine):
    result = engine.create_model(name="My Model")
    assert isinstance(result, dict)


def test_create_model_has_model_id(engine):
    result = engine.create_model(name="My Model")
    assert "model_id" in result
    assert len(result["model_id"]) > 0


def test_create_model_state_is_draft(engine):
    result = engine.create_model(name="Draft Model")
    assert result["state"] == "draft"


def test_create_model_stores_name(engine):
    result = engine.create_model(name="Named Model")
    assert result["name"] == "Named Model"


# ---------------------------------------------------------------------------
# add_component
# ---------------------------------------------------------------------------


def test_add_component_returns_dict(engine, model):
    result = engine.add_component(model["model_id"], "API Gateway", "api")
    assert isinstance(result, dict)


def test_add_component_has_component_id(engine, model):
    result = engine.add_component(model["model_id"], "API Gateway", "api")
    assert "component_id" in result
    assert len(result["component_id"]) > 0


def test_add_component_invalid_type_raises_value_error(engine, model):
    with pytest.raises(ValueError):
        engine.add_component(model["model_id"], "Bad Component", "invalid_type")


def test_add_component_all_valid_types(engine, model):
    for ctype in COMPONENT_TYPES:
        result = engine.add_component(model["model_id"], f"Comp-{ctype}", ctype)
        assert result["component_type"] == ctype


# ---------------------------------------------------------------------------
# add_data_flow
# ---------------------------------------------------------------------------


def test_add_data_flow_returns_dict(engine, model):
    result = engine.add_data_flow(model["model_id"], "UI", "API", "user_credentials")
    assert isinstance(result, dict)


def test_add_data_flow_has_flow_id(engine, model):
    result = engine.add_data_flow(model["model_id"], "UI", "API", "user_credentials")
    assert "flow_id" in result
    assert len(result["flow_id"]) > 0


def test_add_data_flow_crosses_trust_boundary(engine, model):
    result = engine.add_data_flow(
        model["model_id"], "External", "Internal", "pii", crosses_trust_boundary=True
    )
    assert result["crosses_trust_boundary"] is True


# ---------------------------------------------------------------------------
# analyze_threats
# ---------------------------------------------------------------------------


def test_analyze_threats_returns_dict(engine, model_with_components):
    result = engine.analyze_threats(model_with_components["model_id"])
    assert isinstance(result, dict)


def test_analyze_threats_total_threats_is_int(engine, model_with_components):
    result = engine.analyze_threats(model_with_components["model_id"])
    assert isinstance(result["total_threats"], int)
    assert result["total_threats"] > 0


def test_analyze_threats_external_component_includes_spoofing(engine, model):
    engine.add_component(model["model_id"], "ExternalService", "external_service", trust_level="external")
    result = engine.analyze_threats(model["model_id"])
    categories = [t["category"] for t in result["threats"]]
    assert "spoofing" in categories


def test_analyze_threats_by_category_is_dict(engine, model_with_components):
    result = engine.analyze_threats(model_with_components["model_id"])
    assert isinstance(result["threats_by_category"], dict)


def test_analyze_threats_each_threat_has_category(engine, model_with_components):
    result = engine.analyze_threats(model_with_components["model_id"])
    for threat in result["threats"]:
        assert "category" in threat


def test_analyze_threats_each_threat_has_severity(engine, model_with_components):
    result = engine.analyze_threats(model_with_components["model_id"])
    for threat in result["threats"]:
        assert "severity" in threat


def test_analyze_threats_severity_values_valid(engine, model_with_components):
    result = engine.analyze_threats(model_with_components["model_id"])
    for threat in result["threats"]:
        assert threat["severity"] in VALID_SEVERITIES, (
            f"Invalid severity '{threat['severity']}' for threat '{threat['title']}'"
        )


def test_analyze_threats_trust_boundary_flow_generates_disclosure(engine, model):
    engine.add_component(model["model_id"], "Frontend", "web_app")
    engine.add_component(model["model_id"], "Backend", "api")
    engine.add_data_flow(
        model["model_id"], "Frontend", "Backend", "session_data", crosses_trust_boundary=True
    )
    result = engine.analyze_threats(model["model_id"])
    categories = [t["category"] for t in result["threats"]]
    assert "information_disclosure" in categories
    assert "tampering" in categories


def test_analyze_threats_database_generates_elevation(engine, model):
    engine.add_component(model["model_id"], "UserDB", "database")
    result = engine.analyze_threats(model["model_id"])
    categories = [t["category"] for t in result["threats"]]
    assert "elevation_of_privilege" in categories


def test_analyze_threats_every_component_gets_dos(engine, model):
    engine.add_component(model["model_id"], "Queue", "queue")
    result = engine.analyze_threats(model["model_id"])
    categories = [t["category"] for t in result["threats"]]
    assert "denial_of_service" in categories


# ---------------------------------------------------------------------------
# add_mitigation
# ---------------------------------------------------------------------------


def test_add_mitigation_returns_dict(engine, model_with_components):
    threats = engine.analyze_threats(model_with_components["model_id"])["threats"]
    threat_id = threats[0]["threat_id"]
    result = engine.add_mitigation(
        model_with_components["model_id"], threat_id, "Add OAuth2 authentication"
    )
    assert isinstance(result, dict)


def test_add_mitigation_has_mitigation_id(engine, model_with_components):
    threats = engine.analyze_threats(model_with_components["model_id"])["threats"]
    threat_id = threats[0]["threat_id"]
    result = engine.add_mitigation(
        model_with_components["model_id"], threat_id, "Enable TLS"
    )
    assert "mitigation_id" in result
    assert len(result["mitigation_id"]) > 0


# ---------------------------------------------------------------------------
# get_model
# ---------------------------------------------------------------------------


def test_get_model_returns_created_model(engine, model):
    result = engine.get_model(model["model_id"])
    assert result is not None
    assert result["model_id"] == model["model_id"]
    assert result["name"] == model["name"]


def test_get_model_returns_none_for_missing(engine):
    result = engine.get_model("nonexistent-id")
    assert result is None


# ---------------------------------------------------------------------------
# list_models
# ---------------------------------------------------------------------------


def test_list_models_returns_list(engine):
    result = engine.list_models()
    assert isinstance(result, list)


def test_list_models_includes_created_model(engine, model):
    result = engine.list_models(org_id="default")
    ids = [m["model_id"] for m in result]
    assert model["model_id"] in ids


# ---------------------------------------------------------------------------
# get_model_report
# ---------------------------------------------------------------------------


def test_get_model_report_has_required_sections(engine, model_with_components):
    engine.analyze_threats(model_with_components["model_id"])
    report = engine.get_model_report(model_with_components["model_id"])
    assert "components" in report
    assert "threats" in report
    assert "mitigations" in report


def test_get_model_report_components_match(engine, model_with_components):
    engine.analyze_threats(model_with_components["model_id"])
    report = engine.get_model_report(model_with_components["model_id"])
    assert len(report["components"]) == 3


# ---------------------------------------------------------------------------
# get_residual_risk
# ---------------------------------------------------------------------------


def test_get_residual_risk_returns_dict(engine, model_with_components):
    engine.analyze_threats(model_with_components["model_id"])
    result = engine.get_residual_risk(model_with_components["model_id"])
    assert isinstance(result, dict)


def test_get_residual_risk_has_counts(engine, model_with_components):
    engine.analyze_threats(model_with_components["model_id"])
    result = engine.get_residual_risk(model_with_components["model_id"])
    assert "mitigated_count" in result
    assert "unmitigated_count" in result


def test_get_residual_risk_counts_sum_to_total(engine, model_with_components):
    analysis = engine.analyze_threats(model_with_components["model_id"])
    total = analysis["total_threats"]
    risk = engine.get_residual_risk(model_with_components["model_id"])
    assert risk["mitigated_count"] + risk["unmitigated_count"] == total


def test_get_residual_risk_after_mitigation_decreases_unmitigated(engine, model_with_components):
    threats = engine.analyze_threats(model_with_components["model_id"])["threats"]
    threat_id = threats[0]["threat_id"]
    before = engine.get_residual_risk(model_with_components["model_id"])
    engine.add_mitigation(model_with_components["model_id"], threat_id, "Apply fix")
    after = engine.get_residual_risk(model_with_components["model_id"])
    assert after["mitigated_count"] == before["mitigated_count"] + 1
    assert after["unmitigated_count"] == before["unmitigated_count"] - 1
