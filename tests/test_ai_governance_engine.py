"""Tests for AIGovernanceEngine — wave 18."""

import pytest
from core.ai_governance_engine import AIGovernanceEngine


@pytest.fixture
def engine(tmp_path):
    return AIGovernanceEngine(db_path=str(tmp_path / "ai_gov.db"))


# ---------------------------------------------------------------------------
# register_model — basic
# ---------------------------------------------------------------------------

def test_register_model_minimal(engine):
    m = engine.register_model("org1", {"model_name": "GPT-4", "model_type": "llm"})
    assert m["model_name"] == "GPT-4"
    assert m["model_type"] == "llm"
    assert m["deployment_status"] == "development"
    assert m["risk_level"] == "medium"
    assert m["data_classification"] == "internal"
    assert "id" in m
    assert "created_at" in m


def test_register_model_all_types(engine):
    types = [
        "llm", "classification", "regression",
        "computer_vision", "nlp", "recommendation", "anomaly_detection"
    ]
    for mtype in types:
        m = engine.register_model("org1", {"model_name": f"model-{mtype}", "model_type": mtype})
        assert m["model_type"] == mtype


def test_register_model_all_deployment_statuses(engine):
    for status in ["development", "staging", "production", "retired"]:
        m = engine.register_model(
            "org1",
            {"model_name": f"m-{status}", "model_type": "llm", "deployment_status": status},
        )
        assert m["deployment_status"] == status


def test_register_model_all_risk_levels(engine):
    for lvl in ["critical", "high", "medium", "low"]:
        m = engine.register_model(
            "org1",
            {"model_name": f"m-{lvl}", "model_type": "classification", "risk_level": lvl},
        )
        assert m["risk_level"] == lvl


def test_register_model_all_data_classifications(engine):
    for cls in ["public", "internal", "confidential", "restricted"]:
        m = engine.register_model(
            "org1",
            {"model_name": f"m-{cls}", "model_type": "nlp", "data_classification": cls},
        )
        assert m["data_classification"] == cls


def test_register_model_missing_name_raises(engine):
    with pytest.raises(ValueError, match="model_name"):
        engine.register_model("org1", {"model_type": "llm"})


def test_register_model_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="Invalid model_type"):
        engine.register_model("org1", {"model_name": "x", "model_type": "transformer"})


def test_register_model_invalid_status_raises(engine):
    with pytest.raises(ValueError, match="Invalid deployment_status"):
        engine.register_model("org1", {"model_name": "x", "model_type": "llm", "deployment_status": "live"})


def test_register_model_invalid_risk_level_raises(engine):
    with pytest.raises(ValueError, match="Invalid risk_level"):
        engine.register_model("org1", {"model_name": "x", "model_type": "llm", "risk_level": "extreme"})


# ---------------------------------------------------------------------------
# list_models / get_model
# ---------------------------------------------------------------------------

def test_list_models_empty(engine):
    assert engine.list_models("org1") == []


def test_list_models_filters(engine):
    engine.register_model("org1", {"model_name": "A", "model_type": "llm", "risk_level": "high"})
    engine.register_model("org1", {"model_name": "B", "model_type": "classification", "risk_level": "low"})
    llm = engine.list_models("org1", model_type="llm")
    assert len(llm) == 1
    assert llm[0]["model_name"] == "A"
    low = engine.list_models("org1", risk_level="low")
    assert len(low) == 1
    assert low[0]["model_name"] == "B"


def test_get_model_returns_none_for_wrong_org(engine):
    m = engine.register_model("org1", {"model_name": "X", "model_type": "llm"})
    assert engine.get_model("org2", m["id"]) is None


def test_get_model_found(engine):
    m = engine.register_model("org1", {"model_name": "Y", "model_type": "nlp"})
    found = engine.get_model("org1", m["id"])
    assert found["id"] == m["id"]


# ---------------------------------------------------------------------------
# update_model_status
# ---------------------------------------------------------------------------

def test_update_model_status_lifecycle(engine):
    m = engine.register_model("org1", {"model_name": "Z", "model_type": "llm"})
    assert m["deployment_status"] == "development"
    updated = engine.update_model_status("org1", m["id"], "staging")
    assert updated["deployment_status"] == "staging"
    updated2 = engine.update_model_status("org1", m["id"], "production")
    assert updated2["deployment_status"] == "production"
    updated3 = engine.update_model_status("org1", m["id"], "retired")
    assert updated3["deployment_status"] == "retired"


def test_update_model_status_invalid_raises(engine):
    m = engine.register_model("org1", {"model_name": "Z2", "model_type": "llm"})
    with pytest.raises(ValueError, match="Invalid deployment_status"):
        engine.update_model_status("org1", m["id"], "unknown")


def test_update_model_status_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.update_model_status("org1", "nonexistent-id", "staging")


# ---------------------------------------------------------------------------
# record_assessment
# ---------------------------------------------------------------------------

def test_record_assessment_basic(engine):
    m = engine.register_model("org1", {"model_name": "Assess", "model_type": "llm"})
    a = engine.record_assessment("org1", {
        "model_id": m["id"],
        "assessment_type": "bias",
        "score": 85.0,
        "findings": ["Slight gender skew"],
        "assessor": "Alice",
    })
    assert a["score"] == 85.0
    assert a["assessment_type"] == "bias"
    assert isinstance(a["findings"], list)
    assert "Slight gender skew" in a["findings"]


def test_record_assessment_all_types(engine):
    m = engine.register_model("org1", {"model_name": "Multi", "model_type": "classification"})
    for atype in ["bias", "fairness", "security", "privacy", "performance"]:
        a = engine.record_assessment("org1", {
            "model_id": m["id"],
            "assessment_type": atype,
            "score": 70.0,
        })
        assert a["assessment_type"] == atype


def test_record_assessment_wrong_org_raises(engine):
    m = engine.register_model("org1", {"model_name": "OrgModel", "model_type": "llm"})
    with pytest.raises(KeyError):
        engine.record_assessment("org2", {
            "model_id": m["id"],
            "assessment_type": "bias",
            "score": 50.0,
        })


def test_record_assessment_score_out_of_range_raises(engine):
    m = engine.register_model("org1", {"model_name": "ScoreTest", "model_type": "llm"})
    with pytest.raises(ValueError, match="score"):
        engine.record_assessment("org1", {
            "model_id": m["id"],
            "assessment_type": "bias",
            "score": 150.0,
        })


def test_list_assessments_filter(engine):
    m = engine.register_model("org1", {"model_name": "FilterModel", "model_type": "llm"})
    engine.record_assessment("org1", {"model_id": m["id"], "assessment_type": "bias", "score": 80.0})
    engine.record_assessment("org1", {"model_id": m["id"], "assessment_type": "security", "score": 90.0})
    bias = engine.list_assessments("org1", assessment_type="bias")
    assert len(bias) == 1
    assert bias[0]["assessment_type"] == "bias"


# ---------------------------------------------------------------------------
# report_incident / resolve_incident
# ---------------------------------------------------------------------------

def test_report_incident_basic(engine):
    m = engine.register_model("org1", {"model_name": "IncModel", "model_type": "llm"})
    inc = engine.report_incident("org1", {
        "model_id": m["id"],
        "incident_type": "hallucination",
        "severity": "high",
        "description": "Model hallucinated facts",
    })
    assert inc["status"] == "open"
    assert inc["incident_type"] == "hallucination"
    assert inc["resolved_at"] is None


def test_resolve_incident_lifecycle(engine):
    m = engine.register_model("org1", {"model_name": "ResolveModel", "model_type": "llm"})
    inc = engine.report_incident("org1", {
        "model_id": m["id"],
        "incident_type": "drift",
        "severity": "medium",
    })
    resolved = engine.resolve_incident("org1", inc["id"])
    assert resolved["status"] == "resolved"
    assert resolved["resolved_at"] is not None


def test_resolve_incident_wrong_org_raises(engine):
    m = engine.register_model("org1", {"model_name": "WrongOrg", "model_type": "llm"})
    inc = engine.report_incident("org1", {
        "model_id": m["id"],
        "incident_type": "bias",
        "severity": "low",
    })
    with pytest.raises(KeyError):
        engine.resolve_incident("org2", inc["id"])


def test_report_incident_wrong_org_raises(engine):
    m = engine.register_model("org1", {"model_name": "WO2", "model_type": "llm"})
    with pytest.raises(KeyError):
        engine.report_incident("org2", {
            "model_id": m["id"],
            "incident_type": "bias",
            "severity": "low",
        })


def test_list_incidents_filters(engine):
    m = engine.register_model("org1", {"model_name": "FilterInc", "model_type": "llm"})
    engine.report_incident("org1", {"model_id": m["id"], "incident_type": "bias", "severity": "high"})
    engine.report_incident("org1", {"model_id": m["id"], "incident_type": "drift", "severity": "low"})
    high = engine.list_incidents("org1", severity="high")
    assert len(high) == 1
    assert high[0]["severity"] == "high"
    open_incs = engine.list_incidents("org1", status="open")
    assert len(open_incs) == 2


# ---------------------------------------------------------------------------
# get_governance_stats
# ---------------------------------------------------------------------------

def test_get_governance_stats(engine):
    engine.register_model("org1", {"model_name": "S1", "model_type": "llm", "risk_level": "high"})
    engine.register_model("org1", {"model_name": "S2", "model_type": "classification", "risk_level": "low", "deployment_status": "production"})
    m3 = engine.register_model("org1", {"model_name": "S3", "model_type": "llm", "risk_level": "medium"})
    engine.record_assessment("org1", {"model_id": m3["id"], "assessment_type": "bias", "score": 70.0})
    engine.report_incident("org1", {"model_id": m3["id"], "incident_type": "drift", "severity": "low"})

    stats = engine.get_governance_stats("org1")
    assert stats["total_models"] == 3
    assert stats["production_models"] == 1
    assert stats["by_type"]["llm"] == 2
    assert stats["by_type"]["classification"] == 1
    assert stats["total_assessments"] == 1
    assert stats["total_incidents"] == 1
    assert stats["open_incidents"] == 1


def test_get_governance_stats_org_isolation(engine):
    engine.register_model("org1", {"model_name": "Org1Model", "model_type": "llm"})
    stats = engine.get_governance_stats("org2")
    assert stats["total_models"] == 0
    assert stats["open_incidents"] == 0
