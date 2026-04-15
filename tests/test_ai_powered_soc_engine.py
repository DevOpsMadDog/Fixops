"""Tests for AIPoweredSOCEngine.

Covers detection lifecycle, model registry, automation rules, confidence
clamping, triage workflow, org isolation, and statistics.

Total: 35 tests.
"""

from __future__ import annotations

import os
import pytest
from core.ai_powered_soc_engine import AIPoweredSOCEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "aisoc_test.db")
    return AIPoweredSOCEngine(db_path=db)


@pytest.fixture()
def detection(engine):
    return engine.record_detection("org1", {
        "detection_name": "Lateral Movement Detected",
        "model_type": "graph_ml",
        "confidence_score": 87.5,
        "severity": "high",
        "source_data_type": "network",
    })


@pytest.fixture()
def model(engine):
    return engine.register_model("org1", {
        "model_name": "GraphML v2",
        "model_type": "graph_ml",
        "accuracy_score": 92.0,
        "false_positive_rate": 3.5,
        "version": "2.0",
        "training_data_size": 50000,
    })


@pytest.fixture()
def rule(engine):
    return engine.create_automation_rule("org1", {
        "rule_name": "Auto-close low confidence",
        "trigger_condition": "confidence_score < 30",
        "action_type": "auto_close",
        "confidence_threshold": 30.0,
        "enabled": True,
    })


# ===========================================================================
# 1. Initialisation
# ===========================================================================

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "aisoc_init.db")
    AIPoweredSOCEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "aisoc_idem.db")
    AIPoweredSOCEngine(db_path=db)
    AIPoweredSOCEngine(db_path=db)


# ===========================================================================
# 2. Record Detection
# ===========================================================================

def test_record_detection_returns_dict(engine, detection):
    assert detection["id"]
    assert detection["detection_name"] == "Lateral Movement Detected"
    assert detection["model_type"] == "graph_ml"
    assert detection["confidence_score"] == 87.5
    assert detection["severity"] == "high"
    assert detection["source_data_type"] == "network"
    assert detection["status"] == "new"
    assert detection["auto_triaged"] is False


def test_record_detection_defaults(engine):
    d = engine.record_detection("org1", {"detection_name": "Minimal"})
    assert d["model_type"] == "rule_based"
    assert d["severity"] == "medium"
    assert d["source_data_type"] == "logs"
    assert d["status"] == "new"
    assert d["confidence_score"] == 0.0


def test_record_detection_invalid_model_type(engine):
    with pytest.raises(ValueError, match="model_type"):
        engine.record_detection("org1", {"detection_name": "X", "model_type": "neural_net"})


def test_record_detection_invalid_severity(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.record_detection("org1", {"detection_name": "X", "severity": "fatal"})


def test_record_detection_invalid_source_data_type(engine):
    with pytest.raises(ValueError, match="source_data_type"):
        engine.record_detection("org1", {"detection_name": "X", "source_data_type": "database"})


def test_record_detection_confidence_clamped_high(engine):
    d = engine.record_detection("org1", {"detection_name": "X", "confidence_score": 150.0})
    assert d["confidence_score"] == 100.0


def test_record_detection_confidence_clamped_low(engine):
    d = engine.record_detection("org1", {"detection_name": "X", "confidence_score": -10.0})
    assert d["confidence_score"] == 0.0


# ===========================================================================
# 3. List Detections
# ===========================================================================

def test_list_detections_empty(engine):
    assert engine.list_detections("org1") == []


def test_list_detections_returns_all(engine, detection):
    engine.record_detection("org1", {"detection_name": "Second"})
    result = engine.list_detections("org1")
    assert len(result) == 2


def test_list_detections_filter_severity(engine, detection):
    engine.record_detection("org1", {"detection_name": "Low", "severity": "low"})
    high = engine.list_detections("org1", severity="high")
    assert all(d["severity"] == "high" for d in high)
    assert len(high) == 1


def test_list_detections_filter_status(engine, detection):
    result = engine.list_detections("org1", status="new")
    assert len(result) == 1


def test_list_detections_filter_source_data_type(engine, detection):
    engine.record_detection("org1", {"detection_name": "Cloud det", "source_data_type": "cloud"})
    net = engine.list_detections("org1", source_data_type="network")
    assert all(d["source_data_type"] == "network" for d in net)


def test_list_detections_org_isolation(engine, detection):
    assert engine.list_detections("org2") == []


# ===========================================================================
# 4. Triage Detection
# ===========================================================================

def test_triage_detection_updates_status(engine, detection):
    updated = engine.triage_detection("org1", detection["id"], "investigating")
    assert updated["status"] == "investigating"


def test_triage_detection_auto_triaged(engine, detection):
    updated = engine.triage_detection(
        "org1", detection["id"], "triaged", auto_triaged=True, triage_time_seconds=42
    )
    assert updated["auto_triaged"] is True
    assert updated["triage_time_seconds"] == 42


def test_triage_detection_resolve_sets_resolved_at(engine, detection):
    updated = engine.triage_detection("org1", detection["id"], "resolved")
    assert updated["resolved_at"] is not None


def test_triage_detection_false_positive(engine, detection):
    updated = engine.triage_detection("org1", detection["id"], "false_positive")
    assert updated["status"] == "false_positive"
    assert updated["resolved_at"] is not None


def test_triage_detection_invalid_status(engine, detection):
    with pytest.raises(ValueError, match="new_status"):
        engine.triage_detection("org1", detection["id"], "unknown")


def test_triage_detection_not_found(engine):
    with pytest.raises(KeyError):
        engine.triage_detection("org1", "nonexistent-id", "triaged")


def test_triage_detection_org_isolation(engine, detection):
    with pytest.raises(KeyError):
        engine.triage_detection("org2", detection["id"], "triaged")


# ===========================================================================
# 5. Register Model
# ===========================================================================

def test_register_model_returns_dict(engine, model):
    assert model["id"]
    assert model["model_name"] == "GraphML v2"
    assert model["model_type"] == "graph_ml"
    assert model["accuracy_score"] == 92.0
    assert model["false_positive_rate"] == 3.5
    assert model["status"] == "training"


def test_register_model_invalid_type(engine):
    with pytest.raises(ValueError, match="model_type"):
        engine.register_model("org1", {"model_name": "X", "model_type": "deep_learning"})


def test_register_model_accuracy_clamped(engine):
    m = engine.register_model("org1", {"model_name": "X", "accuracy_score": 200.0})
    assert m["accuracy_score"] == 100.0


def test_register_model_fp_rate_clamped(engine):
    m = engine.register_model("org1", {"model_name": "X", "false_positive_rate": -5.0})
    assert m["false_positive_rate"] == 0.0


# ===========================================================================
# 6. Update Model Status
# ===========================================================================

def test_update_model_status(engine, model):
    updated = engine.update_model_status("org1", model["id"], "active")
    assert updated["status"] == "active"


def test_update_model_status_with_retrained(engine, model):
    ts = "2026-01-01T00:00:00+00:00"
    updated = engine.update_model_status("org1", model["id"], "active", last_retrained=ts)
    assert updated["last_retrained"] == ts


def test_update_model_status_invalid(engine, model):
    with pytest.raises(ValueError, match="status"):
        engine.update_model_status("org1", model["id"], "broken")


def test_update_model_status_not_found(engine):
    with pytest.raises(KeyError):
        engine.update_model_status("org1", "bad-id", "active")


def test_list_models_filter_type(engine, model):
    engine.register_model("org1", {"model_name": "NLP", "model_type": "nlp"})
    result = engine.list_models("org1", model_type="graph_ml")
    assert all(m["model_type"] == "graph_ml" for m in result)


def test_list_models_filter_status(engine, model):
    engine.update_model_status("org1", model["id"], "active")
    active = engine.list_models("org1", status="active")
    assert len(active) == 1
    training = engine.list_models("org1", status="training")
    assert len(training) == 0


def test_list_models_org_isolation(engine, model):
    assert engine.list_models("org2") == []


# ===========================================================================
# 7. Automation Rules
# ===========================================================================

def test_create_automation_rule_returns_dict(engine, rule):
    assert rule["id"]
    assert rule["rule_name"] == "Auto-close low confidence"
    assert rule["action_type"] == "auto_close"
    assert rule["confidence_threshold"] == 30.0
    assert rule["enabled"] is True
    assert rule["execution_count"] == 0
    assert rule["success_count"] == 0


def test_create_automation_rule_invalid_action_type(engine):
    with pytest.raises(ValueError, match="action_type"):
        engine.create_automation_rule("org1", {"rule_name": "X", "action_type": "delete"})


def test_create_automation_rule_threshold_clamped(engine):
    r = engine.create_automation_rule("org1", {
        "rule_name": "X", "action_type": "notify", "confidence_threshold": 999.0
    })
    assert r["confidence_threshold"] == 100.0


def test_execute_automation_increments_counts(engine, rule):
    result = engine.execute_automation("org1", rule["id"], success=True)
    assert result["execution_count"] == 1
    assert result["success_count"] == 1


def test_execute_automation_failed_not_counted_in_success(engine, rule):
    engine.execute_automation("org1", rule["id"], success=True)
    result = engine.execute_automation("org1", rule["id"], success=False)
    assert result["execution_count"] == 2
    assert result["success_count"] == 1


def test_execute_automation_not_found(engine):
    with pytest.raises(KeyError):
        engine.execute_automation("org1", "bad-id")


def test_list_automation_rules_filter_enabled(engine, rule):
    engine.create_automation_rule("org1", {
        "rule_name": "Disabled", "action_type": "notify", "enabled": False
    })
    enabled = engine.list_automation_rules("org1", enabled=True)
    assert all(r["enabled"] is True for r in enabled)
    disabled = engine.list_automation_rules("org1", enabled=False)
    assert all(r["enabled"] is False for r in disabled)


def test_list_automation_rules_org_isolation(engine, rule):
    assert engine.list_automation_rules("org2") == []


# ===========================================================================
# 8. Statistics
# ===========================================================================

def test_get_soc_stats_empty(engine):
    stats = engine.get_soc_stats("org1")
    assert stats["total_detections"] == 0
    assert stats["auto_triaged_count"] == 0
    assert stats["avg_triage_time"] == 0.0
    assert stats["false_positive_rate"] == 0.0
    assert stats["active_models"] == 0
    assert stats["avg_model_accuracy"] == 0.0
    assert stats["total_automation_rules"] == 0
    assert stats["by_severity"] == {}
    assert stats["by_model_type"] == {}
    assert stats["by_status"] == {}


def test_get_soc_stats_with_data(engine, detection, model, rule):
    engine.update_model_status("org1", model["id"], "active")
    stats = engine.get_soc_stats("org1")
    assert stats["total_detections"] == 1
    assert stats["active_models"] == 1
    assert stats["total_automation_rules"] == 1
    assert "high" in stats["by_severity"]
    assert "graph_ml" in stats["by_model_type"]
    assert "new" in stats["by_status"]


def test_get_soc_stats_auto_triaged_count(engine, detection):
    engine.triage_detection("org1", detection["id"], "triaged", auto_triaged=True)
    stats = engine.get_soc_stats("org1")
    assert stats["auto_triaged_count"] == 1


def test_get_soc_stats_false_positive_rate(engine):
    d1 = engine.record_detection("org1", {"detection_name": "A"})
    d2 = engine.record_detection("org1", {"detection_name": "B"})
    engine.triage_detection("org1", d1["id"], "false_positive")
    stats = engine.get_soc_stats("org1")
    assert stats["false_positive_rate"] == 50.0


def test_get_soc_stats_org_isolation(engine, detection):
    stats = engine.get_soc_stats("org2")
    assert stats["total_detections"] == 0
