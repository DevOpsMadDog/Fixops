"""Tests for CloudSecurityAnalyticsEngine — 30+ tests covering all methods,
JSON round-trip, rule trigger count, org isolation, and anomaly status lifecycle."""

from __future__ import annotations

import os
import pytest

from core.cloud_security_analytics_engine import CloudSecurityAnalyticsEngine

ORG_A = "org-alpha"
ORG_B = "org-beta"


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_csa.db")
    return CloudSecurityAnalyticsEngine(db_path=db)


# ---------------------------------------------------------------------------
# Init / schema
# ---------------------------------------------------------------------------


def test_engine_init_creates_db(tmp_path):
    db = str(tmp_path / "csa.db")
    CloudSecurityAnalyticsEngine(db_path=db)
    assert os.path.exists(db)


def test_engine_two_instances_same_db(tmp_path):
    db = str(tmp_path / "csa.db")
    e1 = CloudSecurityAnalyticsEngine(db_path=db)
    e2 = CloudSecurityAnalyticsEngine(db_path=db)
    e1.record_event(ORG_A, {"event_source": "cloudtrail", "event_type": "api_call", "severity": "low"})
    assert len(e2.list_events(ORG_A)) == 1


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


def test_record_event_returns_dict(engine):
    result = engine.record_event(ORG_A, {
        "event_source": "cloudtrail",
        "event_type": "api_call",
        "severity": "high",
        "account_id": "123456789",
        "region": "us-east-1",
        "risk_score": 75.0,
    })
    assert "id" in result
    assert result["org_id"] == ORG_A
    assert result["event_source"] == "cloudtrail"
    assert result["event_type"] == "api_call"
    assert result["severity"] == "high"
    assert result["risk_score"] == 75.0


def test_record_event_invalid_source_raises(engine):
    with pytest.raises(ValueError, match="Invalid event_source"):
        engine.record_event(ORG_A, {
            "event_source": "bad_source", "event_type": "api_call", "severity": "low"
        })


def test_record_event_invalid_event_type_raises(engine):
    with pytest.raises(ValueError, match="Invalid event_type"):
        engine.record_event(ORG_A, {
            "event_source": "cloudtrail", "event_type": "bad_type", "severity": "low"
        })


def test_record_event_invalid_severity_raises(engine):
    with pytest.raises(ValueError, match="Invalid severity"):
        engine.record_event(ORG_A, {
            "event_source": "cloudtrail", "event_type": "api_call", "severity": "extreme"
        })


def test_record_event_clamps_risk_score(engine):
    r1 = engine.record_event(ORG_A, {
        "event_source": "guardduty", "event_type": "threat_detection",
        "severity": "critical", "risk_score": 150.0
    })
    assert r1["risk_score"] == 100.0
    r2 = engine.record_event(ORG_A, {
        "event_source": "guardduty", "event_type": "threat_detection",
        "severity": "critical", "risk_score": -10.0
    })
    assert r2["risk_score"] == 0.0


def test_record_event_all_sources(engine):
    sources = [
        "cloudtrail", "azure_monitor", "gcp_audit", "kubernetes", "lambda",
        "container", "vpc_flow", "config_rule", "guardduty", "defender"
    ]
    for src in sources:
        result = engine.record_event(ORG_A, {
            "event_source": src, "event_type": "api_call", "severity": "low"
        })
        assert result["event_source"] == src


def test_list_events_empty(engine):
    assert engine.list_events(ORG_A) == []


def test_list_events_returns_all(engine):
    engine.record_event(ORG_A, {"event_source": "cloudtrail", "event_type": "api_call", "severity": "low"})
    engine.record_event(ORG_A, {"event_source": "guardduty", "event_type": "threat_detection", "severity": "high"})
    assert len(engine.list_events(ORG_A)) == 2


def test_list_events_filter_by_source(engine):
    engine.record_event(ORG_A, {"event_source": "cloudtrail", "event_type": "api_call", "severity": "low"})
    engine.record_event(ORG_A, {"event_source": "guardduty", "event_type": "api_call", "severity": "low"})
    result = engine.list_events(ORG_A, event_source="cloudtrail")
    assert len(result) == 1
    assert result[0]["event_source"] == "cloudtrail"


def test_list_events_filter_by_severity(engine):
    engine.record_event(ORG_A, {"event_source": "cloudtrail", "event_type": "api_call", "severity": "critical"})
    engine.record_event(ORG_A, {"event_source": "cloudtrail", "event_type": "api_call", "severity": "low"})
    crits = engine.list_events(ORG_A, severity="critical")
    assert len(crits) == 1
    assert crits[0]["severity"] == "critical"


def test_list_events_org_isolation(engine):
    engine.record_event(ORG_A, {"event_source": "cloudtrail", "event_type": "api_call", "severity": "low"})
    engine.record_event(ORG_B, {"event_source": "cloudtrail", "event_type": "api_call", "severity": "low"})
    assert len(engine.list_events(ORG_A)) == 1
    assert len(engine.list_events(ORG_B)) == 1


# ---------------------------------------------------------------------------
# Anomalies
# ---------------------------------------------------------------------------


def test_record_anomaly_returns_dict(engine):
    result = engine.record_anomaly(ORG_A, {
        "anomaly_type": "impossible_travel",
        "severity": "high",
        "account_id": "acct-123",
        "confidence_score": 92.5,
        "affected_resources": ["resource-1", "resource-2"],
    })
    assert "id" in result
    assert result["anomaly_type"] == "impossible_travel"
    assert result["severity"] == "high"
    assert result["confidence_score"] == 92.5
    assert result["status"] == "open"
    assert result["affected_resources"] == ["resource-1", "resource-2"]


def test_record_anomaly_json_round_trip(engine):
    resources = ["res-A", "res-B", "res-C"]
    result = engine.record_anomaly(ORG_A, {
        "anomaly_type": "data_exfil_attempt",
        "severity": "critical",
        "affected_resources": resources,
    })
    assert result["affected_resources"] == resources
    listed = engine.list_anomalies(ORG_A)
    assert listed[0]["affected_resources"] == resources


def test_record_anomaly_clamps_confidence(engine):
    r1 = engine.record_anomaly(ORG_A, {
        "anomaly_type": "crypto_mining", "severity": "high", "confidence_score": 200.0
    })
    assert r1["confidence_score"] == 100.0
    r2 = engine.record_anomaly(ORG_A, {
        "anomaly_type": "crypto_mining", "severity": "high", "confidence_score": -5.0
    })
    assert r2["confidence_score"] == 0.0


def test_record_anomaly_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="Invalid anomaly_type"):
        engine.record_anomaly(ORG_A, {"anomaly_type": "bad_type", "severity": "low"})


def test_record_anomaly_defaults_status_open(engine):
    result = engine.record_anomaly(ORG_A, {"anomaly_type": "unusual_api", "severity": "low"})
    assert result["status"] == "open"


def test_list_anomalies_filter_by_type(engine):
    engine.record_anomaly(ORG_A, {"anomaly_type": "impossible_travel", "severity": "high"})
    engine.record_anomaly(ORG_A, {"anomaly_type": "crypto_mining", "severity": "medium"})
    result = engine.list_anomalies(ORG_A, anomaly_type="impossible_travel")
    assert len(result) == 1
    assert result[0]["anomaly_type"] == "impossible_travel"


def test_list_anomalies_filter_by_status(engine):
    engine.record_anomaly(ORG_A, {"anomaly_type": "unusual_api", "severity": "low"})
    a2 = engine.record_anomaly(ORG_A, {"anomaly_type": "privilege_abuse", "severity": "high"})
    engine.update_anomaly_status(ORG_A, a2["id"], "confirmed")
    confirmed = engine.list_anomalies(ORG_A, status="confirmed")
    assert len(confirmed) == 1
    assert confirmed[0]["status"] == "confirmed"


def test_update_anomaly_status_lifecycle(engine):
    a = engine.record_anomaly(ORG_A, {"anomaly_type": "lateral_movement", "severity": "critical"})
    assert a["status"] == "open"
    r1 = engine.update_anomaly_status(ORG_A, a["id"], "investigating")
    assert r1["status"] == "investigating"
    r2 = engine.update_anomaly_status(ORG_A, a["id"], "confirmed")
    assert r2["status"] == "confirmed"
    r3 = engine.update_anomaly_status(ORG_A, a["id"], "false_positive")
    assert r3["status"] == "false_positive"


def test_update_anomaly_status_invalid_raises(engine):
    a = engine.record_anomaly(ORG_A, {"anomaly_type": "unusual_api", "severity": "low"})
    with pytest.raises(ValueError, match="Invalid status"):
        engine.update_anomaly_status(ORG_A, a["id"], "resolved")


def test_update_anomaly_status_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.update_anomaly_status(ORG_A, "nonexistent", "open")


def test_list_anomalies_org_isolation(engine):
    engine.record_anomaly(ORG_A, {"anomaly_type": "unusual_api", "severity": "low"})
    engine.record_anomaly(ORG_B, {"anomaly_type": "unusual_api", "severity": "low"})
    assert len(engine.list_anomalies(ORG_A)) == 1
    assert len(engine.list_anomalies(ORG_B)) == 1


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def test_create_rule_returns_dict(engine):
    result = engine.create_rule(ORG_A, {
        "rule_name": "Root Login Alert",
        "rule_type": "detection",
        "condition": "actor == 'root'",
        "severity": "critical",
        "event_sources": ["cloudtrail", "guardduty"],
    })
    assert "id" in result
    assert result["rule_name"] == "Root Login Alert"
    assert result["rule_type"] == "detection"
    assert result["severity"] == "critical"
    assert result["enabled"] is True
    assert result["match_count"] == 0
    assert result["event_sources"] == ["cloudtrail", "guardduty"]


def test_create_rule_json_round_trip(engine):
    sources = ["cloudtrail", "azure_monitor", "gcp_audit"]
    result = engine.create_rule(ORG_A, {
        "rule_name": "Multi-cloud Alert",
        "rule_type": "compliance",
        "severity": "high",
        "event_sources": sources,
    })
    assert result["event_sources"] == sources
    listed = engine.list_rules(ORG_A)
    assert listed[0]["event_sources"] == sources


def test_create_rule_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="Invalid rule_type"):
        engine.create_rule(ORG_A, {
            "rule_name": "Bad", "rule_type": "unknown", "severity": "low"
        })


def test_create_rule_invalid_severity_raises(engine):
    with pytest.raises(ValueError, match="Invalid severity"):
        engine.create_rule(ORG_A, {
            "rule_name": "Bad", "rule_type": "detection", "severity": "extreme"
        })


def test_create_rule_defaults_enabled_true(engine):
    result = engine.create_rule(ORG_A, {
        "rule_name": "Rule", "rule_type": "detection", "severity": "low"
    })
    assert result["enabled"] is True


def test_create_rule_disabled(engine):
    result = engine.create_rule(ORG_A, {
        "rule_name": "Rule", "rule_type": "detection", "severity": "low", "enabled": False
    })
    assert result["enabled"] is False


def test_trigger_rule_increments_match_count(engine):
    rule = engine.create_rule(ORG_A, {
        "rule_name": "Rule", "rule_type": "detection", "severity": "medium"
    })
    assert rule["match_count"] == 0
    r1 = engine.trigger_rule(ORG_A, rule["id"])
    assert r1["match_count"] == 1
    r2 = engine.trigger_rule(ORG_A, rule["id"])
    assert r2["match_count"] == 2
    r3 = engine.trigger_rule(ORG_A, rule["id"])
    assert r3["match_count"] == 3


def test_trigger_rule_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.trigger_rule(ORG_A, "nonexistent-rule")


def test_trigger_rule_org_isolation(engine):
    rule = engine.create_rule(ORG_A, {
        "rule_name": "Rule", "rule_type": "detection", "severity": "medium"
    })
    with pytest.raises(KeyError):
        engine.trigger_rule(ORG_B, rule["id"])


def test_list_rules_filter_by_type(engine):
    engine.create_rule(ORG_A, {"rule_name": "R1", "rule_type": "detection", "severity": "low"})
    engine.create_rule(ORG_A, {"rule_name": "R2", "rule_type": "compliance", "severity": "medium"})
    result = engine.list_rules(ORG_A, rule_type="detection")
    assert len(result) == 1
    assert result[0]["rule_type"] == "detection"


def test_list_rules_filter_by_enabled(engine):
    engine.create_rule(ORG_A, {"rule_name": "R1", "rule_type": "detection", "severity": "low", "enabled": True})
    engine.create_rule(ORG_A, {"rule_name": "R2", "rule_type": "detection", "severity": "low", "enabled": False})
    enabled = engine.list_rules(ORG_A, enabled=True)
    assert all(r["enabled"] is True for r in enabled)
    disabled = engine.list_rules(ORG_A, enabled=False)
    assert all(r["enabled"] is False for r in disabled)


def test_list_rules_org_isolation(engine):
    engine.create_rule(ORG_A, {"rule_name": "R", "rule_type": "detection", "severity": "low"})
    engine.create_rule(ORG_B, {"rule_name": "R", "rule_type": "detection", "severity": "low"})
    assert len(engine.list_rules(ORG_A)) == 1
    assert len(engine.list_rules(ORG_B)) == 1


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_get_analytics_stats_empty(engine):
    stats = engine.get_analytics_stats(ORG_A)
    assert stats["total_events"] == 0
    assert stats["critical_events"] == 0
    assert stats["total_anomalies"] == 0
    assert stats["open_anomalies"] == 0
    assert stats["total_rules"] == 0
    assert stats["enabled_rules"] == 0
    assert stats["avg_risk_score"] == 0.0
    assert stats["by_event_source"] == {}
    assert stats["by_anomaly_type"] == {}
    assert stats["by_severity"] == {}


def test_get_analytics_stats_counts(engine):
    engine.record_event(ORG_A, {
        "event_source": "cloudtrail", "event_type": "api_call",
        "severity": "critical", "risk_score": 80.0
    })
    engine.record_event(ORG_A, {
        "event_source": "guardduty", "event_type": "threat_detection",
        "severity": "high", "risk_score": 60.0
    })

    engine.record_anomaly(ORG_A, {"anomaly_type": "impossible_travel", "severity": "high"})
    a2 = engine.record_anomaly(ORG_A, {"anomaly_type": "crypto_mining", "severity": "critical"})
    engine.update_anomaly_status(ORG_A, a2["id"], "confirmed")

    engine.create_rule(ORG_A, {"rule_name": "R1", "rule_type": "detection", "severity": "low"})
    engine.create_rule(ORG_A, {"rule_name": "R2", "rule_type": "compliance", "severity": "medium", "enabled": False})

    stats = engine.get_analytics_stats(ORG_A)
    assert stats["total_events"] == 2
    assert stats["critical_events"] == 1
    assert stats["total_anomalies"] == 2
    assert stats["open_anomalies"] == 1
    assert stats["total_rules"] == 2
    assert stats["enabled_rules"] == 1
    assert stats["avg_risk_score"] == 70.0
    assert stats["by_event_source"]["cloudtrail"] == 1
    assert stats["by_event_source"]["guardduty"] == 1
    assert stats["by_anomaly_type"]["impossible_travel"] == 1
    assert stats["by_severity"]["critical"] == 1


def test_get_analytics_stats_org_isolation(engine):
    engine.record_event(ORG_A, {"event_source": "cloudtrail", "event_type": "api_call", "severity": "low"})
    engine.record_event(ORG_B, {"event_source": "cloudtrail", "event_type": "api_call", "severity": "low"})
    engine.record_event(ORG_B, {"event_source": "guardduty", "event_type": "api_call", "severity": "high"})
    assert engine.get_analytics_stats(ORG_A)["total_events"] == 1
    assert engine.get_analytics_stats(ORG_B)["total_events"] == 2
