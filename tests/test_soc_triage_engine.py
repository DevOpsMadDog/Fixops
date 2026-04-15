"""Tests for SOC Alert Triage AI Engine — ALDECI.

35+ tests covering:
- Alert ingestion + AI triage
- MITRE mapping per keyword category
- Severity amplifiers / dampeners
- Classification thresholds
- Filtering + retrieval
- Analyst verdict workflow
- Rule creation, listing, application
- Triage sessions
- Stats + daily metrics
- Org isolation (multi-tenancy)
- Confidence score range
"""

from __future__ import annotations

import uuid
import pytest

from core.soc_triage_engine import SOCTriageEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def org_id() -> str:
    return f"test-org-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def org_b() -> str:
    return f"test-org-b-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def engine(org_id: str, tmp_path, monkeypatch) -> SOCTriageEngine:
    monkeypatch.setattr(
        "core.soc_triage_engine._DATA_DIR", tmp_path
    )
    # Clear singleton cache so each test gets a fresh instance
    SOCTriageEngine._instances.clear()
    return SOCTriageEngine.for_org(org_id)


@pytest.fixture
def engine_b(org_b: str, tmp_path, monkeypatch) -> SOCTriageEngine:
    monkeypatch.setattr(
        "core.soc_triage_engine._DATA_DIR", tmp_path
    )
    return SOCTriageEngine.for_org(org_b)


def _alert(title: str, severity: str = "medium", source: str = "siem") -> dict:
    return {
        "title": title,
        "alert_source": source,
        "alert_type": "test",
        "raw_description": f"Raw description for: {title}",
        "severity_original": severity,
    }


# ---------------------------------------------------------------------------
# 1. Basic ingestion
# ---------------------------------------------------------------------------

def test_ingest_alert_basic(engine, org_id):
    result = engine.ingest_alert(org_id, _alert("Unknown Activity Detected"))
    assert "id" in result
    assert result["org_id"] == org_id
    assert "confidence_score" in result
    assert "classification" in result
    assert "recommended_action" in result
    assert "mitre_technique_id" in result
    assert "mitre_tactic" in result
    assert "reasoning" in result
    assert "severity_ai" in result
    assert result["status"] in {"new", "triaging", "escalated", "investigating"}


def test_ingest_alert_returns_triaged_at(engine, org_id):
    result = engine.ingest_alert(org_id, _alert("Generic Alert"))
    assert result["triaged_at"] is not None


def test_ingest_alert_stores_alert_source(engine, org_id):
    result = engine.ingest_alert(org_id, _alert("Test Alert", source="edr"))
    assert result["alert_source"] == "edr"


# ---------------------------------------------------------------------------
# 2. AI triage — MITRE keyword mapping
# ---------------------------------------------------------------------------

def test_ai_triage_brute_force(engine, org_id):
    result = engine.ingest_alert(org_id, _alert("Brute Force Attack Detected on SSH"))
    assert result["mitre_technique_id"] == "T1110"
    assert result["mitre_tactic"] == "credential_access"


def test_ai_triage_credential(engine, org_id):
    result = engine.ingest_alert(org_id, _alert("Credential Stuffing Attempt"))
    assert result["mitre_technique_id"] == "T1110"
    assert result["mitre_tactic"] == "credential_access"


def test_ai_triage_lateral_movement(engine, org_id):
    result = engine.ingest_alert(org_id, _alert("Lateral Movement via SMB Detected"))
    assert result["mitre_technique_id"] == "T1021"
    assert result["mitre_tactic"] == "lateral_movement"


def test_ai_triage_exfiltration(engine, org_id):
    result = engine.ingest_alert(org_id, _alert("Exfiltration of Sensitive Data"))
    assert result["mitre_technique_id"] == "T1041"
    assert result["mitre_tactic"] == "exfiltration"


def test_ai_triage_privilege_escalation(engine, org_id):
    result = engine.ingest_alert(org_id, _alert("Privilege Escalation via SUID Binary"))
    assert result["mitre_technique_id"] == "T1068"
    assert result["mitre_tactic"] == "privilege_escalation"


def test_ai_triage_ransomware(engine, org_id):
    result = engine.ingest_alert(org_id, _alert("Ransomware File Encryption Started"))
    assert result["mitre_technique_id"] == "T1486"
    assert result["mitre_tactic"] == "impact"


def test_ai_triage_phishing(engine, org_id):
    result = engine.ingest_alert(org_id, _alert("Phishing Email with Malicious Attachment"))
    assert result["mitre_technique_id"] == "T1566"
    assert result["mitre_tactic"] == "initial_access"


def test_ai_triage_port_scan(engine, org_id):
    result = engine.ingest_alert(org_id, _alert("Port Scan Detected from External IP"))
    assert result["mitre_technique_id"] == "T1046"
    assert result["mitre_tactic"] == "discovery"


def test_ai_triage_reconnaissance(engine, org_id):
    result = engine.ingest_alert(org_id, _alert("Network Reconnaissance Activity"))
    # "reconnaissance" keyword triggers discovery
    assert result["mitre_tactic"] == "discovery"


# ---------------------------------------------------------------------------
# 3. Severity amplifiers / dampeners
# ---------------------------------------------------------------------------

def test_ai_triage_critical_amplifier(engine, org_id):
    low_sev = engine.ingest_alert(org_id, _alert("Brute Force Login", severity="low"))
    crit_sev = engine.ingest_alert(org_id, _alert("Brute Force Login", severity="critical"))
    # Critical alert should have higher or equal confidence
    assert crit_sev["confidence_score"] >= low_sev["confidence_score"]


def test_ai_triage_critical_amplifier_classification(engine, org_id):
    result = engine.ingest_alert(org_id, _alert("Ransomware File Encryption", severity="critical"))
    assert result["classification"] == "true_positive"
    assert result["recommended_action"] == "escalate"


def test_ai_triage_low_dampener(engine, org_id):
    med = engine.ingest_alert(org_id, _alert("Port Scan Detected", severity="medium"))
    low = engine.ingest_alert(org_id, _alert("Port Scan Detected", severity="low"))
    assert low["confidence_score"] <= med["confidence_score"]


def test_ai_triage_high_amplifier(engine, org_id):
    med = engine.ingest_alert(org_id, _alert("Phishing Email with Malicious Attachment", severity="medium"))
    high = engine.ingest_alert(org_id, _alert("Phishing Email with Malicious Attachment", severity="high"))
    assert high["confidence_score"] >= med["confidence_score"]


# ---------------------------------------------------------------------------
# 4. Classification thresholds
# ---------------------------------------------------------------------------

def test_true_positive_classification(engine, org_id):
    # Ransomware (0.5) at critical severity: 0.5 * 1.5 = 0.75 > 0.7 → true_positive
    result = engine.ingest_alert(org_id, _alert("Ransomware Encryption Active", severity="critical"))
    assert result["classification"] == "true_positive"
    assert result["recommended_action"] == "escalate"


def test_false_positive_classification(engine, org_id):
    # No keywords → score=0 → FP
    result = engine.ingest_alert(org_id, _alert("Normal System Heartbeat Check", severity="low"))
    assert result["classification"] == "false_positive"
    assert result["recommended_action"] == "close"


def test_undetermined_investigate_classification(engine, org_id):
    # Lateral movement (0.4) at medium severity: score=0.4 → undetermined
    result = engine.ingest_alert(org_id, _alert("Lateral Movement via SMB", severity="medium"))
    assert result["classification"] == "undetermined"


def test_auto_escalate_sets_status_escalated(engine, org_id):
    # Ransomware (0.5) at critical severity: 0.5 * 1.5 = 0.75 > 0.7 → escalated
    result = engine.ingest_alert(org_id, _alert("Ransomware Encryption Alert", severity="critical"))
    assert result["status"] == "escalated"


# ---------------------------------------------------------------------------
# 5. Listing + filtering
# ---------------------------------------------------------------------------

def test_list_alerts_returns_all(engine, org_id):
    for i in range(3):
        engine.ingest_alert(org_id, _alert(f"Generic Alert {i}"))
    alerts = engine.list_alerts(org_id)
    assert len(alerts) >= 3


def test_list_alerts_filter_status(engine, org_id):
    engine.ingest_alert(org_id, _alert("Ransomware Active", severity="high"))
    escalated = engine.list_alerts(org_id, status="escalated")
    for a in escalated:
        assert a["status"] == "escalated"


def test_list_alerts_filter_severity(engine, org_id):
    engine.ingest_alert(org_id, _alert("Alert A", severity="critical"))
    engine.ingest_alert(org_id, _alert("Alert B", severity="low"))
    crit_alerts = engine.list_alerts(org_id, severity="critical")
    for a in crit_alerts:
        assert a["severity_original"] == "critical"


def test_list_alerts_filter_classification(engine, org_id):
    engine.ingest_alert(org_id, _alert("Ransomware Encryption", severity="critical"))
    tp_alerts = engine.list_alerts(org_id, classification="true_positive")
    for a in tp_alerts:
        assert a["classification"] == "true_positive"


def test_list_alerts_limit(engine, org_id):
    for i in range(10):
        engine.ingest_alert(org_id, _alert(f"Flood Alert {i}"))
    alerts = engine.list_alerts(org_id, limit=3)
    assert len(alerts) <= 3


# ---------------------------------------------------------------------------
# 6. Get single alert
# ---------------------------------------------------------------------------

def test_get_alert(engine, org_id):
    ingested = engine.ingest_alert(org_id, _alert("Specific Alert to Retrieve"))
    fetched = engine.get_alert(org_id, ingested["id"])
    assert fetched is not None
    assert fetched["id"] == ingested["id"]
    assert fetched["title"] == ingested["title"]


def test_get_alert_not_found(engine, org_id):
    result = engine.get_alert(org_id, str(uuid.uuid4()))
    assert result is None


# ---------------------------------------------------------------------------
# 7. Analyst verdict
# ---------------------------------------------------------------------------

def test_update_verdict_confirmed(engine, org_id):
    alert = engine.ingest_alert(org_id, _alert("Lateral Movement Detected"))
    updated = engine.update_verdict(org_id, alert["id"], "analyst-1", "confirmed")
    assert updated is not None
    assert updated["analyst_verdict"] == "confirmed"
    assert updated["analyst_id"] == "analyst-1"


def test_update_verdict_disputed(engine, org_id):
    alert = engine.ingest_alert(org_id, _alert("Port Scan Detected"))
    updated = engine.update_verdict(org_id, alert["id"], "analyst-2", "disputed")
    assert updated is not None
    assert updated["analyst_verdict"] == "disputed"


def test_update_verdict_closed(engine, org_id):
    alert = engine.ingest_alert(org_id, _alert("Heartbeat Noise"))
    updated = engine.update_verdict(org_id, alert["id"], "analyst-3", "closed")
    assert updated is not None
    assert updated["analyst_verdict"] == "closed"
    assert updated["closed_at"] is not None


def test_update_verdict_invalid_raises(engine, org_id):
    alert = engine.ingest_alert(org_id, _alert("Test Alert"))
    with pytest.raises(ValueError):
        engine.update_verdict(org_id, alert["id"], "analyst-1", "invalid_verdict")


def test_update_verdict_not_found(engine, org_id):
    result = engine.update_verdict(org_id, str(uuid.uuid4()), "analyst-1", "confirmed")
    assert result is None


# ---------------------------------------------------------------------------
# 8. Rules
# ---------------------------------------------------------------------------

def test_create_rule(engine, org_id):
    rule = engine.create_rule(org_id, {
        "rule_name": "Block Critical EDR Alerts",
        "conditions": {"alert_source": "edr", "severity_original": "critical"},
        "action": "escalate",
        "tag": "auto-escalate",
        "enabled": True,
    })
    assert "id" in rule
    assert rule["rule_name"] == "Block Critical EDR Alerts"
    assert rule["enabled"] is True
    assert isinstance(rule["conditions"], dict)


def test_create_rule_missing_name_raises(engine, org_id):
    with pytest.raises(ValueError):
        engine.create_rule(org_id, {"rule_name": "", "conditions": {}})


def test_list_rules(engine, org_id):
    engine.create_rule(org_id, {"rule_name": "Rule A", "conditions": {}})
    engine.create_rule(org_id, {"rule_name": "Rule B", "conditions": {}})
    rules = engine.list_rules(org_id)
    names = [r["rule_name"] for r in rules]
    assert "Rule A" in names
    assert "Rule B" in names


def test_apply_rules_match(engine, org_id):
    engine.create_rule(org_id, {
        "rule_name": "Match EDR Alerts",
        "conditions": {"alert_source": "edr"},
        "action": "escalate",
        "enabled": True,
    })
    alert = engine.ingest_alert(org_id, _alert("EDR Detection", source="edr"))
    matched = engine.apply_rules(org_id, alert["id"])
    assert len(matched) >= 1
    assert any(r["rule_name"] == "Match EDR Alerts" for r in matched)


def test_apply_rules_no_match(engine, org_id):
    engine.create_rule(org_id, {
        "rule_name": "Match SIEM Only",
        "conditions": {"alert_source": "siem"},
        "action": "monitor",
        "enabled": True,
    })
    alert = engine.ingest_alert(org_id, _alert("EDR Alert", source="edr"))
    matched = engine.apply_rules(org_id, alert["id"])
    matching_names = [r["rule_name"] for r in matched]
    assert "Match SIEM Only" not in matching_names


def test_apply_rules_increments_hit_count(engine, org_id):
    engine.create_rule(org_id, {
        "rule_name": "Count Me",
        "conditions": {"alert_source": "manual"},
        "action": "monitor",
        "enabled": True,
    })
    alert = engine.ingest_alert(org_id, _alert("Manual Alert", source="manual"))
    engine.apply_rules(org_id, alert["id"])
    rules = engine.list_rules(org_id)
    rule = next(r for r in rules if r["rule_name"] == "Count Me")
    assert rule["hit_count"] >= 1


def test_apply_rules_disabled_rule_skipped(engine, org_id):
    engine.create_rule(org_id, {
        "rule_name": "Disabled Rule",
        "conditions": {"alert_source": "edr"},
        "action": "escalate",
        "enabled": False,
    })
    alert = engine.ingest_alert(org_id, _alert("EDR Alert", source="edr"))
    matched = engine.apply_rules(org_id, alert["id"])
    disabled = [r for r in matched if r["rule_name"] == "Disabled Rule"]
    assert len(disabled) == 0


# ---------------------------------------------------------------------------
# 9. Sessions
# ---------------------------------------------------------------------------

def test_start_session(engine, org_id):
    session = engine.start_session(org_id, "analyst-42")
    assert "id" in session
    assert session["org_id"] == org_id
    assert session["analyst_id"] == "analyst-42"
    assert session["session_start"] is not None
    assert session["session_end"] is None


def test_start_session_missing_analyst_raises(engine, org_id):
    with pytest.raises(ValueError):
        engine.start_session(org_id, "")


def test_close_session(engine, org_id):
    session = engine.start_session(org_id, "analyst-7")
    closed = engine.close_session(org_id, session["id"])
    assert closed is not None
    assert closed["session_end"] is not None
    assert isinstance(closed["alerts_reviewed"], int)
    assert isinstance(closed["alerts_confirmed_tp"], int)
    assert isinstance(closed["alerts_closed_fp"], int)


def test_close_session_not_found(engine, org_id):
    result = engine.close_session(org_id, str(uuid.uuid4()))
    assert result is None


# ---------------------------------------------------------------------------
# 10. Stats + daily metrics
# ---------------------------------------------------------------------------

def test_get_triage_stats(engine, org_id):
    engine.ingest_alert(org_id, _alert("Ransomware Active", severity="critical"))
    engine.ingest_alert(org_id, _alert("Normal Heartbeat", severity="low"))
    stats = engine.get_triage_stats(org_id)
    assert "total" in stats
    assert stats["total"] >= 2
    assert "by_classification" in stats
    assert "by_severity" in stats
    assert "by_source" in stats
    assert "avg_confidence" in stats
    assert "escalation_rate" in stats
    assert "false_positive_rate" in stats


def test_get_triage_stats_rates_are_fractions(engine, org_id):
    engine.ingest_alert(org_id, _alert("Ransomware Attack", severity="critical"))
    stats = engine.get_triage_stats(org_id)
    assert 0.0 <= stats["escalation_rate"] <= 1.0
    assert 0.0 <= stats["false_positive_rate"] <= 1.0


def test_get_triage_stats_empty_org(engine, org_id):
    stats = engine.get_triage_stats(org_id)
    assert stats["total"] == 0
    assert stats["escalation_rate"] == 0.0
    assert stats["false_positive_rate"] == 0.0


def test_daily_metrics(engine, org_id):
    engine.ingest_alert(org_id, _alert("Lateral Movement", severity="medium"))
    metrics = engine.get_daily_metrics(org_id)
    assert isinstance(metrics, list)
    assert len(metrics) >= 1
    today_metrics = metrics[0]
    assert "date" in today_metrics
    assert "total_alerts" in today_metrics
    assert today_metrics["total_alerts"] >= 1


def test_daily_metrics_true_positives_counted(engine, org_id):
    # Ransomware (0.5) at critical: 0.5 * 1.5 = 0.75 > 0.7 → true_positive
    engine.ingest_alert(org_id, _alert("Ransomware Encryption", severity="critical"))
    metrics = engine.get_daily_metrics(org_id)
    assert metrics[0]["true_positives"] >= 1


def test_daily_metrics_false_positives_counted(engine, org_id):
    engine.ingest_alert(org_id, _alert("Regular System Heartbeat", severity="low"))
    metrics = engine.get_daily_metrics(org_id)
    assert metrics[0]["false_positives"] >= 1


# ---------------------------------------------------------------------------
# 11. Multi-tenancy / org isolation
# ---------------------------------------------------------------------------

def test_org_isolation(tmp_path, monkeypatch):
    monkeypatch.setattr("core.soc_triage_engine._DATA_DIR", tmp_path)
    SOCTriageEngine._instances.clear()

    org_a = f"org-a-{uuid.uuid4().hex[:6]}"
    org_b = f"org-b-{uuid.uuid4().hex[:6]}"

    engine_a = SOCTriageEngine.for_org(org_a)
    engine_b = SOCTriageEngine.for_org(org_b)

    engine_a.ingest_alert(org_a, _alert("Secret Alert for Org A"))

    alerts_a = engine_a.list_alerts(org_a)
    alerts_b = engine_b.list_alerts(org_b)

    assert len(alerts_a) >= 1
    assert len(alerts_b) == 0


def test_rules_org_isolation(tmp_path, monkeypatch):
    monkeypatch.setattr("core.soc_triage_engine._DATA_DIR", tmp_path)
    SOCTriageEngine._instances.clear()

    org_a = f"org-a-{uuid.uuid4().hex[:6]}"
    org_b = f"org-b-{uuid.uuid4().hex[:6]}"

    engine_a = SOCTriageEngine.for_org(org_a)
    engine_b = SOCTriageEngine.for_org(org_b)

    engine_a.create_rule(org_a, {"rule_name": "Org A Rule", "conditions": {}})

    rules_b = engine_b.list_rules(org_b)
    assert not any(r["rule_name"] == "Org A Rule" for r in rules_b)


# ---------------------------------------------------------------------------
# 12. Confidence score range
# ---------------------------------------------------------------------------

def test_confidence_score_range(engine, org_id):
    titles = [
        "Ransomware Encryption Critical",
        "Brute Force SSH",
        "Lateral Movement via RDP",
        "Normal Heartbeat",
        "Port Scan Detected",
        "Phishing Email Attack",
        "Exfiltration Detected",
    ]
    for title in titles:
        result = engine.ingest_alert(org_id, _alert(title))
        score = result["confidence_score"]
        assert 0.0 <= score <= 1.0, f"Score {score} out of range for: {title}"


def test_confidence_score_never_exceeds_095(engine, org_id):
    result = engine.ingest_alert(
        org_id, _alert("Ransomware Exfiltration Lateral Movement Brute Force", severity="critical")
    )
    assert result["confidence_score"] <= 0.95


# ---------------------------------------------------------------------------
# 13. Threat actor hypothesis
# ---------------------------------------------------------------------------

def test_threat_actor_hypothesis_set(engine, org_id):
    result = engine.ingest_alert(org_id, _alert("Ransomware Encryption in Progress"))
    assert result["threat_actor_hypothesis"] != ""


def test_threat_actor_hypothesis_unknown_for_no_match(engine, org_id):
    result = engine.ingest_alert(org_id, _alert("Generic Unknown Alert"))
    # threat_actor_hypothesis may be generic; should still be a string
    assert isinstance(result["threat_actor_hypothesis"], str)


# ---------------------------------------------------------------------------
# 14. Priority rank ordering
# ---------------------------------------------------------------------------

def test_priority_rank_tp_lower_than_fp(engine, org_id):
    # Ransomware at critical: 0.5 * 1.5 = 0.75 → TP, rank=10
    # Normal check at low: score=0 → FP, rank=90
    tp = engine.ingest_alert(org_id, _alert("Ransomware File Encryption", severity="critical"))
    fp = engine.ingest_alert(org_id, _alert("Normal System Check", severity="low"))
    # Lower priority_rank = higher priority
    assert tp["priority_rank"] < fp["priority_rank"]


def test_list_alerts_ordered_by_priority(engine, org_id):
    engine.ingest_alert(org_id, _alert("Normal Heartbeat", severity="low"))    # FP, rank=90
    engine.ingest_alert(org_id, _alert("Ransomware Active", severity="critical"))  # TP, rank=10
    alerts = engine.list_alerts(org_id)
    ranks = [a["priority_rank"] for a in alerts]
    assert ranks == sorted(ranks)
