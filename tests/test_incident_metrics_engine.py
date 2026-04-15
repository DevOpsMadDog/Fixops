"""Tests for IncidentMetricsEngine — Beast Mode wave 19."""

from __future__ import annotations

import pytest
from core.incident_metrics_engine import IncidentMetricsEngine


@pytest.fixture()
def engine(tmp_path):
    return IncidentMetricsEngine(db_path=str(tmp_path / "inc_metrics.db"))


def _inc(engine, org_id="org1", **kwargs):
    data = {
        "incident_id": f"INC-{id(kwargs)}",
        "title": "Test Incident",
        "severity": "high",
        "category": "malware",
    }
    data.update(kwargs)
    return engine.record_incident(org_id, data)


# ---------------------------------------------------------------------------
# record_incident
# ---------------------------------------------------------------------------

def test_record_incident_basic(engine):
    inc = _inc(engine)
    assert inc["id"]
    assert inc["status"] == "open"
    assert inc["escalated"] == 0
    assert inc["detected_at"]


def test_record_incident_all_severities(engine):
    for i, sev in enumerate(["critical", "high", "medium", "low"]):
        inc = engine.record_incident("org1", {
            "incident_id": f"INC-SEV-{i}",
            "title": f"Incident {sev}",
            "severity": sev,
            "category": "malware",
        })
        assert inc["severity"] == sev


def test_record_incident_all_categories(engine):
    categories = [
        "malware", "phishing", "data_breach", "ddos", "insider",
        "ransomware", "misconfiguration", "vulnerability", "other",
    ]
    for i, cat in enumerate(categories):
        inc = engine.record_incident("org1", {
            "incident_id": f"INC-CAT-{i}",
            "title": f"Incident {cat}",
            "severity": "low",
            "category": cat,
        })
        assert inc["category"] == cat


def test_record_incident_invalid_severity(engine):
    with pytest.raises(ValueError, match="Invalid severity"):
        engine.record_incident("org1", {
            "incident_id": "INC-BAD",
            "title": "Bad",
            "severity": "extreme",
            "category": "malware",
        })


def test_record_incident_invalid_category(engine):
    with pytest.raises(ValueError, match="Invalid category"):
        engine.record_incident("org1", {
            "incident_id": "INC-BAD2",
            "title": "Bad",
            "severity": "high",
            "category": "unknown_cat",
        })


def test_record_incident_missing_incident_id(engine):
    with pytest.raises(ValueError, match="incident_id is required"):
        engine.record_incident("org1", {
            "incident_id": "",
            "title": "Missing ID",
            "severity": "high",
            "category": "malware",
        })


def test_record_incident_missing_title(engine):
    with pytest.raises(ValueError, match="title is required"):
        engine.record_incident("org1", {
            "incident_id": "INC-999",
            "title": "",
            "severity": "high",
            "category": "malware",
        })


# ---------------------------------------------------------------------------
# update_incident_timeline
# ---------------------------------------------------------------------------

def test_update_timeline_responded(engine):
    inc = _inc(engine, incident_id="INC-TL-1")
    updated = engine.update_incident_timeline("org1", "INC-TL-1", "responded")
    assert updated["responded_at"] is not None
    assert updated["status"] == "investigating"


def test_update_timeline_contained(engine):
    _inc(engine, incident_id="INC-TL-2")
    updated = engine.update_incident_timeline("org1", "INC-TL-2", "contained")
    assert updated["contained_at"] is not None
    assert updated["status"] == "contained"


def test_update_timeline_resolved(engine):
    _inc(engine, incident_id="INC-TL-3")
    updated = engine.update_incident_timeline("org1", "INC-TL-3", "resolved")
    assert updated["resolved_at"] is not None
    assert updated["status"] == "resolved"


def test_update_timeline_closed(engine):
    _inc(engine, incident_id="INC-TL-4")
    updated = engine.update_incident_timeline("org1", "INC-TL-4", "closed")
    assert updated["closed_at"] is not None
    assert updated["status"] == "closed"


def test_update_timeline_custom_timestamp(engine):
    _inc(engine, incident_id="INC-TL-5")
    ts = "2026-04-16T10:00:00+00:00"
    updated = engine.update_incident_timeline("org1", "INC-TL-5", "resolved", timestamp=ts)
    assert updated["resolved_at"] == ts


def test_update_timeline_not_found(engine):
    with pytest.raises(KeyError):
        engine.update_incident_timeline("org1", "NO-SUCH-INC", "responded")


def test_update_timeline_invalid_event_type(engine):
    _inc(engine, incident_id="INC-TL-6")
    with pytest.raises(ValueError, match="Invalid event_type"):
        engine.update_incident_timeline("org1", "INC-TL-6", "acknowledged")


# ---------------------------------------------------------------------------
# escalate_incident
# ---------------------------------------------------------------------------

def test_escalate_incident(engine):
    _inc(engine, incident_id="INC-ESC-1")
    updated = engine.escalate_incident("org1", "INC-ESC-1")
    assert updated["escalated"] == 1


def test_escalate_incident_not_found(engine):
    with pytest.raises(KeyError):
        engine.escalate_incident("org1", "NO-SUCH-INC")


def test_escalate_wrong_org(engine):
    _inc(engine, org_id="org1", incident_id="INC-ESC-2")
    with pytest.raises(KeyError):
        engine.escalate_incident("org2", "INC-ESC-2")


# ---------------------------------------------------------------------------
# list_incidents / get_incident
# ---------------------------------------------------------------------------

def test_list_incidents_empty(engine):
    assert engine.list_incidents("org1") == []


def test_list_incidents_filter_severity(engine):
    _inc(engine, incident_id="INC-LS-1", severity="high")
    _inc(engine, incident_id="INC-LS-2", severity="low")
    results = engine.list_incidents("org1", severity="high")
    assert len(results) == 1
    assert results[0]["severity"] == "high"


def test_list_incidents_filter_status(engine):
    _inc(engine, incident_id="INC-LS-3")
    engine.update_incident_timeline("org1", "INC-LS-3", "resolved")
    open_incs = engine.list_incidents("org1", status="open")
    resolved_incs = engine.list_incidents("org1", status="resolved")
    assert len(open_incs) == 0
    assert len(resolved_incs) == 1


def test_list_incidents_filter_category(engine):
    _inc(engine, incident_id="INC-LS-4", category="phishing")
    _inc(engine, incident_id="INC-LS-5", category="ddos")
    results = engine.list_incidents("org1", category="phishing")
    assert len(results) == 1


def test_list_incidents_limit(engine):
    for i in range(5):
        _inc(engine, incident_id=f"INC-LIM-{i}")
    results = engine.list_incidents("org1", limit=3)
    assert len(results) == 3


def test_get_incident_by_incident_id(engine):
    _inc(engine, incident_id="INC-GET-1")
    inc = engine.get_incident("org1", "INC-GET-1")
    assert inc is not None
    assert inc["incident_id"] == "INC-GET-1"


def test_get_incident_not_found(engine):
    assert engine.get_incident("org1", "NO-SUCH") is None


# ---------------------------------------------------------------------------
# compute_metrics
# ---------------------------------------------------------------------------

def test_compute_metrics_empty(engine):
    metrics = engine.compute_metrics("org1")
    assert metrics["total_incidents"] == 0
    assert metrics["avg_mttr_minutes"] == 0.0
    assert metrics["avg_mttc_minutes"] == 0.0
    assert metrics["escalation_rate"] == 0.0


def test_compute_metrics_with_data(engine):
    _inc(engine, incident_id="INC-M-1")
    engine.update_incident_timeline("org1", "INC-M-1", "resolved",
                                    timestamp="2026-04-16T10:30:00+00:00")
    # Override detected_at to something earlier to get meaningful MTTR
    import sqlite3
    conn = sqlite3.connect(engine._db_path)
    conn.execute(
        "UPDATE incident_records SET detected_at='2026-04-16T10:00:00+00:00' WHERE incident_id='INC-M-1'"
    )
    conn.commit()
    conn.close()
    metrics = engine.compute_metrics("org1")
    assert metrics["total_incidents"] == 1
    assert metrics["resolved_incidents"] == 1
    assert metrics["avg_mttr_minutes"] == pytest.approx(30.0)


def test_compute_metrics_escalation_rate(engine):
    _inc(engine, incident_id="INC-M-2")
    _inc(engine, incident_id="INC-M-3")
    engine.escalate_incident("org1", "INC-M-2")
    metrics = engine.compute_metrics("org1")
    assert metrics["escalation_rate"] == pytest.approx(0.5)


def test_compute_metrics_returns_dict(engine):
    metrics = engine.compute_metrics("org1")
    for key in ["total_incidents", "resolved_incidents", "avg_mttd_minutes",
                "avg_mttr_minutes", "avg_mttc_minutes", "escalation_rate"]:
        assert key in metrics


# ---------------------------------------------------------------------------
# SLA Config
# ---------------------------------------------------------------------------

def test_set_sla_config(engine):
    cfg = engine.set_sla_config("org1", "critical", 15, 60, 240)
    assert cfg["severity"] == "critical"
    assert cfg["response_sla_minutes"] == 15
    assert cfg["containment_sla_minutes"] == 60
    assert cfg["resolution_sla_minutes"] == 240


def test_get_sla_config(engine):
    engine.set_sla_config("org1", "high", 30, 120, 480)
    cfg = engine.get_sla_config("org1", "high")
    assert cfg is not None
    assert cfg["response_sla_minutes"] == 30


def test_get_sla_config_not_set(engine):
    assert engine.get_sla_config("org1", "low") is None


def test_set_sla_config_upsert(engine):
    engine.set_sla_config("org1", "medium", 60, 240, 1440)
    updated = engine.set_sla_config("org1", "medium", 45, 180, 960)
    assert updated["response_sla_minutes"] == 45
    assert updated["containment_sla_minutes"] == 180


def test_set_sla_config_invalid_severity(engine):
    with pytest.raises(ValueError, match="Invalid severity"):
        engine.set_sla_config("org1", "extreme", 60, 240, 1440)


# ---------------------------------------------------------------------------
# get_metrics_stats
# ---------------------------------------------------------------------------

def test_get_metrics_stats_empty(engine):
    stats = engine.get_metrics_stats("org1")
    assert stats["total_incidents"] == 0
    assert stats["open_incidents"] == 0
    assert stats["escalated_count"] == 0
    assert stats["avg_mttr_minutes"] == 0.0


def test_get_metrics_stats_counts(engine):
    _inc(engine, incident_id="INC-ST-1", severity="critical", category="ransomware")
    _inc(engine, incident_id="INC-ST-2", severity="high", category="phishing")
    _inc(engine, incident_id="INC-ST-3", severity="high", category="phishing")
    engine.escalate_incident("org1", "INC-ST-1")
    engine.update_incident_timeline("org1", "INC-ST-2", "resolved")
    stats = engine.get_metrics_stats("org1")
    assert stats["total_incidents"] == 3
    assert stats["open_incidents"] == 2
    assert stats["escalated_count"] == 1
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_severity"]["high"] == 2
    assert stats["by_category"]["phishing"] == 2
    assert stats["by_category"]["ransomware"] == 1


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation(engine):
    _inc(engine, org_id="org1", incident_id="INC-ISO-1")
    _inc(engine, org_id="org2", incident_id="INC-ISO-2")
    assert len(engine.list_incidents("org1")) == 1
    assert len(engine.list_incidents("org2")) == 1
    assert engine.get_incident("org1", "INC-ISO-2") is None
    assert engine.get_incident("org2", "INC-ISO-1") is None
    stats1 = engine.get_metrics_stats("org1")
    stats2 = engine.get_metrics_stats("org2")
    assert stats1["total_incidents"] == 1
    assert stats2["total_incidents"] == 1
