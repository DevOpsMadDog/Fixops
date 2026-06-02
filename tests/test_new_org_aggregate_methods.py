"""Regression coverage for org-level aggregate engine methods wired this session.

These methods back the UI dashboard endpoints that were previously missing
(SCA org vulns/licenses, chaos observations feed, incident events/MTTR,
SOC alert queue/snapshots, awareness risk trend). Each test seeds REAL data
through the engine's own write path (no direct SQL, no mocks) and asserts the
aggregate reads it back — and that empty orgs return honest-empty, never crash.

Run:
  python -m pytest tests/test_new_org_aggregate_methods.py -q -o "addopts="
"""

from __future__ import annotations

import os
import tempfile
import uuid

import pytest


@pytest.fixture()
def tmp_db(tmp_path):
    """Per-test sqlite path so engines never collide on shared domain DBs."""
    return str(tmp_path / f"{uuid.uuid4().hex}.db")


# ---------------------------------------------------------------------------
# Software Composition Analysis — list_org_vulnerabilities / get_org_license_report
# ---------------------------------------------------------------------------

def test_sca_org_vulnerabilities_and_license_report(tmp_db):
    from core.software_composition_analysis_engine import (
        SoftwareCompositionAnalysisEngine,
    )

    eng = SoftwareCompositionAnalysisEngine(db_path=tmp_db)
    org = "org-sca-test"
    proj = eng.register_project(org, {"name": "svc-a", "language": "python"})
    eng.submit_scan(
        org,
        proj["id"],
        {
            "dependencies": [
                {"name": "log4j-core", "version": "2.14.1", "license": "Apache-2.0"},
                {"name": "leftpad", "version": "1.0.0", "license": "GPL-3.0"},
                {"name": "safe-lib", "version": "9.9.9", "license": "MIT"},
            ]
        },
    )

    vulns = eng.list_org_vulnerabilities(org)
    assert any(v["name"] == "log4j-core" for v in vulns), "known-vulnerable dep must surface"
    assert all(v.get("is_vulnerable") for v in vulns), "only vulnerable deps returned"
    # carries project context for the UI
    assert all("project_id" in v for v in vulns)

    rep = eng.get_org_license_report(org)
    assert rep["licenses"].get("GPL-3.0") == 1
    assert rep["risky_count"] >= 1
    assert any(r["license"] == "GPL-3.0" for r in rep["risky_licenses"])


def test_sca_org_aggregates_honest_empty(tmp_db):
    from core.software_composition_analysis_engine import (
        SoftwareCompositionAnalysisEngine,
    )

    eng = SoftwareCompositionAnalysisEngine(db_path=tmp_db)
    assert eng.list_org_vulnerabilities("empty-org") == []
    rep = eng.get_org_license_report("empty-org")
    assert rep == {"licenses": {}, "risky_licenses": [], "risky_count": 0}


# ---------------------------------------------------------------------------
# Security Chaos — list_all_observations
# ---------------------------------------------------------------------------

def test_chaos_list_all_observations(tmp_db):
    from core.security_chaos_engine import SecurityChaosEngine

    eng = SecurityChaosEngine(db_path=tmp_db)
    org = "org-chaos-test"
    exp = eng.create_experiment(
        org,
        {
            "experiment_name": "fw-bypass-1",
            "experiment_type": "firewall_bypass",
            "target_system": "edge-fw",
        },
    )
    eng.add_observation(
        org,
        exp["id"],
        {"observation_type": "control_held", "severity": "info", "description": "blocked"},
    )
    eng.add_observation(
        org,
        exp["id"],
        {"observation_type": "alert_triggered", "severity": "high", "description": "siem fired"},
    )

    obs = eng.list_all_observations(org)
    assert len(obs) == 2
    assert {o["observation_type"] for o in obs} == {"control_held", "alert_triggered"}
    # honest-empty for unknown org
    assert eng.list_all_observations("nobody") == []


# ---------------------------------------------------------------------------
# Incident Timeline — list_all_events / get_mttr_analytics
# ---------------------------------------------------------------------------

def test_incident_events_and_mttr(tmp_db):
    from core.incident_timeline_engine import IncidentTimelineEngine

    eng = IncidentTimelineEngine(db_path=tmp_db)
    org = "org-incident-test"
    tl = eng.create_timeline(
        org, {"title": "Breach A", "incident_type": "breach", "severity": "high"}
    )
    tid = tl["timeline_id"]
    eng.add_event(org, tid, {"event_type": "detection", "title": "IDS hit", "severity": "high"})
    eng.add_event(org, tid, {"event_type": "containment", "title": "isolated host"})

    events = eng.list_all_events(org)
    assert len(events) == 2
    # evidence_refs must be a parsed list, not a JSON string
    assert all(isinstance(e["evidence_refs"], list) for e in events)

    # unresolved -> avg is None but never crashes
    mttr_open = eng.get_mttr_analytics(org)
    assert mttr_open["total_timelines"] == 1
    assert mttr_open["avg_mttr_minutes"] is None

    # resolve it -> avg becomes a real number
    eng.update_timeline_status(org, tid, "resolved")
    mttr_done = eng.get_mttr_analytics(org)
    assert mttr_done["avg_mttr_minutes"] is not None
    assert mttr_done["avg_mttr_hours"] is not None

    # empty org -> honest-empty, no crash
    empty = eng.get_mttr_analytics("nobody")
    assert empty["total_timelines"] == 0
    assert empty["avg_mttr_minutes"] is None
    assert eng.list_all_events("nobody") == []


# ---------------------------------------------------------------------------
# SOC Metrics — list_alerts / list_snapshots
# ---------------------------------------------------------------------------

def test_soc_alert_queue_and_snapshots(tmp_db):
    from core.security_operations_metrics_engine import (
        SecurityOperationsMetricsEngine,
    )

    eng = SecurityOperationsMetricsEngine(db_path=tmp_db)
    org = "org-soc-test"
    a_open = eng.create_alert(org, "siem", "critical", "intrusion")
    eng.create_alert(org, "edr", "medium", "malware")
    eng.acknowledge_alert(a_open["id"], org, "analyst-1")

    queue = eng.list_alerts(org)
    assert len(queue) == 2
    # acknowledged sorts after open... here open(medium) before acknowledged(critical)
    statuses = [a["status"] for a in queue]
    assert statuses[0] == "open"

    only_ack = eng.list_alerts(org, status="acknowledged")
    assert len(only_ack) == 1
    assert only_ack[0]["id"] == a_open["id"]

    eng.take_daily_snapshot(org)
    snaps = eng.list_snapshots(org)
    assert len(snaps) == 1
    assert snaps[0]["total_alerts"] == 2

    # honest-empty
    assert eng.list_alerts("nobody") == []
    assert eng.list_snapshots("nobody") == []


# ---------------------------------------------------------------------------
# Awareness — get_risk_trend
# ---------------------------------------------------------------------------

def test_awareness_risk_trend(tmp_db):
    from core.awareness_score_engine import AwarenessScoreEngine

    eng = AwarenessScoreEngine(db_path=tmp_db)
    org = "org-aware-test"
    eng.register_employee(org, {"employee_id": "e1", "name": "Pat", "department": "eng"})
    eng.record_training(
        org, "e1", {"training_name": "phishing-101", "passed": True, "score": 90}
    )
    score = eng.calculate_score(org, "e1")
    assert "overall_score" in score

    trend = eng.get_risk_trend(org)
    assert len(trend) >= 1
    assert all(set(pt.keys()) == {"month", "score"} for pt in trend)
    assert all(0 <= pt["score"] <= 100 for pt in trend)

    # honest-empty for org with no scores
    assert eng.get_risk_trend("nobody") == []
