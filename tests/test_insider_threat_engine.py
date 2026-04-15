"""Tests for InsiderThreatEngine — 30 tests covering all public methods + org isolation.

Engine: suite-core/core/insider_threat_engine.py
Constructor: InsiderThreatEngine(db_path=str(tmp_path / "insider.db"))
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

import pytest

from core.insider_threat_engine import InsiderThreatEngine, THREAT_INDICATORS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return InsiderThreatEngine(db_path=str(tmp_path / "insider.db"))


@pytest.fixture
def org():
    return "org-alpha"


@pytest.fixture
def org2():
    return "org-beta"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _event(engine, user_id, event_type="login", resource="/app/home", org_id="org-alpha", details=None):
    return engine.record_user_event(
        user_id=user_id,
        event_type=event_type,
        resource=resource,
        details=details or {},
        org_id=org_id,
    )


def _alert(engine, user_id, indicator="after_hours_access", severity="medium", org_id="org-alpha"):
    return engine.create_alert(
        user_id=user_id,
        indicator=indicator,
        evidence={"detail": "test"},
        severity=severity,
        org_id=org_id,
    )


# ---------------------------------------------------------------------------
# record_user_event
# ---------------------------------------------------------------------------


def test_record_user_event_returns_string_id(engine, org):
    eid = _event(engine, "u1", org_id=org)
    assert isinstance(eid, str)
    assert len(eid) == 36  # UUID4


def test_record_user_event_multiple_unique_ids(engine, org):
    ids = [_event(engine, "u1", org_id=org) for _ in range(5)]
    assert len(set(ids)) == 5


def test_record_user_event_stores_in_timeline(engine, org):
    _event(engine, "u2", event_type="download", resource="/data/report.csv", org_id=org)
    timeline = engine.get_user_timeline("u2", org_id=org)
    assert len(timeline) == 1
    assert timeline[0]["event_type"] == "download"
    assert timeline[0]["resource"] == "/data/report.csv"


def test_record_user_event_accepts_all_event_types(engine, org):
    for etype in ("login", "download", "data_export", "file_access"):
        _event(engine, "u3", event_type=etype, org_id=org)
    timeline = engine.get_user_timeline("u3", org_id=org)
    assert len(timeline) == 4


def test_record_user_event_org_isolation(engine, org, org2):
    _event(engine, "u4", org_id=org)
    timeline = engine.get_user_timeline("u4", org_id=org2)
    assert timeline == []


# ---------------------------------------------------------------------------
# analyze_user_risk — baseline
# ---------------------------------------------------------------------------


def test_analyze_user_risk_baseline_no_events(engine, org):
    result = engine.analyze_user_risk("nobody", org_id=org)
    assert result["risk_score"] == 0.0
    assert result["risk_level"] == "baseline"
    assert result["indicators"] == []
    assert result["event_count"] == 0


def test_analyze_user_risk_returns_required_keys(engine, org):
    _event(engine, "u5", org_id=org)
    result = engine.analyze_user_risk("u5", org_id=org)
    for key in ("user_id", "org_id", "risk_level", "risk_score", "indicators", "event_count", "recommendation"):
        assert key in result, f"Missing key: {key}"


def test_analyze_user_risk_org_isolation(engine, org, org2):
    # Trigger bulk_data_download for org, but query from org2 — should be baseline
    for i in range(55):
        _event(engine, "u6", event_type="download", resource=f"/file/{i}.csv", org_id=org)
    result = engine.analyze_user_risk("u6", org_id=org2)
    assert result["risk_score"] == 0.0


# ---------------------------------------------------------------------------
# analyze_user_risk — bulk_data_download indicator
# ---------------------------------------------------------------------------


def test_analyze_detects_bulk_data_download(engine, org):
    today = datetime.now(timezone.utc).strftime("%Y-%m-%dT10:00:00")
    for i in range(51):
        engine.record_user_event(
            user_id="bulk_user",
            event_type="download",
            resource=f"/file/{i}.csv",
            details={},
            timestamp=f"{today[:10]}T10:{i:02d}:00+00:00",
            org_id=org,
        )
    result = engine.analyze_user_risk("bulk_user", org_id=org)
    indicator_names = [ind["indicator"] for ind in result["indicators"]]
    assert "bulk_data_download" in indicator_names
    assert result["risk_score"] >= 35.0


# ---------------------------------------------------------------------------
# analyze_user_risk — after_hours_access indicator
# ---------------------------------------------------------------------------


def test_analyze_detects_after_hours_access(engine, org):
    # Hour 23 = after hours
    engine.record_user_event(
        user_id="night_user",
        event_type="login",
        resource="/app",
        details={},
        timestamp="2026-04-10T23:30:00+00:00",
        org_id=org,
    )
    result = engine.analyze_user_risk("night_user", org_id=org)
    indicator_names = [ind["indicator"] for ind in result["indicators"]]
    assert "after_hours_access" in indicator_names


# ---------------------------------------------------------------------------
# analyze_user_risk — risk levels
# ---------------------------------------------------------------------------


def test_analyze_risk_level_caps_at_100(engine, org):
    # Generate many high-severity indicators: bulk downloads AND sensitive access
    for i in range(55):
        engine.record_user_event(
            user_id="maxrisk",
            event_type="download",
            resource=f"/secret/credential_{i}.key",
            details={},
            timestamp=f"2026-04-10T10:{i % 60:02d}:00+00:00",
            org_id=org,
        )
    result = engine.analyze_user_risk("maxrisk", org_id=org)
    assert result["risk_score"] <= 100.0


# ---------------------------------------------------------------------------
# get_high_risk_users
# ---------------------------------------------------------------------------


def test_get_high_risk_users_empty_when_no_events(engine, org):
    result = engine.get_high_risk_users(org_id=org)
    assert result == []


def test_get_high_risk_users_returns_above_threshold(engine, org):
    # bulk_data_download = high severity = 35 score
    for i in range(55):
        engine.record_user_event(
            user_id="risky_user",
            event_type="download",
            resource=f"/f/{i}",
            details={},
            timestamp=f"2026-04-10T10:{i % 60:02d}:00+00:00",
            org_id=org,
        )
    result = engine.get_high_risk_users(org_id=org, min_risk_score=30.0)
    user_ids = [r["user_id"] for r in result]
    assert "risky_user" in user_ids


def test_get_high_risk_users_excludes_below_threshold(engine, org):
    _event(engine, "safe_user", org_id=org)
    result = engine.get_high_risk_users(org_id=org, min_risk_score=50.0)
    user_ids = [r["user_id"] for r in result]
    assert "safe_user" not in user_ids


def test_get_high_risk_users_org_isolation(engine, org, org2):
    for i in range(55):
        engine.record_user_event(
            user_id="risky",
            event_type="download",
            resource=f"/f/{i}",
            details={},
            timestamp=f"2026-04-10T10:{i % 60:02d}:00+00:00",
            org_id=org,
        )
    result = engine.get_high_risk_users(org_id=org2, min_risk_score=30.0)
    assert result == []


def test_get_high_risk_users_sorted_descending(engine, org):
    # Create two users with different risk profiles — both above threshold
    for i in range(55):
        engine.record_user_event(
            user_id="user_high",
            event_type="download",
            resource=f"/a/{i}",
            details={},
            timestamp=f"2026-04-10T10:{i % 60:02d}:00+00:00",
            org_id=org,
        )
    engine.record_user_event(
        user_id="user_night",
        event_type="login",
        resource="/app",
        details={},
        timestamp="2026-04-10T23:30:00+00:00",
        org_id=org,
    )
    result = engine.get_high_risk_users(org_id=org, min_risk_score=10.0)
    scores = [r["risk_score"] for r in result]
    assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# create_alert
# ---------------------------------------------------------------------------


def test_create_alert_returns_record(engine, org):
    alert = _alert(engine, "u10", org_id=org)
    assert alert["alert_id"] is not None
    assert alert["user_id"] == "u10"
    assert alert["indicator"] == "after_hours_access"
    assert alert["severity"] == "medium"
    assert alert["status"] == "open"
    assert alert["org_id"] == org


def test_create_alert_accepts_all_valid_indicators(engine, org):
    for indicator in THREAT_INDICATORS:
        a = engine.create_alert(
            user_id="u11",
            indicator=indicator,
            evidence={},
            severity="low",
            org_id=org,
        )
        assert a["indicator"] == indicator


# ---------------------------------------------------------------------------
# get_alerts
# ---------------------------------------------------------------------------


def test_get_alerts_returns_all_for_org(engine, org):
    _alert(engine, "u12", org_id=org)
    _alert(engine, "u13", org_id=org)
    alerts = engine.get_alerts(org_id=org)
    assert len(alerts) == 2


def test_get_alerts_filtered_by_user(engine, org):
    _alert(engine, "u14", org_id=org)
    _alert(engine, "u15", org_id=org)
    alerts = engine.get_alerts(user_id="u14", org_id=org)
    assert all(a["user_id"] == "u14" for a in alerts)
    assert len(alerts) == 1


def test_get_alerts_filtered_by_severity(engine, org):
    _alert(engine, "u16", severity="high", org_id=org)
    _alert(engine, "u17", severity="low", org_id=org)
    highs = engine.get_alerts(org_id=org, severity="high")
    assert all(a["severity"] == "high" for a in highs)
    assert len(highs) == 1


def test_get_alerts_org_isolation(engine, org, org2):
    _alert(engine, "u18", org_id=org)
    alerts = engine.get_alerts(org_id=org2)
    assert alerts == []


def test_get_alerts_evidence_is_dict(engine, org):
    _alert(engine, "u19", org_id=org)
    alerts = engine.get_alerts(org_id=org)
    assert isinstance(alerts[0]["evidence"], dict)


# ---------------------------------------------------------------------------
# resolve_alert
# ---------------------------------------------------------------------------


def test_resolve_alert_marks_resolved(engine, org):
    alert = _alert(engine, "u20", org_id=org)
    resolved = engine.resolve_alert(
        alert_id=alert["alert_id"],
        resolution="false_positive",
        resolved_by="analyst@example.com",
        org_id=org,
    )
    assert resolved["status"] == "resolved"
    assert resolved["resolution"] == "false_positive"
    assert resolved["resolved_by"] == "analyst@example.com"
    assert resolved["resolved_at"] is not None


def test_resolve_alert_not_found_raises(engine, org):
    with pytest.raises(ValueError):
        engine.resolve_alert(
            alert_id="nonexistent-id",
            resolution="confirmed",
            resolved_by="sec@example.com",
            org_id=org,
        )


def test_resolve_alert_org_guard(engine, org, org2):
    alert = _alert(engine, "u21", org_id=org)
    # Resolving from a different org should raise ValueError (row not found for org2)
    with pytest.raises(ValueError):
        engine.resolve_alert(
            alert_id=alert["alert_id"],
            resolution="confirmed",
            resolved_by="hacker",
            org_id=org2,
        )


# ---------------------------------------------------------------------------
# get_user_timeline
# ---------------------------------------------------------------------------


def test_get_user_timeline_returns_events(engine, org):
    _event(engine, "u22", event_type="login", org_id=org)
    _event(engine, "u22", event_type="download", org_id=org)
    timeline = engine.get_user_timeline("u22", org_id=org)
    assert len(timeline) == 2


def test_get_user_timeline_limit(engine, org):
    for _ in range(10):
        _event(engine, "u23", org_id=org)
    timeline = engine.get_user_timeline("u23", org_id=org, limit=3)
    assert len(timeline) == 3


def test_get_user_timeline_details_is_dict(engine, org):
    _event(engine, "u24", details={"ip": "10.0.0.1"}, org_id=org)
    timeline = engine.get_user_timeline("u24", org_id=org)
    assert isinstance(timeline[0]["details"], dict)
    assert timeline[0]["details"]["ip"] == "10.0.0.1"


def test_get_user_timeline_org_isolation(engine, org, org2):
    _event(engine, "u25", org_id=org)
    timeline = engine.get_user_timeline("u25", org_id=org2)
    assert timeline == []


# ---------------------------------------------------------------------------
# get_org_risk_summary
# ---------------------------------------------------------------------------


def test_get_org_risk_summary_empty_org(engine, org):
    summary = engine.get_org_risk_summary(org_id=org)
    assert summary["org_id"] == org
    assert summary["total_users_monitored"] == 0
    assert summary["active_alerts"] == 0
    assert summary["avg_risk_score"] == 0.0


def test_get_org_risk_summary_counts_users(engine, org):
    _event(engine, "user_a", org_id=org)
    _event(engine, "user_b", org_id=org)
    summary = engine.get_org_risk_summary(org_id=org)
    assert summary["total_users_monitored"] == 2


def test_get_org_risk_summary_counts_active_alerts(engine, org):
    _alert(engine, "u26", org_id=org)
    _alert(engine, "u27", org_id=org)
    summary = engine.get_org_risk_summary(org_id=org)
    assert summary["active_alerts"] == 2


def test_get_org_risk_summary_active_alerts_decrease_after_resolve(engine, org):
    alert = _alert(engine, "u28", org_id=org)
    engine.resolve_alert(
        alert_id=alert["alert_id"],
        resolution="confirmed",
        resolved_by="sec",
        org_id=org,
    )
    summary = engine.get_org_risk_summary(org_id=org)
    assert summary["active_alerts"] == 0


def test_get_org_risk_summary_top_indicators_structure(engine, org):
    _alert(engine, "u29", indicator="after_hours_access", org_id=org)
    _alert(engine, "u30", indicator="after_hours_access", org_id=org)
    _alert(engine, "u31", indicator="bulk_data_download", org_id=org)
    summary = engine.get_org_risk_summary(org_id=org)
    assert isinstance(summary["top_indicators"], list)
    # after_hours_access should be first (count=2)
    if summary["top_indicators"]:
        assert summary["top_indicators"][0]["indicator"] == "after_hours_access"
        assert summary["top_indicators"][0]["count"] == 2


def test_get_org_risk_summary_org_isolation(engine, org, org2):
    _event(engine, "u32", org_id=org)
    _alert(engine, "u32", org_id=org)
    summary = engine.get_org_risk_summary(org_id=org2)
    assert summary["total_users_monitored"] == 0
    assert summary["active_alerts"] == 0
