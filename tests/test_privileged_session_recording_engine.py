"""Tests for PrivilegedSessionRecordingEngine.

Covers: init, start_session validation, list/get, end_session lifecycle,
record_alert (alerts_count increment), list_alerts, stats (high_risk_sessions,
avg_duration_minutes, by_session_type, by_alert_type), org isolation.
"""

from __future__ import annotations

import pytest

from core.privileged_session_recording_engine import PrivilegedSessionRecordingEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return PrivilegedSessionRecordingEngine(db_path=str(tmp_path / "psr_test.db"))


def _sess(**overrides):
    base = {
        "user": "admin",
        "session_type": "ssh",
        "target_host": "prod-server-01",
        "target_ip": "10.0.1.1",
        "initiated_by": "pam-system",
    }
    base.update(overrides)
    return base


def _start(engine, org_id="org1", **kw):
    return engine.start_session(org_id, _sess(**kw))


def _alert(**overrides):
    base = {
        "alert_type": "suspicious_command",
        "severity": "high",
        "description": "rm -rf executed",
        "command_context": "rm -rf /etc",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = tmp_path / "psr.db"
    PrivilegedSessionRecordingEngine(db_path=str(db))
    assert db.exists()


def test_init_twice_idempotent(tmp_path):
    db = str(tmp_path / "psr.db")
    PrivilegedSessionRecordingEngine(db_path=db)
    PrivilegedSessionRecordingEngine(db_path=db)


# ---------------------------------------------------------------------------
# 2. start_session — validation
# ---------------------------------------------------------------------------


def test_start_requires_user(engine):
    with pytest.raises(ValueError, match="user"):
        engine.start_session("org1", _sess(user=""))


def test_start_requires_target_host(engine):
    with pytest.raises(ValueError, match="target_host"):
        engine.start_session("org1", _sess(target_host=""))


def test_start_invalid_session_type(engine):
    with pytest.raises(ValueError, match="session_type"):
        engine.start_session("org1", _sess(session_type="ftp"))


def test_start_all_valid_session_types(engine):
    for st in ("ssh", "rdp", "database", "api", "console", "winrm", "telnet"):
        s = _start(engine, session_type=st, target_host=f"host-{st}")
        assert s["session_type"] == st


# ---------------------------------------------------------------------------
# 3. start_session — returned record
# ---------------------------------------------------------------------------


def test_start_returns_id(engine):
    s = _start(engine)
    assert s["id"]


def test_start_status_is_recording(engine):
    s = _start(engine)
    assert s["status"] == "recording"


def test_start_alerts_count_zero(engine):
    s = _start(engine)
    assert s["alerts_count"] == 0


def test_start_ended_at_none(engine):
    s = _start(engine)
    assert s["ended_at"] is None


def test_start_recording_url_empty(engine):
    s = _start(engine)
    assert s["recording_url"] == ""


# ---------------------------------------------------------------------------
# 4. list_sessions / get_session
# ---------------------------------------------------------------------------


def test_list_returns_all(engine):
    _start(engine); _start(engine, user="bob")
    assert len(engine.list_sessions("org1")) == 2


def test_list_filter_by_user(engine):
    _start(engine, user="alice")
    _start(engine, user="bob")
    results = engine.list_sessions("org1", user="alice")
    assert len(results) == 1
    assert results[0]["user"] == "alice"


def test_list_filter_by_session_type(engine):
    _start(engine, session_type="ssh")
    _start(engine, session_type="rdp")
    results = engine.list_sessions("org1", session_type="rdp")
    assert len(results) == 1
    assert results[0]["session_type"] == "rdp"


def test_list_filter_by_status(engine):
    s = _start(engine)
    engine.end_session("org1", s["id"], {"duration_seconds": 60})
    results = engine.list_sessions("org1", status="completed")
    assert all(r["status"] == "completed" for r in results)


def test_list_ordered_by_started_at_desc(engine):
    s1 = _start(engine)
    s2 = _start(engine, user="bob")
    results = engine.list_sessions("org1")
    # most recent first — ids may vary, but order is guaranteed
    assert len(results) == 2


def test_get_session_existing(engine):
    s = _start(engine)
    fetched = engine.get_session("org1", s["id"])
    assert fetched["id"] == s["id"]


def test_get_session_nonexistent_returns_none(engine):
    assert engine.get_session("org1", "bad-id") is None


# ---------------------------------------------------------------------------
# 5. end_session
# ---------------------------------------------------------------------------


def test_end_sets_completed(engine):
    s = _start(engine)
    ended = engine.end_session("org1", s["id"], {"duration_seconds": 300})
    assert ended["status"] == "completed"


def test_end_sets_duration(engine):
    s = _start(engine)
    ended = engine.end_session("org1", s["id"], {"duration_seconds": 1800})
    assert ended["duration_seconds"] == 1800


def test_end_sets_ended_at(engine):
    s = _start(engine)
    ended = engine.end_session("org1", s["id"], {"duration_seconds": 60})
    assert ended["ended_at"] is not None


def test_end_sets_recording_url(engine):
    s = _start(engine)
    ended = engine.end_session(
        "org1", s["id"], {"duration_seconds": 60, "recording_url": "s3://bucket/rec.mp4"}
    )
    assert ended["recording_url"] == "s3://bucket/rec.mp4"


def test_end_nonexistent_raises(engine):
    with pytest.raises(ValueError):
        engine.end_session("org1", "bad-id", {})


# ---------------------------------------------------------------------------
# 6. record_alert — alerts_count increment
# ---------------------------------------------------------------------------


def test_record_alert_returns_alert(engine):
    s = _start(engine)
    a = engine.record_alert("org1", s["id"], _alert())
    assert a["id"]
    assert a["alert_type"] == "suspicious_command"


def test_record_alert_invalid_type(engine):
    s = _start(engine)
    with pytest.raises(ValueError, match="alert_type"):
        engine.record_alert("org1", s["id"], _alert(alert_type="invalid"))


def test_record_alert_all_valid_types(engine):
    s = _start(engine)
    for at in ("suspicious_command", "data_exfiltration", "privilege_escalation",
               "policy_violation", "anomaly"):
        a = engine.record_alert("org1", s["id"], _alert(alert_type=at))
        assert a["alert_type"] == at


def test_record_alert_increments_count(engine):
    s = _start(engine)
    engine.record_alert("org1", s["id"], _alert())
    updated = engine.get_session("org1", s["id"])
    assert updated["alerts_count"] == 1


def test_record_alert_increments_count_multiple(engine):
    s = _start(engine)
    for _ in range(4):
        engine.record_alert("org1", s["id"], _alert())
    updated = engine.get_session("org1", s["id"])
    assert updated["alerts_count"] == 4


def test_record_alert_nonexistent_session_raises(engine):
    with pytest.raises(ValueError):
        engine.record_alert("org1", "bad-session-id", _alert())


def test_record_alert_stores_description(engine):
    s = _start(engine)
    a = engine.record_alert("org1", s["id"], _alert(description="Critical command detected"))
    assert a["description"] == "Critical command detected"


def test_record_alert_stores_command_context(engine):
    s = _start(engine)
    a = engine.record_alert("org1", s["id"], _alert(command_context="sudo rm -rf /"))
    assert a["command_context"] == "sudo rm -rf /"


# ---------------------------------------------------------------------------
# 7. list_alerts
# ---------------------------------------------------------------------------


def test_list_alerts_by_org(engine):
    s = _start(engine)
    engine.record_alert("org1", s["id"], _alert())
    engine.record_alert("org1", s["id"], _alert(alert_type="anomaly"))
    assert len(engine.list_alerts("org1")) == 2


def test_list_alerts_filter_by_session(engine):
    s1 = _start(engine)
    s2 = _start(engine, user="bob")
    engine.record_alert("org1", s1["id"], _alert())
    engine.record_alert("org1", s2["id"], _alert(alert_type="anomaly"))
    results = engine.list_alerts("org1", session_id=s1["id"])
    assert len(results) == 1
    assert results[0]["session_id"] == s1["id"]


def test_list_alerts_filter_by_type(engine):
    s = _start(engine)
    engine.record_alert("org1", s["id"], _alert(alert_type="suspicious_command"))
    engine.record_alert("org1", s["id"], _alert(alert_type="anomaly"))
    results = engine.list_alerts("org1", alert_type="anomaly")
    assert len(results) == 1
    assert results[0]["alert_type"] == "anomaly"


def test_list_alerts_filter_by_severity(engine):
    s = _start(engine)
    engine.record_alert("org1", s["id"], _alert(severity="critical"))
    engine.record_alert("org1", s["id"], _alert(severity="low"))
    results = engine.list_alerts("org1", severity="critical")
    assert len(results) == 1
    assert results[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# 8. get_recording_stats
# ---------------------------------------------------------------------------


def test_stats_empty(engine):
    s = engine.get_recording_stats("org1")
    assert s["total_sessions"] == 0
    assert s["active_sessions"] == 0
    assert s["total_alerts"] == 0
    assert s["high_risk_sessions"] == 0
    assert s["avg_duration_minutes"] == 0.0


def test_stats_active_sessions(engine):
    _start(engine)
    _start(engine, user="bob")
    s = engine.get_recording_stats("org1")
    assert s["active_sessions"] == 2


def test_stats_active_sessions_after_end(engine):
    sess = _start(engine)
    engine.end_session("org1", sess["id"], {"duration_seconds": 60})
    s = engine.get_recording_stats("org1")
    assert s["active_sessions"] == 0


def test_stats_total_alerts(engine):
    sess = _start(engine)
    engine.record_alert("org1", sess["id"], _alert())
    engine.record_alert("org1", sess["id"], _alert(alert_type="anomaly"))
    s = engine.get_recording_stats("org1")
    assert s["total_alerts"] == 2


def test_stats_high_risk_sessions(engine):
    sess = _start(engine)
    for _ in range(4):
        engine.record_alert("org1", sess["id"], _alert())
    s = engine.get_recording_stats("org1")
    assert s["high_risk_sessions"] == 1


def test_stats_high_risk_threshold(engine):
    # Exactly 3 alerts — NOT high risk (threshold is >3)
    sess = _start(engine)
    for _ in range(3):
        engine.record_alert("org1", sess["id"], _alert())
    s = engine.get_recording_stats("org1")
    assert s["high_risk_sessions"] == 0


def test_stats_avg_duration_minutes(engine):
    s1 = _start(engine)
    s2 = _start(engine, user="bob")
    engine.end_session("org1", s1["id"], {"duration_seconds": 120})
    engine.end_session("org1", s2["id"], {"duration_seconds": 60})
    stats = engine.get_recording_stats("org1")
    # avg of 120s and 60s = 90s = 1.5 min
    assert stats["avg_duration_minutes"] == pytest.approx(1.5, abs=0.01)


def test_stats_by_session_type(engine):
    _start(engine, session_type="ssh")
    _start(engine, session_type="rdp", user="bob")
    s = engine.get_recording_stats("org1")
    assert s["by_session_type"].get("ssh", 0) >= 1
    assert s["by_session_type"].get("rdp", 0) >= 1


def test_stats_by_alert_type(engine):
    sess = _start(engine)
    engine.record_alert("org1", sess["id"], _alert(alert_type="suspicious_command"))
    engine.record_alert("org1", sess["id"], _alert(alert_type="data_exfiltration"))
    s = engine.get_recording_stats("org1")
    assert s["by_alert_type"].get("suspicious_command", 0) >= 1
    assert s["by_alert_type"].get("data_exfiltration", 0) >= 1


# ---------------------------------------------------------------------------
# 9. Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_list(engine):
    _start(engine, org_id="orgA")
    _start(engine, org_id="orgB")
    assert len(engine.list_sessions("orgA")) == 1
    assert len(engine.list_sessions("orgB")) == 1


def test_org_isolation_get(engine):
    s = _start(engine, org_id="orgA")
    assert engine.get_session("orgB", s["id"]) is None


def test_org_isolation_stats(engine):
    _start(engine, org_id="orgA")
    s = engine.get_recording_stats("orgB")
    assert s["total_sessions"] == 0


def test_org_isolation_alerts(engine):
    s = _start(engine, org_id="orgA")
    engine.record_alert("orgA", s["id"], _alert())
    # orgB should see no alerts
    assert engine.list_alerts("orgB") == []


def test_org_isolation_end_session(engine):
    s = _start(engine, org_id="orgA")
    with pytest.raises(ValueError):
        engine.end_session("orgB", s["id"], {"duration_seconds": 60})
