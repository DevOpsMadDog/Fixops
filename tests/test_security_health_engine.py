"""Tests for SecurityHealthEngine — Beast Mode suite."""

from __future__ import annotations

import pytest

from core.security_health_engine import SecurityHealthEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_security_health.db")
    return SecurityHealthEngine(db_path=db)


ORG = "org-health-001"
ORG2 = "org-health-002"


# ---------------------------------------------------------------------------
# register_check
# ---------------------------------------------------------------------------

def test_register_check_basic(engine):
    check = engine.register_check(ORG, {
        "check_name": "Firewall Rules Audit",
        "category": "network",
    })
    assert check["check_id"]
    assert check["check_name"] == "Firewall Rules Audit"
    assert check["org_id"] == ORG
    assert check["category"] == "network"


def test_register_check_all_fields(engine):
    check = engine.register_check(ORG, {
        "check_name": "MFA Enforcement",
        "category": "identity",
        "status": "healthy",
        "score": 95,
        "details": "All users have MFA",
        "check_interval_hours": 12,
    })
    assert check["status"] == "healthy"
    assert check["score"] == 95
    assert check["check_interval_hours"] == 12


def test_register_check_missing_name(engine):
    with pytest.raises(ValueError, match="check_name"):
        engine.register_check(ORG, {"category": "network"})


def test_register_check_invalid_category(engine):
    with pytest.raises(ValueError, match="category"):
        engine.register_check(ORG, {"check_name": "x", "category": "unknown_cat"})


def test_register_check_invalid_status(engine):
    with pytest.raises(ValueError, match="status"):
        engine.register_check(ORG, {"check_name": "x", "status": "bad_status"})


def test_register_all_categories(engine):
    categories = ["network", "endpoint", "identity", "cloud", "data", "application", "compliance"]
    for cat in categories:
        c = engine.register_check(ORG, {"check_name": f"check-{cat}", "category": cat})
        assert c["category"] == cat


def test_register_all_statuses(engine):
    statuses = ["healthy", "degraded", "critical", "unknown"]
    for st in statuses:
        c = engine.register_check(ORG, {"check_name": f"check-{st}", "status": st})
        assert c["status"] == st


# ---------------------------------------------------------------------------
# update_check_status
# ---------------------------------------------------------------------------

def test_update_check_status(engine):
    check = engine.register_check(ORG, {"check_name": "DNS Check", "score": 50})
    result = engine.update_check_status(ORG, check["check_id"], "healthy", 95, "All good")
    assert result is True
    checks = engine.list_checks(ORG)
    updated = next(c for c in checks if c["check_id"] == check["check_id"])
    assert updated["status"] == "healthy"
    assert updated["score"] == 95
    assert updated["last_checked"] is not None


def test_update_check_status_not_found(engine):
    result = engine.update_check_status(ORG, "nonexistent", "healthy", 100)
    assert result is False


def test_update_check_status_invalid_status(engine):
    check = engine.register_check(ORG, {"check_name": "x"})
    with pytest.raises(ValueError, match="status"):
        engine.update_check_status(ORG, check["check_id"], "invalid_status", 50)


def test_update_check_status_org_isolation(engine):
    check = engine.register_check(ORG, {"check_name": "x"})
    result = engine.update_check_status(ORG2, check["check_id"], "healthy", 80)
    assert result is False


# ---------------------------------------------------------------------------
# list_checks
# ---------------------------------------------------------------------------

def test_list_checks_empty(engine):
    assert engine.list_checks(ORG) == []


def test_list_checks_org_isolation(engine):
    engine.register_check(ORG, {"check_name": "c1"})
    engine.register_check(ORG2, {"check_name": "c2"})
    checks = engine.list_checks(ORG)
    assert len(checks) == 1
    assert checks[0]["check_name"] == "c1"


def test_list_checks_filter_category(engine):
    engine.register_check(ORG, {"check_name": "net-check", "category": "network"})
    engine.register_check(ORG, {"check_name": "id-check", "category": "identity"})
    net = engine.list_checks(ORG, category="network")
    assert len(net) == 1
    assert net[0]["check_name"] == "net-check"


def test_list_checks_filter_status(engine):
    engine.register_check(ORG, {"check_name": "healthy-check", "status": "healthy"})
    engine.register_check(ORG, {"check_name": "crit-check", "status": "critical"})
    crits = engine.list_checks(ORG, status="critical")
    assert len(crits) == 1
    assert crits[0]["check_name"] == "crit-check"


# ---------------------------------------------------------------------------
# run_health_snapshot / get_latest_snapshot / list_snapshots
# ---------------------------------------------------------------------------

def test_snapshot_no_checks(engine):
    snap = engine.run_health_snapshot(ORG)
    assert snap["snapshot_id"]
    assert snap["overall_score"] == 0
    assert snap["healthy_count"] == 0


def test_snapshot_with_checks(engine):
    engine.register_check(ORG, {"check_name": "c1", "status": "healthy", "score": 90})
    engine.register_check(ORG, {"check_name": "c2", "status": "degraded", "score": 60})
    engine.register_check(ORG, {"check_name": "c3", "status": "critical", "score": 20})
    snap = engine.run_health_snapshot(ORG)
    assert snap["overall_score"] == 56  # (90+60+20)//3
    assert snap["healthy_count"] == 1
    assert snap["degraded_count"] == 1
    assert snap["critical_count"] == 1


def test_snapshot_by_category(engine):
    engine.register_check(ORG, {"check_name": "n1", "category": "network", "score": 80})
    engine.register_check(ORG, {"check_name": "n2", "category": "network", "score": 60})
    engine.register_check(ORG, {"check_name": "id1", "category": "identity", "score": 100})
    snap = engine.run_health_snapshot(ORG)
    assert snap["by_category"]["network"] == 70
    assert snap["by_category"]["identity"] == 100


def test_get_latest_snapshot_none(engine):
    assert engine.get_latest_snapshot(ORG) is None


def test_get_latest_snapshot_returns_most_recent(engine):
    engine.register_check(ORG, {"check_name": "c1", "score": 50})
    engine.run_health_snapshot(ORG)
    engine.update_check_status(ORG, engine.list_checks(ORG)[0]["check_id"], "healthy", 90)
    engine.run_health_snapshot(ORG)
    snap = engine.get_latest_snapshot(ORG)
    assert snap is not None
    assert snap["overall_score"] == 90


def test_list_snapshots(engine):
    engine.register_check(ORG, {"check_name": "c1", "score": 70})
    engine.run_health_snapshot(ORG)
    engine.run_health_snapshot(ORG)
    snaps = engine.list_snapshots(ORG)
    assert len(snaps) == 2


def test_list_snapshots_limit(engine):
    engine.register_check(ORG, {"check_name": "c1", "score": 70})
    for _ in range(5):
        engine.run_health_snapshot(ORG)
    snaps = engine.list_snapshots(ORG, limit=3)
    assert len(snaps) == 3


def test_snapshot_org_isolation(engine):
    engine.register_check(ORG, {"check_name": "c1", "score": 70})
    engine.run_health_snapshot(ORG)
    assert engine.get_latest_snapshot(ORG2) is None


# ---------------------------------------------------------------------------
# log_incident / resolve_incident / list_incidents
# ---------------------------------------------------------------------------

def test_log_incident(engine):
    check = engine.register_check(ORG, {"check_name": "SSL Check"})
    incident = engine.log_incident(ORG, check["check_id"], {
        "title": "Expired SSL cert",
        "description": "Certificate expired on port 443",
        "severity": "critical",
    })
    assert incident["incident_id"]
    assert incident["title"] == "Expired SSL cert"
    assert incident["severity"] == "critical"
    assert incident["resolved_at"] is None


def test_log_incident_invalid_severity(engine):
    check = engine.register_check(ORG, {"check_name": "x"})
    with pytest.raises(ValueError, match="severity"):
        engine.log_incident(ORG, check["check_id"], {"title": "x", "severity": "extreme"})


def test_all_severities(engine):
    check = engine.register_check(ORG, {"check_name": "x"})
    for sev in ["critical", "high", "medium", "low"]:
        inc = engine.log_incident(ORG, check["check_id"], {"title": f"inc-{sev}", "severity": sev})
        assert inc["severity"] == sev


def test_resolve_incident(engine):
    check = engine.register_check(ORG, {"check_name": "x"})
    incident = engine.log_incident(ORG, check["check_id"], {"title": "issue"})
    result = engine.resolve_incident(ORG, incident["incident_id"])
    assert result is True
    open_incs = engine.list_incidents(ORG, resolved=False)
    assert len(open_incs) == 0
    resolved_incs = engine.list_incidents(ORG, resolved=True)
    assert len(resolved_incs) == 1


def test_resolve_incident_not_found(engine):
    result = engine.resolve_incident(ORG, "bad-id")
    assert result is False


def test_resolve_incident_already_resolved(engine):
    check = engine.register_check(ORG, {"check_name": "x"})
    incident = engine.log_incident(ORG, check["check_id"], {"title": "issue"})
    engine.resolve_incident(ORG, incident["incident_id"])
    # Second resolve should return False (already resolved)
    result = engine.resolve_incident(ORG, incident["incident_id"])
    assert result is False


def test_list_incidents_open_default(engine):
    check = engine.register_check(ORG, {"check_name": "x"})
    engine.log_incident(ORG, check["check_id"], {"title": "open1"})
    engine.log_incident(ORG, check["check_id"], {"title": "open2"})
    incs = engine.list_incidents(ORG)
    assert len(incs) == 2


def test_list_incidents_org_isolation(engine):
    c1 = engine.register_check(ORG, {"check_name": "c1"})
    c2 = engine.register_check(ORG2, {"check_name": "c2"})
    engine.log_incident(ORG, c1["check_id"], {"title": "i1"})
    engine.log_incident(ORG2, c2["check_id"], {"title": "i2"})
    assert len(engine.list_incidents(ORG)) == 1
    assert len(engine.list_incidents(ORG2)) == 1


# ---------------------------------------------------------------------------
# get_health_stats
# ---------------------------------------------------------------------------

def test_get_health_stats_empty(engine):
    stats = engine.get_health_stats(ORG)
    assert stats["total_checks"] == 0
    assert stats["overall_score"] == 0
    assert stats["open_incidents"] == 0
    assert stats["critical_incidents"] == 0


def test_get_health_stats_with_checks(engine):
    engine.register_check(ORG, {"check_name": "c1", "status": "healthy", "score": 90, "category": "network"})
    engine.register_check(ORG, {"check_name": "c2", "status": "degraded", "score": 50, "category": "network"})
    engine.register_check(ORG, {"check_name": "c3", "status": "critical", "score": 10, "category": "identity"})
    stats = engine.get_health_stats(ORG)
    assert stats["total_checks"] == 3
    assert stats["by_status"]["healthy"] == 1
    assert stats["by_status"]["degraded"] == 1
    assert stats["by_status"]["critical"] == 1
    assert stats["by_category"]["network"] == 70
    assert stats["by_category"]["identity"] == 10
    assert stats["overall_score"] == 50  # (90+50+10)//3


def test_get_health_stats_incidents(engine):
    check = engine.register_check(ORG, {"check_name": "c1", "score": 80})
    engine.log_incident(ORG, check["check_id"], {"title": "critical issue", "severity": "critical"})
    engine.log_incident(ORG, check["check_id"], {"title": "medium issue", "severity": "medium"})
    stats = engine.get_health_stats(ORG)
    assert stats["open_incidents"] == 2
    assert stats["critical_incidents"] == 1


def test_get_health_stats_org_isolation(engine):
    engine.register_check(ORG, {"check_name": "c1", "score": 80})
    engine.register_check(ORG, {"check_name": "c2", "score": 60})
    engine.register_check(ORG2, {"check_name": "c3", "score": 40})
    stats = engine.get_health_stats(ORG)
    assert stats["total_checks"] == 2
    stats2 = engine.get_health_stats(ORG2)
    assert stats2["total_checks"] == 1
