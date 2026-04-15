"""Tests for PrivilegedAccessGovernanceEngine — wave 24."""

import pytest
from core.privileged_access_governance_engine import PrivilegedAccessGovernanceEngine


@pytest.fixture
def engine(tmp_path):
    return PrivilegedAccessGovernanceEngine(
        db_path=str(tmp_path / "pag.db")
    )


# ---------------------------------------------------------------------------
# register_privileged_account
# ---------------------------------------------------------------------------

def test_register_account_minimal(engine):
    acc = engine.register_privileged_account("org1", {"username": "svc-deploy"})
    assert acc["username"] == "svc-deploy"
    assert acc["account_type"] == "service"
    assert acc["status"] == "active"
    assert acc["risk_score"] == 50.0
    assert acc["last_used"] is None
    assert "id" in acc
    assert "created_at" in acc


def test_register_account_all_types(engine):
    for idx, atype in enumerate(["service", "admin", "root", "sa", "break_glass"]):
        acc = engine.register_privileged_account(
            "org1", {"username": f"acct{idx}", "account_type": atype}
        )
        assert acc["account_type"] == atype


def test_register_account_missing_username_raises(engine):
    with pytest.raises(ValueError, match="username"):
        engine.register_privileged_account("org1", {"account_type": "admin"})


def test_register_account_empty_username_raises(engine):
    with pytest.raises(ValueError, match="username"):
        engine.register_privileged_account("org1", {"username": "  "})


def test_register_account_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="account_type"):
        engine.register_privileged_account(
            "org1", {"username": "acct", "account_type": "superuser"}
        )


def test_register_account_stores_metadata(engine):
    acc = engine.register_privileged_account("org1", {
        "username": "admin-bob",
        "account_type": "admin",
        "system": "prod-db-01",
        "owner": "bob@example.com",
        "justification": "DB admin tasks",
    })
    assert acc["system"] == "prod-db-01"
    assert acc["owner"] == "bob@example.com"
    assert acc["justification"] == "DB admin tasks"


# ---------------------------------------------------------------------------
# list_privileged_accounts
# ---------------------------------------------------------------------------

def test_list_accounts_empty(engine):
    assert engine.list_privileged_accounts("org1") == []


def test_list_accounts_filter_by_type(engine):
    engine.register_privileged_account("org1", {"username": "svc1", "account_type": "service"})
    engine.register_privileged_account("org1", {"username": "admin1", "account_type": "admin"})
    admins = engine.list_privileged_accounts("org1", account_type="admin")
    assert len(admins) == 1
    assert admins[0]["account_type"] == "admin"


def test_list_accounts_filter_by_status(engine):
    engine.register_privileged_account("org1", {"username": "active-svc"})
    result = engine.list_privileged_accounts("org1", status="active")
    assert len(result) == 1
    assert result[0]["status"] == "active"


def test_list_accounts_org_isolation(engine):
    engine.register_privileged_account("org1", {"username": "svc"})
    assert engine.list_privileged_accounts("org2") == []


def test_list_accounts_multiple_results(engine):
    for i in range(3):
        engine.register_privileged_account("org1", {"username": f"svc{i}"})
    result = engine.list_privileged_accounts("org1")
    assert len(result) == 3


# ---------------------------------------------------------------------------
# get_privileged_account
# ---------------------------------------------------------------------------

def test_get_account_found(engine):
    created = engine.register_privileged_account(
        "org1", {"username": "root-acct", "account_type": "root"}
    )
    fetched = engine.get_privileged_account("org1", created["id"])
    assert fetched is not None
    assert fetched["id"] == created["id"]
    assert fetched["username"] == "root-acct"


def test_get_account_not_found_returns_none(engine):
    assert engine.get_privileged_account("org1", "nonexistent-id") is None


def test_get_account_org_isolation(engine):
    created = engine.register_privileged_account("org1", {"username": "svc"})
    assert engine.get_privileged_account("org2", created["id"]) is None


# ---------------------------------------------------------------------------
# record_access_session
# ---------------------------------------------------------------------------

def test_record_session_basic(engine):
    acc = engine.register_privileged_account("org1", {"username": "svc-deploy"})
    session = engine.record_access_session("org1", acc["id"], {
        "accessed_by": "alice@example.com",
        "system": "prod-k8s",
        "duration_minutes": 45,
        "commands_executed": 12,
        "justification": "Deployment window",
        "approved_by": "manager@example.com",
    })
    assert session["accessed_by"] == "alice@example.com"
    assert session["duration_minutes"] == 45
    assert session["commands_executed"] == 12
    assert session["status"] == "completed"
    assert session["account_id"] == acc["id"]
    assert "id" in session


def test_record_session_updates_last_used(engine):
    acc = engine.register_privileged_account("org1", {"username": "svc"})
    assert acc["last_used"] is None
    engine.record_access_session("org1", acc["id"], {"accessed_by": "user"})
    updated = engine.get_privileged_account("org1", acc["id"])
    assert updated["last_used"] is not None


def test_record_session_with_custom_session_at(engine):
    acc = engine.register_privileged_account("org1", {"username": "svc"})
    session = engine.record_access_session("org1", acc["id"], {
        "accessed_by": "bob",
        "session_at": "2026-04-16T10:00:00+00:00",
    })
    assert session["session_at"] == "2026-04-16T10:00:00+00:00"


def test_record_session_defaults(engine):
    acc = engine.register_privileged_account("org1", {"username": "svc"})
    session = engine.record_access_session("org1", acc["id"], {})
    assert session["duration_minutes"] == 0
    assert session["commands_executed"] == 0
    assert session["status"] == "completed"


# ---------------------------------------------------------------------------
# list_sessions
# ---------------------------------------------------------------------------

def test_list_sessions_empty(engine):
    assert engine.list_sessions("org1") == []


def test_list_sessions_filter_by_account(engine):
    acc1 = engine.register_privileged_account("org1", {"username": "svc1"})
    acc2 = engine.register_privileged_account("org1", {"username": "svc2"})
    engine.record_access_session("org1", acc1["id"], {"accessed_by": "alice"})
    engine.record_access_session("org1", acc2["id"], {"accessed_by": "bob"})
    sessions = engine.list_sessions("org1", account_id=acc1["id"])
    assert len(sessions) == 1
    assert sessions[0]["account_id"] == acc1["id"]


def test_list_sessions_filter_by_status(engine):
    acc = engine.register_privileged_account("org1", {"username": "svc"})
    engine.record_access_session("org1", acc["id"], {"accessed_by": "user"})
    sessions = engine.list_sessions("org1", status="completed")
    assert len(sessions) == 1


def test_list_sessions_org_isolation(engine):
    acc = engine.register_privileged_account("org1", {"username": "svc"})
    engine.record_access_session("org1", acc["id"], {"accessed_by": "user"})
    assert engine.list_sessions("org2") == []


# ---------------------------------------------------------------------------
# flag_anomaly
# ---------------------------------------------------------------------------

def test_flag_anomaly_basic(engine):
    acc = engine.register_privileged_account("org1", {"username": "svc"})
    anomaly = engine.flag_anomaly("org1", acc["id"], {
        "anomaly_type": "off_hours",
        "severity": "high",
        "description": "Access at 3am",
    })
    assert anomaly["anomaly_type"] == "off_hours"
    assert anomaly["severity"] == "high"
    assert anomaly["status"] == "open"
    assert anomaly["account_id"] == acc["id"]
    assert "id" in anomaly
    assert "detected_at" in anomaly


def test_flag_anomaly_all_types(engine):
    acc = engine.register_privileged_account("org1", {"username": "svc"})
    for atype in [
        "off_hours", "unusual_commands", "excessive_access",
        "unauthorized_system", "policy_violation"
    ]:
        anomaly = engine.flag_anomaly("org1", acc["id"], {
            "anomaly_type": atype, "severity": "medium"
        })
        assert anomaly["anomaly_type"] == atype


def test_flag_anomaly_all_severities(engine):
    acc = engine.register_privileged_account("org1", {"username": "svc"})
    for sev in ["critical", "high", "medium", "low"]:
        anomaly = engine.flag_anomaly("org1", acc["id"], {
            "anomaly_type": "off_hours", "severity": sev
        })
        assert anomaly["severity"] == sev


def test_flag_anomaly_invalid_type_raises(engine):
    acc = engine.register_privileged_account("org1", {"username": "svc"})
    with pytest.raises(ValueError, match="anomaly_type"):
        engine.flag_anomaly("org1", acc["id"], {
            "anomaly_type": "alien_intrusion", "severity": "critical"
        })


def test_flag_anomaly_invalid_severity_raises(engine):
    acc = engine.register_privileged_account("org1", {"username": "svc"})
    with pytest.raises(ValueError, match="severity"):
        engine.flag_anomaly("org1", acc["id"], {
            "anomaly_type": "off_hours", "severity": "extreme"
        })


def test_flag_anomaly_with_custom_detected_at(engine):
    acc = engine.register_privileged_account("org1", {"username": "svc"})
    anomaly = engine.flag_anomaly("org1", acc["id"], {
        "anomaly_type": "off_hours",
        "severity": "low",
        "detected_at": "2026-04-16T03:00:00+00:00",
    })
    assert anomaly["detected_at"] == "2026-04-16T03:00:00+00:00"


# ---------------------------------------------------------------------------
# list_anomalies
# ---------------------------------------------------------------------------

def test_list_anomalies_empty(engine):
    assert engine.list_anomalies("org1") == []


def test_list_anomalies_filter_by_account(engine):
    acc1 = engine.register_privileged_account("org1", {"username": "svc1"})
    acc2 = engine.register_privileged_account("org1", {"username": "svc2"})
    engine.flag_anomaly("org1", acc1["id"], {"anomaly_type": "off_hours", "severity": "high"})
    engine.flag_anomaly("org1", acc2["id"], {"anomaly_type": "unusual_commands", "severity": "medium"})
    anomalies = engine.list_anomalies("org1", account_id=acc1["id"])
    assert len(anomalies) == 1
    assert anomalies[0]["account_id"] == acc1["id"]


def test_list_anomalies_filter_by_severity(engine):
    acc = engine.register_privileged_account("org1", {"username": "svc"})
    engine.flag_anomaly("org1", acc["id"], {"anomaly_type": "off_hours", "severity": "critical"})
    engine.flag_anomaly("org1", acc["id"], {"anomaly_type": "off_hours", "severity": "low"})
    criticals = engine.list_anomalies("org1", severity="critical")
    assert len(criticals) == 1
    assert criticals[0]["severity"] == "critical"


def test_list_anomalies_org_isolation(engine):
    acc = engine.register_privileged_account("org1", {"username": "svc"})
    engine.flag_anomaly("org1", acc["id"], {"anomaly_type": "off_hours", "severity": "high"})
    assert engine.list_anomalies("org2") == []


# ---------------------------------------------------------------------------
# get_pag_stats
# ---------------------------------------------------------------------------

def test_get_pag_stats_empty(engine):
    stats = engine.get_pag_stats("org1")
    assert stats["total_accounts"] == 0
    assert stats["active_accounts"] == 0
    assert stats["sessions_today"] == 0
    assert stats["anomalies_open"] == 0
    assert stats["by_account_type"] == {}
    assert stats["high_risk_accounts"] == 0


def test_get_pag_stats_counts(engine):
    acc1 = engine.register_privileged_account(
        "org1", {"username": "svc1", "account_type": "service"}
    )
    acc2 = engine.register_privileged_account(
        "org1", {"username": "admin1", "account_type": "admin"}
    )
    # Record a session with today's date
    from datetime import datetime, timezone
    today_ts = datetime.now(timezone.utc).isoformat()
    engine.record_access_session("org1", acc1["id"], {
        "accessed_by": "alice", "session_at": today_ts
    })
    engine.flag_anomaly("org1", acc1["id"], {"anomaly_type": "off_hours", "severity": "high"})
    engine.flag_anomaly("org1", acc2["id"], {"anomaly_type": "unusual_commands", "severity": "critical"})

    stats = engine.get_pag_stats("org1")
    assert stats["total_accounts"] == 2
    assert stats["active_accounts"] == 2
    assert stats["sessions_today"] == 1
    assert stats["anomalies_open"] == 2
    assert stats["by_account_type"].get("service", 0) == 1
    assert stats["by_account_type"].get("admin", 0) == 1
    assert stats["high_risk_accounts"] == 0  # both at 50.0


def test_get_pag_stats_high_risk_accounts(engine):
    from sqlite3 import connect
    engine2 = engine
    acc = engine2.register_privileged_account("org1", {"username": "high-risk-svc"})
    # Directly update risk_score above 70
    import sqlite3
    conn = sqlite3.connect(engine2._db_path)
    conn.execute(
        "UPDATE pag_accounts SET risk_score = 85.0 WHERE id = ?", (acc["id"],)
    )
    conn.commit()
    conn.close()
    stats = engine2.get_pag_stats("org1")
    assert stats["high_risk_accounts"] == 1


def test_get_pag_stats_org_isolation(engine):
    engine.register_privileged_account("org1", {"username": "svc"})
    stats = engine.get_pag_stats("org2")
    assert stats["total_accounts"] == 0


def test_get_pag_stats_sessions_today_only_counts_today(engine):
    acc = engine.register_privileged_account("org1", {"username": "svc"})
    # Record session with old date
    engine.record_access_session("org1", acc["id"], {
        "accessed_by": "user",
        "session_at": "2020-01-01T00:00:00+00:00",
    })
    stats = engine.get_pag_stats("org1")
    assert stats["sessions_today"] == 0
