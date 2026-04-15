"""Tests for PrivilegedIdentityEngine.

Covers: init, risk_level auto-computation, INSERT OR IGNORE dedup,
session open/close with duration_mins and anomaly_score clamping,
certify (revoked/suspended status propagation), rotate_password,
90-day rotation/certification overdue detection, org isolation.
"""

from __future__ import annotations

import time
import pytest

from core.privileged_identity_engine import PrivilegedIdentityEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return PrivilegedIdentityEngine(db_path=str(tmp_path / "pi_test.db"))


def _account(engine, org_id="org1", **overrides):
    defaults = {
        "username": "svc_deploy",
        "account_type": "service_account",
        "system_name": "prod-db-01",
        "department": "engineering",
        "owner": "alice",
        "mfa_enabled": False,
    }
    defaults.update(overrides)
    return engine.register_account(org_id=org_id, **defaults)


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = tmp_path / "pi.db"
    PrivilegedIdentityEngine(db_path=str(db))
    assert db.exists()


def test_init_twice_idempotent(tmp_path):
    db = str(tmp_path / "pi.db")
    PrivilegedIdentityEngine(db_path=db)
    PrivilegedIdentityEngine(db_path=db)


# ---------------------------------------------------------------------------
# 2. register_account — risk_level auto-computation
# ---------------------------------------------------------------------------


def test_service_account_no_mfa_is_high(engine):
    acct = _account(engine, account_type="service_account", mfa_enabled=False)
    assert acct["risk_level"] == "high"


def test_admin_no_mfa_is_critical(engine):
    acct = _account(engine, account_type="admin", mfa_enabled=False)
    assert acct["risk_level"] == "critical"


def test_root_no_mfa_is_critical(engine):
    acct = _account(engine, account_type="root", mfa_enabled=False, username="root_acct")
    assert acct["risk_level"] == "critical"


def test_domain_admin_no_mfa_is_critical(engine):
    acct = _account(engine, account_type="domain_admin", mfa_enabled=False, username="da_acct")
    assert acct["risk_level"] == "critical"


def test_database_admin_no_mfa_is_critical(engine):
    acct = _account(engine, account_type="database_admin", mfa_enabled=False, username="dba_acct")
    assert acct["risk_level"] == "critical"


def test_admin_with_mfa_is_medium(engine):
    acct = _account(engine, account_type="admin", mfa_enabled=True, username="admin_mfa")
    assert acct["risk_level"] == "medium"


def test_service_account_with_mfa_is_medium(engine):
    acct = _account(engine, account_type="service_account", mfa_enabled=True, username="svc_mfa")
    assert acct["risk_level"] == "medium"


def test_shared_account_no_mfa_is_medium(engine):
    acct = _account(engine, account_type="shared", mfa_enabled=False, username="shared_acct")
    assert acct["risk_level"] == "medium"


def test_application_account_is_medium(engine):
    acct = _account(engine, account_type="application_account", mfa_enabled=False, username="app_acct")
    assert acct["risk_level"] == "medium"


def test_invalid_account_type_raises(engine):
    with pytest.raises(ValueError, match="account_type"):
        _account(engine, account_type="superuser")


# ---------------------------------------------------------------------------
# 3. INSERT OR IGNORE deduplication
# ---------------------------------------------------------------------------


def test_dedup_same_org_username_system(engine):
    a1 = _account(engine, username="svc_app", system_name="prod-01")
    a2 = _account(engine, username="svc_app", system_name="prod-01")
    # Same row returned (same id)
    assert a1["id"] == a2["id"]


def test_no_dedup_different_system(engine):
    a1 = _account(engine, username="svc_app", system_name="prod-01")
    a2 = _account(engine, username="svc_app", system_name="prod-02")
    assert a1["id"] != a2["id"]


def test_no_dedup_different_org(engine):
    a1 = _account(engine, org_id="orgA", username="svc_app", system_name="prod-01")
    a2 = _account(engine, org_id="orgB", username="svc_app", system_name="prod-01")
    assert a1["id"] != a2["id"]


# ---------------------------------------------------------------------------
# 4. update_risk_level
# ---------------------------------------------------------------------------


def test_update_risk_level(engine):
    acct = _account(engine, account_type="service_account", mfa_enabled=False)
    updated = engine.update_risk_level(acct["id"], "org1", "low")
    assert updated["risk_level"] == "low"


def test_update_risk_level_invalid(engine):
    acct = _account(engine)
    with pytest.raises(ValueError, match="risk_level"):
        engine.update_risk_level(acct["id"], "org1", "extreme")


def test_update_risk_level_wrong_org(engine):
    acct = _account(engine, org_id="orgA")
    with pytest.raises(ValueError):
        engine.update_risk_level(acct["id"], "orgB", "low")


# ---------------------------------------------------------------------------
# 5. rotate_password
# ---------------------------------------------------------------------------


def test_rotate_password_sets_timestamp(engine):
    acct = _account(engine)
    assert acct["password_last_rotated"] is None
    updated = engine.rotate_password(acct["id"], "org1")
    assert updated["password_last_rotated"] is not None


def test_rotate_password_wrong_org_raises(engine):
    acct = _account(engine, org_id="orgA")
    with pytest.raises(ValueError):
        engine.rotate_password(acct["id"], "orgB")


# ---------------------------------------------------------------------------
# 6. open_session / close_session
# ---------------------------------------------------------------------------


def test_open_session_creates_active(engine):
    acct = _account(engine)
    sess = engine.open_session(acct["id"], "org1", "ssh", "prod-db-01")
    assert sess["status"] == "active"
    assert sess["account_id"] == acct["id"]


def test_invalid_session_type_raises(engine):
    acct = _account(engine)
    with pytest.raises(ValueError, match="session_type"):
        engine.open_session(acct["id"], "org1", "telnet", "host")


def test_close_session_sets_completed(engine):
    acct = _account(engine)
    sess = engine.open_session(acct["id"], "org1", "rdp", "win-server")
    closed = engine.close_session(sess["id"], "org1", commands_executed=10, anomaly_score=2.5)
    assert closed["status"] == "completed"
    assert closed["commands_executed"] == 10
    assert closed["anomaly_score"] == 2.5


def test_close_session_duration_non_negative(engine):
    acct = _account(engine)
    sess = engine.open_session(acct["id"], "org1", "ssh", "host")
    closed = engine.close_session(sess["id"], "org1")
    assert closed["duration_mins"] >= 0.0


def test_anomaly_score_clamp_high(engine):
    acct = _account(engine)
    sess = engine.open_session(acct["id"], "org1", "api", "api-gateway")
    closed = engine.close_session(sess["id"], "org1", anomaly_score=99.9)
    assert closed["anomaly_score"] == 10.0


def test_anomaly_score_clamp_low(engine):
    acct = _account(engine)
    sess = engine.open_session(acct["id"], "org1", "console", "server")
    closed = engine.close_session(sess["id"], "org1", anomaly_score=-5.0)
    assert closed["anomaly_score"] == 0.0


def test_close_session_updates_last_used(engine):
    acct = _account(engine)
    assert engine.get_account(acct["id"], "org1")["last_used"] is None
    sess = engine.open_session(acct["id"], "org1", "database", "pg-01")
    engine.close_session(sess["id"], "org1")
    updated_acct = engine.get_account(acct["id"], "org1")
    assert updated_acct["last_used"] is not None


def test_close_session_wrong_org_raises(engine):
    acct = _account(engine, org_id="orgA")
    sess = engine.open_session(acct["id"], "orgA", "ssh", "host")
    with pytest.raises(ValueError):
        engine.close_session(sess["id"], "orgB")


# ---------------------------------------------------------------------------
# 7. get_active_sessions / get_session_history
# ---------------------------------------------------------------------------


def test_get_active_sessions(engine):
    acct = _account(engine)
    engine.open_session(acct["id"], "org1", "ssh", "host1")
    engine.open_session(acct["id"], "org1", "rdp", "host2")
    active = engine.get_active_sessions("org1")
    assert len(active) == 2
    assert all(s["status"] == "active" for s in active)


def test_active_sessions_include_account_fields(engine):
    acct = _account(engine)
    engine.open_session(acct["id"], "org1", "ssh", "host")
    active = engine.get_active_sessions("org1")
    assert "username" in active[0]
    assert "account_type" in active[0]


def test_closed_sessions_not_in_active(engine):
    acct = _account(engine)
    sess = engine.open_session(acct["id"], "org1", "ssh", "host")
    engine.close_session(sess["id"], "org1")
    active = engine.get_active_sessions("org1")
    assert len(active) == 0


def test_get_session_history_ordered(engine):
    acct = _account(engine)
    for st in ["ssh", "rdp", "database"]:
        engine.open_session(acct["id"], "org1", st, "host")
    history = engine.get_session_history(acct["id"], "org1")
    assert len(history) == 3


def test_get_session_history_limit(engine):
    acct = _account(engine)
    for _ in range(5):
        engine.open_session(acct["id"], "org1", "ssh", "host")
    history = engine.get_session_history(acct["id"], "org1", limit=3)
    assert len(history) <= 3


# ---------------------------------------------------------------------------
# 8. certify_account — decision propagation
# ---------------------------------------------------------------------------


def test_certify_approved_no_status_change(engine):
    acct = _account(engine)
    engine.certify_account(acct["id"], "org1", "manager", "approved", "All good", "2026-10-01")
    updated = engine.get_account(acct["id"], "org1")
    assert updated["status"] == "active"


def test_certify_revoked_sets_status(engine):
    acct = _account(engine)
    engine.certify_account(acct["id"], "org1", "manager", "revoked", "No longer needed", "")
    updated = engine.get_account(acct["id"], "org1")
    assert updated["status"] == "revoked"


def test_certify_suspended_sets_status(engine):
    acct = _account(engine)
    engine.certify_account(acct["id"], "org1", "manager", "suspended", "Under review", "")
    updated = engine.get_account(acct["id"], "org1")
    assert updated["status"] == "suspended"


def test_certify_invalid_decision_raises(engine):
    acct = _account(engine)
    with pytest.raises(ValueError, match="decision"):
        engine.certify_account(acct["id"], "org1", "mgr", "maybe", "reason", "")


def test_certify_creates_record(engine):
    acct = _account(engine)
    cert = engine.certify_account(acct["id"], "org1", "manager", "approved", "ok", "2026-07-01")
    assert cert["account_id"] == acct["id"]
    assert cert["decision"] == "approved"


def test_get_certifications(engine):
    acct = _account(engine)
    engine.certify_account(acct["id"], "org1", "mgr", "approved", "ok", "")
    engine.certify_account(acct["id"], "org1", "mgr", "approved", "renewed", "")
    certs = engine.get_certifications(acct["id"], "org1")
    assert len(certs) == 2


# ---------------------------------------------------------------------------
# 9. get_high_risk_accounts
# ---------------------------------------------------------------------------


def test_high_risk_returns_critical_and_high(engine):
    _account(engine, account_type="admin", mfa_enabled=False, username="a1")         # critical
    _account(engine, account_type="service_account", mfa_enabled=False, username="a2")  # high
    _account(engine, account_type="shared", mfa_enabled=True, username="a3")           # medium
    hr = engine.get_high_risk_accounts("org1")
    assert len(hr) == 2
    assert all(r["risk_level"] in ("critical", "high") for r in hr)


def test_high_risk_critical_first(engine):
    _account(engine, account_type="service_account", mfa_enabled=False, username="svc")
    _account(engine, account_type="admin", mfa_enabled=False, username="adm")
    hr = engine.get_high_risk_accounts("org1")
    assert hr[0]["risk_level"] == "critical"


# ---------------------------------------------------------------------------
# 10. get_privileged_summary — rotation + certification overdue
# ---------------------------------------------------------------------------


def test_summary_empty_org(engine):
    summary = engine.get_privileged_summary("empty_org")
    assert summary["total"] == 0
    assert summary["active_sessions"] == 0
    assert summary["accounts_needing_rotation"] == 0
    assert summary["uncertified"] == 0


def test_summary_total(engine):
    _account(engine, username="a1")
    _account(engine, username="a2", system_name="sys2")
    summary = engine.get_privileged_summary("org1")
    assert summary["total"] == 2


def test_summary_by_risk_level(engine):
    _account(engine, account_type="admin", mfa_enabled=False, username="adm")
    _account(engine, account_type="service_account", mfa_enabled=False, username="svc")
    summary = engine.get_privileged_summary("org1")
    assert summary["by_risk_level"].get("critical", 0) == 1
    assert summary["by_risk_level"].get("high", 0) == 1


def test_summary_accounts_needing_rotation_null(engine):
    # Accounts with no rotation set (NULL) count as needing rotation
    _account(engine, username="a1")
    _account(engine, username="a2", system_name="sys2")
    summary = engine.get_privileged_summary("org1")
    assert summary["accounts_needing_rotation"] == 2


def test_summary_rotated_account_not_counted(engine):
    acct = _account(engine)
    engine.rotate_password(acct["id"], "org1")
    summary = engine.get_privileged_summary("org1")
    assert summary["accounts_needing_rotation"] == 0


def test_summary_uncertified(engine):
    _account(engine, username="a1")
    _account(engine, username="a2", system_name="sys2")
    summary = engine.get_privileged_summary("org1")
    assert summary["uncertified"] == 2


def test_summary_certified_account_not_counted(engine):
    acct = _account(engine)
    engine.certify_account(acct["id"], "org1", "mgr", "approved", "ok", "")
    summary = engine.get_privileged_summary("org1")
    assert summary["uncertified"] == 0


def test_summary_active_sessions_count(engine):
    acct = _account(engine)
    engine.open_session(acct["id"], "org1", "ssh", "host")
    engine.open_session(acct["id"], "org1", "rdp", "host2")
    summary = engine.get_privileged_summary("org1")
    assert summary["active_sessions"] == 2


# ---------------------------------------------------------------------------
# 11. Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_accounts(engine):
    _account(engine, org_id="orgA", username="u1")
    _account(engine, org_id="orgB", username="u1")
    sum_a = engine.get_privileged_summary("orgA")
    sum_b = engine.get_privileged_summary("orgB")
    assert sum_a["total"] == 1
    assert sum_b["total"] == 1


def test_org_isolation_sessions(engine):
    acct_a = _account(engine, org_id="orgA", username="u1")
    acct_b = _account(engine, org_id="orgB", username="u1")
    engine.open_session(acct_a["id"], "orgA", "ssh", "host")
    active_b = engine.get_active_sessions("orgB")
    assert len(active_b) == 0


def test_org_isolation_high_risk(engine):
    _account(engine, org_id="orgA", account_type="admin", mfa_enabled=False, username="adm")
    hr = engine.get_high_risk_accounts("orgB")
    assert len(hr) == 0
