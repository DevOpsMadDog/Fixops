"""
Tests for RiskAcceptanceEngine — the SQLite-backed risk acceptance workflow.

Tests the engine directly (not the manager or router), using tmp_path for
isolated per-test databases.
"""
from __future__ import annotations

import sys
import os
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.risk_acceptance_engine import RiskAcceptanceEngine, ACCEPTANCE_STATES, RISK_LEVELS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _engine(tmp_path) -> RiskAcceptanceEngine:
    return RiskAcceptanceEngine(db_path=str(tmp_path / "ra_test.db"))


def _submit(engine: RiskAcceptanceEngine, **kwargs) -> dict:
    defaults = dict(
        finding_id="finding-001",
        requestor="alice@example.com",
        justification="Business deadline requires temporary risk acceptance.",
        risk_level="medium",
        expiry_days=90,
        org_id="org-test",
    )
    defaults.update(kwargs)
    return engine.submit_acceptance(**defaults)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestConstants:
    def test_acceptance_states_includes_required(self):
        required = {"pending_review", "approved", "rejected", "expired", "revoked"}
        assert required.issubset(set(ACCEPTANCE_STATES))

    def test_risk_levels_includes_all_severities(self):
        assert set(RISK_LEVELS) == {"low", "medium", "high", "critical"}


# ---------------------------------------------------------------------------
# Engine instantiation
# ---------------------------------------------------------------------------


class TestEngineInit:
    def test_instantiates_with_tmp_path(self, tmp_path):
        engine = _engine(tmp_path)
        assert engine is not None

    def test_db_file_created(self, tmp_path):
        _engine(tmp_path)
        assert (tmp_path / "ra_test.db").exists()

    def test_creates_parent_dirs(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c"
        RiskAcceptanceEngine(db_path=str(nested / "ra.db"))
        assert nested.exists()


# ---------------------------------------------------------------------------
# submit_acceptance
# ---------------------------------------------------------------------------


class TestSubmitAcceptance:
    def test_returns_dict(self, tmp_path):
        engine = _engine(tmp_path)
        result = _submit(engine)
        assert isinstance(result, dict)

    def test_result_has_id_field(self, tmp_path):
        engine = _engine(tmp_path)
        result = _submit(engine)
        assert "acceptance_id" in result
        assert result["acceptance_id"]

    def test_initial_state_is_pending_review(self, tmp_path):
        engine = _engine(tmp_path)
        result = _submit(engine)
        assert result["state"] == "pending_review"

    def test_stores_finding_id(self, tmp_path):
        engine = _engine(tmp_path)
        result = _submit(engine, finding_id="CVE-2024-1234")
        assert result["finding_id"] == "CVE-2024-1234"

    def test_stores_requestor(self, tmp_path):
        engine = _engine(tmp_path)
        result = _submit(engine, requestor="bob@corp.com")
        assert result["requestor"] == "bob@corp.com"

    def test_stores_risk_level(self, tmp_path):
        engine = _engine(tmp_path)
        result = _submit(engine, risk_level="critical")
        assert result["risk_level"] == "critical"

    def test_stores_org_id(self, tmp_path):
        engine = _engine(tmp_path)
        result = _submit(engine, org_id="org-acme")
        assert result["org_id"] == "org-acme"

    def test_invalid_risk_level_raises(self, tmp_path):
        engine = _engine(tmp_path)
        with pytest.raises(ValueError, match="Invalid risk_level"):
            _submit(engine, risk_level="extreme")

    def test_includes_audit_trail_entry(self, tmp_path):
        engine = _engine(tmp_path)
        result = _submit(engine)
        assert "audit_trail" in result
        assert len(result["audit_trail"]) >= 1

    def test_audit_trail_first_action_is_submitted(self, tmp_path):
        engine = _engine(tmp_path)
        result = _submit(engine)
        first_audit = result["audit_trail"][0]
        assert first_audit["action"] == "submitted"


# ---------------------------------------------------------------------------
# get_acceptance
# ---------------------------------------------------------------------------


class TestGetAcceptance:
    def test_returns_dict_for_known_id(self, tmp_path):
        engine = _engine(tmp_path)
        submitted = _submit(engine)
        record = engine.get_acceptance(submitted["acceptance_id"])
        assert isinstance(record, dict)
        assert record["acceptance_id"] == submitted["acceptance_id"]

    def test_returns_none_for_unknown_id(self, tmp_path):
        engine = _engine(tmp_path)
        assert engine.get_acceptance("does-not-exist") is None

    def test_returned_record_has_audit_trail(self, tmp_path):
        engine = _engine(tmp_path)
        submitted = _submit(engine)
        record = engine.get_acceptance(submitted["acceptance_id"])
        assert "audit_trail" in record
        assert isinstance(record["audit_trail"], list)


# ---------------------------------------------------------------------------
# approve
# ---------------------------------------------------------------------------


class TestApprove:
    def test_approve_changes_state_to_approved(self, tmp_path):
        engine = _engine(tmp_path)
        submitted = _submit(engine)
        result = engine.approve(submitted["acceptance_id"], approver="admin@corp.com")
        assert result["state"] == "approved"

    def test_approve_records_approver(self, tmp_path):
        engine = _engine(tmp_path)
        submitted = _submit(engine)
        result = engine.approve(submitted["acceptance_id"], approver="ciso@corp.com")
        assert result["approver"] == "ciso@corp.com"

    def test_approve_sets_resolved_at(self, tmp_path):
        engine = _engine(tmp_path)
        submitted = _submit(engine)
        result = engine.approve(submitted["acceptance_id"], approver="admin")
        assert result["resolved_at"] is not None

    def test_approve_nonexistent_raises(self, tmp_path):
        engine = _engine(tmp_path)
        with pytest.raises(ValueError, match="not found"):
            engine.approve("ghost-id", approver="admin")

    def test_double_approve_raises(self, tmp_path):
        engine = _engine(tmp_path)
        submitted = _submit(engine)
        engine.approve(submitted["acceptance_id"], approver="admin")
        with pytest.raises(ValueError):
            engine.approve(submitted["acceptance_id"], approver="admin2")

    def test_approve_adds_audit_entry(self, tmp_path):
        engine = _engine(tmp_path)
        submitted = _submit(engine)
        result = engine.approve(submitted["acceptance_id"], approver="admin@corp.com", notes="Looks fine")
        actions = [a["action"] for a in result["audit_trail"]]
        assert "approved" in actions


# ---------------------------------------------------------------------------
# reject
# ---------------------------------------------------------------------------


class TestReject:
    def test_reject_changes_state_to_rejected(self, tmp_path):
        engine = _engine(tmp_path)
        submitted = _submit(engine)
        result = engine.reject(submitted["acceptance_id"], approver="security@corp.com", reason="Too risky")
        assert result["state"] == "rejected"

    def test_reject_stores_reason(self, tmp_path):
        engine = _engine(tmp_path)
        submitted = _submit(engine)
        result = engine.reject(submitted["acceptance_id"], approver="security@corp.com", reason="Policy violation")
        assert result["reject_reason"] == "Policy violation"

    def test_reject_nonexistent_raises(self, tmp_path):
        engine = _engine(tmp_path)
        with pytest.raises(ValueError, match="not found"):
            engine.reject("ghost-id", approver="admin", reason="n/a")

    def test_reject_already_approved_raises(self, tmp_path):
        engine = _engine(tmp_path)
        submitted = _submit(engine)
        engine.approve(submitted["acceptance_id"], approver="admin")
        with pytest.raises(ValueError):
            engine.reject(submitted["acceptance_id"], approver="admin", reason="late rejection")

    def test_reject_adds_audit_entry(self, tmp_path):
        engine = _engine(tmp_path)
        submitted = _submit(engine)
        result = engine.reject(submitted["acceptance_id"], approver="admin", reason="risk too high")
        actions = [a["action"] for a in result["audit_trail"]]
        assert "rejected" in actions


# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------


class TestRevoke:
    def test_revoke_approved_changes_state(self, tmp_path):
        engine = _engine(tmp_path)
        submitted = _submit(engine)
        engine.approve(submitted["acceptance_id"], approver="admin")
        result = engine.revoke(submitted["acceptance_id"], revoker="ciso@corp.com", reason="Conditions changed")
        assert result["state"] == "revoked"

    def test_revoke_pending_raises(self, tmp_path):
        engine = _engine(tmp_path)
        submitted = _submit(engine)
        with pytest.raises(ValueError, match="approved"):
            engine.revoke(submitted["acceptance_id"], revoker="admin", reason="n/a")

    def test_revoke_nonexistent_raises(self, tmp_path):
        engine = _engine(tmp_path)
        with pytest.raises(ValueError, match="not found"):
            engine.revoke("ghost-id", revoker="admin", reason="n/a")

    def test_revoke_adds_audit_entry(self, tmp_path):
        engine = _engine(tmp_path)
        submitted = _submit(engine)
        engine.approve(submitted["acceptance_id"], approver="admin")
        result = engine.revoke(submitted["acceptance_id"], revoker="ciso@corp.com", reason="policy change")
        actions = [a["action"] for a in result["audit_trail"]]
        assert "revoked" in actions


# ---------------------------------------------------------------------------
# list_acceptances
# ---------------------------------------------------------------------------


class TestListAcceptances:
    def test_returns_list(self, tmp_path):
        engine = _engine(tmp_path)
        result = engine.list_acceptances("org-test")
        assert isinstance(result, list)

    def test_returns_submitted_records(self, tmp_path):
        engine = _engine(tmp_path)
        _submit(engine, finding_id="f1")
        _submit(engine, finding_id="f2")
        result = engine.list_acceptances("org-test")
        assert len(result) == 2

    def test_filter_by_state(self, tmp_path):
        engine = _engine(tmp_path)
        submitted = _submit(engine, finding_id="f1")
        _submit(engine, finding_id="f2")
        engine.approve(submitted["acceptance_id"], approver="admin")
        approved = engine.list_acceptances("org-test", state="approved")
        assert len(approved) == 1
        assert approved[0]["finding_id"] == "f1"

    def test_isolated_by_org(self, tmp_path):
        engine = _engine(tmp_path)
        _submit(engine, org_id="org-a")
        _submit(engine, org_id="org-b")
        assert len(engine.list_acceptances("org-a")) == 1
        assert len(engine.list_acceptances("org-b")) == 1


# ---------------------------------------------------------------------------
# is_accepted
# ---------------------------------------------------------------------------


class TestIsAccepted:
    def test_returns_bool(self, tmp_path):
        engine = _engine(tmp_path)
        result = engine.is_accepted("no-such-finding")
        assert isinstance(result, bool)

    def test_false_when_not_submitted(self, tmp_path):
        engine = _engine(tmp_path)
        assert engine.is_accepted("unknown-finding", org_id="org-test") is False

    def test_false_when_pending(self, tmp_path):
        engine = _engine(tmp_path)
        _submit(engine, finding_id="CVE-pending")
        assert engine.is_accepted("CVE-pending", org_id="org-test") is False

    def test_true_when_approved_and_not_expired(self, tmp_path):
        engine = _engine(tmp_path)
        submitted = _submit(engine, finding_id="CVE-active", expiry_days=90)
        engine.approve(submitted["acceptance_id"], approver="admin")
        assert engine.is_accepted("CVE-active", org_id="org-test") is True

    def test_false_after_revoke(self, tmp_path):
        engine = _engine(tmp_path)
        submitted = _submit(engine, finding_id="CVE-revoked")
        engine.approve(submitted["acceptance_id"], approver="admin")
        engine.revoke(submitted["acceptance_id"], revoker="ciso", reason="changed")
        assert engine.is_accepted("CVE-revoked", org_id="org-test") is False

    def test_false_after_reject(self, tmp_path):
        engine = _engine(tmp_path)
        submitted = _submit(engine, finding_id="CVE-rejected")
        engine.reject(submitted["acceptance_id"], approver="admin", reason="too risky")
        assert engine.is_accepted("CVE-rejected", org_id="org-test") is False


# ---------------------------------------------------------------------------
# get_metrics
# ---------------------------------------------------------------------------


class TestGetMetrics:
    def test_returns_dict(self, tmp_path):
        engine = _engine(tmp_path)
        metrics = engine.get_metrics("org-test")
        assert isinstance(metrics, dict)

    def test_has_total_key(self, tmp_path):
        engine = _engine(tmp_path)
        metrics = engine.get_metrics("org-test")
        assert "total" in metrics
        assert isinstance(metrics["total"], int)

    def test_has_pending_key(self, tmp_path):
        engine = _engine(tmp_path)
        metrics = engine.get_metrics("org-test")
        assert "pending" in metrics

    def test_has_approved_key(self, tmp_path):
        engine = _engine(tmp_path)
        metrics = engine.get_metrics("org-test")
        assert "approved" in metrics

    def test_counts_submissions(self, tmp_path):
        engine = _engine(tmp_path)
        _submit(engine, finding_id="f1")
        _submit(engine, finding_id="f2")
        metrics = engine.get_metrics("org-test")
        assert metrics["total"] == 2
        assert metrics["pending"] == 2

    def test_counts_approved(self, tmp_path):
        engine = _engine(tmp_path)
        s = _submit(engine)
        engine.approve(s["acceptance_id"], approver="admin")
        metrics = engine.get_metrics("org-test")
        assert metrics["approved"] == 1
        assert metrics["pending"] == 0

    def test_counts_rejected(self, tmp_path):
        engine = _engine(tmp_path)
        s = _submit(engine)
        engine.reject(s["acceptance_id"], approver="admin", reason="too risky")
        metrics = engine.get_metrics("org-test")
        assert metrics["rejected"] == 1

    def test_has_by_risk_level_key(self, tmp_path):
        engine = _engine(tmp_path)
        metrics = engine.get_metrics("org-test")
        assert "by_risk_level" in metrics
        assert isinstance(metrics["by_risk_level"], dict)

    def test_by_risk_level_counts(self, tmp_path):
        engine = _engine(tmp_path)
        _submit(engine, finding_id="f1", risk_level="high")
        _submit(engine, finding_id="f2", risk_level="high")
        _submit(engine, finding_id="f3", risk_level="low")
        metrics = engine.get_metrics("org-test")
        assert metrics["by_risk_level"]["high"] == 2
        assert metrics["by_risk_level"]["low"] == 1


# ---------------------------------------------------------------------------
# check_expired
# ---------------------------------------------------------------------------


class TestCheckExpired:
    def test_returns_list(self, tmp_path):
        engine = _engine(tmp_path)
        result = engine.check_expired("org-test")
        assert isinstance(result, list)

    def test_empty_when_no_approved_records(self, tmp_path):
        engine = _engine(tmp_path)
        _submit(engine)  # pending, not approved
        result = engine.check_expired("org-test")
        assert result == []

    def test_marks_overdue_approved_as_expired(self, tmp_path):
        engine = _engine(tmp_path)
        # Submit with 1-day expiry then immediately approve
        submitted = _submit(engine, expiry_days=1)
        engine.approve(submitted["acceptance_id"], approver="admin")

        # Manually backdating: update expires_at to the past directly in DB
        import sqlite3
        conn = sqlite3.connect(str(tmp_path / "ra_test.db"))
        past = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        conn.execute(
            "UPDATE risk_acceptances SET expires_at=? WHERE acceptance_id=?",
            (past, submitted["acceptance_id"]),
        )
        conn.commit()
        conn.close()

        expired = engine.check_expired("org-test")
        assert len(expired) == 1

    def test_does_not_expire_pending_records(self, tmp_path):
        engine = _engine(tmp_path)
        _submit(engine)  # pending, never approved
        expired = engine.check_expired("org-test")
        assert len(expired) == 0

    def test_expired_state_persisted(self, tmp_path):
        engine = _engine(tmp_path)
        submitted = _submit(engine, expiry_days=1)
        engine.approve(submitted["acceptance_id"], approver="admin")

        import sqlite3
        conn = sqlite3.connect(str(tmp_path / "ra_test.db"))
        past = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        conn.execute(
            "UPDATE risk_acceptances SET expires_at=? WHERE acceptance_id=?",
            (past, submitted["acceptance_id"]),
        )
        conn.commit()
        conn.close()

        engine.check_expired("org-test")
        record = engine.get_acceptance(submitted["acceptance_id"])
        assert record["state"] == "expired"


# ---------------------------------------------------------------------------
# State transition ordering
# ---------------------------------------------------------------------------


class TestStateTransitions:
    def test_pending_to_approved(self, tmp_path):
        engine = _engine(tmp_path)
        s = _submit(engine)
        result = engine.approve(s["acceptance_id"], approver="admin")
        assert result["state"] == "approved"

    def test_pending_to_rejected(self, tmp_path):
        engine = _engine(tmp_path)
        s = _submit(engine)
        result = engine.reject(s["acceptance_id"], approver="admin", reason="no")
        assert result["state"] == "rejected"

    def test_approved_to_revoked(self, tmp_path):
        engine = _engine(tmp_path)
        s = _submit(engine)
        engine.approve(s["acceptance_id"], approver="admin")
        result = engine.revoke(s["acceptance_id"], revoker="ciso", reason="done")
        assert result["state"] == "revoked"

    def test_rejected_cannot_be_approved(self, tmp_path):
        engine = _engine(tmp_path)
        s = _submit(engine)
        engine.reject(s["acceptance_id"], approver="admin", reason="no")
        with pytest.raises(ValueError):
            engine.approve(s["acceptance_id"], approver="admin")

    def test_revoked_cannot_be_rejected(self, tmp_path):
        engine = _engine(tmp_path)
        s = _submit(engine)
        engine.approve(s["acceptance_id"], approver="admin")
        engine.revoke(s["acceptance_id"], revoker="ciso", reason="done")
        with pytest.raises(ValueError):
            engine.reject(s["acceptance_id"], approver="admin", reason="too late")
