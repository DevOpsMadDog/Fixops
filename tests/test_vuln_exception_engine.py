"""
Comprehensive tests for VulnExceptionEngine — 30+ tests.

Covers:
- create_exception: valid/invalid types, required fields, status=pending
- list_exceptions: filters by type/status, org isolation
- get_exception: found, not found, org isolation
- approve_exception: sets status/approved_by/approved_at, missing exception
- reject_exception: sets status/rejected_by/rejection_reason, missing exception
- expire_exceptions: only expires approved with past expiry_date, not pending/rejected
- get_exception_stats: by_type, by_status, pending_count, approved_count,
  expired_count, acceptance_rate calculation, org isolation
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")

from core.vuln_exception_engine import VulnExceptionEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return VulnExceptionEngine(db_path=str(tmp_path / "vuln_exceptions.db"))


ORG = "org-vexc-test"
ORG2 = "org-vexc-other"


def _exc(overrides=None):
    base = {
        "cve_id": "CVE-2024-1234",
        "asset_id": "asset-abc",
        "reason": "Mitigated by WAF rule 5678",
        "exception_type": "compensating_control",
        "requested_by": "sec-team",
    }
    if overrides:
        base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# create_exception
# ---------------------------------------------------------------------------

class TestCreateException:
    def test_returns_dict_with_id(self, engine):
        result = engine.create_exception(ORG, _exc())
        assert "id" in result
        assert len(result["id"]) == 36

    def test_status_is_pending(self, engine):
        result = engine.create_exception(ORG, _exc())
        assert result["status"] == "pending"

    def test_stores_cve_id(self, engine):
        result = engine.create_exception(ORG, _exc({"cve_id": "CVE-2023-9999"}))
        assert result["cve_id"] == "CVE-2023-9999"

    def test_stores_asset_id(self, engine):
        result = engine.create_exception(ORG, _exc({"asset_id": "asset-xyz"}))
        assert result["asset_id"] == "asset-xyz"

    def test_stores_reason(self, engine):
        result = engine.create_exception(ORG, _exc({"reason": "False positive confirmed"}))
        assert result["reason"] == "False positive confirmed"

    def test_missing_cve_id_raises(self, engine):
        with pytest.raises(ValueError, match="cve_id"):
            engine.create_exception(ORG, _exc({"cve_id": ""}))

    def test_missing_asset_id_raises(self, engine):
        with pytest.raises(ValueError, match="asset_id"):
            engine.create_exception(ORG, _exc({"asset_id": ""}))

    def test_missing_reason_raises(self, engine):
        with pytest.raises(ValueError, match="reason"):
            engine.create_exception(ORG, _exc({"reason": ""}))

    def test_invalid_exception_type_raises(self, engine):
        with pytest.raises(ValueError, match="exception_type"):
            engine.create_exception(ORG, _exc({"exception_type": "wrong_type"}))

    def test_all_valid_exception_types(self, engine):
        for etype in ("false_positive", "accepted_risk", "compensating_control", "deferred", "not_applicable"):
            r = engine.create_exception(ORG, _exc({"exception_type": etype, "cve_id": f"CVE-{etype}"}))
            assert r["exception_type"] == etype

    def test_expiry_date_stored(self, engine):
        future = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
        result = engine.create_exception(ORG, _exc({"expiry_date": future}))
        assert result["expiry_date"] == future

    def test_org_id_stored(self, engine):
        result = engine.create_exception(ORG, _exc())
        assert result["org_id"] == ORG

    def test_no_expiry_by_default(self, engine):
        result = engine.create_exception(ORG, _exc())
        assert result["expiry_date"] is None


# ---------------------------------------------------------------------------
# list_exceptions
# ---------------------------------------------------------------------------

class TestListExceptions:
    def test_empty_org_returns_empty(self, engine):
        assert engine.list_exceptions(ORG) == []

    def test_returns_created_exceptions(self, engine):
        engine.create_exception(ORG, _exc())
        engine.create_exception(ORG, _exc({"cve_id": "CVE-2024-5678"}))
        assert len(engine.list_exceptions(ORG)) == 2

    def test_filter_by_exception_type(self, engine):
        engine.create_exception(ORG, _exc({"exception_type": "false_positive"}))
        engine.create_exception(ORG, _exc({"exception_type": "deferred", "cve_id": "CVE-B"}))
        results = engine.list_exceptions(ORG, exception_type="false_positive")
        assert len(results) == 1
        assert results[0]["exception_type"] == "false_positive"

    def test_filter_by_status(self, engine):
        exc = engine.create_exception(ORG, _exc())
        engine.approve_exception(ORG, exc["id"], "manager")
        pending_results = engine.list_exceptions(ORG, status="pending")
        approved_results = engine.list_exceptions(ORG, status="approved")
        assert len(pending_results) == 0
        assert len(approved_results) == 1

    def test_org_isolation(self, engine):
        engine.create_exception(ORG, _exc())
        engine.create_exception(ORG2, _exc({"cve_id": "CVE-OTHER"}))
        assert len(engine.list_exceptions(ORG)) == 1
        assert len(engine.list_exceptions(ORG2)) == 1


# ---------------------------------------------------------------------------
# get_exception
# ---------------------------------------------------------------------------

class TestGetException:
    def test_found_returns_exception(self, engine):
        created = engine.create_exception(ORG, _exc())
        result = engine.get_exception(ORG, created["id"])
        assert result["id"] == created["id"]

    def test_not_found_returns_empty(self, engine):
        result = engine.get_exception(ORG, "nonexistent-id")
        assert result == {}

    def test_org_isolation(self, engine):
        created = engine.create_exception(ORG, _exc())
        result = engine.get_exception(ORG2, created["id"])
        assert result == {}


# ---------------------------------------------------------------------------
# approve_exception
# ---------------------------------------------------------------------------

class TestApproveException:
    def test_sets_status_approved(self, engine):
        exc = engine.create_exception(ORG, _exc())
        result = engine.approve_exception(ORG, exc["id"], "ciso")
        assert result["status"] == "approved"

    def test_stores_approved_by(self, engine):
        exc = engine.create_exception(ORG, _exc())
        result = engine.approve_exception(ORG, exc["id"], "ciso")
        assert result["approved_by"] == "ciso"

    def test_stores_approved_at(self, engine):
        exc = engine.create_exception(ORG, _exc())
        result = engine.approve_exception(ORG, exc["id"], "ciso")
        assert result["approved_at"] is not None

    def test_stores_approval_notes(self, engine):
        exc = engine.create_exception(ORG, _exc())
        result = engine.approve_exception(ORG, exc["id"], "ciso", notes="Reviewed OK")
        assert result["approval_notes"] == "Reviewed OK"

    def test_missing_exception_raises(self, engine):
        with pytest.raises(ValueError):
            engine.approve_exception(ORG, "no-such-id", "ciso")

    def test_org_isolation_approve(self, engine):
        exc = engine.create_exception(ORG, _exc())
        with pytest.raises(ValueError):
            engine.approve_exception(ORG2, exc["id"], "ciso")


# ---------------------------------------------------------------------------
# reject_exception
# ---------------------------------------------------------------------------

class TestRejectException:
    def test_sets_status_rejected(self, engine):
        exc = engine.create_exception(ORG, _exc())
        result = engine.reject_exception(ORG, exc["id"], "ciso", "Risk too high")
        assert result["status"] == "rejected"

    def test_stores_rejected_by(self, engine):
        exc = engine.create_exception(ORG, _exc())
        result = engine.reject_exception(ORG, exc["id"], "ciso", "reason")
        assert result["rejected_by"] == "ciso"

    def test_stores_rejection_reason(self, engine):
        exc = engine.create_exception(ORG, _exc())
        result = engine.reject_exception(ORG, exc["id"], "ciso", "Policy violation")
        assert result["rejection_reason"] == "Policy violation"

    def test_stores_rejected_at(self, engine):
        exc = engine.create_exception(ORG, _exc())
        result = engine.reject_exception(ORG, exc["id"], "ciso", "reason")
        assert result["rejected_at"] is not None

    def test_missing_exception_raises(self, engine):
        with pytest.raises(ValueError):
            engine.reject_exception(ORG, "no-such-id", "ciso", "reason")


# ---------------------------------------------------------------------------
# expire_exceptions
# ---------------------------------------------------------------------------

class TestExpireExceptions:
    def test_expires_approved_past_expiry(self, engine):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        exc = engine.create_exception(ORG, _exc({"expiry_date": past}))
        engine.approve_exception(ORG, exc["id"], "ciso")
        result = engine.expire_exceptions(ORG)
        assert result["expired_count"] == 1
        updated = engine.get_exception(ORG, exc["id"])
        assert updated["status"] == "expired"

    def test_does_not_expire_pending(self, engine):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        engine.create_exception(ORG, _exc({"expiry_date": past}))
        result = engine.expire_exceptions(ORG)
        assert result["expired_count"] == 0

    def test_does_not_expire_rejected(self, engine):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        exc = engine.create_exception(ORG, _exc({"expiry_date": past}))
        engine.reject_exception(ORG, exc["id"], "ciso", "nope")
        result = engine.expire_exceptions(ORG)
        assert result["expired_count"] == 0

    def test_does_not_expire_future_expiry(self, engine):
        future = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
        exc = engine.create_exception(ORG, _exc({"expiry_date": future}))
        engine.approve_exception(ORG, exc["id"], "ciso")
        result = engine.expire_exceptions(ORG)
        assert result["expired_count"] == 0

    def test_does_not_expire_no_expiry_date(self, engine):
        exc = engine.create_exception(ORG, _exc())
        engine.approve_exception(ORG, exc["id"], "ciso")
        result = engine.expire_exceptions(ORG)
        assert result["expired_count"] == 0

    def test_org_isolation_expire(self, engine):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        exc = engine.create_exception(ORG, _exc({"expiry_date": past}))
        engine.approve_exception(ORG, exc["id"], "ciso")
        # expiring ORG2 should not affect ORG
        engine.expire_exceptions(ORG2)
        updated = engine.get_exception(ORG, exc["id"])
        assert updated["status"] == "approved"

    def test_returns_zero_when_nothing_to_expire(self, engine):
        result = engine.expire_exceptions(ORG)
        assert result["expired_count"] == 0


# ---------------------------------------------------------------------------
# get_exception_stats
# ---------------------------------------------------------------------------

class TestGetExceptionStats:
    def test_empty_org_returns_zeros(self, engine):
        stats = engine.get_exception_stats(ORG)
        assert stats["total_exceptions"] == 0
        assert stats["pending_count"] == 0
        assert stats["approved_count"] == 0
        assert stats["expired_count"] == 0
        assert stats["acceptance_rate"] == 0.0

    def test_total_exceptions_count(self, engine):
        engine.create_exception(ORG, _exc())
        engine.create_exception(ORG, _exc({"cve_id": "CVE-B"}))
        stats = engine.get_exception_stats(ORG)
        assert stats["total_exceptions"] == 2

    def test_by_type_counts(self, engine):
        engine.create_exception(ORG, _exc({"exception_type": "false_positive"}))
        engine.create_exception(ORG, _exc({"exception_type": "false_positive", "cve_id": "CVE-B"}))
        engine.create_exception(ORG, _exc({"exception_type": "deferred", "cve_id": "CVE-C"}))
        stats = engine.get_exception_stats(ORG)
        assert stats["by_type"]["false_positive"] == 2
        assert stats["by_type"]["deferred"] == 1

    def test_by_status_counts(self, engine):
        exc1 = engine.create_exception(ORG, _exc())
        exc2 = engine.create_exception(ORG, _exc({"cve_id": "CVE-B"}))
        engine.create_exception(ORG, _exc({"cve_id": "CVE-C"}))
        engine.approve_exception(ORG, exc1["id"], "ciso")
        engine.reject_exception(ORG, exc2["id"], "ciso", "nope")
        stats = engine.get_exception_stats(ORG)
        assert stats["by_status"]["approved"] == 1
        assert stats["by_status"]["rejected"] == 1
        assert stats["by_status"]["pending"] == 1

    def test_pending_count(self, engine):
        engine.create_exception(ORG, _exc())
        engine.create_exception(ORG, _exc({"cve_id": "CVE-B"}))
        stats = engine.get_exception_stats(ORG)
        assert stats["pending_count"] == 2

    def test_approved_count(self, engine):
        exc = engine.create_exception(ORG, _exc())
        engine.approve_exception(ORG, exc["id"], "ciso")
        stats = engine.get_exception_stats(ORG)
        assert stats["approved_count"] == 1

    def test_expired_count(self, engine):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        exc = engine.create_exception(ORG, _exc({"expiry_date": past}))
        engine.approve_exception(ORG, exc["id"], "ciso")
        engine.expire_exceptions(ORG)
        stats = engine.get_exception_stats(ORG)
        assert stats["expired_count"] == 1

    def test_acceptance_rate_100_percent(self, engine):
        exc1 = engine.create_exception(ORG, _exc())
        exc2 = engine.create_exception(ORG, _exc({"cve_id": "CVE-B"}))
        engine.approve_exception(ORG, exc1["id"], "ciso")
        engine.approve_exception(ORG, exc2["id"], "ciso")
        stats = engine.get_exception_stats(ORG)
        assert stats["acceptance_rate"] == 100.0

    def test_acceptance_rate_50_percent(self, engine):
        exc1 = engine.create_exception(ORG, _exc())
        exc2 = engine.create_exception(ORG, _exc({"cve_id": "CVE-B"}))
        engine.approve_exception(ORG, exc1["id"], "ciso")
        engine.reject_exception(ORG, exc2["id"], "ciso", "nope")
        stats = engine.get_exception_stats(ORG)
        assert stats["acceptance_rate"] == 50.0

    def test_acceptance_rate_zero_when_all_rejected(self, engine):
        exc = engine.create_exception(ORG, _exc())
        engine.reject_exception(ORG, exc["id"], "ciso", "reason")
        stats = engine.get_exception_stats(ORG)
        assert stats["acceptance_rate"] == 0.0

    def test_acceptance_rate_zero_when_no_decisions(self, engine):
        engine.create_exception(ORG, _exc())
        stats = engine.get_exception_stats(ORG)
        assert stats["acceptance_rate"] == 0.0

    def test_org_isolation(self, engine):
        engine.create_exception(ORG, _exc())
        engine.create_exception(ORG, _exc({"cve_id": "CVE-B"}))
        engine.create_exception(ORG2, _exc({"cve_id": "CVE-C"}))
        stats = engine.get_exception_stats(ORG)
        stats2 = engine.get_exception_stats(ORG2)
        assert stats["total_exceptions"] == 2
        assert stats2["total_exceptions"] == 1
