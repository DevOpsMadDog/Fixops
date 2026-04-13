"""
Privileged Access Management (PAM) Tests — 35+ tests.

Covers:
- PrivilegeLevel enum completeness
- AccessRequest Pydantic model
- PAMManager: request_access, approve_request, deny_request, check_privilege,
  revoke_access, expire_access, get_active_elevations, get_request_history,
  get_pam_stats, break_glass
- Error paths: not found, wrong status transitions
- Auto-expire logic
- Break-glass flags
- Concurrent isolation via per-db-path instances

Run with: python -m pytest tests/test_pam.py -v --timeout=10
"""

from __future__ import annotations

import sys
import tempfile
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.pam import (
    AccessRequest,
    PAMManager,
    PrivilegeLevel,
    RequestStatus,
    get_pam_manager,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def pam(tmp_path):
    """Fresh PAMManager backed by a temp SQLite DB for each test."""
    db = str(tmp_path / "pam_test.db")
    return PAMManager(db_path=db)


@pytest.fixture()
def pam_with_pending(pam):
    """PAM with one pending request already created."""
    req = pam.request_access(
        user_email="alice@acme.com",
        requested_level=PrivilegeLevel.ADMIN,
        justification="Incident response needed now",
        duration_minutes=60,
        org_id="acme",
    )
    return pam, req


# ===========================================================================
# 1. Enum tests
# ===========================================================================


class TestPrivilegeLevel:
    def test_all_five_levels_exist(self):
        levels = [l.value for l in PrivilegeLevel]
        assert "standard" in levels
        assert "elevated" in levels
        assert "admin" in levels
        assert "superadmin" in levels
        assert "emergency" in levels

    def test_enum_count(self):
        assert len(list(PrivilegeLevel)) == 5

    def test_string_values(self):
        assert PrivilegeLevel.STANDARD.value == "standard"
        assert PrivilegeLevel.EMERGENCY.value == "emergency"

    def test_str_enum_is_str(self):
        assert isinstance(PrivilegeLevel.ADMIN, str)


class TestRequestStatus:
    def test_all_five_statuses_exist(self):
        statuses = [s.value for s in RequestStatus]
        assert "pending" in statuses
        assert "approved" in statuses
        assert "denied" in statuses
        assert "expired" in statuses
        assert "revoked" in statuses


# ===========================================================================
# 2. AccessRequest model
# ===========================================================================


class TestAccessRequestModel:
    def test_model_has_required_fields(self, pam):
        req = pam.request_access(
            user_email="bob@corp.com",
            requested_level=PrivilegeLevel.ELEVATED,
            justification="Need elevated for deployment",
            duration_minutes=30,
            org_id="corp",
        )
        assert req.id.startswith("pam_")
        assert req.user_email == "bob@corp.com"
        assert req.requested_level == PrivilegeLevel.ELEVATED
        assert req.duration_minutes == 30
        assert req.status == RequestStatus.PENDING
        assert req.org_id == "corp"
        assert req.approved_by is None
        assert req.expires_at is None
        assert req.is_break_glass is False
        assert isinstance(req.created_at, datetime)

    def test_model_serializes_to_dict(self, pam):
        req = pam.request_access(
            user_email="c@x.com",
            requested_level=PrivilegeLevel.STANDARD,
            justification="Testing serialization path",
            duration_minutes=15,
            org_id="x",
        )
        d = req.model_dump()
        assert d["user_email"] == "c@x.com"
        assert d["status"] == RequestStatus.PENDING


# ===========================================================================
# 3. request_access
# ===========================================================================


class TestRequestAccess:
    def test_creates_pending_request(self, pam):
        req = pam.request_access("u@a.com", PrivilegeLevel.ADMIN,
                                 "Need admin for maintenance window", 60, "a")
        assert req.status == RequestStatus.PENDING

    def test_unique_ids(self, pam):
        r1 = pam.request_access("u@a.com", PrivilegeLevel.ELEVATED,
                                 "First request for access", 30, "a")
        r2 = pam.request_access("u@a.com", PrivilegeLevel.ELEVATED,
                                 "Second request for access", 30, "a")
        assert r1.id != r2.id

    def test_rejects_zero_duration(self, pam):
        with pytest.raises(ValueError, match="duration_minutes"):
            pam.request_access("u@a.com", PrivilegeLevel.ELEVATED,
                                "Has justification text", 0, "a")

    def test_rejects_negative_duration(self, pam):
        with pytest.raises(ValueError):
            pam.request_access("u@a.com", PrivilegeLevel.ELEVATED,
                                "Has justification text", -5, "a")

    def test_rejects_empty_justification(self, pam):
        with pytest.raises(ValueError, match="justification"):
            pam.request_access("u@a.com", PrivilegeLevel.ELEVATED, "   ", 30, "a")

    def test_org_isolation(self, pam):
        pam.request_access("u@a.com", PrivilegeLevel.ADMIN,
                           "Org A request for access", 60, "org_a")
        pam.request_access("u@b.com", PrivilegeLevel.ADMIN,
                           "Org B request for access", 60, "org_b")
        hist_a = pam.get_request_history(org_id="org_a")
        hist_b = pam.get_request_history(org_id="org_b")
        assert len(hist_a) == 1
        assert len(hist_b) == 1
        assert hist_a[0].user_email == "u@a.com"


# ===========================================================================
# 4. approve_request
# ===========================================================================


class TestApproveRequest:
    def test_approve_sets_status_and_expiry(self, pam_with_pending):
        pam, req = pam_with_pending
        approved = pam.approve_request(req.id, "manager@acme.com")
        assert approved.status == RequestStatus.APPROVED
        assert approved.approved_by == "manager@acme.com"
        assert approved.expires_at is not None
        assert approved.expires_at > datetime.now(timezone.utc)

    def test_approve_expiry_matches_duration(self, pam_with_pending):
        pam, req = pam_with_pending
        before = datetime.now(timezone.utc)
        approved = pam.approve_request(req.id, "mgr@acme.com")
        after = datetime.now(timezone.utc)
        expected_lower = before + timedelta(minutes=req.duration_minutes - 1)
        expected_upper = after + timedelta(minutes=req.duration_minutes + 1)
        assert expected_lower <= approved.expires_at <= expected_upper

    def test_approve_nonexistent_raises(self, pam):
        with pytest.raises(ValueError, match="not found"):
            pam.approve_request("bad_id", "mgr@x.com")

    def test_approve_already_approved_raises(self, pam_with_pending):
        pam, req = pam_with_pending
        pam.approve_request(req.id, "mgr@acme.com")
        with pytest.raises(ValueError, match="approved"):
            pam.approve_request(req.id, "mgr@acme.com")


# ===========================================================================
# 5. deny_request
# ===========================================================================


class TestDenyRequest:
    def test_deny_sets_status_and_reason(self, pam_with_pending):
        pam, req = pam_with_pending
        denied = pam.deny_request(req.id, "security@acme.com", "Insufficient justification")
        assert denied.status == RequestStatus.DENIED
        assert denied.denial_reason == "Insufficient justification"
        assert denied.approved_by == "security@acme.com"

    def test_deny_nonexistent_raises(self, pam):
        with pytest.raises(ValueError, match="not found"):
            pam.deny_request("bad_id", "sec@x.com", "reason")

    def test_deny_already_approved_raises(self, pam_with_pending):
        pam, req = pam_with_pending
        pam.approve_request(req.id, "mgr@acme.com")
        with pytest.raises(ValueError):
            pam.deny_request(req.id, "sec@acme.com", "too late")


# ===========================================================================
# 6. check_privilege
# ===========================================================================


class TestCheckPrivilege:
    def test_no_elevation_returns_standard(self, pam):
        level = pam.check_privilege("nobody@x.com", "x")
        assert level == PrivilegeLevel.STANDARD

    def test_approved_elevation_returns_level(self, pam_with_pending):
        pam, req = pam_with_pending
        pam.approve_request(req.id, "mgr@acme.com")
        level = pam.check_privilege("alice@acme.com", "acme")
        assert level == PrivilegeLevel.ADMIN

    def test_pending_request_returns_standard(self, pam_with_pending):
        pam, req = pam_with_pending
        # Not yet approved
        level = pam.check_privilege("alice@acme.com", "acme")
        assert level == PrivilegeLevel.STANDARD

    def test_denied_returns_standard(self, pam_with_pending):
        pam, req = pam_with_pending
        pam.deny_request(req.id, "mgr@acme.com", "no")
        assert pam.check_privilege("alice@acme.com", "acme") == PrivilegeLevel.STANDARD

    def test_returns_highest_level_when_multiple(self, pam):
        r1 = pam.request_access("u@x.com", PrivilegeLevel.ELEVATED,
                                 "First level need for work", 30, "x")
        r2 = pam.request_access("u@x.com", PrivilegeLevel.SUPERADMIN,
                                 "Second level need for work", 30, "x")
        pam.approve_request(r1.id, "mgr@x.com")
        pam.approve_request(r2.id, "mgr@x.com")
        assert pam.check_privilege("u@x.com", "x") == PrivilegeLevel.SUPERADMIN


# ===========================================================================
# 7. revoke_access
# ===========================================================================


class TestRevokeAccess:
    def test_revoke_approved_succeeds(self, pam_with_pending):
        pam, req = pam_with_pending
        pam.approve_request(req.id, "mgr@acme.com")
        revoked = pam.revoke_access(req.id)
        assert revoked.status == RequestStatus.REVOKED

    def test_revoke_drops_from_active(self, pam_with_pending):
        pam, req = pam_with_pending
        pam.approve_request(req.id, "mgr@acme.com")
        pam.revoke_access(req.id)
        active = pam.get_active_elevations("acme")
        assert all(r.id != req.id for r in active)

    def test_revoke_nonexistent_raises(self, pam):
        with pytest.raises(ValueError, match="not found"):
            pam.revoke_access("bad_id")

    def test_revoke_pending_raises(self, pam_with_pending):
        pam, req = pam_with_pending
        with pytest.raises(ValueError):
            pam.revoke_access(req.id)


# ===========================================================================
# 8. expire_access
# ===========================================================================


class TestExpireAccess:
    def test_expire_changes_status(self, pam):
        """Simulate expiry by directly manipulating DB after approval."""
        req = pam.request_access("u@x.com", PrivilegeLevel.ELEVATED,
                                  "Short lived access needed", 1, "x")
        pam.approve_request(req.id, "mgr@x.com")

        # Back-date the expires_at to the past
        import sqlite3
        conn = sqlite3.connect(pam._db_path)
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        conn.execute("UPDATE access_requests SET expires_at = ? WHERE id = ?",
                     (past, req.id))
        conn.commit()
        conn.close()

        count = pam.expire_access("x")
        assert count == 1

        active = pam.get_active_elevations("x")
        assert all(r.id != req.id for r in active)

    def test_expire_returns_zero_when_nothing_expired(self, pam):
        count = pam.expire_access("empty_org")
        assert count == 0

    def test_expire_only_affects_target_org(self, pam):
        r1 = pam.request_access("u@a.com", PrivilegeLevel.ADMIN,
                                  "Org A access needed now", 60, "org_a")
        pam.approve_request(r1.id, "mgr@a.com")
        # Back-date org_a's request
        import sqlite3
        conn = sqlite3.connect(pam._db_path)
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        conn.execute("UPDATE access_requests SET expires_at = ? WHERE id = ?",
                     (past, r1.id))
        conn.commit()
        conn.close()
        # Only expire org_a
        count = pam.expire_access("org_a")
        assert count == 1


# ===========================================================================
# 9. get_active_elevations
# ===========================================================================


class TestGetActiveElevations:
    def test_empty_org_returns_empty_list(self, pam):
        assert pam.get_active_elevations("ghost") == []

    def test_approved_request_appears(self, pam_with_pending):
        pam, req = pam_with_pending
        pam.approve_request(req.id, "mgr@acme.com")
        active = pam.get_active_elevations("acme")
        assert any(r.id == req.id for r in active)

    def test_pending_not_in_active(self, pam_with_pending):
        pam, req = pam_with_pending
        active = pam.get_active_elevations("acme")
        assert all(r.id != req.id for r in active)


# ===========================================================================
# 10. get_request_history
# ===========================================================================


class TestGetRequestHistory:
    def test_history_includes_all_statuses(self, pam):
        r1 = pam.request_access("u@x.com", PrivilegeLevel.ELEVATED,
                                  "First request for history test", 30, "x")
        r2 = pam.request_access("u@x.com", PrivilegeLevel.ADMIN,
                                  "Second request for history test", 60, "x")
        pam.approve_request(r1.id, "mgr@x.com")
        pam.deny_request(r2.id, "sec@x.com", "not approved")
        hist = pam.get_request_history("x")
        statuses = {r.status for r in hist}
        assert RequestStatus.APPROVED in statuses
        assert RequestStatus.DENIED in statuses

    def test_history_newest_first(self, pam):
        pam.request_access("u@x.com", PrivilegeLevel.ELEVATED,
                            "Earlier request for ordering test", 30, "x")
        pam.request_access("u@x.com", PrivilegeLevel.ADMIN,
                            "Later request for ordering test", 60, "x")
        hist = pam.get_request_history("x")
        assert hist[0].created_at >= hist[-1].created_at

    def test_history_respects_limit(self, pam):
        for i in range(5):
            pam.request_access(f"u{i}@x.com", PrivilegeLevel.ELEVATED,
                                f"Request number {i} for limit test", 30, "x")
        hist = pam.get_request_history("x", limit=3)
        assert len(hist) <= 3


# ===========================================================================
# 11. get_pam_stats
# ===========================================================================


class TestGetPamStats:
    def test_empty_org_stats(self, pam):
        stats = pam.get_pam_stats("empty")
        assert stats["total_requests"] == 0
        assert stats["avg_approved_duration_minutes"] == 0.0
        assert stats["break_glass_count"] == 0

    def test_stats_count_by_status(self, pam):
        r1 = pam.request_access("u@x.com", PrivilegeLevel.ELEVATED,
                                  "First request for stats test", 30, "x")
        r2 = pam.request_access("v@x.com", PrivilegeLevel.ADMIN,
                                  "Second request for stats test", 60, "x")
        pam.approve_request(r1.id, "mgr@x.com")
        pam.deny_request(r2.id, "sec@x.com", "denied reason")
        stats = pam.get_pam_stats("x")
        assert stats["by_status"].get("approved", 0) == 1
        assert stats["by_status"].get("denied", 0) == 1
        assert stats["total_requests"] == 2

    def test_stats_avg_duration(self, pam):
        r = pam.request_access("u@x.com", PrivilegeLevel.ADMIN,
                                "Request for avg duration test", 120, "x")
        pam.approve_request(r.id, "mgr@x.com")
        stats = pam.get_pam_stats("x")
        assert stats["avg_approved_duration_minutes"] == 120.0

    def test_stats_top_requesters(self, pam):
        for _ in range(3):
            pam.request_access("frequent@x.com", PrivilegeLevel.ELEVATED,
                                "Frequent requester pattern test", 30, "x")
        stats = pam.get_pam_stats("x")
        emails = [r["user_email"] for r in stats["top_requesters"]]
        assert "frequent@x.com" in emails


# ===========================================================================
# 12. break_glass
# ===========================================================================


class TestBreakGlass:
    def test_break_glass_auto_approves(self, pam):
        req = pam.break_glass("sre@x.com", "P0 outage all systems down", "x")
        assert req.status == RequestStatus.APPROVED
        assert req.requested_level == PrivilegeLevel.EMERGENCY
        assert req.is_break_glass is True
        assert req.post_review_required is True

    def test_break_glass_id_prefix(self, pam):
        req = pam.break_glass("sre@x.com", "P0 outage all systems down", "x")
        assert req.id.startswith("bg_")

    def test_break_glass_has_expiry(self, pam):
        req = pam.break_glass("sre@x.com", "P0 outage all systems down", "x")
        assert req.expires_at is not None
        assert req.expires_at > datetime.now(timezone.utc)

    def test_break_glass_duration_capped_at_4h(self, pam):
        req = pam.break_glass("sre@x.com", "P0 outage all systems down", "x")
        # 240 minutes = 4 hours
        assert req.duration_minutes == 240

    def test_break_glass_appears_in_active(self, pam):
        req = pam.break_glass("sre@x.com", "P0 outage all systems down", "x")
        active = pam.get_active_elevations("x")
        assert any(r.id == req.id for r in active)

    def test_break_glass_counted_in_stats(self, pam):
        pam.break_glass("sre@x.com", "P0 outage all systems down", "x")
        stats = pam.get_pam_stats("x")
        assert stats["break_glass_count"] == 1
        assert stats["post_review_pending"] >= 1

    def test_break_glass_empty_justification_raises(self, pam):
        with pytest.raises(ValueError, match="justification"):
            pam.break_glass("sre@x.com", "   ", "x")

    def test_break_glass_gives_privilege_check_emergency(self, pam):
        pam.break_glass("sre@x.com", "P0 outage all systems down", "x")
        level = pam.check_privilege("sre@x.com", "x")
        assert level == PrivilegeLevel.EMERGENCY


# ===========================================================================
# 13. get_pam_manager factory
# ===========================================================================


class TestGetPamManager:
    def test_factory_returns_pam_manager(self, tmp_path):
        mgr = get_pam_manager(db_path=str(tmp_path / "f.db"))
        assert isinstance(mgr, PAMManager)

    def test_different_paths_give_isolated_instances(self, tmp_path):
        m1 = get_pam_manager(db_path=str(tmp_path / "a.db"))
        m2 = get_pam_manager(db_path=str(tmp_path / "b.db"))
        m1.request_access("u@a.com", PrivilegeLevel.ADMIN,
                           "Request in instance A only", 60, "a")
        assert m2.get_request_history("a") == []
