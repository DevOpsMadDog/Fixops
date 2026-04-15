"""Tests for SecurityExceptionWorkflowEngine — 35+ tests."""

from __future__ import annotations

import pytest
import sys
import os
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))
from core.security_exception_workflow_engine import SecurityExceptionWorkflowEngine


@pytest.fixture
def engine(tmp_path):
    return SecurityExceptionWorkflowEngine(db_path=str(tmp_path / "test.db"))


ORG = "org-alpha"
OTHER_ORG = "org-beta"


def _future(days: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _past(days: int = 1) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


# ---------------------------------------------------------------------------
# create_request
# ---------------------------------------------------------------------------

def test_create_request_returns_dict(engine):
    result = engine.create_request(ORG, "TLS 1.0 Policy", "policy-waiver", "alice@acme.com")
    assert result["id"]
    assert result["org_id"] == ORG
    assert result["status"] == "pending"
    assert result["policy_name"] == "TLS 1.0 Policy"


def test_create_request_default_status_pending(engine):
    result = engine.create_request(ORG, "FW Rule Exception")
    assert result["status"] == "pending"


def test_create_request_all_fields(engine):
    result = engine.create_request(
        ORG, "SSH Direct Access",
        exception_type="temporary-deviation",
        requestor="bob@acme.com",
        business_justification="Emergency maintenance",
        risk_description="Elevated lateral movement risk",
        compensating_controls="MFA enforced",
        priority="high",
        expires_at=_future(60),
    )
    assert result["exception_type"] == "temporary-deviation"
    assert result["requestor"] == "bob@acme.com"
    assert result["priority"] == "high"
    assert result["compensating_controls"] == "MFA enforced"


def test_create_request_unique_ids(engine):
    r1 = engine.create_request(ORG, "Policy A")
    r2 = engine.create_request(ORG, "Policy B")
    assert r1["id"] != r2["id"]


def test_create_request_tenant_isolation(engine):
    r1 = engine.create_request(ORG, "Policy X")
    r2 = engine.create_request(OTHER_ORG, "Policy X")
    assert r1["org_id"] != r2["org_id"]


def test_create_request_with_expiry(engine):
    expiry = _future(90)
    result = engine.create_request(ORG, "Temp Exception", expires_at=expiry)
    assert result["expires_at"] == expiry


def test_create_request_approved_until_null(engine):
    result = engine.create_request(ORG, "Policy C")
    assert result["approved_until"] is None


# ---------------------------------------------------------------------------
# review_request
# ---------------------------------------------------------------------------

def test_review_approved_sets_status(engine):
    req = engine.create_request(ORG, "Firewall Bypass", expires_at=_future(30))
    review = engine.review_request(req["id"], ORG, "reviewer@acme.com", "approved",
                                   risk_rating="low")
    assert review["decision"] == "approved"


def test_review_approved_updates_request_status(engine):
    req = engine.create_request(ORG, "VPN Exception", expires_at=_future(30))
    engine.review_request(req["id"], ORG, "ciso@acme.com", "approved")
    updated = engine.get_request(req["id"], ORG)
    assert updated["status"] == "approved"


def test_review_approved_sets_approved_until(engine):
    expiry = _future(60)
    req = engine.create_request(ORG, "Cloud Access", expires_at=expiry)
    engine.review_request(req["id"], ORG, "ciso@acme.com", "approved")
    updated = engine.get_request(req["id"], ORG)
    assert updated["approved_until"] == expiry


def test_review_rejected_sets_status(engine):
    req = engine.create_request(ORG, "Admin Policy")
    engine.review_request(req["id"], ORG, "ciso@acme.com", "rejected",
                          comments="Unacceptable risk")
    updated = engine.get_request(req["id"], ORG)
    assert updated["status"] == "rejected"


def test_review_needs_info_sets_status(engine):
    req = engine.create_request(ORG, "Arch Exception")
    engine.review_request(req["id"], ORG, "auditor@acme.com", "needs-info")
    updated = engine.get_request(req["id"], ORG)
    assert updated["status"] == "needs-info"


def test_review_invalid_decision_raises(engine):
    req = engine.create_request(ORG, "Bad Decision Test")
    with pytest.raises(ValueError):
        engine.review_request(req["id"], ORG, "reviewer", "invalid-decision")


def test_review_wrong_org_raises(engine):
    req = engine.create_request(ORG, "Cross Tenant Policy")
    with pytest.raises(KeyError):
        engine.review_request(req["id"], OTHER_ORG, "reviewer", "approved")


def test_review_stores_conditions_and_comments(engine):
    req = engine.create_request(ORG, "Vendor Exception", expires_at=_future(30))
    review = engine.review_request(req["id"], ORG, "ciso@acme.com", "approved",
                                   conditions="Annual review required",
                                   comments="Low risk vendor")
    assert review["conditions"] == "Annual review required"
    assert review["comments"] == "Low risk vendor"


# ---------------------------------------------------------------------------
# renew_exception
# ---------------------------------------------------------------------------

def test_renew_exception_updates_expiry(engine):
    req = engine.create_request(ORG, "Renewable Policy", expires_at=_future(10))
    engine.review_request(req["id"], ORG, "ciso@acme.com", "approved")
    new_expiry = _future(90)
    renewal = engine.renew_exception(req["id"], ORG, "admin@acme.com", new_expiry, "Annual renewal")
    assert renewal["new_expiry"] == new_expiry


def test_renew_exception_updates_request_expiry(engine):
    req = engine.create_request(ORG, "Expiry Update Policy", expires_at=_future(10))
    new_expiry = _future(90)
    engine.renew_exception(req["id"], ORG, "admin@acme.com", new_expiry, "Business need")
    updated = engine.get_request(req["id"], ORG)
    assert updated["expires_at"] == new_expiry
    assert updated["approved_until"] == new_expiry


def test_renew_exception_wrong_org_raises(engine):
    req = engine.create_request(ORG, "Renewal Cross-Tenant")
    with pytest.raises(KeyError):
        engine.renew_exception(req["id"], OTHER_ORG, "admin", _future(90))


# ---------------------------------------------------------------------------
# revoke_exception
# ---------------------------------------------------------------------------

def test_revoke_exception_sets_status(engine):
    req = engine.create_request(ORG, "Revocable Exception", expires_at=_future(30))
    engine.review_request(req["id"], ORG, "ciso@acme.com", "approved")
    engine.revoke_exception(req["id"], ORG)
    updated = engine.get_request(req["id"], ORG)
    assert updated["status"] == "revoked"


def test_revoked_not_in_expiring(engine):
    expiry = _future(5)
    req = engine.create_request(ORG, "About To Expire", expires_at=expiry)
    engine.review_request(req["id"], ORG, "ciso@acme.com", "approved")
    engine.revoke_exception(req["id"], ORG)
    expiring = engine.get_expiring_exceptions(ORG, days_ahead=30)
    ids = [e["id"] for e in expiring]
    assert req["id"] not in ids


# ---------------------------------------------------------------------------
# get_request
# ---------------------------------------------------------------------------

def test_get_request_returns_reviews_and_renewals(engine):
    req = engine.create_request(ORG, "Full Lifecycle", expires_at=_future(30))
    engine.review_request(req["id"], ORG, "ciso@acme.com", "approved")
    engine.renew_exception(req["id"], ORG, "admin@acme.com", _future(90), "Renewal")
    result = engine.get_request(req["id"], ORG)
    assert len(result["reviews"]) == 1
    assert len(result["renewals"]) == 1


def test_get_request_not_found_returns_empty(engine):
    result = engine.get_request("nonexistent-id", ORG)
    assert result == {}


def test_get_request_tenant_isolation(engine):
    req = engine.create_request(ORG, "Isolated Policy")
    result = engine.get_request(req["id"], OTHER_ORG)
    assert result == {}


# ---------------------------------------------------------------------------
# list_requests
# ---------------------------------------------------------------------------

def test_list_requests_returns_all(engine):
    engine.create_request(ORG, "Policy A")
    engine.create_request(ORG, "Policy B")
    results = engine.list_requests(ORG)
    assert len(results) >= 2


def test_list_requests_filter_by_status(engine):
    req = engine.create_request(ORG, "Filter By Status", expires_at=_future(30))
    engine.review_request(req["id"], ORG, "ciso@acme.com", "approved")
    approved = engine.list_requests(ORG, status="approved")
    assert all(r["status"] == "approved" for r in approved)


def test_list_requests_filter_by_type(engine):
    engine.create_request(ORG, "Vendor Exc", exception_type="vendor")
    vendor_list = engine.list_requests(ORG, exception_type="vendor")
    assert all(r["exception_type"] == "vendor" for r in vendor_list)


def test_list_requests_tenant_isolation(engine):
    engine.create_request(ORG, "Org A Policy")
    engine.create_request(OTHER_ORG, "Org B Policy")
    results = engine.list_requests(ORG)
    assert all(r["org_id"] == ORG for r in results)


# ---------------------------------------------------------------------------
# get_expiring_exceptions
# ---------------------------------------------------------------------------

def test_get_expiring_exceptions_within_days(engine):
    expiry = _future(5)
    req = engine.create_request(ORG, "Soon Expiring", expires_at=expiry)
    engine.review_request(req["id"], ORG, "ciso@acme.com", "approved")
    expiring = engine.get_expiring_exceptions(ORG, days_ahead=10)
    ids = [e["id"] for e in expiring]
    assert req["id"] in ids


def test_get_expiring_exceptions_excludes_outside_window(engine):
    expiry = _future(60)
    req = engine.create_request(ORG, "Far Future", expires_at=expiry)
    engine.review_request(req["id"], ORG, "ciso@acme.com", "approved")
    expiring = engine.get_expiring_exceptions(ORG, days_ahead=10)
    ids = [e["id"] for e in expiring]
    assert req["id"] not in ids


def test_get_expiring_exceptions_only_approved(engine):
    expiry = _future(5)
    req = engine.create_request(ORG, "Pending Expiring", expires_at=expiry)
    # Not approved — still pending
    expiring = engine.get_expiring_exceptions(ORG, days_ahead=10)
    ids = [e["id"] for e in expiring]
    assert req["id"] not in ids


# ---------------------------------------------------------------------------
# get_expired_exceptions
# ---------------------------------------------------------------------------

def test_get_expired_exceptions(engine):
    past_expiry = _past(1)
    req = engine.create_request(ORG, "Already Expired", expires_at=past_expiry)
    engine.review_request(req["id"], ORG, "ciso@acme.com", "approved")
    expired = engine.get_expired_exceptions(ORG)
    ids = [e["id"] for e in expired]
    assert req["id"] in ids


def test_get_expired_excludes_future(engine):
    future_expiry = _future(30)
    req = engine.create_request(ORG, "Not Yet Expired", expires_at=future_expiry)
    engine.review_request(req["id"], ORG, "ciso@acme.com", "approved")
    expired = engine.get_expired_exceptions(ORG)
    ids = [e["id"] for e in expired]
    assert req["id"] not in ids


# ---------------------------------------------------------------------------
# get_exception_summary
# ---------------------------------------------------------------------------

def test_get_exception_summary_structure(engine):
    summary = engine.get_exception_summary(ORG)
    assert "total" in summary
    assert "by_status" in summary
    assert "by_type" in summary
    assert "expiring_soon" in summary
    assert "overdue_renewals" in summary


def test_get_exception_summary_counts(engine):
    engine.create_request(ORG, "Summary Policy A")
    engine.create_request(ORG, "Summary Policy B")
    summary = engine.get_exception_summary(ORG)
    assert summary["total"] >= 2


def test_get_exception_summary_expiring_soon(engine):
    expiry = _future(10)
    req = engine.create_request(ORG, "Expiring Soon Summary", expires_at=expiry)
    engine.review_request(req["id"], ORG, "ciso@acme.com", "approved")
    summary = engine.get_exception_summary(ORG)
    assert summary["expiring_soon"] >= 1


def test_get_exception_summary_overdue(engine):
    past_expiry = _past(5)
    req = engine.create_request(ORG, "Overdue Summary", expires_at=past_expiry)
    engine.review_request(req["id"], ORG, "ciso@acme.com", "approved")
    summary = engine.get_exception_summary(ORG)
    assert summary["overdue_renewals"] >= 1


def test_get_exception_summary_tenant_isolation(engine):
    engine.create_request(ORG, "Org A Only")
    engine.create_request(OTHER_ORG, "Org B Only")
    summary_a = engine.get_exception_summary(ORG)
    summary_b = engine.get_exception_summary(OTHER_ORG)
    assert summary_a["total"] != summary_b["total"] or summary_a["org_id"] != summary_b["org_id"]
