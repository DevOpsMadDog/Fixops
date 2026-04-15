"""Tests for SecurityExceptionEngine — 25+ tests."""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone
from core.security_exception_engine import SecurityExceptionEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_exceptions.db")
    return SecurityExceptionEngine(db_path=db)


ORG = "org-alpha"
OTHER_ORG = "org-beta"


def _future(days: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _past(days: int = 1) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


# ---------------------------------------------------------------------------
# request_exception
# ---------------------------------------------------------------------------

def test_request_exception_returns_dict(engine):
    result = engine.request_exception(ORG, {
        "title": "Allow CVE-2024-1234",
        "exception_type": "vulnerability",
        "risk_level": "high",
        "requestor": "dev@example.com",
    })
    assert result["exception_id"]
    assert result["org_id"] == ORG
    assert result["status"] == "pending"
    assert result["title"] == "Allow CVE-2024-1234"


def test_request_exception_defaults(engine):
    result = engine.request_exception(ORG, {"title": "Basic Exception"})
    assert result["exception_type"] == "vulnerability"
    assert result["risk_level"] == "medium"
    assert result["status"] == "pending"


def test_request_exception_with_expiry(engine):
    expiry = _future(90)
    result = engine.request_exception(ORG, {
        "title": "Expiring Exception",
        "expires_at": expiry,
    })
    assert result["expires_at"] == expiry


def test_request_exception_has_timestamps(engine):
    result = engine.request_exception(ORG, {"title": "Timestamped"})
    assert result["requested_at"]
    assert result["approved_at"] is None


# ---------------------------------------------------------------------------
# list_exceptions
# ---------------------------------------------------------------------------

def test_list_exceptions_empty(engine):
    assert engine.list_exceptions(ORG) == []


def test_list_exceptions_returns_all(engine):
    engine.request_exception(ORG, {"title": "E1"})
    engine.request_exception(ORG, {"title": "E2"})
    engine.request_exception(ORG, {"title": "E3"})
    assert len(engine.list_exceptions(ORG)) == 3


def test_list_exceptions_org_isolation(engine):
    engine.request_exception(ORG, {"title": "OrgExc"})
    engine.request_exception(OTHER_ORG, {"title": "OtherExc"})
    assert len(engine.list_exceptions(ORG)) == 1
    assert len(engine.list_exceptions(OTHER_ORG)) == 1


def test_list_exceptions_filter_status(engine):
    engine.request_exception(ORG, {"title": "Pending One"})
    exc = engine.request_exception(ORG, {"title": "To Approve"})
    engine.review_exception(ORG, exc["exception_id"], "approve", "admin")
    pending = engine.list_exceptions(ORG, status="pending")
    approved = engine.list_exceptions(ORG, status="approved")
    assert len(pending) == 1
    assert len(approved) == 1


def test_list_exceptions_filter_risk_level(engine):
    engine.request_exception(ORG, {"title": "Critical Exc", "risk_level": "critical"})
    engine.request_exception(ORG, {"title": "Low Exc", "risk_level": "low"})
    critical = engine.list_exceptions(ORG, risk_level="critical")
    assert len(critical) == 1
    assert critical[0]["risk_level"] == "critical"


# ---------------------------------------------------------------------------
# get_exception
# ---------------------------------------------------------------------------

def test_get_exception_returns_record(engine):
    created = engine.request_exception(ORG, {"title": "GetMe"})
    fetched = engine.get_exception(ORG, created["exception_id"])
    assert fetched is not None
    assert fetched["exception_id"] == created["exception_id"]


def test_get_exception_not_found(engine):
    assert engine.get_exception(ORG, "nonexistent") is None


def test_get_exception_org_isolation(engine):
    exc = engine.request_exception(ORG, {"title": "IsolationTest"})
    assert engine.get_exception(OTHER_ORG, exc["exception_id"]) is None


# ---------------------------------------------------------------------------
# review_exception
# ---------------------------------------------------------------------------

def test_review_approve(engine):
    exc = engine.request_exception(ORG, {"title": "ApproveMe"})
    result = engine.review_exception(ORG, exc["exception_id"], "approve", "ciso@corp.com")
    assert result["status"] == "approved"
    assert result["approved_at"] is not None
    assert result["approver"] == "ciso@corp.com"


def test_review_reject(engine):
    exc = engine.request_exception(ORG, {"title": "RejectMe"})
    result = engine.review_exception(ORG, exc["exception_id"], "reject", "ciso@corp.com", notes="Too risky")
    assert result["status"] == "rejected"


def test_review_extend(engine):
    exc = engine.request_exception(ORG, {
        "title": "ExtendMe",
        "expires_at": _future(10),
    })
    engine.review_exception(ORG, exc["exception_id"], "approve", "admin")
    new_expiry = _future(60)
    result = engine.review_exception(
        ORG, exc["exception_id"], "extend", "admin",
        new_expiry=new_expiry,
    )
    assert result["expires_at"] == new_expiry


def test_review_request_info(engine):
    exc = engine.request_exception(ORG, {"title": "InfoNeeded"})
    result = engine.review_exception(
        ORG, exc["exception_id"], "request_info", "reviewer",
        notes="Need more justification",
    )
    assert result["exception_id"] == exc["exception_id"]
    # status unchanged (still pending)
    assert result["status"] == "pending"


def test_review_sets_reviewed_at(engine):
    exc = engine.request_exception(ORG, {"title": "ReviewedAt"})
    result = engine.review_exception(ORG, exc["exception_id"], "approve", "admin")
    assert result["reviewed_at"] is not None


# ---------------------------------------------------------------------------
# add_asset / list_assets
# ---------------------------------------------------------------------------

def test_add_asset(engine):
    exc = engine.request_exception(ORG, {"title": "AssetTest"})
    asset = engine.add_asset(ORG, exc["exception_id"], {
        "asset_name": "prod-server-01",
        "asset_type": "server",
    })
    assert asset["asset_id"]
    assert asset["asset_name"] == "prod-server-01"
    assert asset["asset_type"] == "server"


def test_list_assets(engine):
    exc = engine.request_exception(ORG, {"title": "ListAssets"})
    engine.add_asset(ORG, exc["exception_id"], {"asset_name": "asset-A", "asset_type": "container"})
    engine.add_asset(ORG, exc["exception_id"], {"asset_name": "asset-B", "asset_type": "vm"})
    assets = engine.list_assets(ORG, exc["exception_id"])
    assert len(assets) == 2


def test_list_assets_empty(engine):
    exc = engine.request_exception(ORG, {"title": "EmptyAssets"})
    assert engine.list_assets(ORG, exc["exception_id"]) == []


# ---------------------------------------------------------------------------
# check_expiring
# ---------------------------------------------------------------------------

def test_check_expiring_returns_expiring(engine):
    exc = engine.request_exception(ORG, {
        "title": "Expiring Soon",
        "expires_at": _future(3),
    })
    engine.review_exception(ORG, exc["exception_id"], "approve", "admin")
    expiring = engine.check_expiring(ORG, days_ahead=7)
    assert len(expiring) == 1
    assert expiring[0]["exception_id"] == exc["exception_id"]


def test_check_expiring_excludes_far_future(engine):
    exc = engine.request_exception(ORG, {
        "title": "Far Future",
        "expires_at": _future(60),
    })
    engine.review_exception(ORG, exc["exception_id"], "approve", "admin")
    expiring = engine.check_expiring(ORG, days_ahead=7)
    assert len(expiring) == 0


def test_check_expiring_excludes_pending(engine):
    # pending exceptions should not appear even if expiry is near
    engine.request_exception(ORG, {
        "title": "Pending Expiring",
        "expires_at": _future(2),
    })
    expiring = engine.check_expiring(ORG, days_ahead=7)
    assert len(expiring) == 0


# ---------------------------------------------------------------------------
# revoke_exception
# ---------------------------------------------------------------------------

def test_revoke_exception(engine):
    exc = engine.request_exception(ORG, {"title": "RevokeMe"})
    engine.review_exception(ORG, exc["exception_id"], "approve", "admin")
    ok = engine.revoke_exception(ORG, exc["exception_id"], revoker="security@corp.com", reason="Breach detected")
    assert ok is True
    fetched = engine.get_exception(ORG, exc["exception_id"])
    assert fetched["status"] == "revoked"


def test_revoke_exception_not_found(engine):
    ok = engine.revoke_exception(ORG, "nonexistent", revoker="admin")
    assert ok is False


# ---------------------------------------------------------------------------
# get_exception_stats
# ---------------------------------------------------------------------------

def test_stats_empty(engine):
    stats = engine.get_exception_stats(ORG)
    assert stats["total_exceptions"] == 0
    assert stats["pending"] == 0
    assert stats["approved"] == 0
    assert stats["expired"] == 0
    assert stats["expiring_soon"] == 0
    assert stats["avg_approval_days"] == 0.0
    assert isinstance(stats["by_type"], dict)
    assert isinstance(stats["by_risk"], dict)


def test_stats_with_data(engine):
    e1 = engine.request_exception(ORG, {
        "title": "Vuln Exc",
        "exception_type": "vulnerability",
        "risk_level": "high",
        "expires_at": _future(5),
    })
    e2 = engine.request_exception(ORG, {
        "title": "Policy Exc",
        "exception_type": "policy",
        "risk_level": "medium",
    })
    engine.review_exception(ORG, e1["exception_id"], "approve", "admin")
    # e2 stays pending

    stats = engine.get_exception_stats(ORG)
    assert stats["total_exceptions"] == 2
    assert stats["pending"] == 1
    assert stats["approved"] == 1
    assert stats["by_type"]["vulnerability"] == 1
    assert stats["by_type"]["policy"] == 1
    assert stats["by_risk"]["high"] == 1
    assert stats["by_risk"]["medium"] == 1
    assert stats["expiring_soon"] == 1  # e1 expires in 5 days
    assert stats["avg_approval_days"] >= 0.0


def test_stats_org_isolation(engine):
    engine.request_exception(ORG, {"title": "Org Exc"})
    engine.request_exception(OTHER_ORG, {"title": "Other Org Exc"})
    stats_org = engine.get_exception_stats(ORG)
    stats_other = engine.get_exception_stats(OTHER_ORG)
    assert stats_org["total_exceptions"] == 1
    assert stats_other["total_exceptions"] == 1
