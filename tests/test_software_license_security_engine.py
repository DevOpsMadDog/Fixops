"""Tests for SoftwareLicenseSecurityEngine — 35 tests.

Covers:
- add_license_record: valid types, invalid type raises ValueError
- list_license_records with filters
- get_license_record: found, not found, wrong org
- approve_license: toggles approved, raises KeyError if not found
- record_violation: valid types/severities, invalid raises ValueError
- resolve_violation lifecycle (waived/remediated)
- resolve_violation with wrong org raises KeyError
- list_violations with filters
- create_policy and list_policies
- get_license_stats counts
- Org isolation
"""

import sys
sys.path.insert(0, "suite-core")

import pytest

from core.software_license_security_engine import SoftwareLicenseSecurityEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return SoftwareLicenseSecurityEngine(db_path=str(tmp_path / "license.db"))


# ---------------------------------------------------------------------------
# 1. add_license_record — basics
# ---------------------------------------------------------------------------

def test_add_license_record_returns_dict(engine):
    rec = engine.add_license_record("org1", {
        "package_name": "requests",
        "package_version": "2.31.0",
        "license_type": "Apache-2.0",
        "license_risk": "low",
    })
    assert isinstance(rec, dict)
    assert "id" in rec
    assert rec["org_id"] == "org1"
    assert rec["package_name"] == "requests"
    assert rec["license_type"] == "Apache-2.0"


def test_add_license_record_requires_package_name(engine):
    with pytest.raises(ValueError, match="package_name"):
        engine.add_license_record("org1", {"license_type": "MIT"})


def test_add_license_record_defaults_license_type_unknown(engine):
    rec = engine.add_license_record("org1", {"package_name": "mypkg"})
    assert rec["license_type"] == "unknown"


def test_add_license_record_defaults_license_risk_low(engine):
    rec = engine.add_license_record("org1", {"package_name": "mypkg"})
    assert rec["license_risk"] == "low"


def test_add_license_record_defaults_is_oss_true(engine):
    rec = engine.add_license_record("org1", {"package_name": "mypkg"})
    assert rec["is_oss"] is True


def test_add_license_record_defaults_approved_false(engine):
    rec = engine.add_license_record("org1", {"package_name": "mypkg"})
    assert rec["approved"] is False


# ---------------------------------------------------------------------------
# 2. Valid license_types (all 9)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("lt", [
    "MIT", "Apache-2.0", "GPL-2.0", "GPL-3.0", "LGPL",
    "BSD-2-Clause", "BSD-3-Clause", "proprietary", "unknown",
])
def test_add_license_record_all_valid_types(engine, lt):
    rec = engine.add_license_record("org1", {"package_name": f"pkg-{lt}", "license_type": lt})
    assert rec["license_type"] == lt


def test_add_license_record_invalid_type_raises(engine):
    with pytest.raises(ValueError):
        engine.add_license_record("org1", {
            "package_name": "bad-pkg",
            "license_type": "NONEXISTENT-LICENSE",
        })


# ---------------------------------------------------------------------------
# 3. list_license_records with filters
# ---------------------------------------------------------------------------

def test_list_license_records_returns_created(engine):
    engine.add_license_record("org2", {"package_name": "a", "license_type": "MIT"})
    engine.add_license_record("org2", {"package_name": "b", "license_type": "GPL-2.0"})
    recs = engine.list_license_records("org2")
    assert len(recs) == 2


def test_list_license_records_filter_by_type(engine):
    engine.add_license_record("org3", {"package_name": "a", "license_type": "MIT"})
    engine.add_license_record("org3", {"package_name": "b", "license_type": "GPL-3.0"})
    mit_recs = engine.list_license_records("org3", license_type="MIT")
    assert len(mit_recs) == 1
    assert mit_recs[0]["license_type"] == "MIT"


def test_list_license_records_filter_by_risk(engine):
    engine.add_license_record("org4", {"package_name": "a", "license_risk": "critical"})
    engine.add_license_record("org4", {"package_name": "b", "license_risk": "low"})
    critical = engine.list_license_records("org4", license_risk="critical")
    assert len(critical) == 1
    assert critical[0]["license_risk"] == "critical"


def test_list_license_records_filter_approved(engine):
    engine.add_license_record("org5", {"package_name": "a"})
    rec = engine.add_license_record("org5", {"package_name": "b"})
    engine.approve_license("org5", rec["id"])
    approved = engine.list_license_records("org5", approved=True)
    assert len(approved) == 1
    assert approved[0]["approved"] is True


# ---------------------------------------------------------------------------
# 4. get_license_record
# ---------------------------------------------------------------------------

def test_get_license_record_found(engine):
    rec = engine.add_license_record("org6", {"package_name": "mypkg"})
    found = engine.get_license_record("org6", rec["id"])
    assert found is not None
    assert found["id"] == rec["id"]


def test_get_license_record_not_found_returns_none(engine):
    assert engine.get_license_record("org6", "nonexistent-id") is None


def test_get_license_record_wrong_org_returns_none(engine):
    rec = engine.add_license_record("org7", {"package_name": "mypkg"})
    assert engine.get_license_record("other-org", rec["id"]) is None


# ---------------------------------------------------------------------------
# 5. approve_license
# ---------------------------------------------------------------------------

def test_approve_license_sets_approved_true(engine):
    rec = engine.add_license_record("org8", {"package_name": "mypkg"})
    assert rec["approved"] is False
    updated = engine.approve_license("org8", rec["id"])
    assert updated["approved"] is True


def test_approve_license_not_found_raises_key_error(engine):
    with pytest.raises(KeyError):
        engine.approve_license("org8", "nonexistent-id")


def test_approve_license_wrong_org_raises_key_error(engine):
    rec = engine.add_license_record("org9", {"package_name": "mypkg"})
    with pytest.raises(KeyError):
        engine.approve_license("other-org", rec["id"])


# ---------------------------------------------------------------------------
# 6. record_violation
# ---------------------------------------------------------------------------

def test_record_violation_returns_dict(engine):
    rec = engine.add_license_record("org10", {"package_name": "gpl-pkg", "license_type": "GPL-2.0"})
    viol = engine.record_violation("org10", {
        "record_id": rec["id"],
        "violation_type": "copyleft_conflict",
        "severity": "high",
        "description": "Copyleft conflicts with proprietary code",
    })
    assert isinstance(viol, dict)
    assert "id" in viol
    assert viol["status"] == "open"
    assert viol["severity"] == "high"


def test_record_violation_invalid_type_raises(engine):
    rec = engine.add_license_record("org10", {"package_name": "pkg"})
    with pytest.raises(ValueError):
        engine.record_violation("org10", {
            "record_id": rec["id"],
            "violation_type": "INVALID_TYPE",
        })


def test_record_violation_invalid_severity_raises(engine):
    rec = engine.add_license_record("org10", {"package_name": "pkg"})
    with pytest.raises(ValueError):
        engine.record_violation("org10", {
            "record_id": rec["id"],
            "severity": "SUPER_CRITICAL",
        })


def test_record_violation_nonexistent_record_raises(engine):
    with pytest.raises(ValueError):
        engine.record_violation("org10", {
            "record_id": "nonexistent-id",
        })


def test_record_violation_wrong_org_raises(engine):
    rec = engine.add_license_record("org11", {"package_name": "pkg"})
    with pytest.raises(ValueError):
        engine.record_violation("other-org", {"record_id": rec["id"]})


# ---------------------------------------------------------------------------
# 7. resolve_violation lifecycle
# ---------------------------------------------------------------------------

def test_resolve_violation_waived(engine):
    rec = engine.add_license_record("org12", {"package_name": "pkg"})
    viol = engine.record_violation("org12", {"record_id": rec["id"]})
    resolved = engine.resolve_violation("org12", viol["id"], "waived")
    assert resolved["status"] == "waived"
    assert resolved["resolved_at"] is not None


def test_resolve_violation_remediated(engine):
    rec = engine.add_license_record("org12", {"package_name": "pkg2"})
    viol = engine.record_violation("org12", {"record_id": rec["id"]})
    resolved = engine.resolve_violation("org12", viol["id"], "remediated")
    assert resolved["status"] == "remediated"


def test_resolve_violation_wrong_org_raises_key_error(engine):
    rec = engine.add_license_record("org13", {"package_name": "pkg"})
    viol = engine.record_violation("org13", {"record_id": rec["id"]})
    with pytest.raises(KeyError):
        engine.resolve_violation("other-org", viol["id"], "waived")


def test_resolve_violation_not_found_raises_key_error(engine):
    with pytest.raises(KeyError):
        engine.resolve_violation("org13", "nonexistent-id", "waived")


# ---------------------------------------------------------------------------
# 8. list_violations with filters
# ---------------------------------------------------------------------------

def test_list_violations_by_severity(engine):
    rec = engine.add_license_record("org14", {"package_name": "pkg"})
    engine.record_violation("org14", {"record_id": rec["id"], "severity": "critical"})
    engine.record_violation("org14", {"record_id": rec["id"], "severity": "low"})
    critical = engine.list_violations("org14", severity="critical")
    assert len(critical) == 1
    assert critical[0]["severity"] == "critical"


def test_list_violations_by_status(engine):
    rec = engine.add_license_record("org15", {"package_name": "pkg"})
    viol = engine.record_violation("org15", {"record_id": rec["id"]})
    engine.record_violation("org15", {"record_id": rec["id"]})
    engine.resolve_violation("org15", viol["id"], "waived")
    open_viols = engine.list_violations("org15", status="open")
    assert len(open_viols) == 1


# ---------------------------------------------------------------------------
# 9. create_policy and list_policies
# ---------------------------------------------------------------------------

def test_create_policy_returns_dict(engine):
    pol = engine.create_policy("org16", {
        "policy_name": "No Copyleft",
        "allowed_licenses": ["MIT", "Apache-2.0"],
        "blocked_licenses": ["GPL-2.0", "GPL-3.0"],
        "require_approval": True,
    })
    assert isinstance(pol, dict)
    assert pol["policy_name"] == "No Copyleft"
    assert "MIT" in pol["allowed_licenses"]
    assert "GPL-2.0" in pol["blocked_licenses"]
    assert pol["require_approval"] is True


def test_create_policy_requires_name(engine):
    with pytest.raises(ValueError, match="policy_name"):
        engine.create_policy("org16", {"allowed_licenses": ["MIT"]})


def test_list_policies_returns_created(engine):
    engine.create_policy("org17", {"policy_name": "Policy A"})
    engine.create_policy("org17", {"policy_name": "Policy B"})
    policies = engine.list_policies("org17")
    assert len(policies) == 2
    names = [p["policy_name"] for p in policies]
    assert "Policy A" in names and "Policy B" in names


def test_create_policy_defaults_empty_lists(engine):
    pol = engine.create_policy("org17", {"policy_name": "Default Policy"})
    assert pol["allowed_licenses"] == []
    assert pol["blocked_licenses"] == []


# ---------------------------------------------------------------------------
# 10. get_license_stats
# ---------------------------------------------------------------------------

def test_get_license_stats_returns_dict(engine):
    stats = engine.get_license_stats("orgX")
    assert isinstance(stats, dict)
    assert "total_packages" in stats
    assert "by_license_type" in stats
    assert "by_risk" in stats
    assert "unapproved_count" in stats
    assert "open_violations" in stats
    assert "critical_violations" in stats
    assert "oss_packages" in stats


def test_get_license_stats_counts(engine):
    engine.add_license_record("orgS", {"package_name": "a", "license_type": "MIT", "is_oss": True})
    engine.add_license_record("orgS", {"package_name": "b", "license_type": "GPL-3.0", "license_risk": "high", "is_oss": True})
    rec_c = engine.add_license_record("orgS", {"package_name": "c", "license_type": "proprietary", "is_oss": False})
    engine.approve_license("orgS", rec_c["id"])
    stats = engine.get_license_stats("orgS")
    assert stats["total_packages"] == 3
    assert stats["oss_packages"] == 2
    assert stats["unapproved_count"] == 2
    assert stats["by_license_type"]["MIT"] == 1
    assert stats["by_license_type"]["GPL-3.0"] == 1


def test_get_license_stats_violations(engine):
    rec = engine.add_license_record("orgV", {"package_name": "pkg", "license_type": "GPL-2.0"})
    engine.record_violation("orgV", {"record_id": rec["id"], "severity": "critical"})
    engine.record_violation("orgV", {"record_id": rec["id"], "severity": "low"})
    stats = engine.get_license_stats("orgV")
    assert stats["open_violations"] == 2
    assert stats["critical_violations"] == 1


# ---------------------------------------------------------------------------
# 11. Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_records(engine):
    engine.add_license_record("orgA", {"package_name": "a"})
    engine.add_license_record("orgB", {"package_name": "b"})
    assert len(engine.list_license_records("orgA")) == 1
    assert len(engine.list_license_records("orgB")) == 1


def test_org_isolation_violations(engine):
    rec_a = engine.add_license_record("orgA", {"package_name": "a"})
    rec_b = engine.add_license_record("orgB", {"package_name": "b"})
    engine.record_violation("orgA", {"record_id": rec_a["id"]})
    engine.record_violation("orgB", {"record_id": rec_b["id"]})
    assert len(engine.list_violations("orgA")) == 1
    assert len(engine.list_violations("orgB")) == 1


def test_org_isolation_policies(engine):
    engine.create_policy("orgA", {"policy_name": "A Policy"})
    engine.create_policy("orgB", {"policy_name": "B Policy"})
    a_pols = engine.list_policies("orgA")
    b_pols = engine.list_policies("orgB")
    assert len(a_pols) == 1 and a_pols[0]["policy_name"] == "A Policy"
    assert len(b_pols) == 1 and b_pols[0]["policy_name"] == "B Policy"
