"""Tests for EndpointComplianceEngine — CIS benchmark compliance for endpoints.

Coverage:
  - Endpoint CRUD
  - Check recording + weighted score computation
  - Bulk check recording
  - Compliance level thresholds (compliant/partial/non_compliant)
  - Exception management
  - Baseline CRUD
  - Stats aggregation
  - Department compliance rates
  - Org isolation
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def engine(tmp_path):
    from core.endpoint_compliance_engine import EndpointComplianceEngine
    db = str(tmp_path / "test_endpoint_compliance.db")
    return EndpointComplianceEngine(db_path=db)


ORG = "org_ep_test"
ORG2 = "org_ep_other"


# ---------------------------------------------------------------------------
# Endpoint registration
# ---------------------------------------------------------------------------

def test_register_endpoint_basic(engine):
    ep = engine.register_endpoint(ORG, {
        "hostname": "win-srv-01",
        "os_type": "windows",
        "os_version": "10.0.19044",
        "department": "IT",
        "owner_id": "user-abc",
    })
    assert ep["id"]
    assert ep["hostname"] == "win-srv-01"
    assert ep["os_type"] == "windows"
    assert ep["compliance_score"] == 0.0
    assert ep["compliance_level"] == "non_compliant"


def test_register_endpoint_requires_hostname(engine):
    with pytest.raises(ValueError, match="hostname is required"):
        engine.register_endpoint(ORG, {"os_type": "linux"})


def test_register_endpoint_invalid_os_type(engine):
    with pytest.raises(ValueError, match="Invalid os_type"):
        engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "bsd"})


def test_register_endpoint_all_os_types(engine):
    for os_type in ("windows", "linux", "macos", "android", "ios"):
        ep = engine.register_endpoint(ORG, {"hostname": f"host-{os_type}", "os_type": os_type})
        assert ep["os_type"] == os_type


# ---------------------------------------------------------------------------
# List / Get endpoints
# ---------------------------------------------------------------------------

def test_list_endpoints_empty(engine):
    assert engine.list_endpoints(ORG) == []


def test_list_endpoints_returns_created(engine):
    engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux"})
    engine.register_endpoint(ORG, {"hostname": "h2", "os_type": "windows"})
    assert len(engine.list_endpoints(ORG)) == 2


def test_list_endpoints_filter_os_type(engine):
    engine.register_endpoint(ORG, {"hostname": "lin1", "os_type": "linux"})
    engine.register_endpoint(ORG, {"hostname": "win1", "os_type": "windows"})
    linux_eps = engine.list_endpoints(ORG, os_type="linux")
    assert len(linux_eps) == 1
    assert linux_eps[0]["os_type"] == "linux"


def test_list_endpoints_filter_department(engine):
    engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux", "department": "IT"})
    engine.register_endpoint(ORG, {"hostname": "h2", "os_type": "linux", "department": "HR"})
    it_eps = engine.list_endpoints(ORG, department="IT")
    assert len(it_eps) == 1
    assert it_eps[0]["department"] == "IT"


def test_get_endpoint_not_found(engine):
    assert engine.get_endpoint(ORG, "nonexistent") is None


def test_get_endpoint_includes_check_summary(engine):
    ep = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux"})
    engine.record_check(ORG, ep["id"], {
        "check_id": "1.1.1", "status": "passed", "severity": "high",
        "benchmark": "cis_ubuntu", "category": "local_policy",
    })
    result = engine.get_endpoint(ORG, ep["id"])
    assert "check_summary" in result
    assert result["compliance_score"] > 0


# ---------------------------------------------------------------------------
# Check recording + score computation
# ---------------------------------------------------------------------------

def test_record_check_basic(engine):
    ep = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux"})
    chk = engine.record_check(ORG, ep["id"], {
        "check_id": "1.1.1",
        "check_name": "Ensure passwd is not empty",
        "benchmark": "cis_ubuntu",
        "category": "account_policy",
        "severity": "critical",
        "status": "passed",
        "actual_value": "0644",
        "expected_value": "0644",
    })
    assert chk["id"]
    assert chk["check_id"] == "1.1.1"
    assert chk["status"] == "passed"


def test_record_check_updates_endpoint_score(engine):
    ep = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "windows"})
    # 3 passed, 1 failed — all same severity so simple avg
    for i in range(3):
        engine.record_check(ORG, ep["id"], {
            "check_id": f"C{i}", "status": "passed", "severity": "medium",
            "benchmark": "cis_windows_l1", "category": "local_policy",
        })
    engine.record_check(ORG, ep["id"], {
        "check_id": "C3", "status": "failed", "severity": "medium",
        "benchmark": "cis_windows_l1", "category": "local_policy",
    })
    updated = engine.get_endpoint(ORG, ep["id"])
    assert updated["compliance_score"] == pytest.approx(75.0)


def test_record_check_invalid_status(engine):
    ep = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux"})
    with pytest.raises(ValueError, match="Invalid status"):
        engine.record_check(ORG, ep["id"], {"check_id": "C1", "status": "skipped"})


def test_record_check_invalid_severity(engine):
    ep = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux"})
    with pytest.raises(ValueError, match="Invalid severity"):
        engine.record_check(ORG, ep["id"], {"check_id": "C1", "severity": "extreme"})


def test_record_check_invalid_benchmark(engine):
    ep = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux"})
    with pytest.raises(ValueError, match="Invalid benchmark"):
        engine.record_check(ORG, ep["id"], {"check_id": "C1", "benchmark": "cis_solaris"})


def test_record_check_invalid_category(engine):
    ep = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux"})
    with pytest.raises(ValueError, match="Invalid category"):
        engine.record_check(ORG, ep["id"], {"check_id": "C1", "category": "disk_quota"})


def test_record_check_requires_check_id(engine):
    ep = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux"})
    with pytest.raises(ValueError, match="check_id is required"):
        engine.record_check(ORG, ep["id"], {"check_id": ""})


# ---------------------------------------------------------------------------
# Compliance level thresholds
# ---------------------------------------------------------------------------

def test_compliance_level_compliant(engine):
    """Score >= 90 → compliant."""
    ep = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux"})
    for i in range(9):
        engine.record_check(ORG, ep["id"], {
            "check_id": f"C{i}", "status": "passed", "severity": "medium",
            "benchmark": "cis_ubuntu", "category": "local_policy",
        })
    engine.record_check(ORG, ep["id"], {
        "check_id": "C9", "status": "failed", "severity": "medium",
        "benchmark": "cis_ubuntu", "category": "local_policy",
    })
    ep_data = engine.get_endpoint(ORG, ep["id"])
    # 90% passed → compliant
    assert ep_data["compliance_level"] == "compliant"


def test_compliance_level_non_compliant(engine):
    """Score < 60 → non_compliant."""
    ep = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux"})
    engine.record_check(ORG, ep["id"], {
        "check_id": "C1", "status": "passed", "severity": "medium",
        "benchmark": "cis_ubuntu", "category": "local_policy",
    })
    for i in range(4):
        engine.record_check(ORG, ep["id"], {
            "check_id": f"F{i}", "status": "failed", "severity": "medium",
            "benchmark": "cis_ubuntu", "category": "local_policy",
        })
    ep_data = engine.get_endpoint(ORG, ep["id"])
    assert ep_data["compliance_level"] == "non_compliant"


def test_critical_failures_tracked(engine):
    ep = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux"})
    engine.record_check(ORG, ep["id"], {
        "check_id": "C1", "status": "failed", "severity": "critical",
        "benchmark": "cis_ubuntu", "category": "firewall",
    })
    engine.record_check(ORG, ep["id"], {
        "check_id": "C2", "status": "failed", "severity": "high",
        "benchmark": "cis_ubuntu", "category": "firewall",
    })
    ep_data = engine.get_endpoint(ORG, ep["id"])
    assert ep_data["critical_failures"] == 1
    assert ep_data["high_failures"] == 1


# ---------------------------------------------------------------------------
# Bulk check recording
# ---------------------------------------------------------------------------

def test_bulk_record_checks(engine):
    ep = engine.register_endpoint(ORG, {"hostname": "bulk-host", "os_type": "windows"})
    checks = [
        {"check_id": f"W{i}", "status": "passed", "severity": "medium",
         "benchmark": "cis_windows_l1", "category": "local_policy"}
        for i in range(10)
    ]
    results = engine.bulk_record_checks(ORG, ep["id"], checks)
    assert len(results) == 10
    ep_data = engine.get_endpoint(ORG, ep["id"])
    assert ep_data["compliance_score"] == pytest.approx(100.0)


def test_bulk_record_checks_skips_missing_check_id(engine):
    ep = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux"})
    checks = [
        {"check_id": "valid-1", "status": "passed", "severity": "medium",
         "benchmark": "cis_ubuntu", "category": "local_policy"},
        {"check_id": "", "status": "passed", "severity": "medium",
         "benchmark": "cis_ubuntu", "category": "local_policy"},  # should be skipped
    ]
    results = engine.bulk_record_checks(ORG, ep["id"], checks)
    assert len(results) == 1


def test_bulk_record_checks_mixed_statuses(engine):
    ep = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux"})
    checks = [
        {"check_id": "C1", "status": "passed", "severity": "high",
         "benchmark": "cis_ubuntu", "category": "local_policy"},
        {"check_id": "C2", "status": "failed", "severity": "high",
         "benchmark": "cis_ubuntu", "category": "local_policy"},
    ]
    engine.bulk_record_checks(ORG, ep["id"], checks)
    ep_data = engine.get_endpoint(ORG, ep["id"])
    assert ep_data["compliance_score"] == pytest.approx(50.0)


# ---------------------------------------------------------------------------
# List checks
# ---------------------------------------------------------------------------

def test_list_checks_filter_status(engine):
    ep = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux"})
    engine.record_check(ORG, ep["id"], {"check_id": "C1", "status": "passed", "severity": "low",
                                         "benchmark": "cis_ubuntu", "category": "local_policy"})
    engine.record_check(ORG, ep["id"], {"check_id": "C2", "status": "failed", "severity": "high",
                                         "benchmark": "cis_ubuntu", "category": "local_policy"})
    failed = engine.list_checks(ORG, status="failed")
    assert len(failed) == 1 and failed[0]["status"] == "failed"


def test_list_checks_filter_benchmark(engine):
    ep = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux"})
    engine.record_check(ORG, ep["id"], {"check_id": "U1", "status": "passed", "severity": "medium",
                                         "benchmark": "cis_ubuntu", "category": "local_policy"})
    engine.record_check(ORG, ep["id"], {"check_id": "R1", "status": "passed", "severity": "medium",
                                         "benchmark": "cis_rhel", "category": "local_policy"})
    ubuntu = engine.list_checks(ORG, benchmark="cis_ubuntu")
    assert len(ubuntu) == 1


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

def test_add_exception_basic(engine):
    ep = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux"})
    exc = engine.add_exception(ORG, {
        "endpoint_id": ep["id"],
        "check_id": "1.1.1",
        "reason": "Legacy system requirement",
        "approved_by": "CISO",
        "expires_at": "2026-12-31",
    })
    assert exc["id"]
    assert exc["check_id"] == "1.1.1"
    assert exc["approved_by"] == "CISO"


def test_add_exception_requires_endpoint_and_check(engine):
    with pytest.raises(ValueError, match="endpoint_id and check_id are required"):
        engine.add_exception(ORG, {"endpoint_id": "ep1"})


# ---------------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------------

def test_create_baseline_basic(engine):
    bl = engine.create_baseline(ORG, {
        "baseline_name": "Windows L1 Standard",
        "os_type": "windows",
        "benchmark": "cis_windows_l1",
        "required_checks": ["W1.1", "W1.2", "W1.3"],
        "target_score": 85.0,
    })
    assert bl["id"]
    assert bl["baseline_name"] == "Windows L1 Standard"
    assert isinstance(bl["required_checks"], list)
    assert len(bl["required_checks"]) == 3
    assert bl["target_score"] == 85.0


def test_create_baseline_requires_name(engine):
    with pytest.raises(ValueError, match="baseline_name is required"):
        engine.create_baseline(ORG, {"baseline_name": "", "benchmark": "cis_ubuntu"})


def test_create_baseline_invalid_os(engine):
    with pytest.raises(ValueError, match="Invalid os_type"):
        engine.create_baseline(ORG, {"baseline_name": "BL", "os_type": "solaris", "benchmark": "cis_ubuntu"})


def test_create_baseline_invalid_benchmark(engine):
    with pytest.raises(ValueError, match="Invalid benchmark"):
        engine.create_baseline(ORG, {"baseline_name": "BL", "os_type": "linux", "benchmark": "cis_solaris"})


def test_list_baselines(engine):
    engine.create_baseline(ORG, {"baseline_name": "BL1", "os_type": "linux", "benchmark": "cis_ubuntu"})
    engine.create_baseline(ORG, {"baseline_name": "BL2", "os_type": "windows", "benchmark": "cis_windows_l1"})
    bls = engine.list_baselines(ORG)
    assert len(bls) == 2


def test_list_baselines_empty(engine):
    assert engine.list_baselines(ORG) == []


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_endpoint_stats_empty(engine):
    stats = engine.get_endpoint_stats(ORG)
    assert stats["total_endpoints"] == 0
    assert stats["compliant_rate"] == 0.0


def test_get_endpoint_stats_populated(engine):
    ep1 = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux", "department": "IT"})
    ep2 = engine.register_endpoint(ORG, {"hostname": "h2", "os_type": "windows", "department": "HR"})

    # ep1: all passed → compliant
    for i in range(10):
        engine.record_check(ORG, ep1["id"], {
            "check_id": f"C{i}", "status": "passed", "severity": "medium",
            "benchmark": "cis_ubuntu", "category": "local_policy",
        })
    # ep2: mostly failed → non_compliant
    for i in range(5):
        engine.record_check(ORG, ep2["id"], {
            "check_id": f"W{i}", "status": "failed", "severity": "critical",
            "benchmark": "cis_windows_l1", "category": "local_policy",
        })

    stats = engine.get_endpoint_stats(ORG)
    assert stats["total_endpoints"] == 2
    assert "compliant" in stats["by_compliance_level"]
    assert "non_compliant" in stats["by_compliance_level"]
    assert stats["critical_failures_total"] >= 5
    assert stats["avg_compliance_score"] >= 0.0


# ---------------------------------------------------------------------------
# Department compliance
# ---------------------------------------------------------------------------

def test_get_department_compliance(engine):
    ep1 = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux", "department": "Engineering"})
    ep2 = engine.register_endpoint(ORG, {"hostname": "h2", "os_type": "linux", "department": "Engineering"})
    ep3 = engine.register_endpoint(ORG, {"hostname": "h3", "os_type": "windows", "department": "Finance"})

    # Make ep1 compliant (all passed)
    for i in range(10):
        engine.record_check(ORG, ep1["id"], {
            "check_id": f"C{i}", "status": "passed", "severity": "medium",
            "benchmark": "cis_ubuntu", "category": "local_policy",
        })

    dept = engine.get_department_compliance(ORG)
    dept_names = [d["department"] for d in dept]
    assert "Engineering" in dept_names or "Finance" in dept_names


def test_get_department_compliance_empty(engine):
    result = engine.get_department_compliance(ORG)
    assert result == []


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_endpoints(engine):
    engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux"})
    assert engine.list_endpoints(ORG2) == []


def test_org_isolation_checks(engine):
    ep = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux"})
    engine.record_check(ORG, ep["id"], {"check_id": "C1", "status": "passed", "severity": "low",
                                         "benchmark": "cis_ubuntu", "category": "local_policy"})
    assert engine.list_checks(ORG2) == []


def test_org_isolation_baselines(engine):
    engine.create_baseline(ORG, {"baseline_name": "BL1", "os_type": "linux", "benchmark": "cis_ubuntu"})
    assert engine.list_baselines(ORG2) == []


def test_org_isolation_stats(engine):
    ep = engine.register_endpoint(ORG, {"hostname": "h1", "os_type": "linux"})
    engine.record_check(ORG, ep["id"], {"check_id": "C1", "status": "failed", "severity": "critical",
                                         "benchmark": "cis_ubuntu", "category": "local_policy"})
    stats = engine.get_endpoint_stats(ORG2)
    assert stats["total_endpoints"] == 0
    assert stats["critical_failures_total"] == 0
