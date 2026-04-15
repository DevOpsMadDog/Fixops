"""
Tests for CCMEngine (Continuous Control Monitoring).
25+ tests covering all methods with org isolation.
"""
from __future__ import annotations

import os
import tempfile
import pytest

from core.ccm_engine import CCMEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_ccm.db")
    return CCMEngine(db_path=db)


ORG_A = "org-alpha"
ORG_B = "org-beta"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_control(name="MFA Enforcement", framework="SOC2", **kwargs):
    return {
        "control_name": name,
        "framework": framework,
        "control_ref": "CC6.1",
        "category": "Access Control",
        "description": "Enforce MFA for all users",
        "control_type": "preventive",
        "frequency": "monthly",
        "owner": "security-team",
        **kwargs,
    }


def _make_test(name="Check MFA enabled", **kwargs):
    return {
        "test_name": name,
        "test_type": "automated",
        "expected_result": "All users have MFA enabled",
        **kwargs,
    }


def _make_failure(control_id, **kwargs):
    return {
        "control_id": control_id,
        "failure_type": "gap",
        "severity": "high",
        "description": "MFA not enforced for service accounts",
        **kwargs,
    }


# ---------------------------------------------------------------------------
# register_control
# ---------------------------------------------------------------------------

class TestRegisterControl:
    def test_register_returns_record(self, engine):
        ctrl = engine.register_control(ORG_A, _make_control())
        assert ctrl["control_id"]
        assert ctrl["org_id"] == ORG_A
        assert ctrl["framework"] == "SOC2"
        assert ctrl["control_type"] == "preventive"
        assert ctrl["enabled"] == 1

    def test_register_all_frameworks(self, engine):
        for fw in ["SOC2", "ISO27001", "NIST", "PCI", "HIPAA", "CIS"]:
            ctrl = engine.register_control(ORG_A, _make_control(framework=fw))
            assert ctrl["framework"] == fw

    def test_register_invalid_framework_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid framework"):
            engine.register_control(ORG_A, _make_control(framework="UNKNOWN"))

    def test_register_invalid_control_type_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid control_type"):
            engine.register_control(ORG_A, _make_control(control_type="reactive"))

    def test_register_invalid_frequency_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid frequency"):
            engine.register_control(ORG_A, _make_control(frequency="yearly"))

    def test_register_org_isolation(self, engine):
        engine.register_control(ORG_A, _make_control("Control A"))
        engine.register_control(ORG_B, _make_control("Control B"))
        a_ctrls = engine.list_controls(ORG_A)
        b_ctrls = engine.list_controls(ORG_B)
        assert len(a_ctrls) == 1
        assert len(b_ctrls) == 1
        assert a_ctrls[0]["control_name"] == "Control A"
        assert b_ctrls[0]["control_name"] == "Control B"


# ---------------------------------------------------------------------------
# list_controls
# ---------------------------------------------------------------------------

class TestListControls:
    def test_list_by_framework(self, engine):
        engine.register_control(ORG_A, _make_control(framework="SOC2"))
        engine.register_control(ORG_A, _make_control(framework="NIST"))
        soc2 = engine.list_controls(ORG_A, framework="SOC2")
        assert all(c["framework"] == "SOC2" for c in soc2)

    def test_list_by_control_type(self, engine):
        engine.register_control(ORG_A, _make_control(control_type="preventive"))
        engine.register_control(ORG_A, _make_control(control_type="detective"))
        det = engine.list_controls(ORG_A, control_type="detective")
        assert all(c["control_type"] == "detective" for c in det)

    def test_list_disabled_controls(self, engine):
        engine.register_control(ORG_A, _make_control(enabled=False))
        engine.register_control(ORG_A, _make_control(enabled=True))
        enabled = engine.list_controls(ORG_A, enabled_only=True)
        all_ctrls = engine.list_controls(ORG_A, enabled_only=False)
        assert len(enabled) == 1
        assert len(all_ctrls) == 2


# ---------------------------------------------------------------------------
# add_test & run_test
# ---------------------------------------------------------------------------

class TestTests:
    def test_add_test_returns_record(self, engine):
        ctrl = engine.register_control(ORG_A, _make_control())
        t = engine.add_test(ORG_A, ctrl["control_id"], _make_test())
        assert t["test_id"]
        assert t["status"] == "not_tested"
        assert t["control_id"] == ctrl["control_id"]

    def test_add_test_wrong_org_raises(self, engine):
        ctrl = engine.register_control(ORG_A, _make_control())
        with pytest.raises(ValueError, match="not found"):
            engine.add_test(ORG_B, ctrl["control_id"], _make_test())

    def test_add_test_invalid_type_raises(self, engine):
        ctrl = engine.register_control(ORG_A, _make_control())
        with pytest.raises(ValueError, match="Invalid test_type"):
            engine.add_test(ORG_A, ctrl["control_id"], _make_test(test_type="magic"))

    def test_run_test_returns_status(self, engine):
        ctrl = engine.register_control(ORG_A, _make_control())
        t = engine.add_test(ORG_A, ctrl["control_id"], _make_test())
        result = engine.run_test(ORG_A, t["test_id"])
        assert result["status"] in {"passing", "failing", "degraded"}
        assert result["last_run"]
        assert result["next_run"]

    def test_run_test_wrong_org_raises(self, engine):
        ctrl = engine.register_control(ORG_A, _make_control())
        t = engine.add_test(ORG_A, ctrl["control_id"], _make_test())
        with pytest.raises(ValueError, match="not found"):
            engine.run_test(ORG_B, t["test_id"])

    def test_run_test_updates_status(self, engine):
        ctrl = engine.register_control(ORG_A, _make_control())
        t = engine.add_test(ORG_A, ctrl["control_id"], _make_test())
        engine.run_test(ORG_A, t["test_id"])
        tests = engine.list_tests(ORG_A, control_id=ctrl["control_id"])
        assert tests[0]["status"] != "not_tested"

    def test_list_tests_by_status(self, engine):
        ctrl = engine.register_control(ORG_A, _make_control())
        t1 = engine.add_test(ORG_A, ctrl["control_id"], _make_test("T1"))
        t2 = engine.add_test(ORG_A, ctrl["control_id"], _make_test("T2"))
        not_tested = engine.list_tests(ORG_A, status="not_tested")
        assert len(not_tested) == 2

    def test_run_test_records_history(self, engine):
        """Running a test should create a history entry."""
        ctrl = engine.register_control(ORG_A, _make_control())
        t = engine.add_test(ORG_A, ctrl["control_id"], _make_test())
        result = engine.run_test(ORG_A, t["test_id"])
        assert result["evidence_snapshot"]
        import json
        snap = json.loads(result["evidence_snapshot"])
        assert snap["status"] in {"passing", "failing", "degraded"}


# ---------------------------------------------------------------------------
# Failures
# ---------------------------------------------------------------------------

class TestFailures:
    def test_log_failure_returns_record(self, engine):
        ctrl = engine.register_control(ORG_A, _make_control())
        f = engine.log_failure(ORG_A, _make_failure(ctrl["control_id"]))
        assert f["failure_id"]
        assert f["org_id"] == ORG_A
        assert f["severity"] == "high"

    def test_log_failure_invalid_type_raises(self, engine):
        ctrl = engine.register_control(ORG_A, _make_control())
        with pytest.raises(ValueError, match="Invalid failure_type"):
            engine.log_failure(ORG_A, _make_failure(ctrl["control_id"], failure_type="bogus"))

    def test_log_failure_invalid_severity_raises(self, engine):
        ctrl = engine.register_control(ORG_A, _make_control())
        with pytest.raises(ValueError, match="Invalid severity"):
            engine.log_failure(ORG_A, _make_failure(ctrl["control_id"], severity="extreme"))

    def test_remediate_failure(self, engine):
        ctrl = engine.register_control(ORG_A, _make_control())
        f = engine.log_failure(ORG_A, _make_failure(ctrl["control_id"]))
        ok = engine.remediate_failure(ORG_A, f["failure_id"], "Applied MFA policy")
        assert ok is True

    def test_remediate_failure_wrong_org(self, engine):
        ctrl = engine.register_control(ORG_A, _make_control())
        f = engine.log_failure(ORG_A, _make_failure(ctrl["control_id"]))
        ok = engine.remediate_failure(ORG_B, f["failure_id"], "notes")
        assert ok is False

    def test_list_open_failures(self, engine):
        ctrl = engine.register_control(ORG_A, _make_control())
        f = engine.log_failure(ORG_A, _make_failure(ctrl["control_id"]))
        open_fails = engine.list_failures(ORG_A, remediated=False)
        assert len(open_fails) == 1
        engine.remediate_failure(ORG_A, f["failure_id"], "Fixed")
        open_fails_after = engine.list_failures(ORG_A, remediated=False)
        assert len(open_fails_after) == 0

    def test_list_remediated_failures(self, engine):
        ctrl = engine.register_control(ORG_A, _make_control())
        f = engine.log_failure(ORG_A, _make_failure(ctrl["control_id"]))
        engine.remediate_failure(ORG_A, f["failure_id"], "Done")
        done = engine.list_failures(ORG_A, remediated=True)
        assert len(done) == 1

    def test_list_failures_by_severity(self, engine):
        ctrl = engine.register_control(ORG_A, _make_control())
        engine.log_failure(ORG_A, _make_failure(ctrl["control_id"], severity="critical"))
        engine.log_failure(ORG_A, _make_failure(ctrl["control_id"], severity="low"))
        crits = engine.list_failures(ORG_A, severity="critical")
        assert all(f["severity"] == "critical" for f in crits)

    def test_failure_org_isolation(self, engine):
        ctrl_a = engine.register_control(ORG_A, _make_control())
        ctrl_b = engine.register_control(ORG_B, _make_control())
        engine.log_failure(ORG_A, _make_failure(ctrl_a["control_id"]))
        engine.log_failure(ORG_B, _make_failure(ctrl_b["control_id"]))
        assert len(engine.list_failures(ORG_A)) == 1
        assert len(engine.list_failures(ORG_B)) == 1


# ---------------------------------------------------------------------------
# Coverage & Stats
# ---------------------------------------------------------------------------

class TestCoverageAndStats:
    def test_get_control_coverage_empty(self, engine):
        cov = engine.get_control_coverage(ORG_A)
        assert cov["total_controls"] == 0
        assert cov["overall_pass_rate"] == 0.0
        assert cov["critical_failures"] == 0

    def test_get_control_coverage_with_data(self, engine):
        ctrl = engine.register_control(ORG_A, _make_control(framework="SOC2"))
        t = engine.add_test(ORG_A, ctrl["control_id"], _make_test())
        engine.run_test(ORG_A, t["test_id"])
        cov = engine.get_control_coverage(ORG_A)
        assert cov["total_controls"] == 1
        assert "SOC2" in cov["by_framework"]

    def test_get_ccm_stats_empty(self, engine):
        stats = engine.get_ccm_stats(ORG_A)
        assert stats["total_controls"] == 0
        assert stats["coverage_pct"] == 0.0

    def test_get_ccm_stats_with_controls(self, engine):
        ctrl = engine.register_control(ORG_A, _make_control())
        t = engine.add_test(ORG_A, ctrl["control_id"], _make_test())
        engine.run_test(ORG_A, t["test_id"])
        engine.log_failure(ORG_A, _make_failure(ctrl["control_id"], severity="critical"))
        stats = engine.get_ccm_stats(ORG_A)
        assert stats["total_controls"] == 1
        assert stats["total_tests"] == 1
        assert stats["open_failures"] == 1
        assert stats["critical_failures"] == 1

    def test_coverage_org_isolation(self, engine):
        engine.register_control(ORG_A, _make_control())
        engine.register_control(ORG_B, _make_control())
        engine.register_control(ORG_B, _make_control("Control B2"))
        cov_a = engine.get_control_coverage(ORG_A)
        cov_b = engine.get_control_coverage(ORG_B)
        assert cov_a["total_controls"] == 1
        assert cov_b["total_controls"] == 2
