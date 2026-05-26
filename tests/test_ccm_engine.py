"""
Tests for CCMEngine (Continuous Control Monitoring).

Covers:
- All CRUD methods with org isolation (kept from original)
- Real conftest/OPA integration tests (new — replaces NotImplementedError tests)
- Error-path tests: conftest absent, missing input, empty policy dir
- Router 422 / 200 behaviour
- get_control_coverage / get_ccm_stats reflect real run_test results
"""
from __future__ import annotations

import importlib
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from core.ccm_engine import CCMEngine, CCMError


def _now_str() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "ccm"
POLICY_DIR = FIXTURES_DIR / "policy"
BAD_INPUT = FIXTURES_DIR / "bad_input.json"
GOOD_INPUT = FIXTURES_DIR / "good_input.json"

CONFTEST_PRESENT = shutil.which("conftest") is not None


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


def _seed_test_and_control(engine, org=ORG_A):
    ctrl = engine.register_control(org, _make_control())
    t = engine.add_test(org, ctrl["control_id"], _make_test())
    return ctrl, t


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
# add_test
# ---------------------------------------------------------------------------

class TestAddTest:
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

    def test_list_tests_by_status(self, engine):
        ctrl = engine.register_control(ORG_A, _make_control())
        engine.add_test(ORG_A, ctrl["control_id"], _make_test("T1"))
        engine.add_test(ORG_A, ctrl["control_id"], _make_test("T2"))
        not_tested = engine.list_tests(ORG_A, status="not_tested")
        assert len(not_tested) == 2


# ---------------------------------------------------------------------------
# run_test — error-path tests (no conftest needed)
# ---------------------------------------------------------------------------

class TestRunTestErrorPaths:
    def test_conftest_absent_raises_ccm_error(self, engine):
        """When conftest is not on PATH, CCMError is raised immediately."""
        ctrl, t = _seed_test_and_control(engine)
        with patch("shutil.which", return_value=None):
            with pytest.raises(CCMError, match="conftest"):
                engine.run_test(ORG_A, t["test_id"],
                                input_path=str(BAD_INPUT),
                                policy_path=str(POLICY_DIR))

    def test_missing_input_path_raises_ccm_error(self, engine):
        ctrl, t = _seed_test_and_control(engine)
        with pytest.raises(CCMError, match="input_path"):
            engine.run_test(ORG_A, t["test_id"],
                            input_path=None,
                            policy_path=str(POLICY_DIR))

    def test_nonexistent_input_file_raises_ccm_error(self, engine, tmp_path):
        ctrl, t = _seed_test_and_control(engine)
        with pytest.raises(CCMError, match="input_path not found"):
            engine.run_test(ORG_A, t["test_id"],
                            input_path=str(tmp_path / "does_not_exist.json"),
                            policy_path=str(POLICY_DIR))

    def test_missing_policy_path_raises_ccm_error(self, engine):
        ctrl, t = _seed_test_and_control(engine)
        with pytest.raises(CCMError, match="policy_path"):
            engine.run_test(ORG_A, t["test_id"],
                            input_path=str(BAD_INPUT),
                            policy_path=None)

    def test_empty_policy_dir_raises_ccm_error(self, engine, tmp_path):
        """A directory with no .rego files raises CCMError."""
        ctrl, t = _seed_test_and_control(engine)
        empty_policy = tmp_path / "policies"
        empty_policy.mkdir()
        with pytest.raises(CCMError, match="no Rego policies found"):
            engine.run_test(ORG_A, t["test_id"],
                            input_path=str(BAD_INPUT),
                            policy_path=str(empty_policy))

    def test_nonexistent_policy_path_raises_ccm_error(self, engine, tmp_path):
        ctrl, t = _seed_test_and_control(engine)
        with pytest.raises(CCMError, match="no Rego policies found"):
            engine.run_test(ORG_A, t["test_id"],
                            input_path=str(BAD_INPUT),
                            policy_path=str(tmp_path / "no_such_dir"))

    def test_test_not_found_raises_value_error(self, engine):
        """Nonexistent test_id raises ValueError, not CCMError."""
        with pytest.raises(ValueError, match="not found"):
            engine.run_test(ORG_A, "nonexistent-test-id",
                            input_path=str(BAD_INPUT),
                            policy_path=str(POLICY_DIR))

    def test_error_does_not_update_status(self, engine, tmp_path):
        """run_test() must not mutate the test row when it raises."""
        ctrl, t = _seed_test_and_control(engine)
        empty_policy = tmp_path / "pol"
        empty_policy.mkdir()
        try:
            engine.run_test(ORG_A, t["test_id"],
                            input_path=str(BAD_INPUT),
                            policy_path=str(empty_policy))
        except CCMError:
            pass
        tests = engine.list_tests(ORG_A, control_id=ctrl["control_id"])
        assert tests[0]["status"] == "not_tested"

    def test_error_does_not_create_history(self, engine, tmp_path):
        """run_test() must not insert a history row when it raises."""
        ctrl, t = _seed_test_and_control(engine)
        empty_policy = tmp_path / "pol"
        empty_policy.mkdir()
        try:
            engine.run_test(ORG_A, t["test_id"],
                            input_path=str(BAD_INPUT),
                            policy_path=str(empty_policy))
        except CCMError:
            pass
        with sqlite3.connect(engine.db_path) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM control_history WHERE org_id = ?", (ORG_A,)
            ).fetchone()
        assert row[0] == 0


# ---------------------------------------------------------------------------
# run_test — real conftest integration tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not CONFTEST_PRESENT, reason="conftest not installed")
class TestRunTestRealConftest:
    def test_failing_input_returns_failing_status(self, engine):
        """BAD input (privileged=true) → status='failing' with real failure messages."""
        ctrl, t = _seed_test_and_control(engine)
        result = engine.run_test(
            ORG_A, t["test_id"],
            input_path=str(BAD_INPUT),
            policy_path=str(POLICY_DIR),
        )
        assert result["status"] == "failing"
        assert len(result["failures"]) > 0
        assert any("privileged" in msg.lower() for msg in result["failures"])
        assert result["test_id"] == t["test_id"]
        assert result["org_id"] == ORG_A
        assert "evaluated_at" in result

    def test_failing_input_persists_history_row(self, engine):
        """A real failure must write a control_history row."""
        ctrl, t = _seed_test_and_control(engine)
        engine.run_test(
            ORG_A, t["test_id"],
            input_path=str(BAD_INPUT),
            policy_path=str(POLICY_DIR),
        )
        with sqlite3.connect(engine.db_path) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM control_history WHERE org_id = ? AND status = 'failing'",
                (ORG_A,),
            ).fetchone()
        assert row[0] == 1

    def test_failing_input_updates_test_status(self, engine):
        """After a real failure, control_tests.status must be 'failing'."""
        ctrl, t = _seed_test_and_control(engine)
        engine.run_test(
            ORG_A, t["test_id"],
            input_path=str(BAD_INPUT),
            policy_path=str(POLICY_DIR),
        )
        tests = engine.list_tests(ORG_A, control_id=ctrl["control_id"])
        assert tests[0]["status"] == "failing"

    def test_passing_input_returns_passing_status(self, engine):
        """GOOD input (privileged=false) → status='passing' with 0 failures."""
        ctrl, t = _seed_test_and_control(engine)
        result = engine.run_test(
            ORG_A, t["test_id"],
            input_path=str(GOOD_INPUT),
            policy_path=str(POLICY_DIR),
        )
        assert result["status"] == "passing"
        assert result["failures"] == []
        assert result["successes"] >= 1

    def test_passing_input_persists_history_row(self, engine):
        ctrl, t = _seed_test_and_control(engine)
        engine.run_test(
            ORG_A, t["test_id"],
            input_path=str(GOOD_INPUT),
            policy_path=str(POLICY_DIR),
        )
        with sqlite3.connect(engine.db_path) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM control_history WHERE org_id = ? AND status = 'passing'",
                (ORG_A,),
            ).fetchone()
        assert row[0] == 1

    def test_passing_input_updates_test_status(self, engine):
        ctrl, t = _seed_test_and_control(engine)
        engine.run_test(
            ORG_A, t["test_id"],
            input_path=str(GOOD_INPUT),
            policy_path=str(POLICY_DIR),
        )
        tests = engine.list_tests(ORG_A, control_id=ctrl["control_id"])
        assert tests[0]["status"] == "passing"

    def test_stats_reflect_real_run(self, engine):
        """get_ccm_stats reflects the real passing test written by run_test."""
        ctrl, t = _seed_test_and_control(engine)
        engine.run_test(
            ORG_A, t["test_id"],
            input_path=str(GOOD_INPUT),
            policy_path=str(POLICY_DIR),
        )
        stats = engine.get_ccm_stats(ORG_A)
        assert stats["passing_tests"] == 1
        assert stats["failing_tests"] == 0

    def test_coverage_reflects_real_run(self, engine):
        """get_control_coverage reflects the real passing test."""
        ctrl, t = _seed_test_and_control(engine)
        engine.run_test(
            ORG_A, t["test_id"],
            input_path=str(GOOD_INPUT),
            policy_path=str(POLICY_DIR),
        )
        cov = engine.get_control_coverage(ORG_A)
        assert cov["total_controls"] == 1
        assert cov["overall_pass_rate"] == 100.0

    def test_result_has_evidence_snapshot_with_real_data(self, engine):
        """evidence_snapshot must contain real conftest data (no fabricated counts)."""
        import json as _json
        ctrl, t = _seed_test_and_control(engine)
        result = engine.run_test(
            ORG_A, t["test_id"],
            input_path=str(BAD_INPUT),
            policy_path=str(POLICY_DIR),
        )
        snap = _json.loads(result["evidence_snapshot"])
        assert snap["status"] == "failing"
        assert snap["failure_count"] >= 1
        assert len(snap["failures"]) >= 1
        assert snap["conftest_exit_code"] == 1  # real conftest exits 1 on failure


# ---------------------------------------------------------------------------
# Router tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not CONFTEST_PRESENT, reason="conftest not installed")
class TestCCMRouter:
    def _get_client(self, engine_instance):
        """Return a FastAPI TestClient wired to a fresh engine instance."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        import core.ccm_engine as _eng_mod

        app = FastAPI()

        # Re-import router pointing at our test engine
        for key in list(sys.modules.keys()):
            if "ccm_router" in key:
                del sys.modules[key]

        original_get_engine = _eng_mod.get_engine
        _eng_mod._engine = engine_instance

        import apps.api.ccm_router as _router_mod
        app.include_router(_router_mod.router)
        client = TestClient(app, raise_server_exceptions=False)

        yield client

        _eng_mod._engine = None
        _eng_mod.get_engine = original_get_engine

    def test_router_run_test_200_on_valid_run(self, engine):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        import core.ccm_engine as _eng_mod

        # Wire test engine
        _eng_mod._engine = engine

        for key in list(sys.modules.keys()):
            if "ccm_router" in key:
                del sys.modules[key]

        import apps.api.ccm_router as _router_mod
        app = FastAPI()
        app.include_router(_router_mod.router)
        client = TestClient(app, raise_server_exceptions=False)

        # Register control + test
        ctrl = engine.register_control(ORG_A, _make_control())
        t = engine.add_test(ORG_A, ctrl["control_id"], _make_test())

        resp = client.post(
            f"/api/v1/ccm/orgs/{ORG_A}/tests/{t['test_id']}/run",
            json={"input_path": str(GOOD_INPUT), "policy_path": str(POLICY_DIR)},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"]["status"] == "passing"
        assert body["_data_source"]["is_simulated"] is False

        _eng_mod._engine = None

    def test_router_422_on_missing_input(self, engine):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        import core.ccm_engine as _eng_mod

        _eng_mod._engine = engine

        for key in list(sys.modules.keys()):
            if "ccm_router" in key:
                del sys.modules[key]

        import apps.api.ccm_router as _router_mod
        app = FastAPI()
        app.include_router(_router_mod.router)
        client = TestClient(app, raise_server_exceptions=False)

        ctrl = engine.register_control(ORG_A, _make_control())
        t = engine.add_test(ORG_A, ctrl["control_id"], _make_test())

        resp = client.post(
            f"/api/v1/ccm/orgs/{ORG_A}/tests/{t['test_id']}/run",
            json={"input_path": "/nonexistent/path.json", "policy_path": str(POLICY_DIR)},
        )
        assert resp.status_code == 422

        _eng_mod._engine = None


# ---------------------------------------------------------------------------
# Coverage & Stats (seeded via direct sqlite UPDATE — kept from original)
# ---------------------------------------------------------------------------

class TestCoverageAndStats:
    def test_get_control_coverage_empty(self, engine):
        cov = engine.get_control_coverage(ORG_A)
        assert cov["total_controls"] == 0
        assert cov["overall_pass_rate"] == 0.0
        assert cov["critical_failures"] == 0

    def test_get_control_coverage_with_data(self, engine):
        """Coverage query reads controls + test statuses from DB directly.
        Seed a 'passing' test status via direct UPDATE."""
        ctrl = engine.register_control(ORG_A, _make_control(framework="SOC2"))
        t = engine.add_test(ORG_A, ctrl["control_id"], _make_test())
        with sqlite3.connect(engine.db_path) as conn:
            conn.execute(
                "UPDATE control_tests SET status = 'passing', last_run = ? WHERE test_id = ?",
                (_now_str(), t["test_id"]),
            )
        cov = engine.get_control_coverage(ORG_A)
        assert cov["total_controls"] == 1
        assert "SOC2" in cov["by_framework"]

    def test_get_ccm_stats_empty(self, engine):
        stats = engine.get_ccm_stats(ORG_A)
        assert stats["total_controls"] == 0
        assert stats["coverage_pct"] == 0.0

    def test_get_ccm_stats_with_controls(self, engine):
        """Stats query reads controls/tests/failures from DB directly.
        Seed a 'passing' test status via direct UPDATE."""
        ctrl = engine.register_control(ORG_A, _make_control())
        t = engine.add_test(ORG_A, ctrl["control_id"], _make_test())
        with sqlite3.connect(engine.db_path) as conn:
            conn.execute(
                "UPDATE control_tests SET status = 'passing', last_run = ? WHERE test_id = ?",
                (_now_str(), t["test_id"]),
            )
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
