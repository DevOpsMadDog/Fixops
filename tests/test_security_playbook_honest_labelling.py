"""
Tests asserting that SecurityPlaybookEngine honest-labelling contract holds.

Every simulated run MUST:
  - carry ``"simulated": True`` at the top level of the execute_playbook result
  - carry ``"execution_mode": "simulated"`` at the top level
  - carry ``"execution_mode": "simulated"`` inside output dict
  - carry ``"execution_mode": "simulated"`` on EVERY per-step result in output["steps"]

A simulated run MUST never be indistinguishable from a real one — these tests
enforce that invariant.  If EXECUTION_MODE is ever changed to "real", the tests
that check mode == "simulated" will fail, forcing a deliberate update.

Run with:
  python -m pytest tests/test_security_playbook_honest_labelling.py --timeout=10 -q -o "addopts="
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.security_playbook_engine import (
    EXECUTION_MODE,
    SecurityPlaybookEngine,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return SecurityPlaybookEngine(db_path=str(tmp_path / "honest_test.db"))


_MULTI_STEP_PLAYBOOK: Dict[str, Any] = {
    "name": "Multi-step honest test",
    "trigger_type": "manual",
    "steps": [
        {
            "step_id": "s1",
            "name": "Isolate host",
            "action_type": "isolate_host",
            "params": {"reason": "test", "simulate_success": True},
            "on_success": "s2",
            "on_failure": "s2",
        },
        {
            "step_id": "s2",
            "name": "Send alert",
            "action_type": "send_alert",
            "params": {"channel": "email", "simulate_success": True},
            "on_success": "s3",
            "on_failure": "s3",
        },
        {
            "step_id": "s3",
            "name": "Create ticket",
            "action_type": "create_ticket",
            "params": {"priority": "high", "simulate_success": True},
            "on_success": None,
            "on_failure": None,
        },
    ],
}

_FAIL_STEP_PLAYBOOK: Dict[str, Any] = {
    "name": "Failing step honest test",
    "trigger_type": "manual",
    "steps": [
        {
            "step_id": "s1",
            "name": "Block IP (fails)",
            "action_type": "block_ip",
            "params": {"simulate_success": False},
            "on_success": None,
            "on_failure": None,
        }
    ],
}


# ---------------------------------------------------------------------------
# Module-level constant
# ---------------------------------------------------------------------------

def test_execution_mode_constant_is_string():
    assert isinstance(EXECUTION_MODE, str)


def test_execution_mode_is_simulated():
    """Until real connectors are wired, EXECUTION_MODE must equal 'simulated'."""
    assert EXECUTION_MODE == "simulated", (
        "EXECUTION_MODE changed to non-simulated without wiring real connectors. "
        "Update tests and ensure _dispatch_step routes to real integrations."
    )


# ---------------------------------------------------------------------------
# Top-level run result carries mode flags
# ---------------------------------------------------------------------------

def test_execute_result_has_simulated_flag(engine):
    pb_id = engine.create_playbook("org1", _MULTI_STEP_PLAYBOOK)
    result = engine.execute_playbook(pb_id, "org1", context={})
    assert "simulated" in result, "execute_playbook result missing 'simulated' key"
    assert result["simulated"] is True


def test_execute_result_has_execution_mode(engine):
    pb_id = engine.create_playbook("org1", _MULTI_STEP_PLAYBOOK)
    result = engine.execute_playbook(pb_id, "org1", context={})
    assert "execution_mode" in result, "execute_playbook result missing 'execution_mode' key"
    assert result["execution_mode"] == "simulated"


def test_execute_result_simulated_flag_for_failing_run(engine):
    """Even a failed/partial run must carry the simulated flag."""
    pb_id = engine.create_playbook("org1", _FAIL_STEP_PLAYBOOK)
    result = engine.execute_playbook(pb_id, "org1", context={})
    assert result["simulated"] is True
    assert result["execution_mode"] == "simulated"


def test_execute_result_simulated_flag_for_empty_steps(engine):
    """A playbook with no steps must still carry the mode flags."""
    pb_id = engine.create_playbook("org1", {"name": "Empty", "trigger_type": "manual", "steps": []})
    result = engine.execute_playbook(pb_id, "org1", context={})
    assert result["simulated"] is True
    assert result["execution_mode"] == "simulated"


# ---------------------------------------------------------------------------
# output dict carries mode flag
# ---------------------------------------------------------------------------

def test_execute_output_dict_has_execution_mode(engine):
    pb_id = engine.create_playbook("org1", _MULTI_STEP_PLAYBOOK)
    result = engine.execute_playbook(pb_id, "org1", context={})
    assert "execution_mode" in result["output"], (
        "output dict missing 'execution_mode' key"
    )
    assert result["output"]["execution_mode"] == "simulated"


# ---------------------------------------------------------------------------
# Every per-step result carries execution_mode
# ---------------------------------------------------------------------------

def test_every_step_result_has_execution_mode(engine):
    pb_id = engine.create_playbook("org1", _MULTI_STEP_PLAYBOOK)
    result = engine.execute_playbook(pb_id, "org1", context={"host": "web-01"})
    steps = result["output"]["steps"]
    assert len(steps) == 3, "Expected 3 steps in output"
    for step_out in steps:
        assert "execution_mode" in step_out, (
            f"Step {step_out.get('step_id')} missing 'execution_mode'"
        )
        assert step_out["execution_mode"] == "simulated", (
            f"Step {step_out.get('step_id')} execution_mode != 'simulated'"
        )


def test_failing_step_result_has_execution_mode(engine):
    pb_id = engine.create_playbook("org1", _FAIL_STEP_PLAYBOOK)
    result = engine.execute_playbook(pb_id, "org1", context={})
    steps = result["output"]["steps"]
    assert len(steps) == 1
    assert steps[0]["execution_mode"] == "simulated"


def test_all_action_types_step_results_carry_mode(engine):
    """All 7 VALID_ACTION_TYPES must carry execution_mode on step output."""
    from core.security_playbook_engine import VALID_ACTION_TYPES
    for action_type in VALID_ACTION_TYPES:
        pb = {
            "name": f"Mode test {action_type}",
            "trigger_type": "manual",
            "steps": [
                {
                    "step_id": "s1",
                    "name": action_type,
                    "action_type": action_type,
                    "params": {"simulate_success": True},
                    "on_success": None,
                    "on_failure": None,
                }
            ],
        }
        pb_id = engine.create_playbook("org1", pb)
        result = engine.execute_playbook(pb_id, "org1", context={})
        step_out = result["output"]["steps"][0]
        assert step_out["execution_mode"] == "simulated", (
            f"action_type={action_type} step result missing execution_mode='simulated'"
        )


# ---------------------------------------------------------------------------
# Simulated run is distinguishable from a (future) real run
# ---------------------------------------------------------------------------

def test_simulated_true_means_no_real_action_occurred(engine):
    """
    When simulated=True the run MUST NOT claim real side-effects.
    This test documents the invariant: any future real-dispatch path
    must set simulated=False (or execution_mode='real') so UIs and
    auditors can tell runs apart.
    """
    pb_id = engine.create_playbook("org1", _MULTI_STEP_PLAYBOOK)
    result = engine.execute_playbook(pb_id, "org1", context={})
    # Simulated run → simulated must be True
    assert result["simulated"] is True
    # Simulated run → execution_mode must NOT be "real"
    assert result["execution_mode"] != "real"


def test_simulate_step_directly_labels_output():
    """_simulate_step must label its output without needing engine context."""
    engine_instance = SecurityPlaybookEngine.__new__(SecurityPlaybookEngine)
    step = {
        "step_id": "direct-s1",
        "name": "Direct test",
        "action_type": "run_scan",
        "params": {"scan_type": "quick"},
    }
    out = SecurityPlaybookEngine._simulate_step(step, {}, True)
    assert out["execution_mode"] == "simulated"
    assert out["status"] == "completed"


def test_simulate_step_failed_also_labelled():
    step = {
        "step_id": "direct-s2",
        "name": "Direct fail",
        "action_type": "block_ip",
        "params": {},
    }
    out = SecurityPlaybookEngine._simulate_step(step, {}, False)
    assert out["execution_mode"] == "simulated"
    assert out["status"] == "failed"


# ---------------------------------------------------------------------------
# Existing contract still holds (regression guard)
# ---------------------------------------------------------------------------

def test_existing_return_keys_preserved(engine):
    """All keys present before the honest-labelling fix must still be present."""
    pb_id = engine.create_playbook("org1", _MULTI_STEP_PLAYBOOK)
    result = engine.execute_playbook(pb_id, "org1", context={})
    for key in ("execution_id", "status", "steps_completed", "steps_failed",
                "duration_ms", "output"):
        assert key in result, f"Pre-existing key '{key}' was removed — regression"


def test_existing_output_keys_preserved(engine):
    pb_id = engine.create_playbook("org1", _MULTI_STEP_PLAYBOOK)
    result = engine.execute_playbook(pb_id, "org1", context={"ip": "1.2.3.4"})
    assert "steps" in result["output"]
    assert "context_keys" in result["output"]


def test_existing_step_output_keys_preserved(engine):
    pb_id = engine.create_playbook("org1", _MULTI_STEP_PLAYBOOK)
    result = engine.execute_playbook(pb_id, "org1", context={})
    for step_out in result["output"]["steps"]:
        for key in ("step_id", "name", "action_type", "status", "result"):
            assert key in step_out, (
                f"Pre-existing step key '{key}' missing for step {step_out.get('step_id')}"
            )
