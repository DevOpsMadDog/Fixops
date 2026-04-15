"""
Tests for SecurityPlaybookEngine — automated security response playbooks.

Covers:
- create_playbook (happy path, validation, multi-tenant)
- list_playbooks (empty, multi-org isolation)
- get_playbook (found, not found, wrong org)
- execute_playbook (happy path, all step action types, failed steps,
  simulate_success=False, unknown playbook)
- list_executions (limit, org isolation)
- get_execution (found, not found, wrong org)
- get_builtin_playbooks (count, required fields, known names)
- WAL mode persistence across instances
- Thread-safety smoke test

Run with: python -m pytest tests/test_playbook_engine.py --timeout=10 -q -o "addopts="
"""

from __future__ import annotations

import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Dict

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.security_playbook_engine import (
    VALID_ACTION_TYPES,
    VALID_TRIGGER_TYPES,
    SecurityPlaybookEngine,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def engine(tmp_path):
    """Fresh SecurityPlaybookEngine backed by a temp SQLite DB."""
    return SecurityPlaybookEngine(db_path=str(tmp_path / "test_playbooks.db"))


@pytest.fixture
def sample_playbook() -> Dict[str, Any]:
    return {
        "name": "Test Phishing Response",
        "trigger_type": "auto_alert",
        "trigger_conditions": {"alert_type": "phishing_detected"},
        "severity_filter": "high",
        "enabled": True,
        "steps": [
            {
                "step_id": "s1",
                "name": "Block sender",
                "action_type": "block_ip",
                "params": {"reason": "phishing", "simulate_success": True},
                "on_success": "s2",
                "on_failure": None,
            },
            {
                "step_id": "s2",
                "name": "Notify team",
                "action_type": "send_alert",
                "params": {"channel": "email", "simulate_success": True},
                "on_success": None,
                "on_failure": None,
            },
        ],
    }


# ============================================================================
# create_playbook
# ============================================================================


def test_create_playbook_returns_id(engine, sample_playbook):
    pb_id = engine.create_playbook("org1", sample_playbook)
    assert isinstance(pb_id, str)
    assert len(pb_id) == 36  # UUID format


def test_create_playbook_invalid_trigger_type_raises(engine):
    with pytest.raises(ValueError, match="trigger_type"):
        engine.create_playbook("org1", {"name": "X", "trigger_type": "invalid"})


def test_create_playbook_default_trigger_type(engine):
    pb_id = engine.create_playbook("org1", {"name": "Manual PB"})
    pb = engine.get_playbook(pb_id, "org1")
    assert pb["trigger_type"] == "manual"


def test_create_playbook_all_trigger_types(engine):
    for tt in VALID_TRIGGER_TYPES:
        pb_id = engine.create_playbook("org1", {"name": f"PB-{tt}", "trigger_type": tt})
        pb = engine.get_playbook(pb_id, "org1")
        assert pb["trigger_type"] == tt


def test_create_playbook_stores_steps(engine, sample_playbook):
    pb_id = engine.create_playbook("org1", sample_playbook)
    pb = engine.get_playbook(pb_id, "org1")
    assert len(pb["steps"]) == 2
    assert pb["steps"][0]["action_type"] == "block_ip"


def test_create_playbook_stores_trigger_conditions(engine, sample_playbook):
    pb_id = engine.create_playbook("org1", sample_playbook)
    pb = engine.get_playbook(pb_id, "org1")
    assert pb["trigger_conditions"] == {"alert_type": "phishing_detected"}


# ============================================================================
# list_playbooks
# ============================================================================


def test_list_playbooks_empty(engine):
    assert engine.list_playbooks("org-none") == []


def test_list_playbooks_returns_created(engine, sample_playbook):
    engine.create_playbook("org1", sample_playbook)
    engine.create_playbook("org1", sample_playbook)
    items = engine.list_playbooks("org1")
    assert len(items) == 2


def test_list_playbooks_org_isolation(engine, sample_playbook):
    engine.create_playbook("org1", sample_playbook)
    engine.create_playbook("org2", sample_playbook)
    assert len(engine.list_playbooks("org1")) == 1
    assert len(engine.list_playbooks("org2")) == 1
    assert len(engine.list_playbooks("org3")) == 0


# ============================================================================
# get_playbook
# ============================================================================


def test_get_playbook_found(engine, sample_playbook):
    pb_id = engine.create_playbook("org1", sample_playbook)
    pb = engine.get_playbook(pb_id, "org1")
    assert pb is not None
    assert pb["id"] == pb_id
    assert pb["name"] == sample_playbook["name"]


def test_get_playbook_not_found(engine):
    result = engine.get_playbook(str(uuid.uuid4()), "org1")
    assert result is None


def test_get_playbook_wrong_org(engine, sample_playbook):
    pb_id = engine.create_playbook("org1", sample_playbook)
    assert engine.get_playbook(pb_id, "org2") is None


def test_get_playbook_enabled_flag(engine):
    pb_id = engine.create_playbook("org1", {"name": "Disabled PB", "enabled": False})
    pb = engine.get_playbook(pb_id, "org1")
    assert pb["enabled"] is False


# ============================================================================
# execute_playbook
# ============================================================================


def test_execute_playbook_happy_path(engine, sample_playbook):
    pb_id = engine.create_playbook("org1", sample_playbook)
    result = engine.execute_playbook(pb_id, "org1", {"ip": "1.2.3.4"})
    assert result["status"] == "completed"
    assert result["steps_completed"] == 2
    assert result["steps_failed"] == 0
    assert "execution_id" in result
    assert isinstance(result["duration_ms"], int)


def test_execute_playbook_returns_output(engine, sample_playbook):
    pb_id = engine.create_playbook("org1", sample_playbook)
    result = engine.execute_playbook(pb_id, "org1", {})
    assert "steps" in result["output"]
    assert len(result["output"]["steps"]) == 2


def test_execute_playbook_step_simulate_failure(engine):
    pb = {
        "name": "Fail PB",
        "trigger_type": "manual",
        "steps": [
            {
                "step_id": "s1",
                "name": "Failing step",
                "action_type": "block_ip",
                "params": {"simulate_success": False},
                "on_success": None,
                "on_failure": None,
            }
        ],
    }
    pb_id = engine.create_playbook("org1", pb)
    result = engine.execute_playbook(pb_id, "org1", {})
    assert result["steps_failed"] == 1
    assert result["steps_completed"] == 0
    assert result["status"] == "failed"


def test_execute_playbook_partial_failure(engine):
    pb = {
        "name": "Partial PB",
        "trigger_type": "manual",
        "steps": [
            {
                "step_id": "s1",
                "name": "OK step",
                "action_type": "send_alert",
                "params": {"simulate_success": True},
                "on_success": "s2",
                "on_failure": None,
            },
            {
                "step_id": "s2",
                "name": "Failing step",
                "action_type": "block_ip",
                "params": {"simulate_success": False},
                "on_success": None,
                "on_failure": None,
            },
        ],
    }
    pb_id = engine.create_playbook("org1", pb)
    result = engine.execute_playbook(pb_id, "org1", {})
    assert result["steps_completed"] == 1
    assert result["steps_failed"] == 1
    assert result["status"] == "partial"


def test_execute_playbook_unknown_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.execute_playbook(str(uuid.uuid4()), "org1", {})


def test_execute_playbook_wrong_org_raises(engine, sample_playbook):
    pb_id = engine.create_playbook("org1", sample_playbook)
    with pytest.raises(ValueError, match="not found"):
        engine.execute_playbook(pb_id, "org2", {})


def test_execute_all_action_types(engine):
    """Each action_type should produce a result dict without error."""
    for action_type in VALID_ACTION_TYPES:
        pb = {
            "name": f"Test {action_type}",
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
        result = engine.execute_playbook(pb_id, "org1", {})
        assert result["status"] == "completed", f"Failed for action_type={action_type}"


def test_execute_playbook_no_steps(engine):
    pb_id = engine.create_playbook("org1", {"name": "Empty PB", "trigger_type": "manual"})
    result = engine.execute_playbook(pb_id, "org1", {})
    assert result["steps_completed"] == 0
    assert result["steps_failed"] == 0
    assert result["status"] == "completed"


# ============================================================================
# list_executions / get_execution
# ============================================================================


def test_list_executions_empty(engine):
    assert engine.list_executions("org-none") == []


def test_list_executions_records_after_execute(engine, sample_playbook):
    pb_id = engine.create_playbook("org1", sample_playbook)
    engine.execute_playbook(pb_id, "org1", {})
    engine.execute_playbook(pb_id, "org1", {})
    execs = engine.list_executions("org1")
    assert len(execs) == 2


def test_list_executions_limit(engine, sample_playbook):
    pb_id = engine.create_playbook("org1", sample_playbook)
    for _ in range(5):
        engine.execute_playbook(pb_id, "org1", {})
    assert len(engine.list_executions("org1", limit=3)) == 3


def test_list_executions_org_isolation(engine, sample_playbook):
    pb1 = engine.create_playbook("org1", sample_playbook)
    pb2 = engine.create_playbook("org2", sample_playbook)
    engine.execute_playbook(pb1, "org1", {})
    engine.execute_playbook(pb2, "org2", {})
    assert len(engine.list_executions("org1")) == 1
    assert len(engine.list_executions("org2")) == 1


def test_get_execution_found(engine, sample_playbook):
    pb_id = engine.create_playbook("org1", sample_playbook)
    run = engine.execute_playbook(pb_id, "org1", {"host": "web-01"})
    exec_id = run["execution_id"]
    record = engine.get_execution(exec_id, "org1")
    assert record is not None
    assert record["id"] == exec_id
    assert record["playbook_id"] == pb_id


def test_get_execution_not_found(engine):
    assert engine.get_execution(str(uuid.uuid4()), "org1") is None


def test_get_execution_wrong_org(engine, sample_playbook):
    pb_id = engine.create_playbook("org1", sample_playbook)
    run = engine.execute_playbook(pb_id, "org1", {})
    assert engine.get_execution(run["execution_id"], "org2") is None


# ============================================================================
# get_builtin_playbooks
# ============================================================================


def test_get_builtin_playbooks_count(engine):
    builtins = engine.get_builtin_playbooks()
    assert len(builtins) == 5


def test_get_builtin_playbooks_names(engine):
    names = {pb["name"] for pb in engine.get_builtin_playbooks()}
    assert "Ransomware Response" in names
    assert "Phishing Response" in names
    assert "Credential Stuffing" in names
    assert "Data Exfiltration Alert" in names
    assert "Privilege Escalation" in names


def test_get_builtin_playbooks_required_fields(engine):
    for pb in engine.get_builtin_playbooks():
        assert "name" in pb
        assert "trigger_type" in pb
        assert "steps" in pb
        assert len(pb["steps"]) > 0


def test_get_builtin_playbooks_returns_copy(engine):
    """Mutations to returned list must not affect subsequent calls."""
    builtins = engine.get_builtin_playbooks()
    builtins.clear()
    assert len(engine.get_builtin_playbooks()) == 5


# ============================================================================
# Persistence across instances
# ============================================================================


def test_persistence_across_instances(tmp_path):
    db = str(tmp_path / "persist.db")
    e1 = SecurityPlaybookEngine(db_path=db)
    pb_id = e1.create_playbook("org1", {"name": "Persist PB", "trigger_type": "manual"})

    e2 = SecurityPlaybookEngine(db_path=db)
    pb = e2.get_playbook(pb_id, "org1")
    assert pb is not None
    assert pb["name"] == "Persist PB"


# ============================================================================
# Thread-safety smoke test
# ============================================================================


def test_thread_safety(engine):
    """Concurrent creates and executes must not raise."""
    errors = []
    pb_id = engine.create_playbook(
        "org1",
        {
            "name": "Concurrent PB",
            "trigger_type": "manual",
            "steps": [
                {
                    "step_id": "s1",
                    "name": "step",
                    "action_type": "send_alert",
                    "params": {"simulate_success": True},
                    "on_success": None,
                    "on_failure": None,
                }
            ],
        },
    )

    def worker():
        try:
            engine.execute_playbook(pb_id, "org1", {})
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"Thread errors: {errors}"
    assert len(engine.list_executions("org1")) == 10
