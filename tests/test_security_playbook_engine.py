"""Tests for SecurityPlaybookEngine.

Coverage: create_playbook, list_playbooks, get_playbook, execute_playbook,
          list_executions, get_execution, get_builtin_playbooks,
          org isolation, validation, edge cases.
"""

import pytest
from core.security_playbook_engine import SecurityPlaybookEngine, VALID_TRIGGER_TYPES


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return SecurityPlaybookEngine(db_path=str(tmp_path / "playbook.db"))


ORG_A = "org-alpha"
ORG_B = "org-beta"

_RANSOMWARE_PLAYBOOK = {
    "name": "Ransomware Response",
    "trigger_type": "auto_alert",
    "trigger_conditions": {"alert_type": "ransomware_detected"},
    "severity_filter": "critical",
    "enabled": True,
    "steps": [
        {
            "step_id": "step-1",
            "name": "Isolate host",
            "action_type": "isolate_host",
            "params": {"reason": "ransomware_containment", "simulate_success": True},
            "on_success": "step-2",
            "on_failure": None,
        },
        {
            "step_id": "step-2",
            "name": "Alert team",
            "action_type": "send_alert",
            "params": {"channel": "email", "simulate_success": True},
            "on_success": None,
            "on_failure": None,
        },
    ],
}

_SIMPLE_PLAYBOOK = {
    "name": "Simple Manual Playbook",
    "trigger_type": "manual",
    "steps": [
        {
            "step_id": "step-a",
            "name": "Run scan",
            "action_type": "run_scan",
            "params": {"scan_type": "quick", "simulate_success": True},
            "on_success": None,
            "on_failure": None,
        }
    ],
}


# ---------------------------------------------------------------------------
# create_playbook
# ---------------------------------------------------------------------------


def test_create_playbook_returns_uuid_string(engine):
    pb_id = engine.create_playbook(ORG_A, _RANSOMWARE_PLAYBOOK)
    assert isinstance(pb_id, str)
    assert len(pb_id) == 36  # UUID4 length


def test_create_playbook_invalid_trigger_type_raises(engine):
    bad = dict(_SIMPLE_PLAYBOOK, trigger_type="on_fire")
    with pytest.raises(ValueError, match="trigger_type"):
        engine.create_playbook(ORG_A, bad)


def test_create_playbook_all_valid_trigger_types(engine):
    for trigger in VALID_TRIGGER_TYPES:
        pb = dict(_SIMPLE_PLAYBOOK, trigger_type=trigger)
        pb_id = engine.create_playbook(ORG_A, pb)
        assert isinstance(pb_id, str)


def test_create_playbook_defaults_name_when_missing(engine):
    pb_id = engine.create_playbook(ORG_A, {"trigger_type": "manual"})
    pb = engine.get_playbook(pb_id, ORG_A)
    assert pb["name"] == "Unnamed Playbook"


def test_create_playbook_stores_steps(engine):
    pb_id = engine.create_playbook(ORG_A, _RANSOMWARE_PLAYBOOK)
    pb = engine.get_playbook(pb_id, ORG_A)
    assert len(pb["steps"]) == 2


def test_create_playbook_stores_trigger_conditions(engine):
    pb_id = engine.create_playbook(ORG_A, _RANSOMWARE_PLAYBOOK)
    pb = engine.get_playbook(pb_id, ORG_A)
    assert pb["trigger_conditions"]["alert_type"] == "ransomware_detected"


# ---------------------------------------------------------------------------
# list_playbooks
# ---------------------------------------------------------------------------


def test_list_playbooks_empty_for_new_org(engine):
    assert engine.list_playbooks(ORG_A) == []


def test_list_playbooks_returns_created_playbooks(engine):
    engine.create_playbook(ORG_A, _RANSOMWARE_PLAYBOOK)
    engine.create_playbook(ORG_A, _SIMPLE_PLAYBOOK)
    pbs = engine.list_playbooks(ORG_A)
    assert len(pbs) == 2


def test_list_playbooks_org_isolation(engine):
    engine.create_playbook(ORG_A, _RANSOMWARE_PLAYBOOK)
    engine.create_playbook(ORG_B, _SIMPLE_PLAYBOOK)
    a_pbs = engine.list_playbooks(ORG_A)
    b_pbs = engine.list_playbooks(ORG_B)
    assert len(a_pbs) == 1
    assert len(b_pbs) == 1
    assert a_pbs[0]["name"] == "Ransomware Response"
    assert b_pbs[0]["name"] == "Simple Manual Playbook"


def test_list_playbooks_fields(engine):
    engine.create_playbook(ORG_A, _RANSOMWARE_PLAYBOOK)
    pb = engine.list_playbooks(ORG_A)[0]
    assert "id" in pb
    assert "name" in pb
    assert "trigger_type" in pb
    assert "steps" in pb
    assert "enabled" in pb
    assert "created_at" in pb


# ---------------------------------------------------------------------------
# get_playbook
# ---------------------------------------------------------------------------


def test_get_playbook_returns_correct_record(engine):
    pb_id = engine.create_playbook(ORG_A, _RANSOMWARE_PLAYBOOK)
    pb = engine.get_playbook(pb_id, ORG_A)
    assert pb["id"] == pb_id
    assert pb["name"] == "Ransomware Response"


def test_get_playbook_returns_none_for_wrong_org(engine):
    pb_id = engine.create_playbook(ORG_A, _RANSOMWARE_PLAYBOOK)
    result = engine.get_playbook(pb_id, ORG_B)
    assert result is None


def test_get_playbook_returns_none_for_unknown_id(engine):
    result = engine.get_playbook("nonexistent-id", ORG_A)
    assert result is None


def test_get_playbook_enabled_field_is_bool(engine):
    pb_id = engine.create_playbook(ORG_A, _RANSOMWARE_PLAYBOOK)
    pb = engine.get_playbook(pb_id, ORG_A)
    assert isinstance(pb["enabled"], bool)
    assert pb["enabled"] is True


def test_get_playbook_disabled_flag(engine):
    disabled_pb = dict(_SIMPLE_PLAYBOOK, enabled=False)
    pb_id = engine.create_playbook(ORG_A, disabled_pb)
    pb = engine.get_playbook(pb_id, ORG_A)
    assert pb["enabled"] is False


# ---------------------------------------------------------------------------
# execute_playbook
# ---------------------------------------------------------------------------


def test_execute_playbook_returns_result_dict(engine):
    pb_id = engine.create_playbook(ORG_A, _RANSOMWARE_PLAYBOOK)
    result = engine.execute_playbook(pb_id, ORG_A, context={"host": "server-01"})
    assert "execution_id" in result
    assert "status" in result
    assert "steps_completed" in result
    assert "steps_failed" in result
    assert "duration_ms" in result
    assert "output" in result


def test_execute_playbook_completed_status(engine):
    pb_id = engine.create_playbook(ORG_A, _RANSOMWARE_PLAYBOOK)
    result = engine.execute_playbook(pb_id, ORG_A, context={})
    assert result["status"] == "completed"


def test_execute_playbook_steps_completed_count(engine):
    pb_id = engine.create_playbook(ORG_A, _RANSOMWARE_PLAYBOOK)
    result = engine.execute_playbook(pb_id, ORG_A, context={})
    assert result["steps_completed"] == 2
    assert result["steps_failed"] == 0


def test_execute_playbook_output_has_steps(engine):
    pb_id = engine.create_playbook(ORG_A, _RANSOMWARE_PLAYBOOK)
    result = engine.execute_playbook(pb_id, ORG_A, context={"host": "web-01"})
    assert "steps" in result["output"]
    assert len(result["output"]["steps"]) == 2


def test_execute_playbook_output_context_keys(engine):
    pb_id = engine.create_playbook(ORG_A, _SIMPLE_PLAYBOOK)
    result = engine.execute_playbook(pb_id, ORG_A, context={"ip": "1.2.3.4", "user": "alice"})
    assert set(result["output"]["context_keys"]) == {"ip", "user"}


def test_execute_playbook_wrong_org_raises(engine):
    pb_id = engine.create_playbook(ORG_A, _SIMPLE_PLAYBOOK)
    with pytest.raises(ValueError, match="not found"):
        engine.execute_playbook(pb_id, ORG_B, context={})


def test_execute_playbook_nonexistent_id_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.execute_playbook("bad-id", ORG_A, context={})


def test_execute_playbook_duration_is_non_negative(engine):
    pb_id = engine.create_playbook(ORG_A, _SIMPLE_PLAYBOOK)
    result = engine.execute_playbook(pb_id, ORG_A, context={})
    assert result["duration_ms"] >= 0


def test_execute_playbook_empty_steps_playbook(engine):
    empty_pb = {"name": "Empty", "trigger_type": "manual", "steps": []}
    pb_id = engine.create_playbook(ORG_A, empty_pb)
    result = engine.execute_playbook(pb_id, ORG_A, context={})
    assert result["steps_completed"] == 0
    assert result["steps_failed"] == 0
    assert result["status"] == "completed"


# ---------------------------------------------------------------------------
# list_executions / get_execution
# ---------------------------------------------------------------------------


def test_list_executions_empty_initially(engine):
    assert engine.list_executions(ORG_A) == []


def test_list_executions_returns_history(engine):
    pb_id = engine.create_playbook(ORG_A, _SIMPLE_PLAYBOOK)
    engine.execute_playbook(pb_id, ORG_A, context={})
    engine.execute_playbook(pb_id, ORG_A, context={})
    execs = engine.list_executions(ORG_A)
    assert len(execs) == 2


def test_list_executions_org_isolation(engine):
    pb_a = engine.create_playbook(ORG_A, _SIMPLE_PLAYBOOK)
    pb_b = engine.create_playbook(ORG_B, _SIMPLE_PLAYBOOK)
    engine.execute_playbook(pb_a, ORG_A, context={})
    engine.execute_playbook(pb_b, ORG_B, context={})
    assert len(engine.list_executions(ORG_A)) == 1
    assert len(engine.list_executions(ORG_B)) == 1


def test_list_executions_limit_respected(engine):
    pb_id = engine.create_playbook(ORG_A, _SIMPLE_PLAYBOOK)
    for _ in range(10):
        engine.execute_playbook(pb_id, ORG_A, context={})
    execs = engine.list_executions(ORG_A, limit=5)
    assert len(execs) == 5


def test_get_execution_returns_record(engine):
    pb_id = engine.create_playbook(ORG_A, _SIMPLE_PLAYBOOK)
    run = engine.execute_playbook(pb_id, ORG_A, context={})
    exec_id = run["execution_id"]
    rec = engine.get_execution(exec_id, ORG_A)
    assert rec is not None
    assert rec["id"] == exec_id
    assert rec["playbook_id"] == pb_id


def test_get_execution_org_isolation(engine):
    pb_id = engine.create_playbook(ORG_A, _SIMPLE_PLAYBOOK)
    run = engine.execute_playbook(pb_id, ORG_A, context={})
    exec_id = run["execution_id"]
    assert engine.get_execution(exec_id, ORG_B) is None


def test_get_execution_returns_none_for_unknown_id(engine):
    assert engine.get_execution("no-such-id", ORG_A) is None


# ---------------------------------------------------------------------------
# get_builtin_playbooks
# ---------------------------------------------------------------------------


def test_get_builtin_playbooks_returns_5(engine):
    builtins = engine.get_builtin_playbooks()
    assert len(builtins) == 5


def test_get_builtin_playbooks_names(engine):
    names = {pb["name"] for pb in engine.get_builtin_playbooks()}
    assert "Ransomware Response" in names
    assert "Phishing Response" in names
    assert "Credential Stuffing" in names
    assert "Data Exfiltration Alert" in names
    assert "Privilege Escalation" in names


def test_get_builtin_playbooks_have_steps(engine):
    for pb in engine.get_builtin_playbooks():
        assert len(pb["steps"]) > 0


def test_get_builtin_playbooks_does_not_require_org(engine):
    # Should succeed with no org_id argument
    builtins = engine.get_builtin_playbooks()
    assert isinstance(builtins, list)
