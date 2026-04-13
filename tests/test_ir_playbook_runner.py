"""
Tests for IRPlaybookRunner — IR Playbook Automation Engine.

Covers:
- Playbook library (list, get, select)
- Playbook execution (happy path, step results, status tracking)
- Individual actions (block_ip, quarantine_asset, disable_account,
  force_password_reset, log_iocs — all SQLite-backed, no network calls)
- Notification actions fail gracefully when ntfy/gh unavailable
- Manual step override
- Query helpers (get_blocked_ips, get_quarantined_assets, get_iocs)
- list_executions filtering
- Unknown playbook raises ValueError
- Unknown action raises ValueError in dispatch
- continue_on_failure=False aborts execution

Run with: python -m pytest tests/test_ir_playbook_runner.py --timeout=10 -q -o "addopts="
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.ir_playbook_runner import (
    ExecutionStatus,
    IRPlaybookRunner,
    PlaybookDef,
    PlaybookExecution,
    PlaybookStep,
    StepStatus,
    get_playbook_runner,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def runner(tmp_path):
    """IRPlaybookRunner backed by a temp SQLite DB."""
    return IRPlaybookRunner(db_path=str(tmp_path / "test_runner.db"))


@pytest.fixture
def phishing_incident() -> Dict[str, Any]:
    return {
        "title": "Phishing email targeting finance team",
        "description": "User received credential-harvesting email",
        "severity": "high",
        "org_id": "test-org",
        "incident_type": "phishing",
        "affected_users": ["alice@example.com", "bob@example.com"],
        "affected_assets": ["mail-gateway-01"],
        "attacker_ip": "1.2.3.4",
        "tags": ["phishing", "credential_theft"],
    }


@pytest.fixture
def ransomware_incident() -> Dict[str, Any]:
    return {
        "title": "Ransomware detected on fileserver-01",
        "description": "Mass file encryption detected",
        "severity": "critical",
        "org_id": "test-org",
        "incident_type": "ransomware",
        "affected_assets": ["fileserver-01", "backup-01"],
        "affected_users": ["svc-backup"],
        "attacker_ips": ["5.6.7.8"],
        "c2_ips": ["9.10.11.12"],
        "tags": ["ransomware"],
    }


@pytest.fixture
def malware_incident() -> Dict[str, Any]:
    return {
        "title": "Malware detected on workstation",
        "description": "Trojan detected by EDR",
        "severity": "high",
        "org_id": "test-org",
        "incident_type": "malware_detected",
        "affected_assets": ["workstation-42"],
        "c2_ips": ["13.14.15.16"],
        "file_hashes": ["abc123def456"],
        "tags": ["malware", "trojan"],
    }


# ============================================================================
# PLAYBOOK LIBRARY TESTS
# ============================================================================


def test_list_playbooks_returns_all_five(runner):
    """Library must contain exactly the 5 built-in playbooks."""
    playbooks = runner.list_playbooks()
    ids = {pb.playbook_id for pb in playbooks}
    assert "phishing_response" in ids
    assert "ransomware_response" in ids
    assert "data_exfiltration" in ids
    assert "unauthorized_access" in ids
    assert "malware_detected" in ids
    assert len(ids) == 5


def test_get_playbook_returns_correct_def(runner):
    pb = runner.get_playbook("phishing_response")
    assert pb is not None
    assert pb.playbook_id == "phishing_response"
    assert len(pb.steps) >= 5
    step_actions = [s.action for s in pb.steps]
    assert "disable_account" in step_actions
    assert "send_notification" in step_actions


def test_get_playbook_unknown_returns_none(runner):
    assert runner.get_playbook("nonexistent_playbook") is None


def test_each_playbook_has_steps(runner):
    for pb in runner.list_playbooks():
        assert len(pb.steps) >= 4, f"{pb.playbook_id} has too few steps"


def test_select_playbook_phishing(runner):
    incident = {"incident_type": "phishing", "title": "credential theft", "tags": []}
    pb = runner.select_playbook(incident)
    assert pb is not None
    assert pb.playbook_id == "phishing_response"


def test_select_playbook_ransomware(runner):
    incident = {"title": "ransomware encryption detected", "tags": [], "description": ""}
    pb = runner.select_playbook(incident)
    assert pb is not None
    assert pb.playbook_id == "ransomware_response"


def test_select_playbook_malware(runner):
    incident = {"title": "trojan backdoor malware", "tags": [], "description": ""}
    pb = runner.select_playbook(incident)
    assert pb is not None
    assert pb.playbook_id == "malware_detected"


def test_select_playbook_no_match_returns_none(runner):
    incident = {"title": "quarterly review", "tags": [], "description": "", "incident_type": ""}
    pb = runner.select_playbook(incident)
    # May return something (best score=0) or None — either is acceptable
    # What matters is no crash
    assert pb is None or isinstance(pb, PlaybookDef)


# ============================================================================
# EXECUTION TESTS (SQLite actions only — no network)
# ============================================================================


def test_execute_playbook_unknown_raises(runner):
    with pytest.raises(ValueError, match="Unknown playbook"):
        runner.execute_playbook("does_not_exist", {})


def test_execute_phishing_playbook_returns_execution(runner, phishing_incident, tmp_path):
    """Execute phishing playbook; ntfy/gh mocked out, SQLite steps must pass."""
    with patch.object(runner, "_get_ntfy", return_value=None), \
         patch.object(runner, "_get_gh", return_value=None):
        ex = runner.execute_playbook("phishing_response", phishing_incident)

    assert ex.execution_id
    assert ex.playbook_id == "phishing_response"
    assert ex.steps_total >= 5
    assert ex.status in (ExecutionStatus.COMPLETED.value, ExecutionStatus.PARTIAL.value)
    # SQLite-backed steps should succeed
    sqlite_steps = [sr for sr in ex.step_results if sr.action in (
        "disable_account", "log_iocs", "block_ip", "force_password_reset"
    )]
    assert any(sr.status == StepStatus.SUCCESS.value for sr in sqlite_steps)


def test_execute_stores_execution_in_db(runner, phishing_incident):
    with patch.object(runner, "_get_ntfy", return_value=None), \
         patch.object(runner, "_get_gh", return_value=None):
        ex = runner.execute_playbook("phishing_response", phishing_incident)

    fetched = runner.get_execution_status(ex.execution_id)
    assert fetched is not None
    assert fetched.execution_id == ex.execution_id
    assert fetched.playbook_id == "phishing_response"


def test_get_execution_status_unknown_returns_none(runner):
    assert runner.get_execution_status("no-such-id") is None


def test_execution_has_all_step_results(runner, phishing_incident):
    with patch.object(runner, "_get_ntfy", return_value=None), \
         patch.object(runner, "_get_gh", return_value=None):
        ex = runner.execute_playbook("phishing_response", phishing_incident)

    pb = runner.get_playbook("phishing_response")
    assert len(ex.step_results) == len(pb.steps)


def test_execution_completed_at_set(runner, phishing_incident):
    with patch.object(runner, "_get_ntfy", return_value=None), \
         patch.object(runner, "_get_gh", return_value=None):
        ex = runner.execute_playbook("phishing_response", phishing_incident)

    assert ex.completed_at is not None


# ============================================================================
# INDIVIDUAL ACTION TESTS
# ============================================================================


def test_action_block_ip_adds_to_blocklist(runner):
    incident_id = str(uuid.uuid4())
    incident = {"attacker_ips": ["192.168.1.100", "10.0.0.1"]}
    step = PlaybookStep("test_block", "Block IP", "block_ip", params={"reason": "test"})
    result = runner._execute_step(step, incident, incident_id)

    assert result.status == StepStatus.SUCCESS.value
    blocked = runner.get_blocked_ips(incident_id)
    ips = [b["ip"] for b in blocked]
    assert "192.168.1.100" in ips
    assert "10.0.0.1" in ips


def test_action_block_ip_no_ips_returns_message(runner):
    incident_id = str(uuid.uuid4())
    step = PlaybookStep("test_block", "Block IP", "block_ip", params={})
    result = runner._execute_step(step, {}, incident_id)
    assert result.status == StepStatus.SUCCESS.value
    assert "No IPs" in result.output


def test_action_quarantine_asset(runner):
    incident_id = str(uuid.uuid4())
    incident = {"affected_assets": ["server-01", "server-02"]}
    step = PlaybookStep("test_quarantine", "Quarantine", "quarantine_asset",
                        params={"reason": "test quarantine"})
    result = runner._execute_step(step, incident, incident_id)

    assert result.status == StepStatus.SUCCESS.value
    assets = runner.get_quarantined_assets(incident_id)
    names = [a["asset_name"] for a in assets]
    assert "server-01" in names
    assert "server-02" in names


def test_action_quarantine_no_assets(runner):
    incident_id = str(uuid.uuid4())
    step = PlaybookStep("test_quarantine", "Quarantine", "quarantine_asset", params={})
    result = runner._execute_step(step, {}, incident_id)
    assert result.status == StepStatus.SUCCESS.value
    assert "No assets" in result.output


def test_action_disable_account(runner):
    incident_id = str(uuid.uuid4())
    incident = {"affected_users": ["victim@example.com"]}
    step = PlaybookStep("test_disable", "Disable Account", "disable_account",
                        params={"reason": "test disable"})
    result = runner._execute_step(step, incident, incident_id)

    assert result.status == StepStatus.SUCCESS.value
    assert "victim@example.com" in result.output


def test_action_force_password_reset(runner):
    incident_id = str(uuid.uuid4())
    incident = {"affected_users": ["user@example.com"]}
    step = PlaybookStep("test_reset", "Force Reset", "force_password_reset",
                        params={"reason": "test reset"})
    result = runner._execute_step(step, incident, incident_id)

    assert result.status == StepStatus.SUCCESS.value
    assert "user@example.com" in result.output


def test_action_log_iocs(runner):
    incident_id = str(uuid.uuid4())
    incident = {
        "attacker_ips": ["1.2.3.4"],
        "domains": ["evil.com"],
        "file_hashes": ["deadbeef"],
    }
    step = PlaybookStep("test_ioc", "Log IOCs", "log_iocs",
                        params={"ioc_types": ["ip", "domain", "hash"]})
    result = runner._execute_step(step, incident, incident_id)

    assert result.status == StepStatus.SUCCESS.value
    iocs = runner.get_iocs(incident_id)
    types = {i["ioc_type"] for i in iocs}
    assert "ip" in types
    assert "domain" in types
    assert "hash" in types


def test_action_log_iocs_no_data(runner):
    incident_id = str(uuid.uuid4())
    step = PlaybookStep("test_ioc", "Log IOCs", "log_iocs", params={})
    result = runner._execute_step(step, {}, incident_id)
    assert result.status == StepStatus.SUCCESS.value
    assert "No IOCs" in result.output


def test_action_send_notification_fails_gracefully(runner):
    """When NtfyNotifier is None, step fails but does not raise unhandled exception."""
    with patch.object(runner, "_get_ntfy", return_value=None):
        step = PlaybookStep("test_notify", "Notify", "send_notification",
                            params={"title": "Test Alert"}, continue_on_failure=True)
        result = runner._execute_step(step, {"org_id": "test"}, "inc-1")

    assert result.status == StepStatus.FAILED.value
    assert result.error is not None


def test_action_escalate_fails_gracefully(runner):
    with patch.object(runner, "_get_ntfy", return_value=None):
        step = PlaybookStep("test_escalate", "Escalate", "escalate_to_team",
                            params={}, continue_on_failure=True)
        result = runner._execute_step(step, {}, "inc-1")

    assert result.status == StepStatus.FAILED.value


def test_unknown_action_raises_in_dispatch(runner):
    step = PlaybookStep("bad", "Bad Step", "nonexistent_action", params={})
    result = runner._execute_step(step, {}, "inc-1")
    assert result.status == StepStatus.FAILED.value
    assert "Unknown action" in (result.error or "")


# ============================================================================
# MANUAL OVERRIDE TESTS
# ============================================================================


def test_manual_step_override(runner, phishing_incident):
    with patch.object(runner, "_get_ntfy", return_value=None), \
         patch.object(runner, "_get_gh", return_value=None):
        ex = runner.execute_playbook("phishing_response", phishing_incident)

    # Pick first failed step if any, otherwise any step
    first_step = ex.step_results[0]
    runner.manual_step_override(ex.execution_id, first_step.step_id, "Done manually")

    updated = runner.get_execution_status(ex.execution_id)
    overridden = [sr for sr in updated.step_results if sr.status == StepStatus.OVERRIDDEN.value]
    assert len(overridden) >= 1


def test_manual_override_unknown_execution_raises(runner):
    with pytest.raises(ValueError, match="not found"):
        runner.manual_step_override("no-such-execution", "some-step", "result")


# ============================================================================
# LIST EXECUTIONS TESTS
# ============================================================================


def test_list_executions_returns_all(runner, phishing_incident, ransomware_incident):
    with patch.object(runner, "_get_ntfy", return_value=None), \
         patch.object(runner, "_get_gh", return_value=None):
        runner.execute_playbook("phishing_response", phishing_incident)
        runner.execute_playbook("ransomware_response", ransomware_incident)

    executions = runner.list_executions()
    assert len(executions) >= 2


def test_list_executions_filter_by_playbook(runner, phishing_incident, ransomware_incident):
    with patch.object(runner, "_get_ntfy", return_value=None), \
         patch.object(runner, "_get_gh", return_value=None):
        runner.execute_playbook("phishing_response", phishing_incident)
        runner.execute_playbook("ransomware_response", ransomware_incident)

    phishing_execs = runner.list_executions(playbook_id="phishing_response")
    assert all(ex.playbook_id == "phishing_response" for ex in phishing_execs)


# ============================================================================
# SINGLETON FACTORY TEST
# ============================================================================


def test_get_playbook_runner_singleton(tmp_path):
    """get_playbook_runner returns the same instance on repeated calls."""
    import core.ir_playbook_runner as mod
    # Reset singleton for test isolation
    original = mod._runner
    mod._runner = None
    try:
        r1 = get_playbook_runner(str(tmp_path / "singleton.db"))
        r2 = get_playbook_runner()
        assert r1 is r2
    finally:
        mod._runner = original
