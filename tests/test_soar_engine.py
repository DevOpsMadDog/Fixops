"""
Comprehensive tests for the SOAR Engine — 35+ tests covering:
- SOAREngine: playbook CRUD, trigger evaluation, manual execution,
  execution history, stats, MTTR
- Default playbooks: all 7 seeded on fresh DB
- Condition matching logic
- Action simulation
- Multi-tenant isolation (separate org_ids)
- Router endpoints (via direct engine calls, no HTTP)

Run with: python -m pytest tests/test_soar_engine.py -v --timeout=15
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.soar_engine import (
    ExecutionStatus,
    PlaybookStats,
    PlaybookTrigger,
    SOARAction,
    SOAREngine,
    SOARExecution,
    SOARPlaybook,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def engine(tmp_path):
    """Fresh SOAREngine backed by a temp SQLite DB."""
    return SOAREngine(db_path=str(tmp_path / "soar_test.db"))


@pytest.fixture
def custom_org():
    return f"org-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def sample_actions() -> List[Dict[str, Any]]:
    return [
        {"action": SOARAction.CREATE_TICKET, "priority": "P1"},
        {"action": SOARAction.SEND_ALERT, "channel": "slack"},
    ]


@pytest.fixture
def critical_playbook(engine, sample_actions):
    return engine.create_playbook(
        name="Test Critical Playbook",
        trigger=PlaybookTrigger.FINDING_CRITICAL,
        actions=sample_actions,
        conditions={"severity": "critical"},
        org_id="testorg",
    )


# ============================================================================
# DEFAULT PLAYBOOKS
# ============================================================================


class TestDefaultPlaybooks:
    def test_seven_defaults_seeded(self, engine):
        playbooks = engine.list_playbooks(org_id="default")
        assert len(playbooks) == 7

    def test_all_triggers_covered(self, engine):
        playbooks = engine.list_playbooks(org_id="default")
        triggers = {pb.trigger for pb in playbooks}
        assert triggers == set(PlaybookTrigger)

    def test_defaults_enabled(self, engine):
        playbooks = engine.list_playbooks(org_id="default")
        assert all(pb.enabled for pb in playbooks)

    def test_defaults_have_actions(self, engine):
        playbooks = engine.list_playbooks(org_id="default")
        assert all(len(pb.actions) > 0 for pb in playbooks)

    def test_default_critical_playbook_exists(self, engine):
        pb = engine.get_playbook("soar-default-critical", org_id="default")
        assert pb is not None
        assert pb.trigger == PlaybookTrigger.FINDING_CRITICAL

    def test_default_insider_threat_playbook_exists(self, engine):
        pb = engine.get_playbook("soar-default-insider", org_id="default")
        assert pb is not None
        assert pb.trigger == PlaybookTrigger.INSIDER_THREAT


# ============================================================================
# CREATE PLAYBOOK
# ============================================================================


class TestCreatePlaybook:
    def test_create_returns_soar_playbook(self, engine, sample_actions):
        pb = engine.create_playbook(
            name="My Playbook",
            trigger=PlaybookTrigger.SLA_BREACH,
            actions=sample_actions,
            org_id="testorg",
        )
        assert isinstance(pb, SOARPlaybook)
        assert pb.name == "My Playbook"
        assert pb.trigger == PlaybookTrigger.SLA_BREACH
        assert pb.enabled is True

    def test_create_assigns_id(self, engine, sample_actions):
        pb = engine.create_playbook(
            name="X", trigger=PlaybookTrigger.ANOMALY_DETECTED, actions=sample_actions
        )
        assert pb.id and len(pb.id) > 0

    def test_create_persists_to_db(self, engine, sample_actions):
        pb = engine.create_playbook(
            name="Persistent", trigger=PlaybookTrigger.COMPLIANCE_GAP, actions=sample_actions
        )
        retrieved = engine.get_playbook(pb.id)
        assert retrieved is not None
        assert retrieved.name == "Persistent"

    def test_create_with_conditions(self, engine, sample_actions):
        pb = engine.create_playbook(
            name="Conditional",
            trigger=PlaybookTrigger.FINDING_HIGH,
            actions=sample_actions,
            conditions={"env": "production", "region": "us-east-1"},
        )
        assert pb.conditions == {"env": "production", "region": "us-east-1"}

    def test_create_disabled(self, engine, sample_actions):
        pb = engine.create_playbook(
            name="Disabled PB", trigger=PlaybookTrigger.INCIDENT_CREATED,
            actions=sample_actions, enabled=False,
        )
        assert pb.enabled is False

    def test_create_org_isolation(self, engine, sample_actions):
        pb_a = engine.create_playbook(
            name="OrgA PB", trigger=PlaybookTrigger.SLA_BREACH, actions=sample_actions, org_id="org-a"
        )
        pb_b = engine.create_playbook(
            name="OrgB PB", trigger=PlaybookTrigger.SLA_BREACH, actions=sample_actions, org_id="org-b"
        )
        org_a_pbs = engine.list_playbooks(org_id="org-a")
        assert any(p.id == pb_a.id for p in org_a_pbs)
        assert not any(p.id == pb_b.id for p in org_a_pbs)


# ============================================================================
# GET / LIST PLAYBOOKS
# ============================================================================


class TestGetListPlaybooks:
    def test_get_existing(self, engine, critical_playbook):
        pb = engine.get_playbook(critical_playbook.id, org_id="testorg")
        assert pb is not None
        assert pb.id == critical_playbook.id

    def test_get_nonexistent_returns_none(self, engine):
        pb = engine.get_playbook("does-not-exist", org_id="testorg")
        assert pb is None

    def test_list_returns_created(self, engine, critical_playbook):
        pbs = engine.list_playbooks(org_id="testorg")
        ids = [p.id for p in pbs]
        assert critical_playbook.id in ids

    def test_list_empty_org_returns_empty(self, engine):
        pbs = engine.list_playbooks(org_id="nonexistent-org-xyz")
        assert pbs == []


# ============================================================================
# EVALUATE TRIGGER
# ============================================================================


class TestEvaluateTrigger:
    def test_trigger_fires_matching_playbook(self, engine, critical_playbook):
        executions = engine.evaluate_trigger(
            event={"trigger": "finding_critical", "severity": "critical"},
            org_id="testorg",
        )
        assert len(executions) >= 1
        exec_ids = [e.playbook_id for e in executions]
        assert critical_playbook.id in exec_ids

    def test_trigger_skips_condition_mismatch(self, engine, sample_actions):
        pb = engine.create_playbook(
            name="Condition PB",
            trigger=PlaybookTrigger.FINDING_HIGH,
            actions=sample_actions,
            conditions={"env": "production"},
            org_id="condorg",
        )
        executions = engine.evaluate_trigger(
            event={"trigger": "finding_high", "env": "staging"},
            org_id="condorg",
        )
        assert not any(e.playbook_id == pb.id for e in executions)

    def test_trigger_fires_no_conditions(self, engine, sample_actions):
        pb = engine.create_playbook(
            name="No Cond PB",
            trigger=PlaybookTrigger.INCIDENT_CREATED,
            actions=sample_actions,
            conditions={},
            org_id="nocondorg",
        )
        executions = engine.evaluate_trigger(
            event={"trigger": "incident_created"},
            org_id="nocondorg",
        )
        assert any(e.playbook_id == pb.id for e in executions)

    def test_trigger_skips_disabled_playbook(self, engine, sample_actions):
        pb = engine.create_playbook(
            name="Disabled",
            trigger=PlaybookTrigger.ANOMALY_DETECTED,
            actions=sample_actions,
            enabled=False,
            org_id="disabledorg",
        )
        executions = engine.evaluate_trigger(
            event={"trigger": "anomaly_detected"},
            org_id="disabledorg",
        )
        assert not any(e.playbook_id == pb.id for e in executions)

    def test_trigger_unknown_returns_empty(self, engine):
        result = engine.evaluate_trigger(
            event={"trigger": "nonexistent_trigger"}, org_id="default"
        )
        assert result == []

    def test_trigger_missing_key_returns_empty(self, engine):
        result = engine.evaluate_trigger(event={"severity": "critical"}, org_id="default")
        assert result == []

    def test_trigger_execution_status_completed(self, engine, critical_playbook):
        executions = engine.evaluate_trigger(
            event={"trigger": "finding_critical", "severity": "critical"},
            org_id="testorg",
        )
        relevant = [e for e in executions if e.playbook_id == critical_playbook.id]
        assert len(relevant) == 1
        assert relevant[0].status in (ExecutionStatus.COMPLETED, ExecutionStatus.PARTIAL)


# ============================================================================
# EXECUTE PLAYBOOK
# ============================================================================


class TestExecutePlaybook:
    def test_manual_execute_returns_execution(self, engine, critical_playbook):
        execution = engine.execute_playbook(
            playbook_id=critical_playbook.id,
            context={"reason": "manual test"},
            org_id="testorg",
        )
        assert isinstance(execution, SOARExecution)
        assert execution.playbook_id == critical_playbook.id

    def test_manual_execute_has_actions_taken(self, engine, critical_playbook):
        execution = engine.execute_playbook(
            playbook_id=critical_playbook.id, org_id="testorg"
        )
        assert len(execution.actions_taken) > 0

    def test_manual_execute_completed_at_set(self, engine, critical_playbook):
        execution = engine.execute_playbook(
            playbook_id=critical_playbook.id, org_id="testorg"
        )
        assert execution.completed_at is not None

    def test_manual_execute_nonexistent_raises(self, engine):
        with pytest.raises(ValueError, match="not found"):
            engine.execute_playbook("no-such-playbook", org_id="testorg")

    def test_manual_execute_disabled_raises(self, engine, sample_actions):
        pb = engine.create_playbook(
            name="Dis PB", trigger=PlaybookTrigger.SLA_BREACH,
            actions=sample_actions, enabled=False, org_id="disorg",
        )
        with pytest.raises(ValueError, match="disabled"):
            engine.execute_playbook(pb.id, org_id="disorg")

    def test_manual_execute_updates_execution_count(self, engine, critical_playbook):
        engine.execute_playbook(playbook_id=critical_playbook.id, org_id="testorg")
        pb = engine.get_playbook(critical_playbook.id, org_id="testorg")
        assert pb.execution_count >= 1


# ============================================================================
# EXECUTION HISTORY
# ============================================================================


class TestExecutionHistory:
    def test_history_records_executions(self, engine, critical_playbook):
        engine.execute_playbook(playbook_id=critical_playbook.id, org_id="testorg")
        engine.execute_playbook(playbook_id=critical_playbook.id, org_id="testorg")
        history = engine.get_execution_history(org_id="testorg")
        assert len(history) >= 2

    def test_history_filter_by_playbook(self, engine, critical_playbook, sample_actions):
        pb2 = engine.create_playbook(
            name="Another", trigger=PlaybookTrigger.SLA_BREACH,
            actions=sample_actions, org_id="testorg",
        )
        engine.execute_playbook(critical_playbook.id, org_id="testorg")
        engine.execute_playbook(pb2.id, org_id="testorg")
        filtered = engine.get_execution_history(org_id="testorg", playbook_id=critical_playbook.id)
        assert all(e.playbook_id == critical_playbook.id for e in filtered)

    def test_history_org_isolation(self, engine, sample_actions):
        pb = engine.create_playbook(
            name="Isolated", trigger=PlaybookTrigger.INCIDENT_CREATED,
            actions=sample_actions, org_id="org-isolated",
        )
        engine.execute_playbook(pb.id, org_id="org-isolated")
        history_other = engine.get_execution_history(org_id="org-other-xyz")
        assert all(e.org_id != "org-isolated" for e in history_other)

    def test_history_limit_respected(self, engine, critical_playbook):
        for _ in range(5):
            engine.execute_playbook(critical_playbook.id, org_id="testorg")
        history = engine.get_execution_history(org_id="testorg", limit=2)
        assert len(history) <= 2


# ============================================================================
# STATS
# ============================================================================


class TestPlaybookStats:
    def test_stats_returns_playbook_stats(self, engine):
        stats = engine.get_playbook_stats(org_id="default")
        assert isinstance(stats, PlaybookStats)

    def test_stats_counts_playbooks(self, engine):
        stats = engine.get_playbook_stats(org_id="default")
        assert stats.total_playbooks == 7
        assert stats.enabled_playbooks == 7

    def test_stats_after_execution(self, engine):
        pb = engine.get_playbook("soar-default-incident", org_id="default")
        engine.execute_playbook(pb.id, org_id="default")
        stats = engine.get_playbook_stats(org_id="default")
        assert stats.total_executions >= 1

    def test_stats_by_trigger(self, engine):
        pb = engine.get_playbook("soar-default-sla", org_id="default")
        engine.execute_playbook(pb.id, org_id="default")
        stats = engine.get_playbook_stats(org_id="default")
        assert stats.executions_by_trigger.get("sla_breach", 0) >= 1

    def test_stats_empty_org(self, engine):
        stats = engine.get_playbook_stats(org_id="org-empty-xyz")
        assert stats.total_playbooks == 0
        assert stats.total_executions == 0


# ============================================================================
# MTTR
# ============================================================================


class TestMTTR:
    def test_mttr_zero_no_executions(self, engine):
        mttr = engine.get_mean_time_to_respond(org_id="mttr-empty-org")
        assert mttr == 0.0

    def test_mttr_positive_after_execution(self, engine):
        pb = engine.get_playbook("soar-default-anomaly", org_id="default")
        engine.execute_playbook(pb.id, org_id="default")
        mttr = engine.get_mean_time_to_respond(org_id="default")
        assert mttr >= 0.0

    def test_mttr_returns_float(self, engine):
        mttr = engine.get_mean_time_to_respond(org_id="default")
        assert isinstance(mttr, float)


# ============================================================================
# ENABLE / DISABLE
# ============================================================================


class TestEnableDisable:
    def test_disable_playbook(self, engine, critical_playbook):
        result = engine.disable_playbook(critical_playbook.id, org_id="testorg")
        assert result is True
        pb = engine.get_playbook(critical_playbook.id, org_id="testorg")
        assert pb.enabled is False

    def test_enable_playbook(self, engine, critical_playbook):
        engine.disable_playbook(critical_playbook.id, org_id="testorg")
        result = engine.enable_playbook(critical_playbook.id, org_id="testorg")
        assert result is True
        pb = engine.get_playbook(critical_playbook.id, org_id="testorg")
        assert pb.enabled is True

    def test_disable_nonexistent_returns_false(self, engine):
        result = engine.disable_playbook("nonexistent-id", org_id="testorg")
        assert result is False


# ============================================================================
# ENUM COVERAGE
# ============================================================================


class TestEnums:
    def test_all_triggers_valid(self):
        expected = {
            "finding_critical", "finding_high", "incident_created", "sla_breach",
            "anomaly_detected", "insider_threat", "compliance_gap",
        }
        assert {t.value for t in PlaybookTrigger} == expected

    def test_all_actions_valid(self):
        expected = {
            "create_ticket", "send_alert", "block_ip", "quarantine_host",
            "rotate_credentials", "run_scan", "escalate", "update_firewall",
            "collect_evidence",
        }
        assert {a.value for a in SOARAction} == expected

    def test_trigger_count(self):
        assert len(PlaybookTrigger) == 7

    def test_action_count(self):
        assert len(SOARAction) == 9
