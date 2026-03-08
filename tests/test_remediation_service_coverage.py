"""Tests for RemediationService — status enums, transitions, SLA policies."""

from core.services.remediation import (
    RemediationStatus,
    VALID_TRANSITIONS,
    DEFAULT_SLA_POLICIES,
    RemediationService,
)


class TestRemediationStatus:
    def test_all_statuses(self):
        assert RemediationStatus.OPEN.value == "open"
        assert RemediationStatus.ASSIGNED.value == "assigned"
        assert RemediationStatus.IN_PROGRESS.value == "in_progress"
        assert RemediationStatus.VERIFICATION.value == "verification"
        assert RemediationStatus.RESOLVED.value == "resolved"
        assert RemediationStatus.DEFERRED.value == "deferred"
        assert RemediationStatus.WONT_FIX.value == "wont_fix"

    def test_status_count(self):
        assert len(RemediationStatus) == 7

    def test_string_enum(self):
        assert isinstance(RemediationStatus.OPEN, str)


class TestValidTransitions:
    def test_open_transitions(self):
        valid = VALID_TRANSITIONS[RemediationStatus.OPEN]
        assert RemediationStatus.ASSIGNED in valid
        assert RemediationStatus.DEFERRED in valid
        assert RemediationStatus.WONT_FIX in valid

    def test_assigned_transitions(self):
        valid = VALID_TRANSITIONS[RemediationStatus.ASSIGNED]
        assert RemediationStatus.IN_PROGRESS in valid
        assert RemediationStatus.DEFERRED in valid

    def test_in_progress_transitions(self):
        valid = VALID_TRANSITIONS[RemediationStatus.IN_PROGRESS]
        assert RemediationStatus.VERIFICATION in valid

    def test_verification_transitions(self):
        valid = VALID_TRANSITIONS[RemediationStatus.VERIFICATION]
        assert RemediationStatus.RESOLVED in valid
        assert RemediationStatus.IN_PROGRESS in valid

    def test_resolved_can_reopen(self):
        valid = VALID_TRANSITIONS[RemediationStatus.RESOLVED]
        assert RemediationStatus.OPEN in valid

    def test_wont_fix_can_reopen(self):
        valid = VALID_TRANSITIONS[RemediationStatus.WONT_FIX]
        assert RemediationStatus.OPEN in valid

    def test_deferred_transitions(self):
        valid = VALID_TRANSITIONS[RemediationStatus.DEFERRED]
        assert RemediationStatus.OPEN in valid

    def test_all_statuses_have_transitions(self):
        for status in RemediationStatus:
            assert status in VALID_TRANSITIONS


class TestDefaultSLAPolicies:
    def test_critical_sla(self):
        assert DEFAULT_SLA_POLICIES["critical"] == 24

    def test_high_sla(self):
        assert DEFAULT_SLA_POLICIES["high"] == 72

    def test_medium_sla(self):
        assert DEFAULT_SLA_POLICIES["medium"] == 168

    def test_low_sla(self):
        assert DEFAULT_SLA_POLICIES["low"] == 720


class TestRemediationService:
    def test_init(self, tmp_path):
        db_path = tmp_path / "remediation" / "tasks.db"
        svc = RemediationService(db_path)
        assert svc.db_path == db_path
        assert db_path.exists()

    def test_custom_sla(self, tmp_path):
        svc = RemediationService(
            tmp_path / "tasks.db",
            sla_policies={"critical": 12, "high": 48},
        )
        assert svc.sla_policies["critical"] == 12
        assert svc.sla_policies["high"] == 48

    def test_create_task(self, tmp_path):
        svc = RemediationService(tmp_path / "tasks.db")
        task = svc.create_task(
            cluster_id="c1",
            org_id="org-1",
            app_id="APP-001",
            title="Fix SQL injection",
            severity="critical",
        )
        assert task is not None
        assert isinstance(task, dict)
        assert task.get("title") == "Fix SQL injection" or "task_id" in task

    def test_list_tasks(self, tmp_path):
        svc = RemediationService(tmp_path / "tasks.db")
        svc.create_task(
            cluster_id="c1",
            org_id="org-1",
            app_id="APP-001",
            title="Test task",
            severity="high",
        )
        tasks = svc.get_tasks(org_id="org-1")
        assert isinstance(tasks, list)
