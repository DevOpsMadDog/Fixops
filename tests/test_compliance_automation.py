"""
Tests for the Compliance Automation Engine — ALDECI.

Covers:
- ComplianceTask model validation
- ComplianceAutomation: schedule_task, run_task, auto_collect_evidence,
  auto_check_controls, generate_compliance_report, get_automation_dashboard,
  get_due_tasks, seed_framework_recipes, seed_all_frameworks
- All 7 frameworks: SOC2, PCI-DSS, HIPAA, ISO27001, NIST-CSF, CIS, GDPR
- Router endpoints via FastAPI TestClient

35+ tests, all passing.
"""

from __future__ import annotations

import sys
import os
import json
import pytest
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.compliance_automation import (
    ComplianceAutomation,
    ComplianceTask,
    TaskType,
    TaskStatus,
    SUPPORTED_FRAMEWORKS,
    _AUTOMATION_RECIPES,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine() -> ComplianceAutomation:
    """In-memory engine for fast tests."""
    return ComplianceAutomation(db_path=":memory:")


@pytest.fixture
def file_engine(tmp_path) -> ComplianceAutomation:
    """File-backed engine for persistence tests."""
    db = str(tmp_path / "test_compliance.db")
    return ComplianceAutomation(db_path=db)


# ---------------------------------------------------------------------------
# ComplianceTask model tests
# ---------------------------------------------------------------------------


class TestComplianceTaskModel:
    def test_model_defaults(self) -> None:
        task = ComplianceTask(
            framework="SOC2",
            control_id="CC6.1",
            task_type=TaskType.COLLECT_EVIDENCE,
            schedule="24h",
        )
        assert task.id is not None
        assert task.org_id == "default"
        assert task.status == TaskStatus.PENDING.value
        assert task.result is None
        assert task.last_run is None

    def test_model_all_fields(self) -> None:
        now = datetime.now(timezone.utc)
        task = ComplianceTask(
            framework="PCI-DSS",
            control_id="REQ-1",
            task_type=TaskType.RUN_CHECK,
            schedule="12h",
            last_run=now,
            status=TaskStatus.COMPLETED,
            result={"score": 80.0},
            org_id="org-abc",
            description="Firewall check",
            interval_hours=12.0,
        )
        assert task.framework == "PCI-DSS"
        assert task.control_id == "REQ-1"
        assert task.interval_hours == 12.0
        assert task.result == {"score": 80.0}

    def test_model_id_is_unique(self) -> None:
        t1 = ComplianceTask(framework="SOC2", control_id="CC6.1", task_type=TaskType.RUN_CHECK, schedule="24h")
        t2 = ComplianceTask(framework="SOC2", control_id="CC6.1", task_type=TaskType.RUN_CHECK, schedule="24h")
        assert t1.id != t2.id

    def test_all_task_types_valid(self) -> None:
        for tt in TaskType:
            task = ComplianceTask(framework="SOC2", control_id="CC6.1", task_type=tt, schedule="24h")
            assert task.task_type == tt.value

    def test_all_task_statuses_valid(self) -> None:
        for ts in TaskStatus:
            task = ComplianceTask(
                framework="SOC2", control_id="CC6.1", task_type=TaskType.RUN_CHECK,
                schedule="24h", status=ts,
            )
            assert task.status == ts.value


# ---------------------------------------------------------------------------
# schedule_task tests
# ---------------------------------------------------------------------------


class TestScheduleTask:
    def test_creates_task(self, engine: ComplianceAutomation) -> None:
        task = engine.schedule_task("SOC2", "CC6.1", TaskType.COLLECT_EVIDENCE)
        assert task.id is not None
        assert task.framework == "SOC2"
        assert task.control_id == "CC6.1"

    def test_default_org_id(self, engine: ComplianceAutomation) -> None:
        task = engine.schedule_task("SOC2", "CC7.1", TaskType.RUN_CHECK)
        assert task.org_id == "default"

    def test_custom_org_id(self, engine: ComplianceAutomation) -> None:
        task = engine.schedule_task("HIPAA", "164.308a1", TaskType.RUN_CHECK, org_id="acme")
        assert task.org_id == "acme"

    def test_interval_hours_stored(self, engine: ComplianceAutomation) -> None:
        task = engine.schedule_task("SOC2", "CC6.1", TaskType.RUN_CHECK, interval_hours=6.0)
        assert task.interval_hours == 6.0
        assert task.schedule == "6.0h"

    def test_invalid_framework_raises(self, engine: ComplianceAutomation) -> None:
        with pytest.raises(ValueError, match="Unsupported framework"):
            engine.schedule_task("UNKNOWN", "CTL-1", TaskType.RUN_CHECK)

    def test_all_frameworks_accepted(self, engine: ComplianceAutomation) -> None:
        for fw in SUPPORTED_FRAMEWORKS:
            task = engine.schedule_task(fw, "CTL-1", TaskType.RUN_CHECK)
            assert task.framework == fw

    def test_description_stored(self, engine: ComplianceAutomation) -> None:
        task = engine.schedule_task("SOC2", "CC6.1", TaskType.RUN_CHECK, description="My check")
        assert task.description == "My check"

    def test_persistence_in_db(self, file_engine: ComplianceAutomation) -> None:
        task = file_engine.schedule_task("GDPR", "ART-5", TaskType.COLLECT_EVIDENCE)
        dashboard = file_engine.get_automation_dashboard()
        ids = [t["id"] for t in dashboard["tasks"]]
        assert task.id in ids


# ---------------------------------------------------------------------------
# run_task tests
# ---------------------------------------------------------------------------


class TestRunTask:
    def test_run_collect_evidence_task(self, engine: ComplianceAutomation) -> None:
        task = engine.schedule_task("SOC2", "CC7.2", TaskType.COLLECT_EVIDENCE)
        result_task = engine.run_task(task.id)
        assert result_task.status == TaskStatus.COMPLETED.value
        assert result_task.result is not None
        assert result_task.last_run is not None

    def test_run_check_task(self, engine: ComplianceAutomation) -> None:
        task = engine.schedule_task("PCI-DSS", "REQ-6", TaskType.RUN_CHECK)
        result_task = engine.run_task(task.id)
        assert result_task.status == TaskStatus.COMPLETED.value
        assert "implementation_status" in result_task.result

    def test_run_generate_report_task(self, engine: ComplianceAutomation) -> None:
        task = engine.schedule_task("HIPAA", "164.308a8", TaskType.GENERATE_REPORT)
        result_task = engine.run_task(task.id)
        assert result_task.status == TaskStatus.COMPLETED.value
        assert "overall_score" in result_task.result

    def test_run_notify_task(self, engine: ComplianceAutomation) -> None:
        task = engine.schedule_task("SOC2", "CC9.1", TaskType.NOTIFY)
        result_task = engine.run_task(task.id)
        assert result_task.status == TaskStatus.COMPLETED.value
        assert result_task.result.get("notified") is True

    def test_run_nonexistent_task_raises(self, engine: ComplianceAutomation) -> None:
        with pytest.raises(KeyError):
            engine.run_task("00000000-0000-0000-0000-000000000000")

    def test_last_run_updated(self, engine: ComplianceAutomation) -> None:
        task = engine.schedule_task("CIS", "CIS-1", TaskType.RUN_CHECK)
        assert task.last_run is None
        result_task = engine.run_task(task.id)
        assert result_task.last_run is not None


# ---------------------------------------------------------------------------
# auto_collect_evidence tests
# ---------------------------------------------------------------------------


class TestAutoCollectEvidence:
    def test_returns_evidence_items(self, engine: ComplianceAutomation) -> None:
        result = engine.auto_collect_evidence("SOC2", "CC6.1")
        assert "evidence_items" in result
        assert len(result["evidence_items"]) > 0

    def test_all_frameworks_return_evidence(self, engine: ComplianceAutomation) -> None:
        for fw in SUPPORTED_FRAMEWORKS:
            result = engine.auto_collect_evidence(fw, "CTL-1")
            assert result["framework"] == fw
            assert result["collection_status"] == "success"

    def test_metadata_fields_present(self, engine: ComplianceAutomation) -> None:
        result = engine.auto_collect_evidence("GDPR", "ART-30", org_id="myorg")
        assert result["org_id"] == "myorg"
        assert result["control_id"] == "ART-30"
        assert "collected_at" in result
        assert result["total_artifacts"] > 0


# ---------------------------------------------------------------------------
# auto_check_controls tests
# ---------------------------------------------------------------------------


class TestAutoCheckControls:
    def test_returns_check_results(self, engine: ComplianceAutomation) -> None:
        result = engine.auto_check_controls("SOC2", "CC6.1")
        assert "check_results" in result
        assert len(result["check_results"]) > 0

    def test_implementation_status_present(self, engine: ComplianceAutomation) -> None:
        result = engine.auto_check_controls("ISO27001", "A.9.2.1")
        assert result["implementation_status"] in (
            "fully_implemented", "partially_implemented", "not_implemented"
        )

    def test_score_is_percentage(self, engine: ComplianceAutomation) -> None:
        result = engine.auto_check_controls("NIST-CSF", "ID.AM-1")
        assert 0 <= result["score"] <= 100

    def test_gaps_list_present(self, engine: ComplianceAutomation) -> None:
        result = engine.auto_check_controls("CIS", "CIS-7")
        assert "gaps" in result
        assert isinstance(result["gaps"], list)

    def test_all_frameworks_checkable(self, engine: ComplianceAutomation) -> None:
        for fw in SUPPORTED_FRAMEWORKS:
            result = engine.auto_check_controls(fw, "CTL-1", org_id="test")
            assert result["framework"] == fw
            assert "score" in result


# ---------------------------------------------------------------------------
# generate_compliance_report tests
# ---------------------------------------------------------------------------


class TestGenerateComplianceReport:
    def test_report_structure(self, engine: ComplianceAutomation) -> None:
        engine.seed_framework_recipes("SOC2")
        # Run a task so there's result data
        due = engine.get_due_tasks()
        if due:
            engine.run_task(due[0].id)
        report = engine.generate_compliance_report("SOC2")
        assert "report_id" in report
        assert report["framework"] == "SOC2"
        assert "overall_score" in report
        assert "control_summaries" in report
        assert "report_sections" in report

    def test_report_metadata_for_all_frameworks(self, engine: ComplianceAutomation) -> None:
        for fw in SUPPORTED_FRAMEWORKS:
            report = engine.generate_compliance_report(fw)
            assert report["framework"] == fw
            assert "full_name" in report
            assert "issuer" in report

    def test_report_recommendations_present(self, engine: ComplianceAutomation) -> None:
        report = engine.generate_compliance_report("GDPR")
        assert len(report["report_sections"]["recommendations"]) > 0

    def test_empty_framework_report(self, engine: ComplianceAutomation) -> None:
        # No tasks seeded — should still return a valid report
        report = engine.generate_compliance_report("PCI-DSS", org_id="empty-org")
        assert report["total_controls"] == 0
        assert report["overall_score"] == 0.0


# ---------------------------------------------------------------------------
# get_automation_dashboard tests
# ---------------------------------------------------------------------------


class TestGetAutomationDashboard:
    def test_empty_dashboard(self, engine: ComplianceAutomation) -> None:
        dashboard = engine.get_automation_dashboard()
        assert dashboard["total_tasks"] == 0
        assert dashboard["tasks"] == []

    def test_dashboard_after_seeding(self, engine: ComplianceAutomation) -> None:
        engine.seed_framework_recipes("SOC2")
        dashboard = engine.get_automation_dashboard()
        assert dashboard["total_tasks"] == len(_AUTOMATION_RECIPES["SOC2"])
        assert dashboard["framework_summary"].get("SOC2") == len(_AUTOMATION_RECIPES["SOC2"])

    def test_dashboard_has_next_run(self, engine: ComplianceAutomation) -> None:
        engine.schedule_task("SOC2", "CC6.1", TaskType.RUN_CHECK)
        dashboard = engine.get_automation_dashboard()
        task = dashboard["tasks"][0]
        assert "next_run" in task
        assert task["next_run"] is not None

    def test_dashboard_status_summary(self, engine: ComplianceAutomation) -> None:
        engine.seed_framework_recipes("CIS")
        dashboard = engine.get_automation_dashboard()
        assert "status_summary" in dashboard
        # All tasks start as pending
        assert dashboard["status_summary"].get("pending", 0) > 0


# ---------------------------------------------------------------------------
# get_due_tasks tests
# ---------------------------------------------------------------------------


class TestGetDueTasks:
    def test_new_tasks_are_due(self, engine: ComplianceAutomation) -> None:
        # Tasks with last_run=None and created_at in the past are due
        engine.schedule_task("SOC2", "CC6.1", TaskType.RUN_CHECK, interval_hours=0.0)
        due = engine.get_due_tasks()
        assert len(due) >= 1

    def test_recently_run_task_not_due(self, engine: ComplianceAutomation) -> None:
        task = engine.schedule_task("SOC2", "CC7.2", TaskType.RUN_CHECK, interval_hours=100.0)
        # Run it so last_run is set to now
        engine.run_task(task.id)
        due = engine.get_due_tasks()
        due_ids = [t.id for t in due]
        assert task.id not in due_ids

    def test_returns_list(self, engine: ComplianceAutomation) -> None:
        due = engine.get_due_tasks()
        assert isinstance(due, list)


# ---------------------------------------------------------------------------
# seed_framework_recipes tests
# ---------------------------------------------------------------------------


class TestSeedFrameworkRecipes:
    def test_seed_soc2(self, engine: ComplianceAutomation) -> None:
        tasks = engine.seed_framework_recipes("SOC2")
        assert len(tasks) == len(_AUTOMATION_RECIPES["SOC2"])
        for task in tasks:
            assert task.framework == "SOC2"

    def test_seed_all_7_frameworks(self, engine: ComplianceAutomation) -> None:
        results = engine.seed_all_frameworks()
        assert set(results.keys()) == set(SUPPORTED_FRAMEWORKS)
        for fw, tasks in results.items():
            assert len(tasks) == len(_AUTOMATION_RECIPES[fw])

    def test_seed_invalid_framework_raises(self, engine: ComplianceAutomation) -> None:
        with pytest.raises(ValueError):
            engine.seed_framework_recipes("UNKNOWN")

    def test_seeded_tasks_in_dashboard(self, engine: ComplianceAutomation) -> None:
        engine.seed_framework_recipes("GDPR")
        dashboard = engine.get_automation_dashboard()
        assert dashboard["total_tasks"] == len(_AUTOMATION_RECIPES["GDPR"])


# ---------------------------------------------------------------------------
# Router endpoint tests
# ---------------------------------------------------------------------------


class TestComplianceAutomationRouter:
    @pytest.fixture
    def client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from apps.api.compliance_automation_router import router

        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_schedule_task_endpoint(self, client) -> None:
        resp = client.post(
            "/api/v1/compliance-automation/tasks",
            json={
                "framework": "SOC2",
                "control_id": "CC6.1",
                "task_type": "run_check",
                "interval_hours": 24.0,
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["framework"] == "SOC2"
        assert data["id"] is not None

    def test_schedule_task_invalid_framework(self, client) -> None:
        resp = client.post(
            "/api/v1/compliance-automation/tasks",
            json={
                "framework": "INVALID",
                "control_id": "CTL-1",
                "task_type": "run_check",
            },
        )
        assert resp.status_code == 422

    def test_run_task_endpoint(self, client) -> None:
        # Schedule first
        resp = client.post(
            "/api/v1/compliance-automation/tasks",
            json={"framework": "PCI-DSS", "control_id": "REQ-1", "task_type": "run_check"},
        )
        task_id = resp.json()["id"]
        run_resp = client.post(f"/api/v1/compliance-automation/tasks/{task_id}/run")
        assert run_resp.status_code == 200
        assert run_resp.json()["status"] == "completed"

    def test_run_task_not_found(self, client) -> None:
        resp = client.post("/api/v1/compliance-automation/tasks/nonexistent-id/run")
        assert resp.status_code == 404

    def test_collect_evidence_endpoint(self, client) -> None:
        resp = client.post(
            "/api/v1/compliance-automation/evidence/collect",
            json={"framework": "HIPAA", "control_id": "164.308a1"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "HIPAA"
        assert "evidence_items" in data

    def test_check_controls_endpoint(self, client) -> None:
        resp = client.post(
            "/api/v1/compliance-automation/controls/check",
            json={"framework": "ISO27001", "control_id": "A.9.2.1"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "implementation_status" in data
        assert "score" in data

    def test_generate_report_endpoint(self, client) -> None:
        resp = client.get("/api/v1/compliance-automation/reports/NIST-CSF")
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "NIST-CSF"
        assert "overall_score" in data

    def test_generate_report_invalid_framework(self, client) -> None:
        resp = client.get("/api/v1/compliance-automation/reports/BOGUS")
        assert resp.status_code == 422

    def test_dashboard_endpoint(self, client) -> None:
        resp = client.get("/api/v1/compliance-automation/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert "tasks" in data
        assert "total_tasks" in data

    def test_due_tasks_endpoint(self, client) -> None:
        resp = client.get("/api/v1/compliance-automation/tasks/due")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_seed_recipes_endpoint(self, client) -> None:
        resp = client.post("/api/v1/compliance-automation/recipes/CIS")
        assert resp.status_code == 201
        data = resp.json()
        assert data["framework"] == "CIS"
        assert data["tasks_created"] > 0

    def test_seed_recipes_invalid_framework(self, client) -> None:
        resp = client.post("/api/v1/compliance-automation/recipes/NOPE")
        assert resp.status_code == 422
