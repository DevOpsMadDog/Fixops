"""Tests for AI Orchestrator — AIOrchestrator class and REST API router.

Covers:
- AgentRole enum values
- AgentTask / ConsensusResult Pydantic models
- AIOrchestrator.create_task / execute_task / get_task
- multi_agent_consensus decision + confidence
- chain_agents sequential pipeline
- parallel_agents concurrent pipeline
- get_task_history filtering
- get_consensus_stats aggregation
- All 8 REST endpoints via FastAPI TestClient
- Error paths (404, 422, 503)

Usage:
    pytest tests/test_ai_orchestrator.py -v --timeout=30
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Path setup — allow importing suite-core modules directly
# ---------------------------------------------------------------------------
_FIXOPS_ROOT = Path(__file__).parent.parent
_SUITE_CORE = _FIXOPS_ROOT / "suite-core"
_SUITE_API = _FIXOPS_ROOT / "suite-api"

for _p in [str(_FIXOPS_ROOT), str(_SUITE_CORE), str(_SUITE_API)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Minimal env so app.py doesn't fail on missing secrets
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------
from core.ai_orchestrator import (
    AgentRole,
    AgentTask,
    ConsensusResult,
    TaskStatus,
    AIOrchestrator,
    ROLE_TEMPLATES,
    get_orchestrator,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path):
    """Fresh SQLite DB for each test."""
    return str(tmp_path / "test_orchestrator.db")


@pytest.fixture
def orch(tmp_db):
    """AIOrchestrator backed by a temporary DB."""
    return AIOrchestrator(db_path=tmp_db)


# ---------------------------------------------------------------------------
# 1. AgentRole enum
# ---------------------------------------------------------------------------


class TestAgentRole:
    def test_all_six_roles_exist(self):
        roles = {r.value for r in AgentRole}
        assert roles == {
            "analyst", "reviewer", "remediator",
            "investigator", "compliance_checker", "threat_hunter",
        }

    def test_role_is_string_enum(self):
        assert AgentRole.ANALYST == "analyst"
        assert isinstance(AgentRole.REVIEWER, str)

    def test_role_roundtrip(self):
        for role in AgentRole:
            assert AgentRole(role.value) is role


# ---------------------------------------------------------------------------
# 2. Pydantic models
# ---------------------------------------------------------------------------


class TestAgentTask:
    def test_default_id_is_uuid(self):
        task = AgentTask(role=AgentRole.ANALYST, prompt="test")
        uuid.UUID(task.id)  # raises if not valid UUID

    def test_default_status_pending(self):
        task = AgentTask(role=AgentRole.REVIEWER, prompt="review this")
        assert task.status == TaskStatus.PENDING

    def test_default_context_empty_dict(self):
        task = AgentTask(role=AgentRole.REMEDIATOR, prompt="fix it")
        assert task.context == {}

    def test_result_optional(self):
        task = AgentTask(role=AgentRole.INVESTIGATOR, prompt="investigate")
        assert task.result is None

    def test_created_at_set(self):
        task = AgentTask(role=AgentRole.THREAT_HUNTER, prompt="hunt")
        assert task.created_at is not None


class TestConsensusResult:
    def test_valid_model(self):
        cr = ConsensusResult(
            decision="ACTION_REQUIRED",
            confidence=0.85,
            agents_agreed=["analyst", "reviewer"],
            agents_disagreed=[],
            reasoning="Two agents agree.",
        )
        assert cr.confidence == 0.85
        assert cr.decision == "ACTION_REQUIRED"

    def test_confidence_bounds(self):
        with pytest.raises(Exception):
            ConsensusResult(
                decision="X", confidence=1.5,
                agents_agreed=[], agents_disagreed=[], reasoning=""
            )
        with pytest.raises(Exception):
            ConsensusResult(
                decision="X", confidence=-0.1,
                agents_agreed=[], agents_disagreed=[], reasoning=""
            )

    def test_confidence_boundary_values(self):
        for val in (0.0, 1.0):
            cr = ConsensusResult(
                decision="TEST", confidence=val,
                agents_agreed=[], agents_disagreed=[], reasoning="ok"
            )
            assert cr.confidence == val


# ---------------------------------------------------------------------------
# 3. ROLE_TEMPLATES
# ---------------------------------------------------------------------------


class TestRoleTemplates:
    def test_all_roles_have_templates(self):
        for role in AgentRole:
            assert role in ROLE_TEMPLATES, f"Missing template for {role}"

    def test_templates_contain_placeholders(self):
        for role, tmpl in ROLE_TEMPLATES.items():
            assert "{context}" in tmpl, f"{role}: missing {{context}}"
            assert "{prompt}" in tmpl, f"{role}: missing {{prompt}}"

    def test_template_renders(self):
        tmpl = ROLE_TEMPLATES[AgentRole.ANALYST]
        rendered = tmpl.format(context="{}", prompt="test finding")
        assert "test finding" in rendered


# ---------------------------------------------------------------------------
# 4. AIOrchestrator — create_task
# ---------------------------------------------------------------------------


class TestCreateTask:
    def test_returns_string_id(self, orch):
        tid = orch.create_task(AgentRole.ANALYST, "Analyse this")
        assert isinstance(tid, str)
        uuid.UUID(tid)

    def test_task_persisted(self, orch):
        tid = orch.create_task(AgentRole.REVIEWER, "Review finding")
        task = orch.get_task(tid)
        assert task is not None
        assert task.role == AgentRole.REVIEWER
        assert task.status == TaskStatus.PENDING

    def test_context_stored(self, orch):
        ctx = {"severity": "high", "cve": "CVE-2024-1234"}
        tid = orch.create_task(AgentRole.INVESTIGATOR, "Investigate", ctx)
        task = orch.get_task(tid)
        assert task.context["severity"] == "high"

    def test_org_id_stored(self, orch):
        tid = orch.create_task(AgentRole.ANALYST, "test", org_id="org-abc")
        task = orch.get_task(tid)
        assert task.org_id == "org-abc"

    def test_multiple_tasks_independent(self, orch):
        ids = [orch.create_task(AgentRole.ANALYST, f"task {i}") for i in range(5)]
        assert len(set(ids)) == 5  # all unique


# ---------------------------------------------------------------------------
# 5. AIOrchestrator — execute_task
# ---------------------------------------------------------------------------


class TestExecuteTask:
    def test_execute_returns_completed_task(self, orch):
        tid = orch.create_task(AgentRole.ANALYST, "Analyse CVE")
        task = orch.execute_task(tid)
        assert task.status == TaskStatus.COMPLETED
        assert task.result is not None
        assert len(task.result) > 0

    def test_execute_unknown_id_raises(self, orch):
        with pytest.raises(ValueError, match="not found"):
            orch.execute_task("nonexistent-id")

    def test_result_persisted_after_execute(self, orch):
        tid = orch.create_task(AgentRole.REMEDIATOR, "Fix vulnerability")
        orch.execute_task(tid)
        task = orch.get_task(tid)
        assert task.status == TaskStatus.COMPLETED
        assert task.result is not None

    def test_all_roles_execute(self, orch):
        for role in AgentRole:
            tid = orch.create_task(role, f"Test prompt for {role.value}")
            task = orch.execute_task(tid)
            assert task.status == TaskStatus.COMPLETED, f"Failed for role {role}"

    def test_execute_idempotent_for_completed(self, orch):
        tid = orch.create_task(AgentRole.ANALYST, "test")
        task1 = orch.execute_task(tid)
        task2 = orch.execute_task(tid)
        assert task1.result == task2.result

    def test_llm_failure_marks_failed(self, orch):
        tid = orch.create_task(AgentRole.ANALYST, "test")
        with patch("core.ai_orchestrator._call_llm", side_effect=RuntimeError("LLM down")):
            task = orch.execute_task(tid)
        assert task.status == TaskStatus.FAILED
        assert "LLM down" in task.result


# ---------------------------------------------------------------------------
# 6. multi_agent_consensus
# ---------------------------------------------------------------------------


class TestMultiAgentConsensus:
    def test_returns_consensus_result(self, orch):
        result = orch.multi_agent_consensus("Is CVE-2024-1234 critical?")
        assert isinstance(result, ConsensusResult)

    def test_decision_is_valid_value(self, orch):
        result = orch.multi_agent_consensus("Assess this finding")
        assert result.decision in ("ACTION_REQUIRED", "INVESTIGATE_FURTHER", "LOW_PRIORITY")

    def test_confidence_in_bounds(self, orch):
        result = orch.multi_agent_consensus("High severity alert")
        assert 0.0 <= result.confidence <= 1.0

    def test_agreed_and_disagreed_are_lists(self, orch):
        result = orch.multi_agent_consensus("Test prompt")
        assert isinstance(result.agents_agreed, list)
        assert isinstance(result.agents_disagreed, list)

    def test_custom_roles(self, orch):
        roles = [AgentRole.ANALYST, AgentRole.COMPLIANCE_CHECKER]
        result = orch.multi_agent_consensus("Compliance check", roles=roles)
        all_agents = set(result.agents_agreed + result.agents_disagreed)
        # All agents should be from our specified roles
        for agent in all_agents:
            assert agent in {r.value for r in roles}

    def test_consensus_persisted_in_stats(self, orch):
        orch.multi_agent_consensus("First consensus", org_id="org-x")
        stats = orch.get_consensus_stats(org_id="org-x")
        assert stats["total_consensus_runs"] >= 1

    def test_reasoning_non_empty(self, orch):
        result = orch.multi_agent_consensus("Any security concern?")
        assert result.reasoning != ""

    def test_single_role_consensus(self, orch):
        result = orch.multi_agent_consensus("Solo check", roles=[AgentRole.THREAT_HUNTER])
        assert result.decision in ("ACTION_REQUIRED", "INVESTIGATE_FURTHER", "LOW_PRIORITY")


# ---------------------------------------------------------------------------
# 7. chain_agents
# ---------------------------------------------------------------------------


class TestChainAgents:
    def test_chain_returns_list(self, orch):
        tasks = [
            {"role": "analyst", "prompt": "Step 1: analyse"},
            {"role": "reviewer", "prompt": "Step 2: review"},
        ]
        results = orch.chain_agents(tasks)
        assert len(results) == 2

    def test_chain_order_preserved(self, orch):
        tasks = [
            {"role": "analyst", "prompt": "First"},
            {"role": "investigator", "prompt": "Second"},
            {"role": "remediator", "prompt": "Third"},
        ]
        results = orch.chain_agents(tasks)
        assert results[0].role == AgentRole.ANALYST
        assert results[1].role == AgentRole.INVESTIGATOR
        assert results[2].role == AgentRole.REMEDIATOR

    def test_chain_injects_previous_result(self, orch):
        tasks = [
            {"role": "analyst", "prompt": "Analyse finding"},
            {"role": "reviewer", "prompt": "Review analysis"},
        ]
        results = orch.chain_agents(tasks)
        # Second task should have previous_result in its context
        second_task = orch.get_task(results[1].id)
        assert "previous_result" in second_task.context

    def test_chain_all_completed(self, orch):
        tasks = [
            {"role": "analyst", "prompt": "A"},
            {"role": "reviewer", "prompt": "B"},
        ]
        results = orch.chain_agents(tasks)
        for r in results:
            assert r.status == TaskStatus.COMPLETED

    def test_chain_with_context(self, orch):
        tasks = [
            {"role": "analyst", "prompt": "Analyse", "context": {"cve": "CVE-2024-0001"}},
        ]
        results = orch.chain_agents(tasks)
        assert len(results) == 1


# ---------------------------------------------------------------------------
# 8. parallel_agents
# ---------------------------------------------------------------------------


class TestParallelAgents:
    def test_parallel_returns_all_results(self, orch):
        tasks = [
            {"role": "analyst", "prompt": "Parallel A"},
            {"role": "reviewer", "prompt": "Parallel B"},
            {"role": "threat_hunter", "prompt": "Parallel C"},
        ]
        results = orch.parallel_agents(tasks)
        assert len(results) == 3

    def test_parallel_all_completed(self, orch):
        tasks = [
            {"role": r.value, "prompt": f"Task for {r.value}"}
            for r in [AgentRole.ANALYST, AgentRole.INVESTIGATOR, AgentRole.COMPLIANCE_CHECKER]
        ]
        results = orch.parallel_agents(tasks)
        for r in results:
            assert r.status == TaskStatus.COMPLETED

    def test_parallel_single_task(self, orch):
        tasks = [{"role": "remediator", "prompt": "Fix it"}]
        results = orch.parallel_agents(tasks)
        assert len(results) == 1

    def test_parallel_results_have_results(self, orch):
        tasks = [
            {"role": "analyst", "prompt": "Check CVE"},
            {"role": "reviewer", "prompt": "Verify"},
        ]
        results = orch.parallel_agents(tasks)
        for r in results:
            assert r.result is not None


# ---------------------------------------------------------------------------
# 9. get_task_history
# ---------------------------------------------------------------------------


class TestGetTaskHistory:
    def test_returns_list(self, orch):
        history = orch.get_task_history()
        assert isinstance(history, list)

    def test_tasks_appear_in_history(self, orch):
        orch.create_task(AgentRole.ANALYST, "History test", org_id="org-hist")
        history = orch.get_task_history(org_id="org-hist")
        assert len(history) >= 1

    def test_org_id_filter_isolates(self, orch):
        orch.create_task(AgentRole.ANALYST, "Org A task", org_id="org-a")
        orch.create_task(AgentRole.ANALYST, "Org B task", org_id="org-b")
        history_a = orch.get_task_history(org_id="org-a")
        history_b = orch.get_task_history(org_id="org-b")
        assert all(t.org_id == "org-a" for t in history_a)
        assert all(t.org_id == "org-b" for t in history_b)

    def test_role_filter(self, orch):
        orch.create_task(AgentRole.ANALYST, "Analyst task")
        orch.create_task(AgentRole.REVIEWER, "Reviewer task")
        analysts = orch.get_task_history(role=AgentRole.ANALYST)
        assert all(t.role == AgentRole.ANALYST for t in analysts)

    def test_status_filter(self, orch):
        tid = orch.create_task(AgentRole.ANALYST, "Run me")
        orch.execute_task(tid)
        completed = orch.get_task_history(status=TaskStatus.COMPLETED)
        assert all(t.status == TaskStatus.COMPLETED for t in completed)

    def test_limit_respected(self, orch):
        for i in range(10):
            orch.create_task(AgentRole.ANALYST, f"task {i}")
        history = orch.get_task_history(limit=3)
        assert len(history) <= 3


# ---------------------------------------------------------------------------
# 10. get_consensus_stats
# ---------------------------------------------------------------------------


class TestGetConsensusStats:
    def test_empty_stats(self, orch):
        stats = orch.get_consensus_stats(org_id="org-empty")
        assert stats["total_consensus_runs"] == 0
        assert stats["avg_confidence"] == 0.0

    def test_stats_after_consensus(self, orch):
        orch.multi_agent_consensus("Test 1", org_id="org-stats")
        orch.multi_agent_consensus("Test 2", org_id="org-stats")
        stats = orch.get_consensus_stats(org_id="org-stats")
        assert stats["total_consensus_runs"] == 2
        assert 0.0 <= stats["avg_confidence"] <= 1.0

    def test_decision_distribution_keys(self, orch):
        orch.multi_agent_consensus("Decision test", org_id="org-dist")
        stats = orch.get_consensus_stats(org_id="org-dist")
        assert "decision_distribution" in stats
        assert isinstance(stats["decision_distribution"], dict)

    def test_avg_agreement_rate_in_bounds(self, orch):
        orch.multi_agent_consensus("Agreement check", org_id="org-agr")
        stats = orch.get_consensus_stats(org_id="org-agr")
        assert 0.0 <= stats["avg_agreement_rate"] <= 1.0


# ---------------------------------------------------------------------------
# 11. REST API via TestClient
# ---------------------------------------------------------------------------

from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def api_client(tmp_db):
    """TestClient wired to a fresh AIOrchestrator DB."""
    app = FastAPI()

    # Patch the module-level singleton so the router uses our tmp DB
    from core.ai_orchestrator import AIOrchestrator as _Orch
    _test_orch = _Orch(db_path=tmp_db)

    with patch("apps.api.ai_orchestrator_router.get_orchestrator", return_value=_test_orch), \
         patch("apps.api.ai_orchestrator_router._ORCHESTRATOR_AVAILABLE", True):
        from apps.api.ai_orchestrator_router import router
        app.include_router(router)
        yield TestClient(app)


class TestCreateTaskEndpoint:
    def test_creates_task_returns_200(self, api_client):
        resp = api_client.post("/api/v1/ai-orchestrator/tasks", json={
            "role": "analyst",
            "prompt": "Analyse this finding",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "task_id" in data
        assert data["status"] == "pending"

    def test_invalid_role_returns_422(self, api_client):
        resp = api_client.post("/api/v1/ai-orchestrator/tasks", json={
            "role": "invalid_role",
            "prompt": "Test",
        })
        assert resp.status_code == 422

    def test_empty_prompt_rejected(self, api_client):
        resp = api_client.post("/api/v1/ai-orchestrator/tasks", json={
            "role": "analyst",
            "prompt": "",
        })
        assert resp.status_code == 422

    def test_context_accepted(self, api_client):
        resp = api_client.post("/api/v1/ai-orchestrator/tasks", json={
            "role": "reviewer",
            "prompt": "Review this",
            "context": {"key": "value"},
        })
        assert resp.status_code == 200


class TestExecuteTaskEndpoint:
    def test_execute_returns_completed(self, api_client):
        create = api_client.post("/api/v1/ai-orchestrator/tasks", json={
            "role": "analyst", "prompt": "Analyse CVE-2024-9999",
        })
        task_id = create.json()["task_id"]
        resp = api_client.post(f"/api/v1/ai-orchestrator/tasks/{task_id}/execute")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["result"] is not None

    def test_execute_unknown_task_404(self, api_client):
        resp = api_client.post("/api/v1/ai-orchestrator/tasks/nonexistent/execute")
        assert resp.status_code == 404


class TestGetTaskEndpoint:
    def test_get_existing_task(self, api_client):
        create = api_client.post("/api/v1/ai-orchestrator/tasks", json={
            "role": "investigator", "prompt": "Investigate alert",
        })
        task_id = create.json()["task_id"]
        resp = api_client.get(f"/api/v1/ai-orchestrator/tasks/{task_id}")
        assert resp.status_code == 200
        assert resp.json()["task_id"] == task_id

    def test_get_unknown_task_404(self, api_client):
        resp = api_client.get("/api/v1/ai-orchestrator/tasks/does-not-exist")
        assert resp.status_code == 404


class TestListTasksEndpoint:
    def test_list_returns_tasks_key(self, api_client):
        resp = api_client.get("/api/v1/ai-orchestrator/tasks")
        assert resp.status_code == 200
        data = resp.json()
        assert "tasks" in data
        assert "total" in data

    def test_list_includes_created_tasks(self, api_client):
        api_client.post("/api/v1/ai-orchestrator/tasks", json={
            "role": "remediator", "prompt": "Fix CVE",
        })
        resp = api_client.get("/api/v1/ai-orchestrator/tasks")
        assert resp.json()["total"] >= 1

    def test_list_role_filter(self, api_client):
        api_client.post("/api/v1/ai-orchestrator/tasks", json={"role": "analyst", "prompt": "A"})
        api_client.post("/api/v1/ai-orchestrator/tasks", json={"role": "reviewer", "prompt": "B"})
        resp = api_client.get("/api/v1/ai-orchestrator/tasks?role=analyst")
        assert resp.status_code == 200

    def test_list_invalid_status_422(self, api_client):
        resp = api_client.get("/api/v1/ai-orchestrator/tasks?status=bogus")
        assert resp.status_code == 422


class TestConsensusEndpoint:
    def test_consensus_returns_decision(self, api_client):
        resp = api_client.post("/api/v1/ai-orchestrator/consensus", json={
            "prompt": "Is this a critical vulnerability?",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "decision" in data
        assert "confidence" in data
        assert data["decision"] in ("ACTION_REQUIRED", "INVESTIGATE_FURTHER", "LOW_PRIORITY")

    def test_consensus_custom_roles(self, api_client):
        resp = api_client.post("/api/v1/ai-orchestrator/consensus", json={
            "prompt": "Check compliance",
            "roles": ["compliance_checker", "reviewer"],
        })
        assert resp.status_code == 200

    def test_consensus_invalid_role_422(self, api_client):
        resp = api_client.post("/api/v1/ai-orchestrator/consensus", json={
            "prompt": "Test",
            "roles": ["nonexistent_role"],
        })
        assert resp.status_code == 422


class TestChainPipelineEndpoint:
    def test_chain_returns_tasks(self, api_client):
        resp = api_client.post("/api/v1/ai-orchestrator/pipeline/chain", json={
            "tasks": [
                {"role": "analyst", "prompt": "Step 1"},
                {"role": "reviewer", "prompt": "Step 2"},
            ]
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["pipeline_type"] == "chain"
        assert len(data["tasks"]) == 2

    def test_chain_missing_role_422(self, api_client):
        resp = api_client.post("/api/v1/ai-orchestrator/pipeline/chain", json={
            "tasks": [{"prompt": "No role here"}]
        })
        assert resp.status_code == 422


class TestParallelPipelineEndpoint:
    def test_parallel_returns_tasks(self, api_client):
        resp = api_client.post("/api/v1/ai-orchestrator/pipeline/parallel", json={
            "tasks": [
                {"role": "analyst", "prompt": "Parallel A"},
                {"role": "threat_hunter", "prompt": "Parallel B"},
            ]
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["pipeline_type"] == "parallel"
        assert len(data["tasks"]) == 2

    def test_parallel_missing_prompt_422(self, api_client):
        resp = api_client.post("/api/v1/ai-orchestrator/pipeline/parallel", json={
            "tasks": [{"role": "analyst"}]
        })
        assert resp.status_code == 422


class TestStatsEndpoint:
    def test_stats_returns_dict(self, api_client):
        resp = api_client.get("/api/v1/ai-orchestrator/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_consensus_runs" in data
        assert "avg_confidence" in data
        assert "decision_distribution" in data

    def test_stats_after_consensus(self, api_client):
        api_client.post("/api/v1/ai-orchestrator/consensus", json={
            "prompt": "Stats test prompt",
        })
        resp = api_client.get("/api/v1/ai-orchestrator/stats")
        assert resp.json()["total_consensus_runs"] >= 1
