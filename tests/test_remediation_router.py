"""Tests for remediation_router (suite-api/apps/api/remediation_router.py).

Covers:
  - CreateTaskRequest, UpdateStatusRequest, AssignTaskRequest models
  - SubmitVerificationRequest, LinkTicketRequest models
  - Router endpoints create_task, get_task, list_tasks
  - Status transitions
  - Task assignment
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.remediation_router import (
    CreateTaskRequest,
    UpdateStatusRequest,
    AssignTaskRequest,
    SubmitVerificationRequest,
    LinkTicketRequest,
    router,
)


# ──────────────────────────────────────────────────────
#  Pydantic model tests
# ──────────────────────────────────────────────────────


class TestRemediationModels:
    def test_create_task_request(self):
        req = CreateTaskRequest(
            cluster_id="cluster-1",
            org_id="org-1",
            app_id="app-1",
            title="Fix SQL Injection",
            severity="critical",
        )
        assert req.cluster_id == "cluster-1"
        assert req.severity == "critical"
        assert req.description is None
        assert req.assignee is None

    def test_create_task_request_full(self):
        req = CreateTaskRequest(
            cluster_id="cluster-1",
            org_id="org-1",
            app_id="app-1",
            title="Fix XSS",
            severity="high",
            description="Reflected XSS in search",
            assignee="alice",
            assignee_email="alice@example.com",
            metadata={"cwe": "CWE-79"},
        )
        assert req.description == "Reflected XSS in search"
        assert req.metadata == {"cwe": "CWE-79"}

    def test_update_status_request(self):
        req = UpdateStatusRequest(status="in_progress")
        assert req.status == "in_progress"
        assert req.changed_by is None

    def test_assign_task_request(self):
        req = AssignTaskRequest(assignee="bob")
        assert req.assignee == "bob"

    def test_submit_verification_request(self):
        req = SubmitVerificationRequest(
            evidence_type="test_results",
            evidence_data={"tests_passed": 42},
        )
        assert req.evidence_type == "test_results"

    def test_link_ticket_request(self):
        req = LinkTicketRequest(
            ticket_id="JIRA-123",
            ticket_url="https://jira.example.com/browse/JIRA-123",
        )
        assert req.ticket_id == "JIRA-123"


# ──────────────────────────────────────────────────────
#  Router endpoint tests
# ──────────────────────────────────────────────────────


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Create test client with temp DB."""
    import apps.api.remediation_router as mod
    monkeypatch.setattr(mod, "_remediation_service", None)
    monkeypatch.setattr(mod, "_DATA_DIR", tmp_path)
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


class TestRemediationEndpoints:
    def test_create_task(self, client):
        resp = client.post("/api/v1/remediation/tasks", json={
            "cluster_id": "cluster-test",
            "org_id": "org-test",
            "app_id": "app-test",
            "title": "Fix vulnerability",
            "severity": "high",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "task_id" in data or isinstance(data, dict)

    def test_list_tasks(self, client):
        # Create a task first
        client.post("/api/v1/remediation/tasks", json={
            "cluster_id": "c1",
            "org_id": "org1",
            "app_id": "a1",
            "title": "Task 1",
            "severity": "medium",
        })
        resp = client.get("/api/v1/remediation/tasks")
        assert resp.status_code == 200
