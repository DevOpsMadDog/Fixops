"""
Unit tests for suite-api/apps/api/bulk_router.py

Tests the bulk operations API including:
- Pydantic models: validation, defaults, constraints
- JobStatus / ActionType enums
- Internal functions: _create_job, _update_job_progress, _complete_job, _is_job_cancelled
- _severity_to_priority mapping
- Router endpoints via TestClient:
  - POST /api/v1/bulk/clusters/status
  - POST /api/v1/bulk/clusters/assign
  - POST /api/v1/bulk/clusters/accept-risk
  - POST /api/v1/bulk/clusters/create-tickets
  - POST /api/v1/bulk/export
  - GET /api/v1/bulk/jobs/{job_id}
  - GET /api/v1/bulk/exports/{filename}
  - POST /api/v1/bulk/clusters/cancel/{job_id}
"""

import os

import pytest

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from apps.api.bulk_router import (
    ActionType,
    BulkAcceptRiskRequest,
    BulkAssignRequest,
    BulkCreateTicketsRequest,
    BulkDeleteRequest,
    BulkExportRequest,
    BulkOperationResponse,
    BulkStatusUpdateRequest,
    BulkUpdateRequest,
    BulkApplyPoliciesRequest,
    JobResponse,
    JobStatus,
    JobStatusResponse,
    _complete_job,
    _create_job,
    _is_job_cancelled,
    _jobs,
    _severity_to_priority,
    _update_job_progress,
)


# ===========================================================================
# Enum tests
# ===========================================================================


class TestJobStatusEnum:
    def test_all_values(self):
        assert JobStatus.PENDING.value == "pending"
        assert JobStatus.IN_PROGRESS.value == "in_progress"
        assert JobStatus.COMPLETED.value == "completed"
        assert JobStatus.FAILED.value == "failed"
        assert JobStatus.PARTIAL.value == "partial"
        assert JobStatus.CANCELLED.value == "cancelled"


class TestActionTypeEnum:
    def test_all_values(self):
        assert ActionType.UPDATE_STATUS.value == "update_status"
        assert ActionType.ASSIGN.value == "assign"
        assert ActionType.CREATE_TICKETS.value == "create_tickets"
        assert ActionType.ACCEPT_RISK.value == "accept_risk"
        assert ActionType.EXPORT.value == "export"
        assert ActionType.DELETE.value == "delete"


# ===========================================================================
# Pydantic model tests
# ===========================================================================


class TestBulkUpdateRequest:
    def test_valid(self):
        req = BulkUpdateRequest(ids=["id-1"], updates={"status": "resolved"})
        assert req.ids == ["id-1"]
        assert req.updates["status"] == "resolved"

    def test_empty_ids_rejected(self):
        with pytest.raises(Exception):
            BulkUpdateRequest(ids=[], updates={})


class TestBulkDeleteRequest:
    def test_valid(self):
        req = BulkDeleteRequest(ids=["id-1", "id-2"])
        assert len(req.ids) == 2

    def test_empty_ids_rejected(self):
        with pytest.raises(Exception):
            BulkDeleteRequest(ids=[])


class TestBulkAssignRequest:
    def test_valid(self):
        req = BulkAssignRequest(ids=["id-1"], assignee="alice@example.com")
        assert req.assignee == "alice@example.com"
        assert req.assignee_email is None

    def test_with_email(self):
        req = BulkAssignRequest(
            ids=["id-1"],
            assignee="alice",
            assignee_email="alice@example.com",
        )
        assert req.assignee_email == "alice@example.com"


class TestBulkStatusUpdateRequest:
    def test_valid(self):
        req = BulkStatusUpdateRequest(ids=["id-1"], new_status="resolved")
        assert req.new_status == "resolved"
        assert req.reason is None
        assert req.changed_by is None

    def test_with_optional_fields(self):
        req = BulkStatusUpdateRequest(
            ids=["id-1"],
            new_status="resolved",
            reason="Fixed in v2.0",
            changed_by="admin",
        )
        assert req.reason == "Fixed in v2.0"


class TestBulkAcceptRiskRequest:
    def test_valid(self):
        req = BulkAcceptRiskRequest(
            ids=["id-1"],
            justification="Low risk",
            approved_by="ciso@company.com",
        )
        assert req.expiry_days == 90  # default

    def test_custom_expiry(self):
        req = BulkAcceptRiskRequest(
            ids=["id-1"],
            justification="temp",
            approved_by="admin",
            expiry_days=30,
        )
        assert req.expiry_days == 30


class TestBulkCreateTicketsRequest:
    def test_valid(self):
        req = BulkCreateTicketsRequest(
            ids=["id-1"],
            integration_id="int-123",
        )
        assert req.issue_type == "Bug"  # default
        assert req.project_key is None

    def test_custom_type(self):
        req = BulkCreateTicketsRequest(
            ids=["id-1"],
            integration_id="int-123",
            issue_type="Security Task",
            project_key="SEC",
        )
        assert req.issue_type == "Security Task"
        assert req.project_key == "SEC"


class TestBulkExportRequest:
    def test_valid(self):
        req = BulkExportRequest(ids=["id-1"], org_id="acme")
        assert req.format == "json"  # default
        assert req.include_fields is None

    def test_csv_format(self):
        req = BulkExportRequest(ids=["id-1"], format="csv", org_id="acme")
        assert req.format == "csv"


class TestBulkApplyPoliciesRequest:
    def test_valid(self):
        req = BulkApplyPoliciesRequest(
            policy_ids=["p1", "p2"],
            target_ids=["t1"],
        )
        assert len(req.policy_ids) == 2


class TestBulkOperationResponse:
    def test_creation(self):
        resp = BulkOperationResponse(success_count=5, failure_count=2)
        assert resp.success_count == 5
        assert resp.failure_count == 2
        assert resp.errors == []


class TestJobResponse:
    def test_creation(self):
        resp = JobResponse(
            job_id="j-1",
            status="pending",
            total_items=10,
            message="Created",
        )
        assert resp.job_id == "j-1"
        assert resp.total_items == 10


class TestJobStatusResponse:
    def test_creation(self):
        resp = JobStatusResponse(
            job_id="j-1",
            status="in_progress",
            action_type="update_status",
            total_items=10,
            processed_items=5,
            success_count=4,
            failure_count=1,
            progress_percent=50.0,
            started_at="2026-01-01T00:00:00Z",
        )
        assert resp.progress_percent == 50.0


# ===========================================================================
# Internal function tests
# ===========================================================================


class TestSeverityToPriority:
    def test_critical(self):
        assert _severity_to_priority("critical") == "Highest"

    def test_high(self):
        assert _severity_to_priority("high") == "High"

    def test_medium(self):
        assert _severity_to_priority("medium") == "Medium"

    def test_low(self):
        assert _severity_to_priority("low") == "Low"

    def test_info(self):
        assert _severity_to_priority("info") == "Lowest"

    def test_unknown_defaults_to_medium(self):
        assert _severity_to_priority("unknown") == "Medium"

    def test_case_insensitive(self):
        assert _severity_to_priority("CRITICAL") == "Highest"
        assert _severity_to_priority("High") == "High"


class TestCreateJob:
    def test_creates_job_with_correct_structure(self):
        job_id = _create_job("update_status", 5, {"test": True})
        assert job_id in _jobs
        job = _jobs[job_id]
        assert job["status"] == "pending"
        assert job["action_type"] == "update_status"
        assert job["total_items"] == 5
        assert job["processed_items"] == 0
        assert job["success_count"] == 0
        assert job["failure_count"] == 0
        assert job["progress_percent"] == 0.0
        assert job["metadata"]["test"] is True
        # Cleanup
        del _jobs[job_id]

    def test_unique_ids(self):
        id1 = _create_job("export", 1, {})
        id2 = _create_job("export", 1, {})
        assert id1 != id2
        del _jobs[id1]
        del _jobs[id2]


class TestUpdateJobProgress:
    def test_updates_progress(self):
        job_id = _create_job("test", 10, {})
        _update_job_progress(job_id, 5, 4, 1, result={"id": "x"}, error={"id": "y", "error": "fail"})
        job = _jobs[job_id]
        assert job["processed_items"] == 5
        assert job["success_count"] == 4
        assert job["failure_count"] == 1
        assert job["progress_percent"] == 50.0
        assert len(job["results"]) == 1
        assert len(job["errors"]) == 1
        del _jobs[job_id]

    def test_nonexistent_job_is_noop(self):
        _update_job_progress("nonexistent", 1, 1, 0)  # Should not raise


class TestCompleteJob:
    def test_marks_completed(self):
        job_id = _create_job("test", 1, {})
        _complete_job(job_id, JobStatus.COMPLETED.value)
        assert _jobs[job_id]["status"] == "completed"
        assert _jobs[job_id]["completed_at"] is not None
        del _jobs[job_id]

    def test_does_not_overwrite_terminal_state(self):
        job_id = _create_job("test", 1, {})
        _complete_job(job_id, JobStatus.COMPLETED.value)
        _complete_job(job_id, JobStatus.FAILED.value)  # Should be ignored
        assert _jobs[job_id]["status"] == "completed"
        del _jobs[job_id]

    def test_nonexistent_job_is_noop(self):
        _complete_job("nonexistent", "completed")  # Should not raise


class TestIsJobCancelled:
    def test_nonexistent_job(self):
        assert _is_job_cancelled("nonexistent") is True

    def test_pending_job(self):
        job_id = _create_job("test", 1, {})
        assert _is_job_cancelled(job_id) is False
        del _jobs[job_id]

    def test_cancelled_job(self):
        job_id = _create_job("test", 1, {})
        _jobs[job_id]["cancel_requested"] = True
        assert _is_job_cancelled(job_id) is True
        del _jobs[job_id]


# ===========================================================================
# Router endpoint tests via TestClient
# ===========================================================================

from apps.api.app import create_app
from fastapi.testclient import TestClient

API_TOKEN = os.environ["FIXOPS_API_TOKEN"]


@pytest.fixture(scope="module")
def client():
    app = create_app()
    return TestClient(app)


@pytest.fixture
def auth_headers():
    return {"X-API-Key": API_TOKEN}


class TestBulkStatusEndpoint:
    def test_bulk_status_update(self, client, auth_headers):
        resp = client.post(
            "/api/v1/bulk/clusters/status",
            headers=auth_headers,
            json={
                "ids": ["cluster-1", "cluster-2"],
                "new_status": "resolved",
                "reason": "Fixed in v2",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "job_id" in data
        assert data["status"] == "pending"
        assert data["total_items"] == 2

    def test_bulk_status_empty_ids(self, client, auth_headers):
        resp = client.post(
            "/api/v1/bulk/clusters/status",
            headers=auth_headers,
            json={"ids": [], "new_status": "resolved"},
        )
        assert resp.status_code == 422


class TestBulkAssignEndpoint:
    def test_bulk_assign(self, client, auth_headers):
        resp = client.post(
            "/api/v1/bulk/clusters/assign",
            headers=auth_headers,
            json={
                "ids": ["cluster-1"],
                "assignee": "alice",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "pending"


class TestBulkAcceptRiskEndpoint:
    def test_bulk_accept_risk(self, client, auth_headers):
        resp = client.post(
            "/api/v1/bulk/clusters/accept-risk",
            headers=auth_headers,
            json={
                "ids": ["cluster-1"],
                "justification": "Low risk, no exposure",
                "approved_by": "ciso@company.com",
                "expiry_days": 60,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "pending"


class TestBulkCreateTicketsEndpoint:
    def test_bulk_create_tickets(self, client, auth_headers):
        resp = client.post(
            "/api/v1/bulk/clusters/create-tickets",
            headers=auth_headers,
            json={
                "ids": ["cluster-1"],
                "integration_id": "jira-prod",
                "project_key": "SEC",
                "issue_type": "Bug",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "pending"


class TestBulkExportEndpoint:
    def test_bulk_export_json(self, client, auth_headers):
        resp = client.post(
            "/api/v1/bulk/export",
            headers=auth_headers,
            json={
                "ids": ["finding-1"],
                "format": "json",
                "org_id": "acme",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "pending"

    def test_bulk_export_invalid_format(self, client, auth_headers):
        resp = client.post(
            "/api/v1/bulk/export",
            headers=auth_headers,
            json={
                "ids": ["finding-1"],
                "format": "xml",
                "org_id": "acme",
            },
        )
        assert resp.status_code == 400


class TestJobStatusEndpoint:
    def test_get_job_status(self, client, auth_headers):
        # Create a job first
        resp = client.post(
            "/api/v1/bulk/clusters/status",
            headers=auth_headers,
            json={"ids": ["c1"], "new_status": "open"},
        )
        job_id = resp.json()["job_id"]

        # Query its status
        resp = client.get(
            f"/api/v1/bulk/jobs/{job_id}",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["job_id"] == job_id

    def test_get_nonexistent_job(self, client, auth_headers):
        resp = client.get(
            "/api/v1/bulk/jobs/nonexistent-id",
            headers=auth_headers,
        )
        assert resp.status_code == 404


class TestExportDownloadEndpoint:
    def test_download_nonexistent_export(self, client, auth_headers):
        resp = client.get(
            "/api/v1/bulk/exports/nonexistent.json",
            headers=auth_headers,
        )
        assert resp.status_code == 404
