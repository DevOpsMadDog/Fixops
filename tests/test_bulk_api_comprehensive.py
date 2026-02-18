"""Comprehensive tests for bulk operations API endpoints with full coverage."""
from unittest.mock import MagicMock, patch

import pytest
from apps.api.app import create_app
from fastapi.testclient import TestClient

API_TOKEN = "demo-token-12345"
AUTH_HEADERS = {"X-API-Key": API_TOKEN}


@pytest.fixture
def client(monkeypatch):
    """Create test client with proper environment variables."""
    monkeypatch.setenv("FIXOPS_API_TOKEN", API_TOKEN)
    monkeypatch.setenv("FIXOPS_MODE", "demo")
    app = create_app()
    return TestClient(app)


@pytest.fixture
def reset_bulk_state():
    """Reset bulk router state before each test."""
    from apps.api import bulk_router

    bulk_router._jobs.clear()
    bulk_router._dedup_service = None
    bulk_router._integration_db = None
    yield
    bulk_router._jobs.clear()


class TestBulkClusterOperations:
    """Tests for cluster-based bulk operations."""

    def test_bulk_update_cluster_status(self, client, reset_bulk_state):
        """Test bulk cluster status update creates a job."""
        response = client.post(
            "/api/v1/bulk/clusters/status",
            headers=AUTH_HEADERS,
            json={
                "ids": ["cluster-1", "cluster-2"],
                "new_status": "resolved",
                "reason": "Fixed in latest release",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "job_id" in data
        assert data["status"] == "pending"
        assert data["total_items"] == 2

    def test_bulk_assign_clusters(self, client, reset_bulk_state):
        """Test bulk cluster assignment creates a job."""
        response = client.post(
            "/api/v1/bulk/clusters/assign",
            headers=AUTH_HEADERS,
            json={
                "ids": ["cluster-1", "cluster-2", "cluster-3"],
                "assignee": "security-team",
                "assignee_email": "security@example.com",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "job_id" in data
        assert data["status"] == "pending"
        assert data["total_items"] == 3

    def test_bulk_accept_risk(self, client, reset_bulk_state):
        """Test bulk accept risk creates a job."""
        response = client.post(
            "/api/v1/bulk/clusters/accept-risk",
            headers=AUTH_HEADERS,
            json={
                "ids": ["cluster-1"],
                "justification": "Low impact, compensating controls in place",
                "approved_by": "ciso@example.com",
                "expiry_days": 180,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "job_id" in data
        assert data["status"] == "pending"

    def test_bulk_create_tickets(self, client, reset_bulk_state):
        """Test bulk ticket creation creates a job."""
        response = client.post(
            "/api/v1/bulk/clusters/create-tickets",
            headers=AUTH_HEADERS,
            json={
                "ids": ["cluster-1", "cluster-2"],
                "integration_id": "jira-integration-1",
                "project_key": "SEC",
                "issue_type": "Bug",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "job_id" in data
        assert data["status"] == "pending"


class TestBulkExport:
    """Tests for bulk export operations."""

    def test_bulk_export_json(self, client, reset_bulk_state):
        """Test bulk export with JSON format."""
        response = client.post(
            "/api/v1/bulk/export",
            headers=AUTH_HEADERS,
            json={
                "ids": ["id1", "id2", "id3"],
                "format": "json",
                "org_id": "org-123",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "job_id" in data
        assert data["status"] == "pending"

    def test_bulk_export_csv(self, client, reset_bulk_state):
        """Test bulk export with CSV format."""
        response = client.post(
            "/api/v1/bulk/export",
            headers=AUTH_HEADERS,
            json={
                "ids": ["id1", "id2"],
                "format": "csv",
                "org_id": "org-123",
                "include_fields": ["id", "severity", "status"],
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "job_id" in data

    def test_bulk_export_sarif(self, client, reset_bulk_state):
        """Test bulk export with SARIF format."""
        response = client.post(
            "/api/v1/bulk/export",
            headers=AUTH_HEADERS,
            json={
                "ids": ["id1"],
                "format": "sarif",
                "org_id": "org-123",
            },
        )
        assert response.status_code == 200

    def test_bulk_export_pdf(self, client, reset_bulk_state):
        """Test bulk export with PDF format."""
        response = client.post(
            "/api/v1/bulk/export",
            headers=AUTH_HEADERS,
            json={
                "ids": ["id1"],
                "format": "pdf",
                "org_id": "org-123",
            },
        )
        assert response.status_code == 200

    def test_bulk_export_invalid_format(self, client, reset_bulk_state):
        """Test bulk export with invalid format returns error."""
        response = client.post(
            "/api/v1/bulk/export",
            headers=AUTH_HEADERS,
            json={
                "ids": ["id1"],
                "format": "invalid",
                "org_id": "org-123",
            },
        )
        assert response.status_code == 400
        assert "Invalid format" in response.json()["detail"]


class TestJobManagement:
    """Tests for job status and management."""

    def test_get_job_status(self, client, reset_bulk_state):
        """Test getting job status."""
        create_response = client.post(
            "/api/v1/bulk/clusters/status",
            headers=AUTH_HEADERS,
            json={
                "ids": ["cluster-1"],
                "new_status": "resolved",
            },
        )
        job_id = create_response.json()["job_id"]

        response = client.get(f"/api/v1/bulk/jobs/{job_id}", headers=AUTH_HEADERS)
        assert response.status_code == 200
        data = response.json()
        assert data["job_id"] == job_id
        assert "status" in data
        assert "total_items" in data

    def test_get_job_status_not_found(self, client, reset_bulk_state):
        """Test getting non-existent job returns 404."""
        response = client.get(
            "/api/v1/bulk/jobs/nonexistent-job-id", headers=AUTH_HEADERS
        )
        assert response.status_code == 404

    def test_list_jobs(self, client, reset_bulk_state):
        """Test listing jobs."""
        client.post(
            "/api/v1/bulk/clusters/status",
            headers=AUTH_HEADERS,
            json={"ids": ["cluster-1"], "new_status": "resolved"},
        )
        client.post(
            "/api/v1/bulk/clusters/assign",
            headers=AUTH_HEADERS,
            json={"ids": ["cluster-2"], "assignee": "user1"},
        )

        response = client.get("/api/v1/bulk/jobs", headers=AUTH_HEADERS)
        assert response.status_code == 200
        data = response.json()
        assert "jobs" in data
        assert "count" in data
        assert "total" in data
        assert data["count"] >= 2

    def test_list_jobs_with_status_filter(self, client, reset_bulk_state):
        """Test listing jobs with status filter."""
        client.post(
            "/api/v1/bulk/clusters/status",
            headers=AUTH_HEADERS,
            json={"ids": ["cluster-1"], "new_status": "resolved"},
        )

        response = client.get("/api/v1/bulk/jobs?status=pending", headers=AUTH_HEADERS)
        assert response.status_code == 200
        data = response.json()
        for job in data["jobs"]:
            assert job["status"] == "pending"

    def test_list_jobs_with_action_type_filter(self, client, reset_bulk_state):
        """Test listing jobs with action type filter."""
        client.post(
            "/api/v1/bulk/clusters/status",
            headers=AUTH_HEADERS,
            json={"ids": ["cluster-1"], "new_status": "resolved"},
        )

        response = client.get(
            "/api/v1/bulk/jobs?action_type=update_status", headers=AUTH_HEADERS
        )
        assert response.status_code == 200
        data = response.json()
        for job in data["jobs"]:
            assert job["action_type"] == "update_status"

    def test_list_jobs_with_limit(self, client, reset_bulk_state):
        """Test listing jobs with limit."""
        for i in range(5):
            client.post(
                "/api/v1/bulk/clusters/status",
                headers=AUTH_HEADERS,
                json={"ids": [f"cluster-{i}"], "new_status": "resolved"},
            )

        response = client.get("/api/v1/bulk/jobs?limit=3", headers=AUTH_HEADERS)
        assert response.status_code == 200
        data = response.json()
        assert data["count"] <= 3

    def test_cancel_job(self, client, reset_bulk_state):
        """Test cancelling a pending job."""
        from apps.api import bulk_router

        create_response = client.post(
            "/api/v1/bulk/clusters/status",
            headers=AUTH_HEADERS,
            json={"ids": ["cluster-1"], "new_status": "resolved"},
        )
        job_id = create_response.json()["job_id"]

        bulk_router._jobs[job_id]["status"] = "pending"

        response = client.delete(f"/api/v1/bulk/jobs/{job_id}", headers=AUTH_HEADERS)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "cancelled"
        assert data["job_id"] == job_id

    def test_cancel_job_not_found(self, client, reset_bulk_state):
        """Test cancelling non-existent job returns 404."""
        response = client.delete(
            "/api/v1/bulk/jobs/nonexistent-job-id", headers=AUTH_HEADERS
        )
        assert response.status_code == 404

    def test_cancel_completed_job_fails(self, client, reset_bulk_state):
        """Test cancelling a completed job fails."""
        from apps.api import bulk_router

        create_response = client.post(
            "/api/v1/bulk/clusters/status",
            headers=AUTH_HEADERS,
            json={"ids": ["cluster-1"], "new_status": "resolved"},
        )
        job_id = create_response.json()["job_id"]

        bulk_router._jobs[job_id]["status"] = "completed"

        response = client.delete(f"/api/v1/bulk/jobs/{job_id}", headers=AUTH_HEADERS)
        assert response.status_code == 400
        assert "Cannot cancel job" in response.json()["detail"]


class TestBackgroundProcessing:
    """Tests for background job processing functions."""

    @pytest.mark.asyncio
    async def test_process_bulk_status_success(self, reset_bulk_state):
        """Test bulk status processing with successful updates."""
        from apps.api import bulk_router

        mock_dedup = MagicMock()
        mock_dedup.update_cluster_status.return_value = True

        with patch.object(bulk_router, "get_dedup_service", return_value=mock_dedup):
            job_id = bulk_router._create_job("update_status", 2, {})
            await bulk_router._process_bulk_status(
                job_id, ["c1", "c2"], "resolved", "Fixed", "user@test.com"
            )

            assert bulk_router._jobs[job_id]["status"] == "completed"
            assert bulk_router._jobs[job_id]["success_count"] == 2
            assert bulk_router._jobs[job_id]["failure_count"] == 0

    @pytest.mark.asyncio
    async def test_process_bulk_status_partial_failure(self, reset_bulk_state):
        """Test bulk status processing with partial failures."""
        from apps.api import bulk_router

        mock_dedup = MagicMock()
        mock_dedup.update_cluster_status.side_effect = [True, False]

        with patch.object(bulk_router, "get_dedup_service", return_value=mock_dedup):
            job_id = bulk_router._create_job("update_status", 2, {})
            await bulk_router._process_bulk_status(
                job_id, ["c1", "c2"], "resolved", "Fixed", None
            )

            assert bulk_router._jobs[job_id]["status"] == "partial"
            assert bulk_router._jobs[job_id]["success_count"] == 1
            assert bulk_router._jobs[job_id]["failure_count"] == 1

    @pytest.mark.asyncio
    async def test_process_bulk_status_all_failures(self, reset_bulk_state):
        """Test bulk status processing with all failures."""
        from apps.api import bulk_router

        mock_dedup = MagicMock()
        mock_dedup.update_cluster_status.return_value = False

        with patch.object(bulk_router, "get_dedup_service", return_value=mock_dedup):
            job_id = bulk_router._create_job("update_status", 2, {})
            await bulk_router._process_bulk_status(
                job_id, ["c1", "c2"], "resolved", "Fixed", None
            )

            assert bulk_router._jobs[job_id]["status"] == "failed"
            assert bulk_router._jobs[job_id]["failure_count"] == 2

    @pytest.mark.asyncio
    async def test_process_bulk_status_value_error(self, reset_bulk_state):
        """Test bulk status processing handles ValueError."""
        from apps.api import bulk_router

        mock_dedup = MagicMock()
        mock_dedup.update_cluster_status.side_effect = ValueError("Invalid status")

        with patch.object(bulk_router, "get_dedup_service", return_value=mock_dedup):
            job_id = bulk_router._create_job("update_status", 1, {})
            await bulk_router._process_bulk_status(
                job_id, ["c1"], "invalid", "Test", None
            )

            assert bulk_router._jobs[job_id]["status"] == "failed"
            assert bulk_router._jobs[job_id]["failure_count"] == 1

    @pytest.mark.asyncio
    async def test_process_bulk_status_exception(self, reset_bulk_state):
        """Test bulk status processing handles generic exceptions."""
        from apps.api import bulk_router

        mock_dedup = MagicMock()
        mock_dedup.update_cluster_status.side_effect = Exception("Database error")

        with patch.object(bulk_router, "get_dedup_service", return_value=mock_dedup):
            job_id = bulk_router._create_job("update_status", 1, {})
            await bulk_router._process_bulk_status(
                job_id, ["c1"], "resolved", "Test", None
            )

            assert bulk_router._jobs[job_id]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_process_bulk_status_cancelled(self, reset_bulk_state):
        """Test bulk status processing respects cancellation."""
        from apps.api import bulk_router

        job_id = bulk_router._create_job("update_status", 2, {})
        bulk_router._jobs[job_id]["cancel_requested"] = True

        await bulk_router._process_bulk_status(
            job_id, ["c1", "c2"], "resolved", "Test", None
        )

        assert bulk_router._jobs[job_id]["status"] == "pending"

    @pytest.mark.asyncio
    async def test_process_bulk_assign_success(self, reset_bulk_state):
        """Test bulk assign processing with successful assignments."""
        from apps.api import bulk_router

        mock_dedup = MagicMock()
        mock_dedup.assign_cluster.return_value = True

        with patch.object(bulk_router, "get_dedup_service", return_value=mock_dedup):
            job_id = bulk_router._create_job("assign", 2, {})
            await bulk_router._process_bulk_assign(
                job_id, ["c1", "c2"], "user@test.com", "user@test.com"
            )

            assert bulk_router._jobs[job_id]["status"] == "completed"
            assert bulk_router._jobs[job_id]["success_count"] == 2

    @pytest.mark.asyncio
    async def test_process_bulk_assign_not_found(self, reset_bulk_state):
        """Test bulk assign processing when cluster not found."""
        from apps.api import bulk_router

        mock_dedup = MagicMock()
        mock_dedup.assign_cluster.return_value = False

        with patch.object(bulk_router, "get_dedup_service", return_value=mock_dedup):
            job_id = bulk_router._create_job("assign", 1, {})
            await bulk_router._process_bulk_assign(
                job_id, ["c1"], "user@test.com", None
            )

            assert bulk_router._jobs[job_id]["status"] == "failed"
            assert bulk_router._jobs[job_id]["failure_count"] == 1

    @pytest.mark.asyncio
    async def test_process_bulk_assign_exception(self, reset_bulk_state):
        """Test bulk assign processing handles exceptions."""
        from apps.api import bulk_router

        mock_dedup = MagicMock()
        mock_dedup.assign_cluster.side_effect = Exception("DB error")

        with patch.object(bulk_router, "get_dedup_service", return_value=mock_dedup):
            job_id = bulk_router._create_job("assign", 1, {})
            await bulk_router._process_bulk_assign(
                job_id, ["c1"], "user@test.com", None
            )

            assert bulk_router._jobs[job_id]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_process_bulk_accept_risk_success(self, reset_bulk_state):
        """Test bulk accept risk processing with success."""
        from apps.api import bulk_router

        mock_dedup = MagicMock()
        mock_dedup.update_cluster_status.return_value = True

        with patch.object(bulk_router, "get_dedup_service", return_value=mock_dedup):
            job_id = bulk_router._create_job("accept_risk", 1, {})
            await bulk_router._process_bulk_accept_risk(
                job_id, ["c1"], "Low impact", "ciso@test.com", 90
            )

            assert bulk_router._jobs[job_id]["status"] == "completed"
            assert bulk_router._jobs[job_id]["success_count"] == 1

    @pytest.mark.asyncio
    async def test_process_bulk_accept_risk_not_found(self, reset_bulk_state):
        """Test bulk accept risk when cluster not found."""
        from apps.api import bulk_router

        mock_dedup = MagicMock()
        mock_dedup.update_cluster_status.return_value = False

        with patch.object(bulk_router, "get_dedup_service", return_value=mock_dedup):
            job_id = bulk_router._create_job("accept_risk", 1, {})
            await bulk_router._process_bulk_accept_risk(
                job_id, ["c1"], "Low impact", "ciso@test.com", 90
            )

            assert bulk_router._jobs[job_id]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_process_bulk_accept_risk_value_error(self, reset_bulk_state):
        """Test bulk accept risk handles ValueError."""
        from apps.api import bulk_router

        mock_dedup = MagicMock()
        mock_dedup.update_cluster_status.side_effect = ValueError("Invalid")

        with patch.object(bulk_router, "get_dedup_service", return_value=mock_dedup):
            job_id = bulk_router._create_job("accept_risk", 1, {})
            await bulk_router._process_bulk_accept_risk(
                job_id, ["c1"], "Low impact", "ciso@test.com", 90
            )

            assert bulk_router._jobs[job_id]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_process_bulk_accept_risk_exception(self, reset_bulk_state):
        """Test bulk accept risk handles generic exceptions."""
        from apps.api import bulk_router

        mock_dedup = MagicMock()
        mock_dedup.update_cluster_status.side_effect = Exception("Error")

        with patch.object(bulk_router, "get_dedup_service", return_value=mock_dedup):
            job_id = bulk_router._create_job("accept_risk", 1, {})
            await bulk_router._process_bulk_accept_risk(
                job_id, ["c1"], "Low impact", "ciso@test.com", 90
            )

            assert bulk_router._jobs[job_id]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_process_bulk_export_success(self, reset_bulk_state):
        """Test bulk export processing."""
        from apps.api import bulk_router

        job_id = bulk_router._create_job("export", 3, {})
        await bulk_router._process_bulk_export(
            job_id, ["id1", "id2", "id3"], "json", "org-123", None
        )

        assert bulk_router._jobs[job_id]["status"] == "completed"
        assert bulk_router._jobs[job_id]["success_count"] == 3
        assert len(bulk_router._jobs[job_id]["results"]) == 1
        assert "export_id" in bulk_router._jobs[job_id]["results"][0]

    @pytest.mark.asyncio
    async def test_process_bulk_export_cancelled(self, reset_bulk_state):
        """Test bulk export respects cancellation."""
        from apps.api import bulk_router

        job_id = bulk_router._create_job("export", 3, {})
        bulk_router._jobs[job_id]["cancel_requested"] = True

        await bulk_router._process_bulk_export(
            job_id, ["id1", "id2", "id3"], "json", "org-123", None
        )

        assert bulk_router._jobs[job_id]["status"] == "pending"


class TestBulkTicketCreation:
    """Tests for bulk ticket creation with various integrations."""

    @pytest.mark.asyncio
    async def test_process_bulk_tickets_integration_not_found(self, reset_bulk_state):
        """Test bulk tickets when integration not found."""
        from apps.api import bulk_router

        mock_db = MagicMock()
        mock_db.get_integration.return_value = None

        with patch.object(bulk_router, "get_integration_db", return_value=mock_db):
            job_id = bulk_router._create_job("create_tickets", 1, {})
            await bulk_router._process_bulk_tickets(
                job_id, ["c1"], "nonexistent", "SEC", "Bug"
            )

            assert bulk_router._jobs[job_id]["status"] == "failed"
            assert any(
                "not found" in str(e) for e in bulk_router._jobs[job_id]["errors"]
            )

    @pytest.mark.asyncio
    async def test_process_bulk_tickets_jira_success(self, reset_bulk_state):
        """Test bulk tickets with Jira integration."""
        from core.integration_models import IntegrationType

        from apps.api import bulk_router

        mock_integration = MagicMock()
        mock_integration.integration_type = IntegrationType.JIRA
        mock_integration.config = {"url": "https://jira.example.com", "token": "test"}

        mock_db = MagicMock()
        mock_db.get_integration.return_value = mock_integration

        mock_dedup = MagicMock()
        mock_dedup.get_cluster.return_value = {
            "title": "SQL Injection",
            "severity": "high",
            "category": "injection",
            "cve_id": "CVE-2024-1234",
        }
        mock_dedup.link_to_ticket.return_value = True

        mock_outcome = MagicMock()
        mock_outcome.success = True
        mock_outcome.details = {"issue_key": "SEC-123", "url": "https://jira/SEC-123"}

        mock_connector = MagicMock()
        mock_connector.configured = True
        mock_connector.create_issue.return_value = mock_outcome

        with patch.object(bulk_router, "get_integration_db", return_value=mock_db):
            with patch.object(
                bulk_router, "get_dedup_service", return_value=mock_dedup
            ):
                with patch.object(
                    bulk_router, "JiraConnector", return_value=mock_connector
                ):
                    job_id = bulk_router._create_job("create_tickets", 1, {})
                    await bulk_router._process_bulk_tickets(
                        job_id, ["c1"], "jira-1", "SEC", "Bug"
                    )

                    assert bulk_router._jobs[job_id]["status"] == "completed"
                    assert bulk_router._jobs[job_id]["success_count"] == 1

    @pytest.mark.asyncio
    async def test_process_bulk_tickets_servicenow(self, reset_bulk_state):
        """Test bulk tickets with ServiceNow integration."""
        from core.integration_models import IntegrationType

        from apps.api import bulk_router

        mock_integration = MagicMock()
        mock_integration.integration_type = IntegrationType.SERVICENOW
        mock_integration.config = {"url": "https://snow.example.com"}

        mock_db = MagicMock()
        mock_db.get_integration.return_value = mock_integration

        mock_dedup = MagicMock()
        mock_dedup.get_cluster.return_value = {"title": "Test", "severity": "medium"}
        mock_dedup.link_to_ticket.return_value = True

        mock_outcome = MagicMock()
        mock_outcome.success = True
        mock_outcome.details = {"id": "INC001", "url": "https://snow/INC001"}

        mock_connector = MagicMock()
        mock_connector.configured = True
        mock_connector.create_incident.return_value = mock_outcome

        with patch.object(bulk_router, "get_integration_db", return_value=mock_db):
            with patch.object(
                bulk_router, "get_dedup_service", return_value=mock_dedup
            ):
                with patch.object(
                    bulk_router, "ServiceNowConnector", return_value=mock_connector
                ):
                    job_id = bulk_router._create_job("create_tickets", 1, {})
                    await bulk_router._process_bulk_tickets(
                        job_id, ["c1"], "snow-1", None, "Incident"
                    )

                    assert bulk_router._jobs[job_id]["status"] == "completed"

    @pytest.mark.asyncio
    async def test_process_bulk_tickets_gitlab(self, reset_bulk_state):
        """Test bulk tickets with GitLab integration."""
        from core.integration_models import IntegrationType

        from apps.api import bulk_router

        mock_integration = MagicMock()
        mock_integration.integration_type = IntegrationType.GITLAB
        mock_integration.config = {"url": "https://gitlab.example.com"}

        mock_db = MagicMock()
        mock_db.get_integration.return_value = mock_integration

        mock_dedup = MagicMock()
        mock_dedup.get_cluster.return_value = {"title": "Test", "severity": "low"}
        mock_dedup.link_to_ticket.return_value = True

        mock_outcome = MagicMock()
        mock_outcome.success = True
        mock_outcome.details = {"issue_id": "42", "url": "https://gitlab/issues/42"}

        mock_connector = MagicMock()
        mock_connector.configured = True
        mock_connector.create_issue.return_value = mock_outcome

        with patch.object(bulk_router, "get_integration_db", return_value=mock_db):
            with patch.object(
                bulk_router, "get_dedup_service", return_value=mock_dedup
            ):
                with patch.object(
                    bulk_router, "GitLabConnector", return_value=mock_connector
                ):
                    job_id = bulk_router._create_job("create_tickets", 1, {})
                    await bulk_router._process_bulk_tickets(
                        job_id, ["c1"], "gitlab-1", "project", "Issue"
                    )

                    assert bulk_router._jobs[job_id]["status"] == "completed"

    @pytest.mark.asyncio
    async def test_process_bulk_tickets_github(self, reset_bulk_state):
        """Test bulk tickets with GitHub integration."""
        from core.integration_models import IntegrationType

        from apps.api import bulk_router

        mock_integration = MagicMock()
        mock_integration.integration_type = IntegrationType.GITHUB
        mock_integration.config = {"token": "ghp_test"}

        mock_db = MagicMock()
        mock_db.get_integration.return_value = mock_integration

        mock_dedup = MagicMock()
        mock_dedup.get_cluster.return_value = {"title": "Test", "severity": "info"}
        mock_dedup.link_to_ticket.return_value = True

        mock_outcome = MagicMock()
        mock_outcome.success = True
        mock_outcome.details = {"number": "99", "url": "https://github/issues/99"}

        mock_connector = MagicMock()
        mock_connector.configured = True
        mock_connector.create_issue.return_value = mock_outcome

        with patch.object(bulk_router, "get_integration_db", return_value=mock_db):
            with patch.object(
                bulk_router, "get_dedup_service", return_value=mock_dedup
            ):
                with patch.object(
                    bulk_router, "GitHubConnector", return_value=mock_connector
                ):
                    job_id = bulk_router._create_job("create_tickets", 1, {})
                    await bulk_router._process_bulk_tickets(
                        job_id, ["c1"], "github-1", "repo", "Issue"
                    )

                    assert bulk_router._jobs[job_id]["status"] == "completed"

    @pytest.mark.asyncio
    async def test_process_bulk_tickets_azure_devops(self, reset_bulk_state):
        """Test bulk tickets with Azure DevOps integration."""
        from core.integration_models import IntegrationType

        from apps.api import bulk_router

        mock_integration = MagicMock()
        mock_integration.integration_type = IntegrationType.AZURE_DEVOPS
        mock_integration.config = {"org": "test-org"}

        mock_db = MagicMock()
        mock_db.get_integration.return_value = mock_integration

        mock_dedup = MagicMock()
        mock_dedup.get_cluster.return_value = {"title": "Test", "severity": "critical"}
        mock_dedup.link_to_ticket.return_value = True

        mock_outcome = MagicMock()
        mock_outcome.success = True
        mock_outcome.details = {"id": "1234", "url": "https://dev.azure.com/1234"}

        mock_connector = MagicMock()
        mock_connector.configured = True
        mock_connector.create_work_item.return_value = mock_outcome

        with patch.object(bulk_router, "get_integration_db", return_value=mock_db):
            with patch.object(
                bulk_router, "get_dedup_service", return_value=mock_dedup
            ):
                with patch.object(
                    bulk_router, "AzureDevOpsConnector", return_value=mock_connector
                ):
                    job_id = bulk_router._create_job("create_tickets", 1, {})
                    await bulk_router._process_bulk_tickets(
                        job_id, ["c1"], "ado-1", "project", "Bug"
                    )

                    assert bulk_router._jobs[job_id]["status"] == "completed"

    @pytest.mark.asyncio
    async def test_process_bulk_tickets_unsupported_type(self, reset_bulk_state):
        """Test bulk tickets with unsupported integration type."""
        from apps.api import bulk_router

        mock_integration = MagicMock()
        mock_integration.integration_type = MagicMock()
        mock_integration.integration_type.value = "unsupported"
        mock_integration.config = {}

        mock_db = MagicMock()
        mock_db.get_integration.return_value = mock_integration

        with patch.object(bulk_router, "get_integration_db", return_value=mock_db):
            job_id = bulk_router._create_job("create_tickets", 1, {})
            await bulk_router._process_bulk_tickets(
                job_id, ["c1"], "unsupported-1", "project", "Bug"
            )

            assert bulk_router._jobs[job_id]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_process_bulk_tickets_not_configured(self, reset_bulk_state):
        """Test bulk tickets when connector not configured."""
        from core.integration_models import IntegrationType

        from apps.api import bulk_router

        mock_integration = MagicMock()
        mock_integration.integration_type = IntegrationType.JIRA
        mock_integration.config = {}

        mock_db = MagicMock()
        mock_db.get_integration.return_value = mock_integration

        mock_connector = MagicMock()
        mock_connector.configured = False

        with patch.object(bulk_router, "get_integration_db", return_value=mock_db):
            with patch.object(
                bulk_router, "JiraConnector", return_value=mock_connector
            ):
                job_id = bulk_router._create_job("create_tickets", 1, {})
                await bulk_router._process_bulk_tickets(
                    job_id, ["c1"], "jira-1", "SEC", "Bug"
                )

                assert bulk_router._jobs[job_id]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_process_bulk_tickets_cluster_not_found(self, reset_bulk_state):
        """Test bulk tickets when cluster not found."""
        from core.integration_models import IntegrationType

        from apps.api import bulk_router

        mock_integration = MagicMock()
        mock_integration.integration_type = IntegrationType.JIRA
        mock_integration.config = {"url": "https://jira.example.com"}

        mock_db = MagicMock()
        mock_db.get_integration.return_value = mock_integration

        mock_dedup = MagicMock()
        mock_dedup.get_cluster.return_value = None

        mock_connector = MagicMock()
        mock_connector.configured = True

        with patch.object(bulk_router, "get_integration_db", return_value=mock_db):
            with patch.object(
                bulk_router, "get_dedup_service", return_value=mock_dedup
            ):
                with patch.object(
                    bulk_router, "JiraConnector", return_value=mock_connector
                ):
                    job_id = bulk_router._create_job("create_tickets", 1, {})
                    await bulk_router._process_bulk_tickets(
                        job_id, ["c1"], "jira-1", "SEC", "Bug"
                    )

                    assert bulk_router._jobs[job_id]["status"] == "failed"
                    assert bulk_router._jobs[job_id]["failure_count"] == 1

    @pytest.mark.asyncio
    async def test_process_bulk_tickets_connector_failure(self, reset_bulk_state):
        """Test bulk tickets when connector returns failure."""
        from core.integration_models import IntegrationType

        from apps.api import bulk_router

        mock_integration = MagicMock()
        mock_integration.integration_type = IntegrationType.JIRA
        mock_integration.config = {"url": "https://jira.example.com"}

        mock_db = MagicMock()
        mock_db.get_integration.return_value = mock_integration

        mock_dedup = MagicMock()
        mock_dedup.get_cluster.return_value = {"title": "Test", "severity": "high"}

        mock_outcome = MagicMock()
        mock_outcome.success = False
        mock_outcome.details = {"reason": "Permission denied"}

        mock_connector = MagicMock()
        mock_connector.configured = True
        mock_connector.create_issue.return_value = mock_outcome

        with patch.object(bulk_router, "get_integration_db", return_value=mock_db):
            with patch.object(
                bulk_router, "get_dedup_service", return_value=mock_dedup
            ):
                with patch.object(
                    bulk_router, "JiraConnector", return_value=mock_connector
                ):
                    job_id = bulk_router._create_job("create_tickets", 1, {})
                    await bulk_router._process_bulk_tickets(
                        job_id, ["c1"], "jira-1", "SEC", "Bug"
                    )

                    assert bulk_router._jobs[job_id]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_process_bulk_tickets_exception(self, reset_bulk_state):
        """Test bulk tickets handles exceptions."""
        from core.integration_models import IntegrationType

        from apps.api import bulk_router

        mock_integration = MagicMock()
        mock_integration.integration_type = IntegrationType.JIRA
        mock_integration.config = {"url": "https://jira.example.com"}

        mock_db = MagicMock()
        mock_db.get_integration.return_value = mock_integration

        mock_dedup = MagicMock()
        mock_dedup.get_cluster.side_effect = Exception("Database error")

        mock_connector = MagicMock()
        mock_connector.configured = True

        with patch.object(bulk_router, "get_integration_db", return_value=mock_db):
            with patch.object(
                bulk_router, "get_dedup_service", return_value=mock_dedup
            ):
                with patch.object(
                    bulk_router, "JiraConnector", return_value=mock_connector
                ):
                    job_id = bulk_router._create_job("create_tickets", 1, {})
                    await bulk_router._process_bulk_tickets(
                        job_id, ["c1"], "jira-1", "SEC", "Bug"
                    )

                    assert bulk_router._jobs[job_id]["status"] == "failed"


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_severity_to_priority_critical(self):
        """Test severity to priority mapping for critical."""
        from apps.api.bulk_router import _severity_to_priority

        assert _severity_to_priority("critical") == "Highest"

    def test_severity_to_priority_high(self):
        """Test severity to priority mapping for high."""
        from apps.api.bulk_router import _severity_to_priority

        assert _severity_to_priority("high") == "High"

    def test_severity_to_priority_medium(self):
        """Test severity to priority mapping for medium."""
        from apps.api.bulk_router import _severity_to_priority

        assert _severity_to_priority("medium") == "Medium"

    def test_severity_to_priority_low(self):
        """Test severity to priority mapping for low."""
        from apps.api.bulk_router import _severity_to_priority

        assert _severity_to_priority("low") == "Low"

    def test_severity_to_priority_info(self):
        """Test severity to priority mapping for info."""
        from apps.api.bulk_router import _severity_to_priority

        assert _severity_to_priority("info") == "Lowest"

    def test_severity_to_priority_unknown(self):
        """Test severity to priority mapping for unknown."""
        from apps.api.bulk_router import _severity_to_priority

        assert _severity_to_priority("unknown") == "Medium"

    def test_severity_to_priority_case_insensitive(self):
        """Test severity to priority is case insensitive."""
        from apps.api.bulk_router import _severity_to_priority

        assert _severity_to_priority("CRITICAL") == "Highest"
        assert _severity_to_priority("High") == "High"

    def test_get_dedup_service_singleton(self, reset_bulk_state):
        """Test dedup service is created as singleton."""
        from apps.api import bulk_router

        with patch.object(bulk_router, "DeduplicationService") as mock_cls:
            mock_instance = MagicMock()
            mock_cls.return_value = mock_instance

            service1 = bulk_router.get_dedup_service()
            service2 = bulk_router.get_dedup_service()

            assert service1 is service2
            mock_cls.assert_called_once()

    def test_get_integration_db_singleton(self, reset_bulk_state):
        """Test integration db is created as singleton."""
        from apps.api import bulk_router

        with patch.object(bulk_router, "IntegrationDB") as mock_cls:
            mock_instance = MagicMock()
            mock_cls.return_value = mock_instance

            db1 = bulk_router.get_integration_db()
            db2 = bulk_router.get_integration_db()

            assert db1 is db2
            mock_cls.assert_called_once()

    def test_is_job_cancelled_nonexistent(self, reset_bulk_state):
        """Test _is_job_cancelled returns True for nonexistent job."""
        from apps.api.bulk_router import _is_job_cancelled

        assert _is_job_cancelled("nonexistent") is True

    def test_is_job_cancelled_not_cancelled(self, reset_bulk_state):
        """Test _is_job_cancelled returns False for active job."""
        from apps.api import bulk_router

        job_id = bulk_router._create_job("test", 1, {})
        assert bulk_router._is_job_cancelled(job_id) is False

    def test_is_job_cancelled_cancelled(self, reset_bulk_state):
        """Test _is_job_cancelled returns True for cancelled job."""
        from apps.api import bulk_router

        job_id = bulk_router._create_job("test", 1, {})
        bulk_router._jobs[job_id]["cancel_requested"] = True
        assert bulk_router._is_job_cancelled(job_id) is True
