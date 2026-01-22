"""
Tests for integrations_router.py connector test endpoints to ensure 100% diff coverage.

These tests cover the connector test endpoint branches for ServiceNow, GitLab, GitHub, and Azure DevOps.
"""
import uuid
from unittest.mock import MagicMock, patch


def test_test_integration_servicenow_configured(authenticated_client):
    """Test ServiceNow integration test when configured."""
    unique_name = f"Test ServiceNow {uuid.uuid4()}"
    # Create a ServiceNow integration first
    create_response = authenticated_client.post(
        "/api/v1/integrations/",
        json={
            "name": unique_name,
            "integration_type": "servicenow",
            "config": {
                "instance_url": "https://test.service-now.com",
                "user": "admin",
                "password": "test-password",
            },
            "enabled": True,
        },
    )
    assert create_response.status_code == 201
    integration_id = create_response.json()["id"]

    # Mock the ServiceNowConnector to return configured=True
    with patch("apps.api.integrations_router.ServiceNowConnector") as mock_connector:
        mock_instance = MagicMock()
        mock_instance.configured = True
        mock_instance.instance_url = "https://test.service-now.com"
        mock_connector.return_value = mock_instance

        response = authenticated_client.post(
            f"/api/v1/integrations/{integration_id}/test"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "ServiceNow" in data["message"]


def test_test_integration_servicenow_not_configured(authenticated_client):
    """Test ServiceNow integration test when not configured."""
    unique_name = f"Test ServiceNow Unconfigured {uuid.uuid4()}"
    # Create a ServiceNow integration first
    create_response = authenticated_client.post(
        "/api/v1/integrations/",
        json={
            "name": unique_name,
            "integration_type": "servicenow",
            "config": {},
            "enabled": True,
        },
    )
    assert create_response.status_code == 201
    integration_id = create_response.json()["id"]

    # Mock the ServiceNowConnector to return configured=False
    with patch("apps.api.integrations_router.ServiceNowConnector") as mock_connector:
        mock_instance = MagicMock()
        mock_instance.configured = False
        mock_connector.return_value = mock_instance

        response = authenticated_client.post(
            f"/api/v1/integrations/{integration_id}/test"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not fully configured" in data["message"]


def test_test_integration_gitlab_configured(authenticated_client):
    """Test GitLab integration test when configured."""
    unique_name = f"Test GitLab {uuid.uuid4()}"
    # Create a GitLab integration first
    create_response = authenticated_client.post(
        "/api/v1/integrations/",
        json={
            "name": unique_name,
            "integration_type": "gitlab",
            "config": {
                "base_url": "https://gitlab.com",
                "project_id": "12345",
                "token": "test-token",
            },
            "enabled": True,
        },
    )
    assert create_response.status_code == 201
    integration_id = create_response.json()["id"]

    # Mock the GitLabConnector to return configured=True
    with patch("apps.api.integrations_router.GitLabConnector") as mock_connector:
        mock_instance = MagicMock()
        mock_instance.configured = True
        mock_instance.base_url = "https://gitlab.com"
        mock_instance.project_id = "12345"
        mock_connector.return_value = mock_instance

        response = authenticated_client.post(
            f"/api/v1/integrations/{integration_id}/test"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "GitLab" in data["message"]


def test_test_integration_gitlab_not_configured(authenticated_client):
    """Test GitLab integration test when not configured."""
    unique_name = f"Test GitLab Unconfigured {uuid.uuid4()}"
    # Create a GitLab integration first
    create_response = authenticated_client.post(
        "/api/v1/integrations/",
        json={
            "name": unique_name,
            "integration_type": "gitlab",
            "config": {},
            "enabled": True,
        },
    )
    assert create_response.status_code == 201
    integration_id = create_response.json()["id"]

    # Mock the GitLabConnector to return configured=False
    with patch("apps.api.integrations_router.GitLabConnector") as mock_connector:
        mock_instance = MagicMock()
        mock_instance.configured = False
        mock_connector.return_value = mock_instance

        response = authenticated_client.post(
            f"/api/v1/integrations/{integration_id}/test"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not fully configured" in data["message"]


def test_test_integration_github_configured(authenticated_client):
    """Test GitHub integration test when configured."""
    unique_name = f"Test GitHub {uuid.uuid4()}"
    # Create a GitHub integration first
    create_response = authenticated_client.post(
        "/api/v1/integrations/",
        json={
            "name": unique_name,
            "integration_type": "github",
            "config": {
                "owner": "test-owner",
                "repo": "test-repo",
                "token": "test-token",
            },
            "enabled": True,
        },
    )
    assert create_response.status_code == 201
    integration_id = create_response.json()["id"]

    # Mock the GitHubConnector to return configured=True
    with patch("apps.api.integrations_router.GitHubConnector") as mock_connector:
        mock_instance = MagicMock()
        mock_instance.configured = True
        mock_instance.owner = "test-owner"
        mock_instance.repo = "test-repo"
        mock_connector.return_value = mock_instance

        response = authenticated_client.post(
            f"/api/v1/integrations/{integration_id}/test"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "GitHub" in data["message"]


def test_test_integration_github_not_configured(authenticated_client):
    """Test GitHub integration test when not configured."""
    unique_name = f"Test GitHub Unconfigured {uuid.uuid4()}"
    # Create a GitHub integration first
    create_response = authenticated_client.post(
        "/api/v1/integrations/",
        json={
            "name": unique_name,
            "integration_type": "github",
            "config": {},
            "enabled": True,
        },
    )
    assert create_response.status_code == 201
    integration_id = create_response.json()["id"]

    # Mock the GitHubConnector to return configured=False
    with patch("apps.api.integrations_router.GitHubConnector") as mock_connector:
        mock_instance = MagicMock()
        mock_instance.configured = False
        mock_connector.return_value = mock_instance

        response = authenticated_client.post(
            f"/api/v1/integrations/{integration_id}/test"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not fully configured" in data["message"]


def test_test_integration_azure_devops_configured(authenticated_client):
    """Test Azure DevOps integration test when configured."""
    unique_name = f"Test Azure DevOps {uuid.uuid4()}"
    # Create an Azure DevOps integration first
    create_response = authenticated_client.post(
        "/api/v1/integrations/",
        json={
            "name": unique_name,
            "integration_type": "azure_devops",
            "config": {
                "organization": "test-org",
                "project": "test-project",
                "token": "test-token",
            },
            "enabled": True,
        },
    )
    assert create_response.status_code == 201
    integration_id = create_response.json()["id"]

    # Mock the AzureDevOpsConnector to return configured=True
    with patch("apps.api.integrations_router.AzureDevOpsConnector") as mock_connector:
        mock_instance = MagicMock()
        mock_instance.configured = True
        mock_instance.organization = "test-org"
        mock_instance.project = "test-project"
        mock_connector.return_value = mock_instance

        response = authenticated_client.post(
            f"/api/v1/integrations/{integration_id}/test"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "Azure DevOps" in data["message"]


def test_test_integration_azure_devops_not_configured(authenticated_client):
    """Test Azure DevOps integration test when not configured."""
    unique_name = f"Test Azure DevOps Unconfigured {uuid.uuid4()}"
    # Create an Azure DevOps integration first
    create_response = authenticated_client.post(
        "/api/v1/integrations/",
        json={
            "name": unique_name,
            "integration_type": "azure_devops",
            "config": {},
            "enabled": True,
        },
    )
    assert create_response.status_code == 201
    integration_id = create_response.json()["id"]

    # Mock the AzureDevOpsConnector to return configured=False
    with patch("apps.api.integrations_router.AzureDevOpsConnector") as mock_connector:
        mock_instance = MagicMock()
        mock_instance.configured = False
        mock_connector.return_value = mock_instance

        response = authenticated_client.post(
            f"/api/v1/integrations/{integration_id}/test"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not fully configured" in data["message"]
