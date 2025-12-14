"""
Tests for workflow orchestration API endpoints.
"""
import os

import pytest
from fastapi.testclient import TestClient

from apps.api.app import create_app
from core.workflow_db import WorkflowDB
from core.workflow_models import Workflow, WorkflowExecution, WorkflowStatus

# Use the API token from environment or default (matches Docker image default)
API_TOKEN = os.getenv("FIXOPS_API_TOKEN", "demo-token-12345")


@pytest.fixture
def client(monkeypatch):
    """Create test client with proper environment variables."""
    monkeypatch.setenv(
        "FIXOPS_API_TOKEN", os.getenv("FIXOPS_API_TOKEN", "demo-token-12345")
    )
    monkeypatch.setenv("FIXOPS_MODE", os.getenv("FIXOPS_MODE", "demo"))
    app = create_app()
    return TestClient(app)


@pytest.fixture
def db():
    """Create test database using the same path as the API router."""
    # Use the same database path as the API router (data/workflows.db)
    return WorkflowDB(db_path="data/workflows.db")


@pytest.fixture(autouse=True)
def cleanup_db():
    """Clean up test database after each test."""
    yield
    # Clean up the workflows database used by both tests and API
    if os.path.exists("data/workflows.db"):
        os.remove("data/workflows.db")


def test_list_workflows_empty(client):
    """Test listing workflows when none exist."""
    response = client.get("/api/v1/workflows", headers={"X-API-Key": API_TOKEN})
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert isinstance(data["items"], list)


def test_create_workflow(client):
    """Test creating a new workflow."""
    response = client.post(
        "/api/v1/workflows",
        headers={"X-API-Key": API_TOKEN},
        json={
            "name": "Security Scan Workflow",
            "description": "Automated security scanning workflow",
            "steps": [
                {"name": "scan", "action": "run_scanner"},
                {"name": "analyze", "action": "analyze_results"},
            ],
            "triggers": {"on_commit": True},
            "enabled": True,
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Security Scan Workflow"
    assert data["enabled"] is True
    assert len(data["steps"]) == 2


def test_get_workflow(client, db):
    """Test getting workflow details."""
    workflow = Workflow(
        id="",
        name="Test Workflow",
        description="Test workflow description",
        steps=[],
        triggers={},
        enabled=True,
    )
    created = db.create_workflow(workflow)

    response = client.get(
        f"/api/v1/workflows/{created.id}", headers={"X-API-Key": API_TOKEN}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == created.id
    assert data["name"] == "Test Workflow"


def test_get_workflow_not_found(client):
    """Test getting non-existent workflow."""
    response = client.get(
        "/api/v1/workflows/nonexistent", headers={"X-API-Key": API_TOKEN}
    )
    assert response.status_code == 404


def test_update_workflow(client, db):
    """Test updating a workflow."""
    workflow = Workflow(
        id="",
        name="Test Workflow",
        description="Original description",
        steps=[],
        triggers={},
        enabled=True,
    )
    created = db.create_workflow(workflow)

    response = client.put(
        f"/api/v1/workflows/{created.id}",
        headers={"X-API-Key": API_TOKEN},
        json={
            "name": "Updated Workflow",
            "description": "Updated description",
            "enabled": False,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Updated Workflow"
    assert data["description"] == "Updated description"
    assert data["enabled"] is False


def test_update_workflow_not_found(client):
    """Test updating non-existent workflow."""
    response = client.put(
        "/api/v1/workflows/nonexistent",
        headers={"X-API-Key": API_TOKEN},
        json={"name": "Updated"},
    )
    assert response.status_code == 404


def test_delete_workflow(client, db):
    """Test deleting a workflow."""
    workflow = Workflow(
        id="",
        name="Test Workflow",
        description="Test workflow",
        steps=[],
        triggers={},
        enabled=True,
    )
    created = db.create_workflow(workflow)

    response = client.delete(
        f"/api/v1/workflows/{created.id}", headers={"X-API-Key": API_TOKEN}
    )
    assert response.status_code == 204


def test_delete_workflow_not_found(client):
    """Test deleting non-existent workflow."""
    response = client.delete(
        "/api/v1/workflows/nonexistent", headers={"X-API-Key": API_TOKEN}
    )
    assert response.status_code == 404


def test_execute_workflow(client, db):
    """Test executing a workflow."""
    workflow = Workflow(
        id="",
        name="Test Workflow",
        description="Test workflow",
        steps=[{"name": "step1", "action": "test"}],
        triggers={},
        enabled=True,
    )
    created = db.create_workflow(workflow)

    response = client.post(
        f"/api/v1/workflows/{created.id}/execute",
        headers={"X-API-Key": API_TOKEN},
        json={"input_param": "value"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["workflow_id"] == created.id
    assert data["status"] == "completed"


def test_execute_disabled_workflow(client, db):
    """Test executing a disabled workflow."""
    workflow = Workflow(
        id="",
        name="Test Workflow",
        description="Test workflow",
        steps=[],
        triggers={},
        enabled=False,
    )
    created = db.create_workflow(workflow)

    response = client.post(
        f"/api/v1/workflows/{created.id}/execute", headers={"X-API-Key": API_TOKEN}
    )
    assert response.status_code == 400


def test_execute_workflow_not_found(client):
    """Test executing non-existent workflow."""
    response = client.post(
        "/api/v1/workflows/nonexistent/execute", headers={"X-API-Key": API_TOKEN}
    )
    assert response.status_code == 404


def test_get_workflow_history(client, db):
    """Test getting workflow execution history."""
    workflow = Workflow(
        id="",
        name="Test Workflow",
        description="Test workflow",
        steps=[],
        triggers={},
        enabled=True,
    )
    created_workflow = db.create_workflow(workflow)

    execution = WorkflowExecution(
        id="",
        workflow_id=created_workflow.id,
        status=WorkflowStatus.COMPLETED,
        input_data={},
        output_data={},
    )
    db.create_execution(execution)

    response = client.get(
        f"/api/v1/workflows/{created_workflow.id}/history",
        headers={"X-API-Key": API_TOKEN},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["workflow_id"] == created_workflow.id
    assert "executions" in data
    assert len(data["executions"]) >= 1


def test_get_workflow_history_not_found(client):
    """Test getting history for non-existent workflow."""
    response = client.get(
        "/api/v1/workflows/nonexistent/history", headers={"X-API-Key": API_TOKEN}
    )
    assert response.status_code == 404


def test_list_workflows_pagination(client):
    """Test workflow list pagination."""
    response = client.get(
        "/api/v1/workflows?limit=10&offset=0", headers={"X-API-Key": API_TOKEN}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["limit"] == 10
    assert data["offset"] == 0


def test_workflow_history_pagination(client, db):
    """Test workflow history pagination."""
    workflow = Workflow(
        id="",
        name="Test Workflow",
        description="Test workflow",
        steps=[],
        triggers={},
        enabled=True,
    )
    created = db.create_workflow(workflow)

    response = client.get(
        f"/api/v1/workflows/{created.id}/history?limit=5&offset=0",
        headers={"X-API-Key": API_TOKEN},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["limit"] == 5
    assert data["offset"] == 0
