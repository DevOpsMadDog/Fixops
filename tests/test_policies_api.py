"""
Tests for policy management API endpoints.
"""
import pytest
from core.policy_db import PolicyDB


@pytest.fixture
def client(authenticated_client):
    """Create test client using shared authenticated_client fixture."""
    return authenticated_client


@pytest.fixture
def db():
    """Create test database."""
    import os
    import tempfile

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    db = PolicyDB(db_path=path)
    yield db

    os.unlink(path)


def test_list_policies_empty(client, db, monkeypatch):
    """Test listing policies when database is empty."""
    monkeypatch.setattr("apps.api.policies_router.db", db)

    response = client.get("/api/v1/policies")
    assert response.status_code == 200
    data = response.json()
    assert data["items"] == []
    assert data["total"] == 0


def test_create_policy(client, db, monkeypatch):
    """Test creating a new policy."""
    monkeypatch.setattr("apps.api.policies_router.db", db)

    policy_data = {
        "name": "Test Policy",
        "description": "A test security policy",
        "policy_type": "guardrail",
        "status": "draft",
        "rules": {"severity": "high"},
        "metadata": {"owner": "security-team"},
    }

    response = client.post("/api/v1/policies", json=policy_data)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Test Policy"
    assert data["policy_type"] == "guardrail"
    assert data["status"] == "draft"


def test_get_policy(client, db, monkeypatch):
    """Test getting policy by ID."""
    monkeypatch.setattr("apps.api.policies_router.db", db)

    policy_data = {
        "name": "Test Policy",
        "description": "A test security policy",
        "policy_type": "guardrail",
        "status": "draft",
        "rules": {},
    }

    create_response = client.post("/api/v1/policies", json=policy_data)
    policy_id = create_response.json()["id"]

    response = client.get(f"/api/v1/policies/{policy_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == policy_id
    assert data["name"] == "Test Policy"


def test_update_policy(client, db, monkeypatch):
    """Test updating policy."""
    monkeypatch.setattr("apps.api.policies_router.db", db)

    policy_data = {
        "name": "Test Policy",
        "description": "A test security policy",
        "policy_type": "guardrail",
        "status": "draft",
        "rules": {},
    }

    create_response = client.post("/api/v1/policies", json=policy_data)
    policy_id = create_response.json()["id"]

    update_data = {"name": "Updated Policy", "status": "active"}

    response = client.put(f"/api/v1/policies/{policy_id}", json=update_data)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Updated Policy"
    assert data["status"] == "active"


def test_delete_policy(client, db, monkeypatch):
    """Test deleting policy."""
    monkeypatch.setattr("apps.api.policies_router.db", db)

    policy_data = {
        "name": "Test Policy",
        "description": "A test security policy",
        "policy_type": "guardrail",
        "status": "draft",
        "rules": {},
    }

    create_response = client.post("/api/v1/policies", json=policy_data)
    policy_id = create_response.json()["id"]

    response = client.delete(f"/api/v1/policies/{policy_id}")
    assert response.status_code == 204


def test_validate_policy(client, db, monkeypatch):
    """Test policy validation."""
    monkeypatch.setattr("apps.api.policies_router.db", db)

    policy_data = {
        "name": "Test Policy",
        "description": "A test security policy",
        "policy_type": "guardrail",
        "status": "draft",
        "rules": {"severity": "high"},
    }

    create_response = client.post("/api/v1/policies", json=policy_data)
    policy_id = create_response.json()["id"]

    response = client.post(f"/api/v1/policies/{policy_id}/validate")
    assert response.status_code == 200
    data = response.json()
    assert "valid" in data


def test_test_policy(client, db, monkeypatch):
    """Test policy testing endpoint."""
    monkeypatch.setattr("apps.api.policies_router.db", db)

    policy_data = {
        "name": "Test Policy",
        "description": "A test security policy",
        "policy_type": "guardrail",
        "status": "draft",
        "rules": {},
    }

    create_response = client.post("/api/v1/policies", json=policy_data)
    policy_id = create_response.json()["id"]

    test_data = {"sample": "data"}
    response = client.post(f"/api/v1/policies/{policy_id}/test", json=test_data)
    assert response.status_code == 200


def test_get_policy_violations(client, db, monkeypatch):
    """Test getting policy violations."""
    monkeypatch.setattr("apps.api.policies_router.db", db)

    policy_data = {
        "name": "Test Policy",
        "description": "A test security policy",
        "policy_type": "guardrail",
        "status": "draft",
        "rules": {},
    }

    create_response = client.post("/api/v1/policies", json=policy_data)
    policy_id = create_response.json()["id"]

    response = client.get(f"/api/v1/policies/{policy_id}/violations")
    assert response.status_code == 200
    data = response.json()
    assert "violations" in data
