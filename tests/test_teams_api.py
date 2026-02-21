"""
Tests for team management API endpoints.
"""
import os

import pytest
from apps.api.app import create_app
from core.user_db import UserDB
from fastapi.testclient import TestClient

# Use shared API token from conftest.py
API_TOKEN = os.getenv("FIXOPS_API_TOKEN", "test-token")


@pytest.fixture
def client(monkeypatch):
    """Create authenticated test client."""
    monkeypatch.setenv("FIXOPS_API_TOKEN", API_TOKEN)
    app = create_app()
    client = TestClient(app)

    # Wrap request method to always include auth header
    orig_request = client.request

    def _request(method, url, **kwargs):
        headers = kwargs.pop("headers", {}) or {}
        headers.setdefault("X-API-Key", API_TOKEN)
        return orig_request(method, url, headers=headers, **kwargs)

    client.request = _request  # type: ignore[method-assign]
    return client


@pytest.fixture
def db():
    """Create test database."""
    import os
    import tempfile

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    db = UserDB(db_path=path)
    yield db

    os.unlink(path)


def test_list_teams_empty(client, db, monkeypatch):
    """Test listing teams when database is empty."""
    monkeypatch.setattr("apps.api.teams_router.db", db)

    response = client.get("/api/v1/teams")
    assert response.status_code == 200
    data = response.json()
    assert data["items"] == []
    assert data["total"] == 0


def test_create_team(client, db, monkeypatch):
    """Test creating a new team."""
    monkeypatch.setattr("apps.api.teams_router.db", db)

    team_data = {"name": "Engineering Team", "description": "Core engineering team"}

    response = client.post("/api/v1/teams", json=team_data)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Engineering Team"
    assert data["description"] == "Core engineering team"


def test_get_team(client, db, monkeypatch):
    """Test getting team by ID."""
    monkeypatch.setattr("apps.api.teams_router.db", db)

    team_data = {"name": "Engineering Team", "description": "Core engineering team"}

    create_response = client.post("/api/v1/teams", json=team_data)
    team_id = create_response.json()["id"]

    response = client.get(f"/api/v1/teams/{team_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == team_id
    assert data["name"] == "Engineering Team"


def test_update_team(client, db, monkeypatch):
    """Test updating team."""
    monkeypatch.setattr("apps.api.teams_router.db", db)

    team_data = {"name": "Engineering Team", "description": "Core engineering team"}

    create_response = client.post("/api/v1/teams", json=team_data)
    team_id = create_response.json()["id"]

    update_data = {"name": "Updated Team", "description": "Updated description"}

    response = client.put(f"/api/v1/teams/{team_id}", json=update_data)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Updated Team"


def test_delete_team(client, db, monkeypatch):
    """Test deleting team."""
    monkeypatch.setattr("apps.api.teams_router.db", db)

    team_data = {"name": "Engineering Team", "description": "Core engineering team"}

    create_response = client.post("/api/v1/teams", json=team_data)
    team_id = create_response.json()["id"]

    response = client.delete(f"/api/v1/teams/{team_id}")
    assert response.status_code == 204


def test_add_team_member(client, db, monkeypatch):
    """Test adding member to team."""
    import uuid

    monkeypatch.setattr("apps.api.teams_router.db", db)
    monkeypatch.setattr("apps.api.users_router.db", db)  # Also patch users router

    # Use unique email to avoid 409 Conflict from previous test runs
    unique_email = f"test-{uuid.uuid4().hex[:8]}@example.com"
    user_data = {
        "email": unique_email,
        "password": "SecurePass123!",
        "first_name": "Test",
        "last_name": "User",
        "role": "viewer",
    }
    user_response = client.post("/api/v1/users", json=user_data)
    assert (
        user_response.status_code == 201
    ), f"User creation failed: {user_response.text}"
    user_id = user_response.json()["id"]

    team_data = {"name": "Engineering Team", "description": "Core engineering team"}
    team_response = client.post("/api/v1/teams", json=team_data)
    team_id = team_response.json()["id"]

    member_data = {"user_id": user_id, "role": "member"}

    response = client.post(f"/api/v1/teams/{team_id}/members", json=member_data)
    assert response.status_code == 201


def test_list_team_members(client, db, monkeypatch):
    """Test listing team members."""
    monkeypatch.setattr("apps.api.teams_router.db", db)

    team_data = {"name": "Engineering Team", "description": "Core engineering team"}
    team_response = client.post("/api/v1/teams", json=team_data)
    team_id = team_response.json()["id"]

    response = client.get(f"/api/v1/teams/{team_id}/members")
    assert response.status_code == 200
    data = response.json()
    assert "members" in data
