"""
Tests for team management API endpoints.
"""
import pytest
from fastapi.testclient import TestClient

from apps.api.app import create_app
from core.user_db import UserDB


@pytest.fixture
def client():
    """Create test client."""
    app = create_app()
    return TestClient(app)


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
    monkeypatch.setattr("apps.api.teams_router.db", db)

    user_data = {
        "email": "test@example.com",
        "password": "SecurePass123!",
        "first_name": "Test",
        "last_name": "User",
        "role": "viewer",
    }
    user_response = client.post("/api/v1/users", json=user_data)
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
