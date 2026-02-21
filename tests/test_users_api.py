"""
Tests for user management API endpoints.
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


def test_list_users_empty(client, db, monkeypatch):
    """Test listing users when database is empty."""
    monkeypatch.setattr("apps.api.users_router.db", db)

    response = client.get("/api/v1/users")
    assert response.status_code == 200
    data = response.json()
    assert data["items"] == []
    assert data["total"] == 0


def test_create_user(client, db, monkeypatch):
    """Test creating a new user."""
    monkeypatch.setattr("apps.api.users_router.db", db)

    user_data = {
        "email": "test@example.com",
        "password": "SecurePass123!",
        "first_name": "Test",
        "last_name": "User",
        "role": "viewer",
        "department": "Engineering",
    }

    response = client.post("/api/v1/users", json=user_data)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "test@example.com"
    assert data["first_name"] == "Test"
    assert data["role"] == "viewer"
    assert "password_hash" not in data


def test_create_user_duplicate_email(client, db, monkeypatch):
    """Test creating user with duplicate email."""
    monkeypatch.setattr("apps.api.users_router.db", db)

    user_data = {
        "email": "test@example.com",
        "password": "SecurePass123!",
        "first_name": "Test",
        "last_name": "User",
        "role": "viewer",
    }

    client.post("/api/v1/users", json=user_data)
    response = client.post("/api/v1/users", json=user_data)
    assert response.status_code == 409


def test_get_user(client, db, monkeypatch):
    """Test getting user by ID."""
    monkeypatch.setattr("apps.api.users_router.db", db)

    user_data = {
        "email": "test@example.com",
        "password": "SecurePass123!",
        "first_name": "Test",
        "last_name": "User",
        "role": "viewer",
    }

    create_response = client.post("/api/v1/users", json=user_data)
    user_id = create_response.json()["id"]

    response = client.get(f"/api/v1/users/{user_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == user_id
    assert data["email"] == "test@example.com"


def test_get_user_not_found(client, db, monkeypatch):
    """Test getting non-existent user."""
    monkeypatch.setattr("apps.api.users_router.db", db)

    response = client.get("/api/v1/users/nonexistent-id")
    assert response.status_code == 404


def test_update_user(client, db, monkeypatch):
    """Test updating user."""
    monkeypatch.setattr("apps.api.users_router.db", db)

    user_data = {
        "email": "test@example.com",
        "password": "SecurePass123!",
        "first_name": "Test",
        "last_name": "User",
        "role": "viewer",
    }

    create_response = client.post("/api/v1/users", json=user_data)
    user_id = create_response.json()["id"]

    update_data = {"first_name": "Updated", "role": "developer"}

    response = client.put(f"/api/v1/users/{user_id}", json=update_data)
    assert response.status_code == 200
    data = response.json()
    assert data["first_name"] == "Updated"
    assert data["role"] == "developer"


def test_delete_user(client, db, monkeypatch):
    """Test deleting user."""
    monkeypatch.setattr("apps.api.users_router.db", db)

    user_data = {
        "email": "test@example.com",
        "password": "SecurePass123!",
        "first_name": "Test",
        "last_name": "User",
        "role": "viewer",
    }

    create_response = client.post("/api/v1/users", json=user_data)
    user_id = create_response.json()["id"]

    response = client.delete(f"/api/v1/users/{user_id}")
    assert response.status_code == 204

    get_response = client.get(f"/api/v1/users/{user_id}")
    assert get_response.status_code == 404


def test_login_success(client, db, monkeypatch):
    """Test successful login."""
    monkeypatch.setattr("apps.api.users_router.db", db)

    user_data = {
        "email": "test@example.com",
        "password": "SecurePass123!",
        "first_name": "Test",
        "last_name": "User",
        "role": "viewer",
    }

    client.post("/api/v1/users", json=user_data)

    login_data = {"email": "test@example.com", "password": "SecurePass123!"}

    response = client.post("/api/v1/users/login", json=login_data)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == "test@example.com"


def test_login_invalid_credentials(client, db, monkeypatch):
    """Test login with invalid credentials."""
    monkeypatch.setattr("apps.api.users_router.db", db)

    login_data = {"email": "test@example.com", "password": "WrongPassword"}

    response = client.post("/api/v1/users/login", json=login_data)
    assert response.status_code == 401
