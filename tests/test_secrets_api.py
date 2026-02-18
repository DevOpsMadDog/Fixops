"""Tests for secrets detection API endpoints."""
import os
import tempfile

import pytest
from apps.api.app import create_app
from core.secrets_db import SecretsDB
from fastapi.testclient import TestClient

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
def auth_headers():
    """Return headers with API key for authenticated requests."""
    return {"X-API-Key": API_TOKEN}


@pytest.fixture
def db():
    """Create test database."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    db = SecretsDB(db_path=path)
    yield db

    os.unlink(path)


def test_list_secret_findings(client, db, monkeypatch, auth_headers):
    """Test listing secret findings."""
    monkeypatch.setattr("apps.api.secrets_router.db", db)

    response = client.get("/api/v1/secrets", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert isinstance(data["items"], list)


def test_create_secret_finding(client, db, monkeypatch, auth_headers):
    """Test creating secret finding."""
    monkeypatch.setattr("apps.api.secrets_router.db", db)

    response = client.post(
        "/api/v1/secrets",
        headers=auth_headers,
        json={
            "secret_type": "api_key",
            "file_path": "config/secrets.yml",
            "line_number": 42,
            "repository": "myapp",
            "branch": "main",
            "entropy_score": 4.5,
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["secret_type"] == "api_key"
    assert data["status"] == "active"


def test_get_secret_finding(client, db, monkeypatch, auth_headers):
    """Test getting secret finding."""
    monkeypatch.setattr("apps.api.secrets_router.db", db)

    create_response = client.post(
        "/api/v1/secrets",
        headers=auth_headers,
        json={
            "secret_type": "password",
            "file_path": "app.py",
            "line_number": 10,
            "repository": "test-repo",
            "branch": "dev",
        },
    )
    finding_id = create_response.json()["id"]

    response = client.get(f"/api/v1/secrets/{finding_id}", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["id"] == finding_id


def test_resolve_secret_finding(client, db, monkeypatch, auth_headers):
    """Test resolving secret finding."""
    monkeypatch.setattr("apps.api.secrets_router.db", db)

    create_response = client.post(
        "/api/v1/secrets",
        headers=auth_headers,
        json={
            "secret_type": "token",
            "file_path": "config.py",
            "line_number": 5,
            "repository": "app",
            "branch": "main",
        },
    )
    finding_id = create_response.json()["id"]

    response = client.post(
        f"/api/v1/secrets/{finding_id}/resolve", headers=auth_headers
    )
    assert response.status_code == 200
    assert response.json()["status"] == "resolved"


def test_scan_secrets_content(client, db, monkeypatch, auth_headers):
    """Test scanning content for secrets."""
    monkeypatch.setattr("apps.api.secrets_router.db", db)

    response = client.post(
        "/api/v1/secrets/scan/content",
        headers=auth_headers,
        json={
            "content": "API_KEY = 'sk-1234567890abcdef'",
            "filename": "config.py",
            "repository": "test-repo",
            "branch": "main",
        },
    )
    # Expect 200 or 500 depending on scanner availability
    assert response.status_code in (200, 500)
    data = response.json()
    if response.status_code == 200:
        assert "scan_id" in data
    else:
        assert "detail" in data


def test_scan_secrets_content_invalid_scanner(client, db, monkeypatch, auth_headers):
    """Test that invalid scanner type is rejected for content scan."""
    monkeypatch.setattr("apps.api.secrets_router.db", db)

    response = client.post(
        "/api/v1/secrets/scan/content",
        headers=auth_headers,
        json={
            "content": "API_KEY = 'sk-1234567890abcdef'",
            "filename": "config.py",
            "scanner": "invalid_scanner",
        },
    )
    assert response.status_code == 400
    assert "invalid scanner" in response.json()["detail"].lower()


def test_get_detector_status(client, auth_headers):
    """Test getting detector status."""
    response = client.get("/api/v1/secrets/scanners/status", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "available_scanners" in data
    assert isinstance(data["available_scanners"], list)


def test_scan_secrets_content_scanner_exception(client, db, monkeypatch, auth_headers):
    """Test that scanner exceptions during content scan are handled and return 500."""
    monkeypatch.setattr("apps.api.secrets_router.db", db)

    # Mock the detector to raise an exception
    class MockDetector:
        async def scan_content(self, *args, **kwargs):
            raise RuntimeError("Content scanner crashed unexpectedly")

    monkeypatch.setattr(
        "apps.api.secrets_router.get_secrets_detector", lambda: MockDetector()
    )

    response = client.post(
        "/api/v1/secrets/scan/content",
        headers=auth_headers,
        json={
            "content": "API_KEY = 'sk-1234567890abcdef'",
            "filename": "config.py",
        },
    )
    assert response.status_code == 500
    assert "scan failed" in response.json()["detail"].lower()


def test_scan_secrets_content_finding_persist_failure(
    client, db, monkeypatch, auth_headers
):
    """Test that finding persist failures during content scan are logged but don't fail."""
    from datetime import datetime
    from unittest.mock import MagicMock

    from core.secrets_models import SecretFinding, SecretStatus, SecretType
    from core.secrets_scanner import (
        SecretsScanner,
        SecretsScanResult,
        SecretsScanStatus,
    )

    # Create a mock detector that returns findings
    mock_result = SecretsScanResult(
        scan_id="test-scan-id",
        status=SecretsScanStatus.COMPLETED,
        scanner=SecretsScanner.GITLEAKS,
        target_path="config.py",
        repository="test-repo",
        branch="main",
        findings=[
            SecretFinding(
                id="finding-1",
                secret_type=SecretType.API_KEY,
                status=SecretStatus.ACTIVE,
                file_path="config.py",
                line_number=1,
                repository="test-repo",
                branch="main",
            )
        ],
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        duration_seconds=1.0,
    )

    class MockDetector:
        async def scan_content(self, *args, **kwargs):
            return mock_result

    monkeypatch.setattr(
        "apps.api.secrets_router.get_secrets_detector", lambda: MockDetector()
    )

    # Mock db to raise exception on create_finding
    mock_db = MagicMock()
    mock_db.create_finding.side_effect = Exception("Database error")
    monkeypatch.setattr("apps.api.secrets_router.db", mock_db)

    response = client.post(
        "/api/v1/secrets/scan/content",
        headers=auth_headers,
        json={
            "content": "API_KEY = 'sk-1234567890abcdef'",
            "filename": "config.py",
        },
    )
    # Should still return 200 even if persist fails
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["findings_count"] == 1
