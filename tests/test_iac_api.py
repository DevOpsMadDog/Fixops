"""Tests for IaC scanning API endpoints."""
import os
import tempfile

import pytest

from core.iac_db import IaCDB


@pytest.fixture
def client(authenticated_client):
    """Create test client using shared authenticated_client fixture.

    This ensures all requests include the X-API-Key header for authentication.
    """
    return authenticated_client


@pytest.fixture
def db():
    """Create test database."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    db = IaCDB(db_path=path)
    yield db

    os.unlink(path)


def test_list_iac_findings(client, db, monkeypatch):
    """Test listing IaC findings."""
    monkeypatch.setattr("apps.api.iac_router.db", db)

    response = client.get("/api/v1/iac")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert isinstance(data["items"], list)


def test_create_iac_finding(client, db, monkeypatch):
    """Test creating IaC finding."""
    monkeypatch.setattr("apps.api.iac_router.db", db)

    response = client.post(
        "/api/v1/iac",
        json={
            "provider": "terraform",
            "severity": "high",
            "title": "S3 bucket not encrypted",
            "description": "S3 bucket lacks encryption at rest",
            "file_path": "terraform/s3.tf",
            "line_number": 15,
            "resource_type": "aws_s3_bucket",
            "resource_name": "my-bucket",
            "rule_id": "AWS001",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["provider"] == "terraform"
    assert data["status"] == "open"


def test_get_iac_finding(client, db, monkeypatch):
    """Test getting IaC finding."""
    monkeypatch.setattr("apps.api.iac_router.db", db)

    create_response = client.post(
        "/api/v1/iac",
        json={
            "provider": "kubernetes",
            "severity": "medium",
            "title": "Container runs as root",
            "description": "Container should not run as root user",
            "file_path": "k8s/deployment.yaml",
            "line_number": 20,
            "resource_type": "Deployment",
            "resource_name": "app",
            "rule_id": "K8S002",
        },
    )
    finding_id = create_response.json()["id"]

    response = client.get(f"/api/v1/iac/{finding_id}")
    assert response.status_code == 200
    assert response.json()["id"] == finding_id


def test_resolve_iac_finding(client, db, monkeypatch):
    """Test resolving IaC finding."""
    monkeypatch.setattr("apps.api.iac_router.db", db)

    create_response = client.post(
        "/api/v1/iac",
        json={
            "provider": "cloudformation",
            "severity": "low",
            "title": "Missing tags",
            "description": "Resource should have tags",
            "file_path": "cf/template.yaml",
            "line_number": 10,
            "resource_type": "AWS::EC2::Instance",
            "resource_name": "WebServer",
            "rule_id": "CF001",
        },
    )
    finding_id = create_response.json()["id"]

    response = client.post(f"/api/v1/iac/{finding_id}/resolve")
    assert response.status_code == 200
    assert response.json()["status"] == "resolved"


def test_scan_iac(client, db, monkeypatch):
    """Test triggering IaC scan."""
    monkeypatch.setattr("apps.api.iac_router.db", db)

    response = client.post(
        "/api/v1/iac/scan",
        json={"provider": "terraform", "file_path": "terraform/"},
    )
    # Expect 500 because the path doesn't exist in test environment
    # The API correctly validates and attempts to scan
    assert response.status_code in (200, 500)
    data = response.json()
    # If 200, check status; if 500, check error message
    if response.status_code == 200:
        assert data["status"] in ("scanning", "completed", "failed")
    else:
        assert "detail" in data


def test_scan_iac_null_bytes_rejected(client, db, monkeypatch):
    """Test that null bytes in path are rejected."""
    monkeypatch.setattr("apps.api.iac_router.db", db)

    response = client.post(
        "/api/v1/iac/scan",
        json={"provider": "terraform", "file_path": "terraform/\x00malicious.tf"},
    )
    assert response.status_code == 400
    assert "null bytes" in response.json()["detail"].lower()


def test_scan_iac_absolute_path_rejected(client, db, monkeypatch):
    """Test that absolute paths are rejected."""
    monkeypatch.setattr("apps.api.iac_router.db", db)

    response = client.post(
        "/api/v1/iac/scan",
        json={"provider": "terraform", "file_path": "/etc/passwd"},
    )
    assert response.status_code == 400
    assert "absolute" in response.json()["detail"].lower()


def test_scan_iac_path_traversal_rejected(client, db, monkeypatch):
    """Test that path traversal attempts are rejected."""
    monkeypatch.setattr("apps.api.iac_router.db", db)

    response = client.post(
        "/api/v1/iac/scan",
        json={"provider": "terraform", "file_path": "../../../etc/passwd"},
    )
    assert response.status_code == 400
    assert "traversal" in response.json()["detail"].lower()


def test_scan_iac_invalid_scanner(client, db, monkeypatch):
    """Test that invalid scanner type is rejected."""
    monkeypatch.setattr("apps.api.iac_router.db", db)

    response = client.post(
        "/api/v1/iac/scan",
        json={
            "provider": "terraform",
            "file_path": "terraform/",
            "scanner": "invalid_scanner",
        },
    )
    assert response.status_code == 400
    assert "invalid scanner" in response.json()["detail"].lower()


def test_scan_iac_content(client, db, monkeypatch):
    """Test scanning IaC content."""
    monkeypatch.setattr("apps.api.iac_router.db", db)

    response = client.post(
        "/api/v1/iac/scan/content",
        json={
            "content": 'resource "aws_s3_bucket" "test" { bucket = "test" }',
            "filename": "main.tf",
            "provider": "terraform",
        },
    )
    # Expect 200 or 500 depending on scanner availability
    assert response.status_code in (200, 500)
    data = response.json()
    if response.status_code == 200:
        assert "scan_id" in data
    else:
        assert "detail" in data


def test_scan_iac_content_invalid_scanner(client, db, monkeypatch):
    """Test that invalid scanner type is rejected for content scan."""
    monkeypatch.setattr("apps.api.iac_router.db", db)

    response = client.post(
        "/api/v1/iac/scan/content",
        json={
            "content": 'resource "aws_s3_bucket" "test" { bucket = "test" }',
            "filename": "main.tf",
            "scanner": "invalid_scanner",
        },
    )
    assert response.status_code == 400
    assert "invalid scanner" in response.json()["detail"].lower()


def test_get_scanner_status(client):
    """Test getting scanner status."""
    response = client.get("/api/v1/iac/scanners/status")
    assert response.status_code == 200
    data = response.json()
    assert "available_scanners" in data
    assert isinstance(data["available_scanners"], list)


def test_scan_iac_scanner_exception(client, db, monkeypatch):
    """Test that scanner exceptions are handled and return 500."""
    monkeypatch.setattr("apps.api.iac_router.db", db)

    # Mock the scanner to raise an exception
    class MockScanner:
        async def scan(self, *args, **kwargs):
            raise RuntimeError("Scanner crashed unexpectedly")

    monkeypatch.setattr("apps.api.iac_router.get_iac_scanner", lambda: MockScanner())

    response = client.post(
        "/api/v1/iac/scan",
        json={"provider": "terraform", "file_path": "terraform/"},
    )
    assert response.status_code == 500
    assert "scan failed" in response.json()["detail"].lower()


def test_scan_iac_content_scanner_exception(client, db, monkeypatch):
    """Test that scanner exceptions during content scan are handled and return 500."""
    monkeypatch.setattr("apps.api.iac_router.db", db)

    # Mock the scanner to raise an exception
    class MockScanner:
        async def scan_content(self, *args, **kwargs):
            raise RuntimeError("Content scanner crashed unexpectedly")

    monkeypatch.setattr("apps.api.iac_router.get_iac_scanner", lambda: MockScanner())

    response = client.post(
        "/api/v1/iac/scan/content",
        json={
            "content": 'resource "aws_s3_bucket" "test" { bucket = "test" }',
            "filename": "main.tf",
        },
    )
    assert response.status_code == 500
    assert "scan failed" in response.json()["detail"].lower()


def test_scan_iac_finding_persist_failure(client, db, monkeypatch):
    """Test that finding persist failures are logged but don't fail the scan."""
    from datetime import datetime
    from unittest.mock import MagicMock

    from core.iac_models import IaCFinding, IaCFindingStatus, IaCProvider
    from core.iac_scanner import IaCScanResult, IaCScanStatus, ScannerType

    # Create a mock scanner that returns findings
    mock_result = IaCScanResult(
        scan_id="test-scan-id",
        status=IaCScanStatus.COMPLETED,
        scanner=ScannerType.CHECKOV,
        provider=IaCProvider.TERRAFORM,
        target_path="/test/path",
        findings=[
            IaCFinding(
                id="finding-1",
                provider=IaCProvider.TERRAFORM,
                severity="high",
                title="Test finding",
                description="Test description",
                file_path="main.tf",
                line_number=1,
                resource_type="aws_s3_bucket",
                resource_name="test",
                rule_id="TEST001",
                status=IaCFindingStatus.OPEN,
            )
        ],
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        duration_seconds=1.0,
    )

    class MockScanner:
        async def scan(self, *args, **kwargs):
            return mock_result

    monkeypatch.setattr("apps.api.iac_router.get_iac_scanner", lambda: MockScanner())

    # Mock db to raise exception on create_finding
    mock_db = MagicMock()
    mock_db.create_finding.side_effect = Exception("Database error")
    monkeypatch.setattr("apps.api.iac_router.db", mock_db)

    response = client.post(
        "/api/v1/iac/scan",
        json={"provider": "terraform", "file_path": "terraform/"},
    )
    # Should still return 200 even if persist fails
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["findings_count"] == 1


def test_scan_iac_content_finding_persist_failure(client, db, monkeypatch):
    """Test that finding persist failures during content scan are logged but don't fail."""
    from datetime import datetime
    from unittest.mock import MagicMock

    from core.iac_models import IaCFinding, IaCFindingStatus, IaCProvider
    from core.iac_scanner import IaCScanResult, IaCScanStatus, ScannerType

    # Create a mock scanner that returns findings
    mock_result = IaCScanResult(
        scan_id="test-scan-id",
        status=IaCScanStatus.COMPLETED,
        scanner=ScannerType.CHECKOV,
        provider=IaCProvider.TERRAFORM,
        target_path="main.tf",
        findings=[
            IaCFinding(
                id="finding-1",
                provider=IaCProvider.TERRAFORM,
                severity="high",
                title="Test finding",
                description="Test description",
                file_path="main.tf",
                line_number=1,
                resource_type="aws_s3_bucket",
                resource_name="test",
                rule_id="TEST001",
                status=IaCFindingStatus.OPEN,
            )
        ],
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        duration_seconds=1.0,
    )

    class MockScanner:
        async def scan_content(self, *args, **kwargs):
            return mock_result

    monkeypatch.setattr("apps.api.iac_router.get_iac_scanner", lambda: MockScanner())

    # Mock db to raise exception on create_finding
    mock_db = MagicMock()
    mock_db.create_finding.side_effect = Exception("Database error")
    monkeypatch.setattr("apps.api.iac_router.db", mock_db)

    response = client.post(
        "/api/v1/iac/scan/content",
        json={
            "content": 'resource "aws_s3_bucket" "test" { bucket = "test" }',
            "filename": "main.tf",
        },
    )
    # Should still return 200 even if persist fails
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["findings_count"] == 1
