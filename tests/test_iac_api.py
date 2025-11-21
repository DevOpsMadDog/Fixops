"""Tests for IaC scanning API endpoints."""
from fastapi.testclient import TestClient


def test_list_iac_findings(client: TestClient, api_key: str):
    """Test listing IaC findings."""
    response = client.get("/api/v1/iac", headers={"X-API-Key": api_key})
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert isinstance(data["items"], list)


def test_create_iac_finding(client: TestClient, api_key: str):
    """Test creating IaC finding."""
    response = client.post(
        "/api/v1/iac",
        headers={"X-API-Key": api_key},
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


def test_get_iac_finding(client: TestClient, api_key: str):
    """Test getting IaC finding."""
    create_response = client.post(
        "/api/v1/iac",
        headers={"X-API-Key": api_key},
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

    response = client.get(f"/api/v1/iac/{finding_id}", headers={"X-API-Key": api_key})
    assert response.status_code == 200
    assert response.json()["id"] == finding_id


def test_resolve_iac_finding(client: TestClient, api_key: str):
    """Test resolving IaC finding."""
    create_response = client.post(
        "/api/v1/iac",
        headers={"X-API-Key": api_key},
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

    response = client.post(
        f"/api/v1/iac/{finding_id}/resolve", headers={"X-API-Key": api_key}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "resolved"


def test_scan_iac(client: TestClient, api_key: str):
    """Test triggering IaC scan."""
    response = client.post(
        "/api/v1/iac/scan",
        headers={"X-API-Key": api_key},
        params={"provider": "terraform", "file_path": "terraform/"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "scanning"
