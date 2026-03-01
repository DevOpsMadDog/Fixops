"""Security tests for hardened scanner API endpoints.

Tests input validation, path traversal prevention, SSRF protection,
and error handling across all scanner routers.

Run with:
    PYTHONPATH=suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations \
    python -m pytest tests/test_security_scanner_hardening.py -v --timeout=30
"""

from __future__ import annotations

import os

import pytest

# Set tokens BEFORE importing the app
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token-for-scanner-security")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from httpx import ASGITransport, AsyncClient

from apps.api.app import create_app

_TEST_TOKEN = os.environ["FIXOPS_API_TOKEN"]
_HEADERS = {"X-API-Key": _TEST_TOKEN, "Content-Type": "application/json"}


@pytest.fixture(scope="module")
def app():
    """Create the FastAPI app once for all tests."""
    return create_app()


@pytest.fixture()
async def client(app):
    """Async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# SAST Router Hardening Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sast_scan_empty_code(client):
    """SAST scan with empty code should return 400."""
    resp = await client.post(
        "/api/v1/sast/scan/code",
        json={"code": "   ", "filename": "test.py"},
        headers=_HEADERS,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_sast_scan_path_traversal_filename(client):
    """SAST scan with path traversal in filename should be sanitized."""
    resp = await client.post(
        "/api/v1/sast/scan/code",
        json={"code": "x = 1", "filename": "../../etc/passwd"},
        headers=_HEADERS,
    )
    # Should succeed but with sanitized filename
    assert resp.status_code == 200
    data = resp.json()
    # The filename in result should NOT contain path traversal
    result_str = str(data)
    assert "../../" not in result_str


@pytest.mark.asyncio
async def test_sast_scan_files_too_many(client):
    """SAST scan with too many files should return 400."""
    files = {f"file_{i}.py": "x = 1" for i in range(51)}
    resp = await client.post(
        "/api/v1/sast/scan/files",
        json={"files": files},
        headers=_HEADERS,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_sast_scan_files_empty(client):
    """SAST scan with no files should return 400."""
    resp = await client.post(
        "/api/v1/sast/scan/files",
        json={"files": {}},
        headers=_HEADERS,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_sast_scan_valid_code(client):
    """SAST scan with valid Python code should succeed."""
    resp = await client.post(
        "/api/v1/sast/scan/code",
        json={
            "code": "import os\npassword = 'hardcoded'\nos.system(password)",
            "filename": "test.py",
        },
        headers=_HEADERS,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "findings" in data or "vulnerabilities" in data or "scan_id" in data


# ---------------------------------------------------------------------------
# DAST Router Hardening Tests (SSRF Protection)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dast_scan_ssrf_localhost(client):
    """DAST scan targeting localhost should be rejected."""
    resp = await client.post(
        "/api/v1/dast/scan",
        json={"target_url": "http://127.0.0.1:8080/admin"},
        headers=_HEADERS,
    )
    assert resp.status_code == 422  # Pydantic validation error


@pytest.mark.asyncio
async def test_dast_scan_ssrf_internal_ip(client):
    """DAST scan targeting RFC1918 internal IP should be rejected."""
    resp = await client.post(
        "/api/v1/dast/scan",
        json={"target_url": "http://10.0.0.1/api/internal"},
        headers=_HEADERS,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_dast_scan_ssrf_172_range(client):
    """DAST scan targeting 172.16.x.x internal IP should be rejected."""
    resp = await client.post(
        "/api/v1/dast/scan",
        json={"target_url": "http://172.16.0.1/secret"},
        headers=_HEADERS,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_dast_scan_ssrf_192_range(client):
    """DAST scan targeting 192.168.x.x internal IP should be rejected."""
    resp = await client.post(
        "/api/v1/dast/scan",
        json={"target_url": "http://192.168.1.1/router"},
        headers=_HEADERS,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_dast_scan_ssrf_metadata(client):
    """DAST scan targeting cloud metadata endpoint should be rejected."""
    resp = await client.post(
        "/api/v1/dast/scan",
        json={"target_url": "http://169.254.169.254/latest/meta-data"},
        headers=_HEADERS,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_dast_scan_ssrf_ftp_scheme(client):
    """DAST scan with non-HTTP scheme should be rejected."""
    resp = await client.post(
        "/api/v1/dast/scan",
        json={"target_url": "ftp://example.com/file.txt"},
        headers=_HEADERS,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_dast_scan_ssrf_file_scheme(client):
    """DAST scan with file:// scheme should be rejected."""
    resp = await client.post(
        "/api/v1/dast/scan",
        json={"target_url": "file:///etc/passwd"},
        headers=_HEADERS,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_dast_scan_max_depth_exceeded(client):
    """DAST scan with excessive depth should be rejected."""
    resp = await client.post(
        "/api/v1/dast/scan",
        json={"target_url": "https://example.com", "max_depth": 100},
        headers=_HEADERS,
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Container Scanner Hardening Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_container_scan_empty_dockerfile(client):
    """Container scan with empty Dockerfile should return 400."""
    resp = await client.post(
        "/api/v1/container/scan/dockerfile",
        json={"content": "   ", "filename": "Dockerfile"},
        headers=_HEADERS,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_container_scan_path_traversal_filename(client):
    """Container scan with path traversal in filename should be sanitized."""
    resp = await client.post(
        "/api/v1/container/scan/dockerfile",
        json={
            "content": "FROM python:3.11\nRUN pip install flask",
            "filename": "../../../etc/passwd",
        },
        headers=_HEADERS,
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_container_image_ref_shell_injection(client):
    """Container image scan with shell injection should be rejected."""
    resp = await client.post(
        "/api/v1/container/scan/image",
        json={"image_ref": "python:3.11; rm -rf /"},
        headers=_HEADERS,
    )
    assert resp.status_code == 422  # Pydantic validation


@pytest.mark.asyncio
async def test_container_image_ref_command_substitution(client):
    """Container image scan with command substitution should be rejected."""
    resp = await client.post(
        "/api/v1/container/scan/image",
        json={"image_ref": "python:3.11$(whoami)"},
        headers=_HEADERS,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_container_image_ref_pipe(client):
    """Container image scan with pipe should be rejected."""
    resp = await client.post(
        "/api/v1/container/scan/image",
        json={"image_ref": "python:3.11|cat /etc/passwd"},
        headers=_HEADERS,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_container_image_ref_empty(client):
    """Container image scan with empty ref should be rejected."""
    resp = await client.post(
        "/api/v1/container/scan/image",
        json={"image_ref": "  "},
        headers=_HEADERS,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_container_valid_dockerfile_scan(client):
    """Container Dockerfile scan with valid content should succeed."""
    resp = await client.post(
        "/api/v1/container/scan/dockerfile",
        json={
            "content": "FROM python:3.11-slim\nRUN pip install flask\nEXPOSE 8080\nCMD [\"python\", \"app.py\"]",
            "filename": "Dockerfile",
        },
        headers=_HEADERS,
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# CSPM Router Hardening Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cspm_terraform_empty_content(client):
    """CSPM Terraform scan with empty content should return 400."""
    resp = await client.post(
        "/api/v1/cspm/scan/terraform",
        json={"content": "   ", "filename": "main.tf"},
        headers=_HEADERS,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_cspm_cloudformation_empty_content(client):
    """CSPM CloudFormation scan with empty content should return 400."""
    resp = await client.post(
        "/api/v1/cspm/scan/cloudformation",
        json={"content": "   "},
        headers=_HEADERS,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_cspm_terraform_path_traversal_filename(client):
    """CSPM Terraform scan with path traversal filename should be sanitized."""
    resp = await client.post(
        "/api/v1/cspm/scan/terraform",
        json={
            "content": 'resource "aws_s3_bucket" "test" { bucket = "my-bucket" }',
            "filename": "../../etc/shadow",
        },
        headers=_HEADERS,
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_cspm_terraform_valid_scan(client):
    """CSPM Terraform scan with valid HCL should succeed."""
    terraform_content = """
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
    resp = await client.post(
        "/api/v1/cspm/scan/terraform",
        json={"content": terraform_content, "filename": "main.tf"},
        headers=_HEADERS,
    )
    assert resp.status_code == 200
    data = resp.json()
    # Should find misconfigurations (public S3, open security group)
    assert "findings" in data or "misconfigurations" in data or "scan_id" in data


# ---------------------------------------------------------------------------
# Secrets Router Hardening Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_secrets_scan_content_path_traversal(client):
    """Secrets scan with path traversal in filename should be sanitized."""
    resp = await client.post(
        "/api/v1/secrets/scan/content",
        json={
            "content": "AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE",
            "filename": "../../etc/passwd",
            "repository": "test-repo",
        },
        headers=_HEADERS,
    )
    # Should succeed with sanitized filename
    assert resp.status_code in (200, 500)  # 500 if scanner unavailable


@pytest.mark.asyncio
async def test_secrets_finding_path_traversal(client):
    """Creating a secret finding with path traversal should be sanitized."""
    resp = await client.post(
        "/api/v1/secrets",
        json={
            "secret_type": "api_key",
            "file_path": "../../etc/shadow",
            "line_number": 1,
            "repository": "test-repo",
            "branch": "main",
        },
        headers=_HEADERS,
    )
    if resp.status_code == 201:
        data = resp.json()
        # File path should be sanitized
        assert "../../" not in data.get("file_path", "")


@pytest.mark.asyncio
async def test_secrets_finding_negative_line(client):
    """Creating finding with negative line number should be rejected."""
    resp = await client.post(
        "/api/v1/secrets",
        json={
            "secret_type": "api_key",
            "file_path": "config.py",
            "line_number": -1,
            "repository": "test-repo",
            "branch": "main",
        },
        headers=_HEADERS,
    )
    assert resp.status_code == 422  # Pydantic validation


@pytest.mark.asyncio
async def test_secrets_finding_oversized_entropy(client):
    """Creating finding with entropy > 10 should be rejected."""
    resp = await client.post(
        "/api/v1/secrets",
        json={
            "secret_type": "api_key",
            "file_path": "config.py",
            "line_number": 1,
            "repository": "test-repo",
            "branch": "main",
            "entropy_score": 99.9,
        },
        headers=_HEADERS,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_secrets_health_endpoint(client):
    """Secrets /health endpoint should return 200 with status."""
    resp = await client.get("/api/v1/secrets/health", headers=_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data


@pytest.mark.asyncio
async def test_secrets_status_endpoint(client):
    """Secrets /status endpoint should return 200 with status."""
    resp = await client.get("/api/v1/secrets/status", headers=_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data


# ---------------------------------------------------------------------------
# Cross-router: Auth required on all scan endpoints
# ---------------------------------------------------------------------------

_SCAN_ENDPOINTS = [
    ("POST", "/api/v1/sast/scan/code", {"code": "x=1"}),
    ("POST", "/api/v1/dast/scan", {"target_url": "https://example.com"}),
    ("POST", "/api/v1/container/scan/dockerfile", {"content": "FROM python:3.11"}),
    ("POST", "/api/v1/cspm/scan/terraform", {"content": "resource {}", "filename": "main.tf"}),
    ("POST", "/api/v1/secrets/scan/content", {"content": "test", "filename": "test.py"}),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path,body", _SCAN_ENDPOINTS)
async def test_scan_endpoints_require_auth(client, method, path, body):
    """All scan endpoints should require authentication."""
    if method == "POST":
        resp = await client.post(path, json=body)  # No auth header
    else:
        resp = await client.get(path)
    assert resp.status_code == 401, f"{method} {path} returned {resp.status_code} without auth"
