"""Tests for container image scan endpoints.

Covers:
  POST /api/v1/containers/images/scan      — image vulnerability scan
  POST /api/v1/containers/images/layer-secrets — layer secret detection

Uses FastAPI TestClient; no external scanner (Trivy/Grype) required.
The scan_image endpoint is mocked so tests don't block on subprocess calls.
"""
from __future__ import annotations

import sys
import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from fastapi.testclient import TestClient
from fastapi import FastAPI

from apps.api.container_scanner_router import router
from apps.api.auth_deps import api_key_auth

app = FastAPI()
app.include_router(router)

# Override auth dependency so no real API key is needed
app.dependency_overrides[api_key_auth] = lambda: None

client = TestClient(app, raise_server_exceptions=True)

HEADERS = {}  # no key needed — dependency is overridden


def _make_fake_result(image_ref="nginx:1.25", findings=None):
    """Build a minimal ContainerScanResult-like object for mocking."""
    from core.container_scanner import ContainerScanResult
    return ContainerScanResult(
        scan_id="cont-testdeadbeef",
        target=image_ref,
        total_findings=len(findings or []),
        findings=findings or [],
        by_severity={},
        by_category={},
        trivy_available=False,
        grype_available=False,
        duration_ms=1.0,
        timestamp=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# 1. POST /images/scan — empty image_ref rejected (422)
# ---------------------------------------------------------------------------
def test_image_scan_rejects_empty_ref():
    resp = client.post(
        "/api/v1/containers/images/scan",
        json={"image_ref": ""},
        headers=HEADERS,
    )
    # empty string hits _validate_image_ref → ValueError → 422
    assert resp.status_code in (400, 422)


# ---------------------------------------------------------------------------
# 2. POST /images/scan — shell-injection chars rejected (422)
# ---------------------------------------------------------------------------
def test_image_scan_rejects_injection():
    resp = client.post(
        "/api/v1/containers/images/scan",
        json={"image_ref": "nginx:1.25; rm -rf /"},
        headers=HEADERS,
    )
    assert resp.status_code in (400, 422)


# ---------------------------------------------------------------------------
# 3. POST /images/scan — valid image ref returns 200 with expected shape
#    (scan_image mocked so no real Trivy/Grype subprocess is spawned)
# ---------------------------------------------------------------------------
def test_image_scan_valid_ref_returns_result():
    fake = _make_fake_result("nginx:1.25")
    with patch(
        "apps.api.container_scanner_router._get_image_scanner"
    ) as mock_getter:
        mock_scanner = mock_getter.return_value
        mock_scanner.scan_image = AsyncMock(return_value=fake)

        resp = client.post(
            "/api/v1/containers/images/scan",
            json={"image_ref": "nginx:1.25"},
            headers=HEADERS,
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["scan_id"] == "cont-testdeadbeef"
    assert data["target"] == "nginx:1.25"
    assert isinstance(data["total_findings"], int)
    assert isinstance(data["findings"], list)
    assert "by_severity" in data
    assert "by_category" in data
    assert data["trivy_available"] is False
    assert data["grype_available"] is False
    assert "duration_ms" in data
    assert "timestamp" in data


# ---------------------------------------------------------------------------
# 4. POST /images/layer-secrets — empty content rejected (400)
# ---------------------------------------------------------------------------
def test_layer_secrets_rejects_empty_content():
    resp = client.post(
        "/api/v1/containers/images/layer-secrets",
        json={"content": "   ", "filename": "Dockerfile"},
        headers=HEADERS,
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# 5. POST /images/layer-secrets — hardcoded secret detected
# ---------------------------------------------------------------------------
def test_layer_secrets_detects_hardcoded_secret():
    dockerfile_with_secret = (
        "FROM python:3.11-slim\n"
        "ENV AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"
        "COPY . /app\n"
        'CMD ["python", "app.py"]\n'
    )
    resp = client.post(
        "/api/v1/containers/images/layer-secrets",
        json={"content": dockerfile_with_secret, "filename": "Dockerfile"},
        headers=HEADERS,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_findings"] >= 1
    severities = {f["severity"] for f in data["findings"]}
    # AWS key or secret env should hit a critical/high rule
    assert severities & {"critical", "high"}
    cwes = {f["cwe_id"] for f in data["findings"]}
    assert "CWE-798" in cwes
