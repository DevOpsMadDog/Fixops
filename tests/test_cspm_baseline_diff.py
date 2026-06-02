"""Tests for CSPM baseline-diff and baseline-capture endpoints.

Covers:
  GET  /api/v1/cspm/baseline-diff  — posture delta against saved baseline
  POST /api/v1/cspm/baseline       — capture current posture as baseline
"""

from __future__ import annotations

import sys
import os

import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI

# Ensure suite paths resolve
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from apps.api.cspm_deep_router import router


@pytest.fixture(scope="module")
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _seed_cloud_findings(org_id: str, n: int = 3) -> None:
    """Ingest real CSPM (cloud) findings so get_posture has data to aggregate.

    FixOps derives posture from INGESTED findings (Prowler/Checkov/etc.), not a
    live cloud scan — so capture/diff tests seed genuine findings rather than
    mock the response.
    """
    from core.security_findings_engine import SecurityFindingsEngine

    sfe = SecurityFindingsEngine()
    sevs = ["critical", "high", "medium", "low"]
    for i in range(n):
        sfe.record_finding(
            org_id=org_id,
            title=f"S3 bucket publicly accessible {i}",
            finding_type="cspm",
            source_tool="checkov",
            severity=sevs[i % len(sevs)],
            cvss_score=7.5,
            asset_id=f"s3-bucket-{org_id}-{i}",
            asset_type="cloud_resource",
            description="Public S3 bucket",
            remediation="Enable Block Public Access",
            correlation_key=f"checkov|CKV_AWS_20|s3-bucket-{org_id}-{i}",
        )


# ---------------------------------------------------------------------------
# 1. baseline-diff with no baseline captured returns no_baseline status
# ---------------------------------------------------------------------------

def test_baseline_diff_no_baseline(client):
    resp = client.get("/api/v1/cspm/baseline-diff", params={"org_id": "test-org-fresh"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "no_baseline"
    assert data["score_delta"] is None
    assert "current_score" in data
    assert data["baseline_captured_at"] is None


# ---------------------------------------------------------------------------
# 2. POST /baseline returns 201 and captures score
# ---------------------------------------------------------------------------

def test_capture_baseline(client):
    _seed_cloud_findings("test-org-b")
    resp = client.post("/api/v1/cspm/baseline", params={"org_id": "test-org-b"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "captured"
    assert "baseline_score" in data
    assert isinstance(data["baseline_score"], float)
    assert "captured_at" in data


# ---------------------------------------------------------------------------
# 3. baseline-diff after capture returns ok status with score_delta
# ---------------------------------------------------------------------------

def test_baseline_diff_after_capture(client):
    org = "test-org-c"
    _seed_cloud_findings(org)
    # Capture baseline first
    cap = client.post("/api/v1/cspm/baseline", params={"org_id": org})
    assert cap.status_code == 201

    resp = client.get("/api/v1/cspm/baseline-diff", params={"org_id": org})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["score_delta"] == 0.0  # same state — no change
    assert "severity_delta" in data
    assert "drift_events" in data
    assert data["baseline_captured_at"] is not None


# ---------------------------------------------------------------------------
# 4. severity_delta has expected keys
# ---------------------------------------------------------------------------

def test_baseline_diff_severity_keys(client):
    org = "test-org-d"
    _seed_cloud_findings(org)
    client.post("/api/v1/cspm/baseline", params={"org_id": org})
    resp = client.get("/api/v1/cspm/baseline-diff", params={"org_id": org})
    data = resp.json()
    delta = data["severity_delta"]
    for key in ("critical", "high", "medium", "low"):
        assert key in delta, f"Missing severity key: {key}"
        assert isinstance(delta[key], int)


# ---------------------------------------------------------------------------
# 5. include_new=false suppresses new_findings list
# ---------------------------------------------------------------------------

def test_baseline_diff_include_new_false(client):
    org = "test-org-e"
    _seed_cloud_findings(org)
    client.post("/api/v1/cspm/baseline", params={"org_id": org})
    resp = client.get(
        "/api/v1/cspm/baseline-diff",
        params={"org_id": org, "include_new": False},
    )
    assert resp.status_code == 200
    assert resp.json()["new_findings"] == []


# ---------------------------------------------------------------------------
# 6. include_resolved=false suppresses resolved_findings list
# ---------------------------------------------------------------------------

def test_baseline_diff_include_resolved_false(client):
    org = "test-org-f"
    _seed_cloud_findings(org)
    client.post("/api/v1/cspm/baseline", params={"org_id": org})
    resp = client.get(
        "/api/v1/cspm/baseline-diff",
        params={"org_id": org, "include_resolved": False},
    )
    assert resp.status_code == 200
    assert resp.json()["resolved_findings"] == []
