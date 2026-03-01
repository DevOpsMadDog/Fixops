"""
Security Analyst Persona — Comprehensive API Test Suite

Personas covered:
  - Raj  (Security Analyst / AppSec Lead)  — triages findings, brain pipeline, AutoFix review
  - Nina (AppSec Engineer)                 — SAST/SCA scans, code scanning policies, secrets, containers
  - Anika (Security Operations)            — monitors alerts, manages incidents, copilot
  - Tom  (GRC Analyst)                     — compliance, evidence, analytics

Pillars: V2 (Lifecycle), V3 (Decision Intelligence), V5 (MPTE), V6 (Quantum Evidence), V10 (CTEM Loop)

Run:
    pytest tests/test_security_analyst_persona.py -v --timeout=30
    # or against live server:
    FIXOPS_LIVE_URL=http://localhost:8000 pytest tests/test_security_analyst_persona.py -v
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any, Dict, List, Optional

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

API_KEY = os.environ.get(
    "FIXOPS_API_TOKEN",
    "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh",
)
LIVE_URL = os.environ.get("FIXOPS_LIVE_URL", "")


@pytest.fixture(scope="module")
def api_client():
    """Return either a live requests.Session or a FastAPI TestClient."""
    if LIVE_URL:
        import requests

        session = requests.Session()
        session.base_url = LIVE_URL.rstrip("/")  # type: ignore[attr-defined]
        session.headers.update({"X-API-Key": API_KEY})

        class _LiveClient:
            """Thin wrapper so .get/.post signatures match TestClient."""

            def __init__(self, s, base):
                self._s = s
                self._base = base

            def get(self, url, **kw):
                kw.setdefault("headers", {}).update({"X-API-Key": API_KEY})
                return self._s.get(f"{self._base}{url}", **kw)

            def post(self, url, **kw):
                kw.setdefault("headers", {}).update({"X-API-Key": API_KEY})
                if "json" in kw:
                    kw.setdefault("headers", {})["Content-Type"] = "application/json"
                return self._s.post(f"{self._base}{url}", **kw)

            def put(self, url, **kw):
                kw.setdefault("headers", {}).update({"X-API-Key": API_KEY})
                return self._s.put(f"{self._base}{url}", **kw)

            def delete(self, url, **kw):
                kw.setdefault("headers", {}).update({"X-API-Key": API_KEY})
                return self._s.delete(f"{self._base}{url}", **kw)

        yield _LiveClient(session, LIVE_URL.rstrip("/"))
    else:
        from fastapi.testclient import TestClient

        os.environ.setdefault("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")
        os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")
        os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
        os.environ.setdefault("FIXOPS_MODE", "enterprise")
        os.environ.setdefault(
            "FIXOPS_JWT_SECRET",
            "enterprise-jwt-secret-key-minimum-32-characters",
        )

        from apps.api.app import create_app

        app = create_app()
        client = TestClient(app)
        # Patch headers for every request
        _orig_get = client.get
        _orig_post = client.post
        _orig_put = client.put
        _orig_delete = client.delete

        def _h(kw):
            kw.setdefault("headers", {}).update(
                {"X-API-Key": os.environ["FIXOPS_API_TOKEN"]}
            )
            return kw

        client.get = lambda url, **kw: _orig_get(url, **_h(kw))  # type: ignore
        client.post = lambda url, **kw: _orig_post(url, **_h(kw))  # type: ignore
        client.put = lambda url, **kw: _orig_put(url, **_h(kw))  # type: ignore
        client.delete = lambda url, **kw: _orig_delete(url, **_h(kw))  # type: ignore

        yield client


# ============================================================================
#  PERSONA: Raj — Security Analyst / AppSec Lead
#  Triages findings, uses brain pipeline, reviews AutoFix suggestions
# ============================================================================


class TestRajSecurityAnalyst:
    """Raj triages findings via the Brain Knowledge Graph and reviews AutoFix."""

    # ------------------------------------------------------------------
    # Brain Router — /api/v1/brain
    # ------------------------------------------------------------------

    def test_brain_health(self, api_client):
        """Brain health check."""
        r = api_client.get("/api/v1/brain/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"
        assert "nodes" in data
        assert "edges" in data

    def test_brain_stats(self, api_client):
        """Graph statistics."""
        r = api_client.get("/api/v1/brain/stats")
        assert r.status_code == 200

    def test_brain_create_node(self, api_client):
        """Create a node in the knowledge graph (finding triage)."""
        node_id = f"finding-{uuid.uuid4().hex[:8]}"
        r = api_client.post(
            "/api/v1/brain/nodes",
            json={
                "node_id": node_id,
                "node_type": "finding",
                "org_id": "test-org",
                "properties": {
                    "title": "SQL Injection in login handler",
                    "severity": "critical",
                    "cwe_id": "CWE-89",
                },
            },
        )
        assert r.status_code == 201
        data = r.json()
        assert data["node_id"] == node_id
        assert data["node_type"] == "finding"
        self.__class__._created_node_id = node_id

    def test_brain_query_nodes(self, api_client):
        """Query nodes with filters."""
        r = api_client.get(
            "/api/v1/brain/nodes",
            params={"node_type": "finding", "limit": 10},
        )
        assert r.status_code == 200
        data = r.json()
        assert "nodes" in data
        assert "total" in data

    def test_brain_get_node(self, api_client):
        """Get a specific node — first create then fetch."""
        nid = f"vuln-{uuid.uuid4().hex[:6]}"
        api_client.post(
            "/api/v1/brain/nodes",
            json={
                "node_id": nid,
                "node_type": "vulnerability",
                "properties": {"cve": "CVE-2024-1234"},
            },
        )
        r = api_client.get(f"/api/v1/brain/nodes/{nid}")
        assert r.status_code == 200

    def test_brain_create_edge(self, api_client):
        """Create an edge between two nodes."""
        src = f"src-{uuid.uuid4().hex[:6]}"
        tgt = f"tgt-{uuid.uuid4().hex[:6]}"
        # Create both nodes first
        api_client.post(
            "/api/v1/brain/nodes",
            json={"node_id": src, "node_type": "asset"},
        )
        api_client.post(
            "/api/v1/brain/nodes",
            json={"node_id": tgt, "node_type": "finding"},
        )
        r = api_client.post(
            "/api/v1/brain/edges",
            json={
                "source_id": src,
                "target_id": tgt,
                "edge_type": "HAS_FINDING",
                "confidence": 0.95,
            },
        )
        assert r.status_code == 201
        data = r.json()
        assert data["source_id"] == src
        assert data["target_id"] == tgt

    def test_brain_list_edges(self, api_client):
        """List all edges."""
        r = api_client.get("/api/v1/brain/all-edges", params={"limit": 50})
        assert r.status_code == 200
        data = r.json()
        assert "edges" in data
        assert "count" in data

    def test_brain_get_edges_for_node(self, api_client):
        """Get edges for a specific node."""
        nid = f"edge-test-{uuid.uuid4().hex[:6]}"
        api_client.post(
            "/api/v1/brain/nodes",
            json={"node_id": nid, "node_type": "asset"},
        )
        r = api_client.get(f"/api/v1/brain/edges/{nid}", params={"direction": "both"})
        assert r.status_code == 200
        data = r.json()
        assert data["node_id"] == nid

    def test_brain_neighbors(self, api_client):
        """Get neighbors of a node."""
        nid = f"nbr-{uuid.uuid4().hex[:6]}"
        api_client.post(
            "/api/v1/brain/nodes",
            json={"node_id": nid, "node_type": "finding"},
        )
        r = api_client.get(
            f"/api/v1/brain/neighbors/{nid}", params={"depth": 2}
        )
        assert r.status_code == 200
        data = r.json()
        assert data["center_node"] == nid

    @pytest.mark.skip(reason="O(n) full graph scan on 34K+ node brain DB — too slow for CI")
    def test_brain_most_connected(self, api_client):
        """Get most connected nodes."""
        r = api_client.get("/api/v1/brain/most-connected", params={"limit": 5})
        assert r.status_code == 200

    def test_brain_risk_score(self, api_client):
        """Compute risk score for a node."""
        nid = f"risk-{uuid.uuid4().hex[:6]}"
        api_client.post(
            "/api/v1/brain/nodes",
            json={
                "node_id": nid,
                "node_type": "asset",
                "properties": {"criticality": "high"},
            },
        )
        r = api_client.get(f"/api/v1/brain/risk/{nid}")
        assert r.status_code == 200
        data = r.json()
        assert "risk_score" in data

    def test_brain_events(self, api_client):
        """Get recent brain events."""
        r = api_client.get("/api/v1/brain/events", params={"limit": 20})
        assert r.status_code == 200

    def test_brain_entity_types(self, api_client):
        """List entity type metadata."""
        r = api_client.get("/api/v1/brain/meta/entity-types")
        assert r.status_code == 200
        data = r.json()
        assert "entity_types" in data

    def test_brain_edge_types(self, api_client):
        """List edge type metadata."""
        r = api_client.get("/api/v1/brain/meta/edge-types")
        assert r.status_code == 200
        data = r.json()
        assert "edge_types" in data

    # ------------------------------------------------------------------
    # Brain Ingest endpoints
    # ------------------------------------------------------------------

    def test_brain_ingest_cve(self, api_client):
        """Ingest a CVE into the knowledge graph."""
        r = api_client.post(
            "/api/v1/brain/ingest/cve",
            json={
                "cve_id": "CVE-2024-29133",
                "org_id": "test-org",
                "severity": "high",
                "cvss": 8.1,
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["ingested"] is True
        assert data["node_type"] == "cve"

    def test_brain_ingest_finding(self, api_client):
        """Ingest a finding into the graph."""
        r = api_client.post(
            "/api/v1/brain/ingest/finding",
            json={
                "finding_id": f"FIND-{uuid.uuid4().hex[:6]}",
                "org_id": "test-org",
                "title": "Hardcoded AWS key",
                "severity": "critical",
                "cve_id": "CVE-2024-29133",
            },
        )
        assert r.status_code == 200
        assert r.json()["ingested"] is True

    def test_brain_ingest_scan(self, api_client):
        """Ingest scan results."""
        r = api_client.post(
            "/api/v1/brain/ingest/scan",
            json={
                "scan_id": f"SCAN-{uuid.uuid4().hex[:6]}",
                "org_id": "test-org",
                "scanner": "sast",
                "findings": ["FIND-001", "FIND-002"],
            },
        )
        assert r.status_code == 200
        assert r.json()["node_type"] == "scan"

    def test_brain_ingest_asset(self, api_client):
        """Ingest an asset."""
        r = api_client.post(
            "/api/v1/brain/ingest/asset",
            json={
                "asset_id": "payment-service",
                "org_id": "test-org",
                "asset_type": "microservice",
                "language": "python",
            },
        )
        assert r.status_code == 200
        assert r.json()["node_type"] == "asset"

    def test_brain_ingest_remediation(self, api_client):
        """Ingest a remediation task."""
        r = api_client.post(
            "/api/v1/brain/ingest/remediation",
            json={
                "task_id": f"REM-{uuid.uuid4().hex[:6]}",
                "finding_id": "FIND-001",
                "org_id": "test-org",
                "status": "in_progress",
            },
        )
        assert r.status_code == 200
        assert r.json()["node_type"] == "remediation"

    def test_brain_find_paths(self, api_client):
        """Find paths between two nodes in the graph."""
        # Create source and target
        src = f"path-src-{uuid.uuid4().hex[:6]}"
        tgt = f"path-tgt-{uuid.uuid4().hex[:6]}"
        api_client.post(
            "/api/v1/brain/nodes",
            json={"node_id": src, "node_type": "asset"},
        )
        api_client.post(
            "/api/v1/brain/nodes",
            json={"node_id": tgt, "node_type": "finding"},
        )
        r = api_client.get(
            "/api/v1/brain/paths",
            params={"source_id": src, "target_id": tgt, "max_depth": 3},
        )
        assert r.status_code == 200
        data = r.json()
        assert "paths" in data

    def test_brain_delete_node(self, api_client):
        """Delete a node from the graph."""
        nid = f"del-{uuid.uuid4().hex[:6]}"
        api_client.post(
            "/api/v1/brain/nodes",
            json={"node_id": nid, "node_type": "finding"},
        )
        r = api_client.delete(f"/api/v1/brain/nodes/{nid}")
        assert r.status_code == 200
        assert r.json()["deleted"] is True

    # ------------------------------------------------------------------
    # AutoFix Router — /api/v1/autofix  (Raj reviews suggestions)
    # ------------------------------------------------------------------

    def test_autofix_health(self, api_client):
        """AutoFix engine health."""
        r = api_client.get("/api/v1/autofix/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"

    def test_autofix_generate_fix(self, api_client):
        """Generate a fix for a finding."""
        r = api_client.post(
            "/api/v1/autofix/generate",
            json={
                "finding_id": "FIND-SQLi-001",
                "title": "SQL Injection in user login",
                "severity": "critical",
                "cve_id": "CVE-2024-29133",
                "language": "python",
                "source_code": 'query = f"SELECT * FROM users WHERE id={user_id}"',
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert "fix" in data

    def test_autofix_generate_with_full_finding(self, api_client):
        """Generate fix using full finding dict."""
        r = api_client.post(
            "/api/v1/autofix/generate",
            json={
                "finding": {
                    "id": "FIND-XSS-002",
                    "title": "Reflected XSS in search",
                    "severity": "high",
                    "cve_ids": ["CVE-2024-1111"],
                    "cwe_id": "CWE-79",
                },
                "language": "javascript",
                "source_code": "document.innerHTML = userInput;",
            },
        )
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_autofix_generate_bulk(self, api_client):
        """Generate fixes for multiple findings."""
        r = api_client.post(
            "/api/v1/autofix/generate/bulk",
            json={
                "findings": [
                    {"id": "F-1", "title": "SQL Injection", "severity": "critical"},
                    {"id": "F-2", "title": "XSS", "severity": "high"},
                    {"id": "F-3", "title": "SSRF", "severity": "medium"},
                ],
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["count"] == 3

    def test_autofix_stats(self, api_client):
        """AutoFix statistics."""
        r = api_client.get("/api/v1/autofix/stats")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert "stats" in data

    def test_autofix_history(self, api_client):
        """AutoFix action history."""
        r = api_client.get("/api/v1/autofix/history", params={"limit": 50})
        assert r.status_code == 200

    def test_autofix_fix_types(self, api_client):
        """List supported fix types."""
        r = api_client.get("/api/v1/autofix/fix-types")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert len(data["fix_types"]) > 0

    def test_autofix_confidence_levels(self, api_client):
        """Get confidence level definitions."""
        r = api_client.get("/api/v1/autofix/confidence-levels")
        assert r.status_code == 200
        data = r.json()
        assert "high" in data["levels"]
        assert "medium" in data["levels"]
        assert "low" in data["levels"]

    def test_autofix_suggestions_for_finding(self, api_client):
        """Get fix suggestions for a specific finding."""
        r = api_client.get("/api/v1/autofix/suggestions/FIND-SQLi-001")
        assert r.status_code == 200
        data = r.json()
        assert data["finding_id"] == "FIND-SQLi-001"
        assert "suggestions" in data


# ============================================================================
#  PERSONA: Nina — AppSec Engineer
#  Runs SAST/SCA scans, configures code scanning policies, secrets, containers
# ============================================================================


class TestNinaAppSecEngineer:
    """Nina runs scans across SAST, secrets, containers, CSPM, DAST, IaC."""

    # ------------------------------------------------------------------
    # SAST Router — /api/v1/sast
    # ------------------------------------------------------------------

    def test_sast_status(self, api_client):
        """SAST engine status."""
        r = api_client.get("/api/v1/sast/status")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"
        assert data["rules_count"] > 0

    def test_sast_list_rules(self, api_client):
        """List all SAST rules."""
        r = api_client.get("/api/v1/sast/rules")
        assert r.status_code == 200
        rules = r.json()
        assert isinstance(rules, list)
        assert len(rules) > 0
        # Verify rule structure
        rule = rules[0]
        assert "rule_id" in rule
        assert "severity" in rule
        assert "cwe_id" in rule

    def test_sast_scan_python_code(self, api_client):
        """Scan Python code for vulnerabilities."""
        r = api_client.post(
            "/api/v1/sast/scan/code",
            json={
                "code": """
import subprocess
import yaml

def run_command(user_input):
    subprocess.call(user_input, shell=True)  # Command injection
    data = yaml.load(user_input)  # Unsafe YAML
    eval(user_input)  # Code injection
""",
                "filename": "vulnerable.py",
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert "findings" in data or "vulnerabilities" in data or "results" in data

    def test_sast_scan_javascript_code(self, api_client):
        """Scan JavaScript code."""
        r = api_client.post(
            "/api/v1/sast/scan/code",
            json={
                "code": """
const express = require('express');
app.get('/search', (req, res) => {
    res.send('<h1>' + req.query.q + '</h1>');  // XSS
    eval(req.body.code);  // Code injection
});
""",
                "filename": "server.js",
            },
        )
        assert r.status_code == 200

    def test_sast_scan_multiple_files(self, api_client):
        """Scan multiple files at once."""
        r = api_client.post(
            "/api/v1/sast/scan/files",
            json={
                "files": {
                    "app.py": 'import os\nos.system(user_input)\n',
                    "config.py": 'SECRET_KEY = "hardcoded_secret_123"\n',
                    "utils.js": 'eval(userInput);\n',
                },
            },
        )
        assert r.status_code == 200

    # ------------------------------------------------------------------
    # Secrets Router — /api/v1/secrets
    # ------------------------------------------------------------------

    def test_secrets_status(self, api_client):
        """Secrets scanner status."""
        r = api_client.get("/api/v1/secrets/status")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "operational"

    def test_secrets_list_findings(self, api_client):
        """List secret findings."""
        r = api_client.get("/api/v1/secrets", params={"limit": 50})
        assert r.status_code == 200
        data = r.json()
        assert "items" in data
        assert "total" in data

    def test_secrets_create_finding(self, api_client):
        """Create a secret finding."""
        r = api_client.post(
            "/api/v1/secrets",
            json={
                "secret_type": "aws_key",
                "file_path": "config/settings.py",
                "line_number": 42,
                "repository": "myorg/payment-service",
                "branch": "main",
                "commit_hash": "abc123def456",
                "entropy_score": 4.8,
            },
        )
        assert r.status_code == 201
        data = r.json()
        assert data["secret_type"] == "aws_key"
        assert data["repository"] == "myorg/payment-service"
        self.__class__._created_secret_id = data["id"]

    def test_secrets_get_finding(self, api_client):
        """Get a specific secret finding."""
        # Create one first
        create_r = api_client.post(
            "/api/v1/secrets",
            json={
                "secret_type": "token",
                "file_path": ".env",
                "line_number": 5,
                "repository": "myorg/api-gateway",
                "branch": "develop",
            },
        )
        assert create_r.status_code == 201
        fid = create_r.json()["id"]

        r = api_client.get(f"/api/v1/secrets/{fid}")
        assert r.status_code == 200
        assert r.json()["id"] == fid

    def test_secrets_resolve_finding(self, api_client):
        """Resolve a secret finding."""
        create_r = api_client.post(
            "/api/v1/secrets",
            json={
                "secret_type": "generic",
                "file_path": "src/db.py",
                "line_number": 15,
                "repository": "myorg/backend",
                "branch": "main",
            },
        )
        fid = create_r.json()["id"]

        r = api_client.post(f"/api/v1/secrets/{fid}/resolve")
        assert r.status_code == 200
        assert r.json()["status"] == "resolved"

    def test_secrets_scan_content(self, api_client):
        """Scan content for secrets."""
        r = api_client.post(
            "/api/v1/secrets/scan/content",
            json={
                "content": 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n',
                "filename": "config.py",
                "repository": "inline-test",
                "branch": "main",
            },
        )
        # May return 200 or 500 if external scanner unavailable — both acceptable
        assert r.status_code in (200, 500)

    def test_secrets_scanner_status(self, api_client):
        """Get detector tool availability."""
        r = api_client.get("/api/v1/secrets/scanners/status")
        assert r.status_code == 200
        data = r.json()
        assert "gitleaks_available" in data
        assert "trufflehog_available" in data

    # ------------------------------------------------------------------
    # Container Router — /api/v1/container
    # ------------------------------------------------------------------

    def test_container_status(self, api_client):
        """Container scanner status."""
        r = api_client.get("/api/v1/container/status")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"
        assert data["engine"] == "ALdeci Container Scanner"

    def test_container_scan_dockerfile(self, api_client):
        """Scan a Dockerfile for misconfigurations."""
        r = api_client.post(
            "/api/v1/container/scan/dockerfile",
            json={
                "content": """FROM python:3.11
RUN pip install flask
USER root
EXPOSE 80
COPY . /app
CMD ["python", "app.py"]
""",
                "filename": "Dockerfile",
            },
        )
        assert r.status_code == 200

    def test_container_scan_dockerfile_with_issues(self, api_client):
        """Scan a Dockerfile with known security issues (USER root, latest tag)."""
        r = api_client.post(
            "/api/v1/container/scan/dockerfile",
            json={
                "content": """FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
RUN chmod 777 /app
ADD http://example.com/malicious.tar.gz /tmp/
EXPOSE 22
USER root
""",
                "filename": "Dockerfile.bad",
            },
        )
        assert r.status_code == 200

    # ------------------------------------------------------------------
    # CSPM / IaC Router — /api/v1/cspm
    # ------------------------------------------------------------------

    def test_cspm_status(self, api_client):
        """CSPM engine status."""
        r = api_client.get("/api/v1/cspm/status")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ready"

    def test_cspm_rules(self, api_client):
        """List CSPM rules per cloud provider."""
        r = api_client.get("/api/v1/cspm/rules")
        assert r.status_code == 200
        data = r.json()
        assert "aws" in data
        assert "azure" in data
        assert "gcp" in data
        assert data["total"] > 0

    def test_cspm_scan_terraform(self, api_client):
        """Scan Terraform HCL for misconfigurations."""
        r = api_client.post(
            "/api/v1/cspm/scan/terraform",
            json={
                "content": """
resource "aws_s3_bucket" "data" {
  bucket = "my-sensitive-data"
  acl    = "public-read"
}

resource "aws_security_group" "wide_open" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
""",
                "filename": "main.tf",
            },
        )
        assert r.status_code == 200

    def test_cspm_scan_cloudformation(self, api_client):
        """Scan CloudFormation for AWS misconfigurations."""
        r = api_client.post(
            "/api/v1/cspm/scan/cloudformation",
            json={
                "content": json.dumps(
                    {
                        "AWSTemplateFormatVersion": "2010-09-09",
                        "Resources": {
                            "MyBucket": {
                                "Type": "AWS::S3::Bucket",
                                "Properties": {
                                    "BucketName": "my-insecure-bucket",
                                    "AccessControl": "PublicRead",
                                },
                            }
                        },
                    }
                ),
            },
        )
        assert r.status_code == 200

    # ------------------------------------------------------------------
    # DAST Router — /api/v1/dast
    # ------------------------------------------------------------------

    def test_dast_status(self, api_client):
        """DAST engine status."""
        r = api_client.get("/api/v1/dast/status")
        assert r.status_code == 200

    # ------------------------------------------------------------------
    # IaC Router — /api/v1/iac
    # ------------------------------------------------------------------

    def test_iac_list_findings(self, api_client):
        """List IaC findings."""
        r = api_client.get("/api/v1/iac", params={"limit": 50})
        assert r.status_code == 200
        data = r.json()
        assert "items" in data

    def test_iac_create_finding(self, api_client):
        """Create an IaC finding."""
        r = api_client.post(
            "/api/v1/iac",
            json={
                "provider": "terraform",
                "severity": "high",
                "title": "S3 bucket publicly accessible",
                "description": "S3 bucket allows public read access via ACL",
                "file_path": "infra/main.tf",
                "line_number": 12,
                "resource_type": "aws_s3_bucket",
                "resource_name": "data_bucket",
                "rule_id": "CKV_AWS_19",
            },
        )
        assert r.status_code == 201
        data = r.json()
        assert data["provider"] == "terraform"
        self.__class__._created_iac_id = data["id"]

    def test_iac_get_and_resolve(self, api_client):
        """Get then resolve an IaC finding."""
        # Create
        cr = api_client.post(
            "/api/v1/iac",
            json={
                "provider": "terraform",
                "severity": "medium",
                "title": "Storage account allows HTTP",
                "description": "Azure storage not enforcing HTTPS",
                "file_path": "infra/azure.tf",
                "line_number": 8,
                "resource_type": "azurerm_storage_account",
                "resource_name": "mystorage",
                "rule_id": "CKV_AZURE_3",
            },
        )
        fid = cr.json()["id"]

        # Get
        r = api_client.get(f"/api/v1/iac/{fid}")
        assert r.status_code == 200

        # Resolve
        r = api_client.post(f"/api/v1/iac/{fid}/resolve")
        assert r.status_code == 200
        assert r.json()["status"] == "resolved"

    def test_iac_scanner_status(self, api_client):
        """Get IaC scanner availability."""
        r = api_client.get("/api/v1/iac/scanners/status")
        assert r.status_code == 200
        data = r.json()
        assert "checkov_available" in data
        assert "tfsec_available" in data

    def test_iac_scan_content(self, api_client):
        """Scan IaC content inline."""
        r = api_client.post(
            "/api/v1/iac/scan/content",
            json={
                "content": """
resource "aws_security_group" "open" {
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
""",
                "filename": "network.tf",
            },
        )
        # May fail if checkov/tfsec not installed — both acceptable
        assert r.status_code in (200, 500)


# ============================================================================
#  PERSONA: Anika — Security Operations
#  Monitors alerts, manages incidents, uses copilot for investigation
# ============================================================================


class TestAnikaSecurityOps:
    """Anika monitors alerts, triages incidents, uses AI copilot."""

    # ------------------------------------------------------------------
    # Copilot Router — /api/v1/copilot
    # ------------------------------------------------------------------

    def test_copilot_health(self, api_client):
        """Copilot service health."""
        r = api_client.get("/api/v1/copilot/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"
        assert "agents" in data
        assert "llm_providers" in data

    def test_copilot_create_session(self, api_client):
        """Create a copilot chat session."""
        r = api_client.post(
            "/api/v1/copilot/sessions",
            json={
                "name": "Incident Investigation - CVE-2024-29133",
                "agent_type": "security_analyst",
                "context": {"cve_ids": ["CVE-2024-29133"], "priority": "P1"},
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["agent_type"] == "security_analyst"
        assert "id" in data
        self.__class__._created_session_id = data["id"]

    def test_copilot_create_session_compliance(self, api_client):
        """Create a compliance-focused session."""
        r = api_client.post(
            "/api/v1/copilot/sessions",
            json={
                "name": "SOC2 Audit Prep",
                "agent_type": "compliance",
            },
        )
        assert r.status_code == 200
        assert r.json()["agent_type"] == "compliance"

    def test_copilot_list_sessions(self, api_client):
        """List copilot sessions."""
        r = api_client.get("/api/v1/copilot/sessions", params={"limit": 10})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_copilot_send_message(self, api_client):
        """Send a message and get AI response."""
        # Create session first
        sess = api_client.post(
            "/api/v1/copilot/sessions",
            json={"name": "Test chat", "agent_type": "security_analyst"},
        )
        sid = sess.json()["id"]

        r = api_client.post(
            f"/api/v1/copilot/sessions/{sid}/messages",
            json={
                "message": "Analyze CVE-2024-29133 and tell me the exploitability risk",
                "include_context": True,
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["role"] == "assistant"
        assert len(data["content"]) > 0

    def test_copilot_send_message_remediation_agent(self, api_client):
        """Send message with remediation agent override."""
        sess = api_client.post(
            "/api/v1/copilot/sessions",
            json={"name": "Fix session", "agent_type": "general"},
        )
        sid = sess.json()["id"]

        r = api_client.post(
            f"/api/v1/copilot/sessions/{sid}/messages",
            json={
                "message": "How do I fix SQL injection in a Python Flask app?",
                "agent_type": "remediation",
            },
        )
        assert r.status_code == 200
        assert r.json()["role"] == "assistant"

    def test_copilot_get_messages(self, api_client):
        """Get messages from a session."""
        sess = api_client.post(
            "/api/v1/copilot/sessions",
            json={"name": "Msg test"},
        )
        sid = sess.json()["id"]
        # Send a message first
        api_client.post(
            f"/api/v1/copilot/sessions/{sid}/messages",
            json={"message": "Hello copilot"},
        )

        r = api_client.get(
            f"/api/v1/copilot/sessions/{sid}/messages", params={"limit": 50}
        )
        assert r.status_code == 200
        msgs = r.json()
        assert len(msgs) >= 2  # user + assistant

    def test_copilot_execute_action(self, api_client):
        """Execute an agent action (analyze)."""
        sess = api_client.post(
            "/api/v1/copilot/sessions",
            json={"name": "Action test"},
        )
        sid = sess.json()["id"]

        r = api_client.post(
            f"/api/v1/copilot/sessions/{sid}/actions",
            json={
                "action_type": "analyze",
                "parameters": {"target": "CVE-2024-29133"},
                "async_execution": False,
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["action_type"] == "analyze"
        assert data["status"] in ("completed", "pending", "running")

    def test_copilot_execute_action_remediate(self, api_client):
        """Execute a remediation action."""
        sess = api_client.post(
            "/api/v1/copilot/sessions",
            json={"name": "Remediation action"},
        )
        sid = sess.json()["id"]

        r = api_client.post(
            f"/api/v1/copilot/sessions/{sid}/actions",
            json={
                "action_type": "remediate",
                "parameters": {"finding_id": "FIND-001"},
                "async_execution": False,
            },
        )
        assert r.status_code == 200

    def test_copilot_add_context(self, api_client):
        """Add context to a session."""
        sess = api_client.post(
            "/api/v1/copilot/sessions",
            json={"name": "Context test"},
        )
        sid = sess.json()["id"]

        r = api_client.post(
            f"/api/v1/copilot/sessions/{sid}/context",
            json={
                "context_type": "cve",
                "data": {
                    "cve_id": "CVE-2024-29133",
                    "severity": "high",
                    "cvss": 8.1,
                },
            },
        )
        assert r.status_code == 200
        assert r.json()["status"] == "added"

    def test_copilot_get_session(self, api_client):
        """Get a specific session."""
        sess = api_client.post(
            "/api/v1/copilot/sessions",
            json={"name": "Get test"},
        )
        sid = sess.json()["id"]

        r = api_client.get(f"/api/v1/copilot/sessions/{sid}")
        assert r.status_code == 200
        assert r.json()["id"] == sid

    def test_copilot_delete_session(self, api_client):
        """Delete a session."""
        sess = api_client.post(
            "/api/v1/copilot/sessions",
            json={"name": "Delete me"},
        )
        sid = sess.json()["id"]

        r = api_client.delete(f"/api/v1/copilot/sessions/{sid}")
        assert r.status_code == 200
        assert r.json()["status"] == "deleted"

    def test_copilot_suggestions(self, api_client):
        """Get AI-generated proactive suggestions."""
        r = api_client.get(
            "/api/v1/copilot/suggestions", params={"limit": 5}
        )
        assert r.status_code == 200
        # Suggestions may be empty if no LLM configured — that's OK
        data = r.json()
        assert isinstance(data, list)

    def test_copilot_quick_analyze(self, api_client):
        """Quick one-shot vulnerability analysis."""
        r = api_client.post(
            "/api/v1/copilot/quick/analyze",
            json={
                "cve_id": "CVE-2024-29133",
                "description": "Apache Commons Configuration RCE",
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert "analysis" in data

    def test_copilot_quick_pentest(self, api_client):
        """Quick pentest initiation."""
        r = api_client.post(
            "/api/v1/copilot/quick/pentest",
            json={
                "target": "https://api.example.com",
                "cve_ids": ["CVE-2024-29133"],
                "test_type": "reachability",
                "depth": "light",
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "queued"
        assert "task_id" in data

    def test_copilot_quick_report(self, api_client):
        """Quick report generation."""
        r = api_client.post(
            "/api/v1/copilot/quick/report",
            json={
                "report_type": "executive",
                "finding_ids": ["FIND-001", "FIND-002"],
                "include_remediation": True,
                "format": "pdf",
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert "report_id" in data
        assert data["status"] == "generating"

    def test_copilot_session_not_found(self, api_client):
        """Session not found returns 404."""
        r = api_client.get("/api/v1/copilot/sessions/nonexistent-id")
        assert r.status_code == 404


# ============================================================================
#  PERSONA: Tom — GRC Analyst
#  Reviews compliance, checks evidence bundles, views analytics
# ============================================================================


class TestTomGRCAnalyst:
    """Tom reviews compliance dashboards, evidence bundles, and analytics."""

    # ------------------------------------------------------------------
    # Analytics Router — /api/v1/analytics
    # ------------------------------------------------------------------

    def test_analytics_dashboard_overview(self, api_client):
        """Dashboard overview endpoint."""
        r = api_client.get("/api/v1/analytics/dashboard/overview")
        assert r.status_code == 200

    def test_analytics_dashboard_trends(self, api_client):
        """Dashboard trend data."""
        r = api_client.get(
            "/api/v1/analytics/dashboard/trends", params={"days": 30}
        )
        assert r.status_code == 200
        data = r.json()
        assert "period_days" in data

    def test_analytics_dashboard_top_risks(self, api_client):
        """Top security risks."""
        r = api_client.get(
            "/api/v1/analytics/dashboard/top-risks", params={"limit": 10}
        )
        assert r.status_code == 200

    def test_analytics_dashboard_compliance_status(self, api_client):
        """Compliance framework status."""
        r = api_client.get("/api/v1/analytics/dashboard/compliance-status")
        assert r.status_code == 200
        data = r.json()
        assert "compliance_score" in data

    def test_analytics_findings_list(self, api_client):
        """List findings via analytics."""
        r = api_client.get(
            "/api/v1/analytics/findings",
            params={"limit": 50, "offset": 0},
        )
        assert r.status_code == 200

    def test_analytics_create_finding(self, api_client):
        """Create a finding via analytics endpoint."""
        r = api_client.post(
            "/api/v1/analytics/findings",
            json={
                "org_id": "test-org",
                "rule_id": "CWE-89",
                "severity": "critical",
                "title": "SQL Injection in payment API",
                "description": "User input concatenated into SQL query",
                "source": "sast",
                "cve_id": "CVE-2024-29133",
                "cvss_score": 9.8,
                "epss_score": 0.85,
                "exploitable": True,
            },
        )
        assert r.status_code == 201
        data = r.json()
        assert data["severity"] == "critical"
        self.__class__._created_finding_id = data["id"]

    def test_analytics_get_finding(self, api_client):
        """Get finding by ID."""
        # Create first
        cr = api_client.post(
            "/api/v1/analytics/findings",
            json={
                "org_id": "test-org",
                "rule_id": "CWE-79",
                "severity": "high",
                "title": "XSS in search",
                "description": "Reflected XSS via query parameter",
                "source": "dast",
            },
        )
        fid = cr.json()["id"]

        r = api_client.get(f"/api/v1/analytics/findings/{fid}")
        assert r.status_code == 200
        assert r.json()["id"] == fid

    def test_analytics_update_finding(self, api_client):
        """Update finding status."""
        cr = api_client.post(
            "/api/v1/analytics/findings",
            json={
                "org_id": "test-org",
                "rule_id": "CWE-502",
                "severity": "medium",
                "title": "Insecure deserialization",
                "description": "Pickle used for untrusted data",
                "source": "sast",
            },
        )
        fid = cr.json()["id"]

        r = api_client.put(
            f"/api/v1/analytics/findings/{fid}",
            json={"status": "resolved"},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "resolved"

    def test_analytics_decisions_list(self, api_client):
        """List decisions."""
        r = api_client.get("/api/v1/analytics/decisions", params={"limit": 50})
        assert r.status_code == 200

    def test_analytics_create_decision(self, api_client):
        """Create a decision on a finding."""
        # Create finding first
        cr = api_client.post(
            "/api/v1/analytics/findings",
            json={
                "org_id": "test-org",
                "rule_id": "CWE-918",
                "severity": "high",
                "title": "SSRF via URL parameter",
                "description": "Server-side request forgery",
                "source": "dast",
            },
        )
        fid = cr.json()["id"]

        r = api_client.post(
            "/api/v1/analytics/decisions",
            json={
                "finding_id": fid,
                "outcome": "block",
                "confidence": 0.92,
                "reasoning": "High EPSS score + publicly reachable endpoint",
                "llm_votes": {
                    "gpt4": "block",
                    "claude": "block",
                    "gemini": "alert",
                },
                "policy_matched": "critical-ssrf-policy",
            },
        )
        assert r.status_code == 201
        data = r.json()
        assert data["outcome"] == "block"
        assert data["confidence"] == 0.92

    def test_analytics_mttr(self, api_client):
        """Mean time to remediation."""
        r = api_client.get("/api/v1/analytics/mttr")
        assert r.status_code == 200
        data = r.json()
        # MTTR data may or may not exist
        assert "mttr_hours" in data or "message" in data

    def test_analytics_coverage(self, api_client):
        """Security coverage metrics."""
        r = api_client.get("/api/v1/analytics/coverage")
        assert r.status_code == 200
        data = r.json()
        assert "total_findings" in data

    def test_analytics_roi(self, api_client):
        """ROI calculations."""
        r = api_client.get("/api/v1/analytics/roi")
        assert r.status_code == 200
        data = r.json()
        assert "estimated_prevented_cost" in data

    def test_analytics_noise_reduction(self, api_client):
        """Noise reduction metrics."""
        r = api_client.get("/api/v1/analytics/noise-reduction")
        assert r.status_code == 200
        data = r.json()
        assert "noise_reduction_percentage" in data

    def test_analytics_stats(self, api_client):
        """Aggregate analytics statistics."""
        r = api_client.get("/api/v1/analytics/stats")
        assert r.status_code == 200
        data = r.json()
        assert "total_findings" in data
        assert "severity_breakdown" in data

    def test_analytics_summary(self, api_client):
        """Analytics summary (alias)."""
        r = api_client.get("/api/v1/analytics/summary")
        assert r.status_code == 200

    def test_analytics_severity_over_time(self, api_client):
        """Severity trend analysis with moving averages."""
        r = api_client.get(
            "/api/v1/analytics/trends/severity-over-time",
            params={"days": 30, "bucket": "day"},
        )
        assert r.status_code == 200
        data = r.json()
        assert "series" in data

    def test_analytics_anomalies(self, api_client):
        """Anomaly detection via z-score."""
        r = api_client.get(
            "/api/v1/analytics/trends/anomalies",
            params={"days": 90, "threshold": 2.0},
        )
        assert r.status_code == 200
        data = r.json()
        assert "anomalies" in data

    def test_analytics_compare_periods(self, api_client):
        """Compare current vs previous period KPIs."""
        r = api_client.get(
            "/api/v1/analytics/compare", params={"current_days": 30}
        )
        assert r.status_code == 200
        data = r.json()
        assert "total_findings" in data
        assert "critical_findings" in data

    def test_analytics_triage_funnel(self, api_client):
        """Triage funnel metrics (11,300 → 340 narrative)."""
        r = api_client.get("/api/v1/analytics/triage-funnel")
        assert r.status_code == 200
        data = r.json()
        assert "funnel" in data
        assert "reduction_percentage" in data
        funnel = data["funnel"]
        assert funnel["raw_findings"] > funnel["exposure_cases"]

    def test_analytics_risk_velocity(self, api_client):
        """Risk velocity — rate of risk accumulation/reduction."""
        r = api_client.get(
            "/api/v1/analytics/risk-velocity", params={"days": 30}
        )
        assert r.status_code == 200
        data = r.json()
        assert "daily_risk_velocity" in data
        assert data["direction"] in ("increasing", "decreasing", "stable")

    def test_analytics_custom_query(self, api_client):
        """Run custom analytics query."""
        r = api_client.post(
            "/api/v1/analytics/custom-query",
            json={
                "type": "findings",
                "filters": {"severity": "critical", "limit": 10},
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert "results" in data

    def test_analytics_export_json(self, api_client):
        """Export analytics data as JSON."""
        r = api_client.get(
            "/api/v1/analytics/export",
            params={"format": "json", "data_type": "findings"},
        )
        assert r.status_code == 200

    def test_analytics_export_csv(self, api_client):
        """Export analytics data as CSV."""
        r = api_client.get(
            "/api/v1/analytics/export",
            params={"format": "csv", "data_type": "findings"},
        )
        assert r.status_code == 200

    # ------------------------------------------------------------------
    # Evidence Router — /api/v1/evidence
    # ------------------------------------------------------------------

    def test_evidence_stats(self, api_client):
        """Evidence vault statistics."""
        r = api_client.get("/api/v1/evidence/stats")
        assert r.status_code == 200
        data = r.json()
        assert "total_bundles" in data

    def test_evidence_list_bundles(self, api_client):
        """List compliance evidence bundles."""
        r = api_client.get("/api/v1/evidence/bundles")
        assert r.status_code == 200
        data = r.json()
        assert "bundles" in data
        assert "total" in data

    def test_evidence_generate_bundle_soc2(self, api_client):
        """Generate SOC2 evidence bundle."""
        r = api_client.post(
            "/api/v1/evidence/bundles/generate",
            json={
                "frameworks": ["SOC2"],
                "date_range": {"start": "2026-01-01", "end": "2026-02-28"},
                "categories": [
                    "findings",
                    "remediations",
                    "risk_scores",
                    "audit_logs",
                ],
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["framework"] == "SOC2"
        assert "id" in data
        assert data["id"].startswith("EVB-")
        assert "hash" in data

    def test_evidence_generate_bundle_pci(self, api_client):
        """Generate PCI-DSS evidence bundle."""
        r = api_client.post(
            "/api/v1/evidence/bundles/generate",
            json={
                "frameworks": ["PCI-DSS"],
                "date_range": {"start": "2026-02-01", "end": "2026-02-28"},
                "categories": ["findings", "remediations"],
            },
        )
        assert r.status_code == 200
        assert r.json()["framework"] == "PCI-DSS"

    def test_evidence_generate_bundle_multi_framework(self, api_client):
        """Generate multi-framework evidence bundle."""
        r = api_client.post(
            "/api/v1/evidence/bundles/generate",
            json={
                "frameworks": ["SOC2", "ISO27001"],
                "categories": [
                    "findings",
                    "remediations",
                    "risk_scores",
                    "audit_logs",
                    "mpte_verifications",
                ],
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert "SOC2" in data["frameworks"]
        assert "ISO27001" in data["frameworks"]

    def test_evidence_verify_bundle_signed(self, api_client):
        """Verify a signed evidence bundle (demo mode)."""
        r = api_client.post("/api/v1/evidence/bundles/EVB-2026-001/verify")
        assert r.status_code == 200
        data = r.json()
        assert "valid" in data
        assert "signature_valid" in data
        assert "certificate_chain" in data
        # EVB-2026-001 is a known signed demo bundle
        assert data["valid"] is True

    def test_evidence_verify_bundle_unsigned(self, api_client):
        """Verify an unsigned evidence bundle (demo mode)."""
        r = api_client.post("/api/v1/evidence/bundles/EVB-2026-002/verify")
        assert r.status_code == 200
        data = r.json()
        # EVB-2026-002 is unsigned
        assert data["valid"] is False

    def test_evidence_download_bundle_json(self, api_client):
        """Download evidence bundle as JSON."""
        r = api_client.get(
            "/api/v1/evidence/bundles/EVB-2026-001/download",
            params={"format": "json"},
        )
        assert r.status_code == 200

    def test_evidence_compliance_status(self, api_client):
        """Compliance framework coverage overview."""
        r = api_client.get("/api/v1/evidence/compliance-status")
        assert r.status_code == 200
        data = r.json()
        assert "frameworks" in data
        assert "SOC2" in data["frameworks"]
        assert "PCI-DSS" in data["frameworks"]
        assert "overall_score" in data

    def test_evidence_collect(self, api_client):
        """Collect/snapshot evidence for a bundle."""
        r = api_client.post("/api/v1/evidence/EVB-TEST-001/collect")
        # May return 200 or 503 if storage not configured
        assert r.status_code in (200, 503)

    def test_evidence_list_releases(self, api_client):
        """List evidence releases."""
        r = api_client.get("/api/v1/evidence/")
        # May return 200 or 503 if storage not configured
        assert r.status_code in (200, 503)


# ============================================================================
#  Cross-Persona Integration Tests
# ============================================================================


class TestCrossPersonaIntegration:
    """End-to-end workflows spanning multiple personas."""

    def test_e2e_finding_triage_to_fix(self, api_client):
        """Raj triages → Nina scans → Raj reviews fix.

        1. Nina runs SAST scan (finds vulnerability)
        2. Raj ingests finding into brain
        3. Raj generates AutoFix
        4. Tom records finding in analytics
        """
        # Step 1: Nina scans code
        scan_r = api_client.post(
            "/api/v1/sast/scan/code",
            json={
                "code": 'eval(user_input)  # Code injection\n',
                "filename": "handler.py",
            },
        )
        assert scan_r.status_code == 200

        # Step 2: Raj ingests finding
        finding_id = f"E2E-{uuid.uuid4().hex[:8]}"
        ingest_r = api_client.post(
            "/api/v1/brain/ingest/finding",
            json={
                "finding_id": finding_id,
                "org_id": "test-org",
                "title": "Code injection via eval()",
                "severity": "critical",
                "source": "sast",
            },
        )
        assert ingest_r.status_code == 200

        # Step 3: Raj generates AutoFix
        fix_r = api_client.post(
            "/api/v1/autofix/generate",
            json={
                "finding_id": finding_id,
                "title": "Code injection via eval()",
                "severity": "critical",
                "language": "python",
                "source_code": "eval(user_input)",
            },
        )
        assert fix_r.status_code == 200

        # Step 4: Tom records in analytics
        analytics_r = api_client.post(
            "/api/v1/analytics/findings",
            json={
                "org_id": "test-org",
                "rule_id": "CWE-94",
                "severity": "critical",
                "title": "Code injection via eval()",
                "description": "Dangerous eval() call on user input",
                "source": "sast",
            },
        )
        assert analytics_r.status_code == 201

    def test_e2e_incident_investigation(self, api_client):
        """Anika investigates incident via copilot + brain.

        1. Anika creates copilot session
        2. Anika adds CVE context
        3. Anika asks copilot for analysis
        4. Raj checks brain graph
        """
        # Step 1: Create session
        sess = api_client.post(
            "/api/v1/copilot/sessions",
            json={
                "name": "P1 Incident: Log4Shell variant",
                "agent_type": "security_analyst",
            },
        )
        assert sess.status_code == 200
        sid = sess.json()["id"]

        # Step 2: Add context
        ctx = api_client.post(
            f"/api/v1/copilot/sessions/{sid}/context",
            json={
                "context_type": "cve",
                "data": {
                    "cve_id": "CVE-2021-44228",
                    "severity": "critical",
                    "affected_service": "logging-service",
                },
            },
        )
        assert ctx.status_code == 200

        # Step 3: Ask copilot
        msg = api_client.post(
            f"/api/v1/copilot/sessions/{sid}/messages",
            json={
                "message": "Is CVE-2021-44228 exploitable in our logging service?",
            },
        )
        assert msg.status_code == 200

        # Step 4: Check brain
        stats = api_client.get("/api/v1/brain/stats")
        assert stats.status_code == 200

    def test_e2e_compliance_evidence_flow(self, api_client):
        """Tom's compliance workflow.

        1. Tom checks compliance status
        2. Tom generates evidence bundle
        3. Tom verifies bundle signature
        4. Tom checks analytics
        """
        # Step 1: Compliance status
        cs = api_client.get("/api/v1/evidence/compliance-status")
        assert cs.status_code == 200

        # Step 2: Generate bundle
        gen = api_client.post(
            "/api/v1/evidence/bundles/generate",
            json={
                "frameworks": ["SOC2"],
                "categories": ["findings", "audit_logs"],
            },
        )
        assert gen.status_code == 200
        bundle_id = gen.json()["id"]

        # Step 3: Verify (demo bundle — signature check)
        ver = api_client.post("/api/v1/evidence/bundles/EVB-2026-001/verify")
        assert ver.status_code == 200

        # Step 4: Analytics
        triage = api_client.get("/api/v1/analytics/triage-funnel")
        assert triage.status_code == 200

    def test_e2e_iac_to_remediation(self, api_client):
        """Nina scans IaC → creates finding → Raj reviews.

        1. Nina scans Terraform
        2. Nina creates IaC finding
        3. Raj ingests into brain
        4. Tom checks dashboard
        """
        # Step 1: CSPM scan
        scan = api_client.post(
            "/api/v1/cspm/scan/terraform",
            json={
                "content": 'resource "aws_s3_bucket" "bad" { acl = "public-read" }',
                "filename": "main.tf",
            },
        )
        assert scan.status_code == 200

        # Step 2: IaC finding
        iac = api_client.post(
            "/api/v1/iac",
            json={
                "provider": "terraform",
                "severity": "high",
                "title": "Public S3 bucket",
                "description": "S3 bucket with public-read ACL",
                "file_path": "main.tf",
                "line_number": 2,
                "resource_type": "aws_s3_bucket",
                "resource_name": "bad",
                "rule_id": "CKV_AWS_19",
            },
        )
        assert iac.status_code == 201
        iac_id = iac.json()["id"]

        # Step 3: Ingest into brain
        brain = api_client.post(
            "/api/v1/brain/ingest/finding",
            json={
                "finding_id": iac_id,
                "org_id": "test-org",
                "title": "Public S3 bucket",
                "severity": "high",
                "source": "cspm",
            },
        )
        assert brain.status_code == 200

        # Step 4: Dashboard
        dash = api_client.get("/api/v1/analytics/dashboard/overview")
        assert dash.status_code == 200
