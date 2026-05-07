"""Multi-tenant isolation smoke tests — Multica #4106.

Verifies that findings, connectors, and vulnerabilities are scoped to org_id
and that tenant A cannot read tenant B's data.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _org_header(org_id: str) -> Dict[str, str]:
    """Return headers that set org_id via X-Org-ID (no JWT needed in tests)."""
    return {"X-Org-ID": org_id}


# ---------------------------------------------------------------------------
# Test 1: /api/v1/findings — tenant A finding not visible to tenant B
# ---------------------------------------------------------------------------


def test_findings_tenant_isolation() -> None:
    """Insert finding for org-a; query as org-b; assert zero results."""
    from apps.api.findings_routes import _findings_store, router

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app, raise_server_exceptions=True)

    # Seed a finding for org-a directly into the in-memory store
    finding_id = "finding-tenant-a-001"
    _findings_store[finding_id] = {
        "id": finding_id,
        "title": "SQL Injection in login form",
        "description": "Org-A secret finding",
        "severity": "critical",
        "status": "open",
        "connector": "github",
        "asset_id": "asset-001",
        "cve_id": "CVE-2024-0001",
        "risk_score": 9.8,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "last_seen": datetime.now(timezone.utc),
        "assigned_to": None,
        "assigned_team": None,
        "pipeline_history": [],
        "related_findings": [],
        "council_verdict": None,
        "playbook_runs": [],
        "comments": [],
        "org_id": "org-a",
    }

    try:
        # Query as org-b — must return zero findings
        resp = client.get("/api/v1/findings", headers=_org_header("org-b"))
        assert resp.status_code == 200, f"Unexpected status: {resp.status_code}"
        data = resp.json()
        ids = [f.get("id") for f in data.get("findings", [])]
        assert finding_id not in ids, (
            f"DATA LEAK: org-b received org-a finding {finding_id}"
        )

        # Sanity: org-a can see its own finding
        resp_a = client.get("/api/v1/findings", headers=_org_header("org-a"))
        assert resp_a.status_code == 200
        ids_a = [f.get("id") for f in resp_a.json().get("findings", [])]
        assert finding_id in ids_a, "org-a should see its own finding"
    finally:
        _findings_store.pop(finding_id, None)


# ---------------------------------------------------------------------------
# Test 2: /api/v1/connectors — tenant A connector not visible to tenant B
# ---------------------------------------------------------------------------


def test_connectors_tenant_isolation() -> None:
    """Register connector under org-a namespace; list as org-b; assert not present."""
    from apps.api.connectors_router import _get_universal, _org_prefix, router

    app = FastAPI()
    app.include_router(router)

    # Patch _get_universal to return a controlled mock registry
    mock_connector = MagicMock()
    mock_connector.connector_type = "github"
    mock_connector.configured = True
    mock_connector.get_metrics.return_value = {}

    # Simulate the universal connector registry with one org-a connector
    prefix_a = _org_prefix("org-a")
    internal_name = f"{prefix_a}my-github"

    mock_uc = MagicMock()
    mock_uc.list_connectors.return_value = [
        {
            "name": internal_name,
            "type": "github",
            "configured": True,
            "metrics": {},
        }
    ]

    with patch("apps.api.connectors_router._get_universal", return_value=mock_uc):
        client = TestClient(app, raise_server_exceptions=True)

        # Query as org-b — must return empty list
        resp_b = client.get("/api/v1/connectors", headers=_org_header("org-b"))
        assert resp_b.status_code == 200, f"Unexpected status: {resp_b.status_code}"
        data_b = resp_b.json()
        names_b = [c["name"] for c in data_b.get("connectors", [])]
        assert "my-github" not in names_b, (
            "DATA LEAK: org-b can see org-a connector 'my-github'"
        )
        assert data_b["total"] == 0, f"Expected 0 connectors for org-b, got {data_b['total']}"

        # Sanity: org-a can see its own connector
        resp_a = client.get("/api/v1/connectors", headers=_org_header("org-a"))
        assert resp_a.status_code == 200
        data_a = resp_a.json()
        names_a = [c["name"] for c in data_a.get("connectors", [])]
        assert "my-github" in names_a, "org-a should see its own connector"
        assert data_a["total"] == 1


# ---------------------------------------------------------------------------
# Test 3: /api/v1/vulns/discovered — tenant A vuln not visible to tenant B
# ---------------------------------------------------------------------------


def test_vulnerabilities_tenant_isolation() -> None:
    """Patch _discovered_vulns with a dict containing one org-a vuln; query as org-b."""
    import apps.api.vuln_discovery_router as _vdr_mod
    from apps.api.vuln_discovery_router import router

    vuln_id = "vuln-tenant-a-001"
    _now = datetime.now(timezone.utc)
    fake_store: Dict[str, Any] = {
        vuln_id: {
            # Fields required by DiscoveredVulnResponse
            "id": vuln_id,
            "internal_id": "ALDECI-2026-9001",
            "title": "RCE in auth service",
            "severity": "critical",
            "status": "draft",
            "created_at": _now,
            "discovered_by": "pentest-team",
            "cvss_score": 9.9,
            "cve_id": None,
            # Extra fields used by the filter logic
            "org_id": "org-a",
            "discovered_date": _now.isoformat(),
        }
    }

    # Build app and client INSIDE the patch context so the router
    # endpoint resolves _discovered_vulns from the patched module global
    with patch.object(_vdr_mod, "_discovered_vulns", fake_store):
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app, raise_server_exceptions=True)

        # Query as org-b — must return empty list
        resp_b = client.get("/api/v1/vulns/discovered", headers=_org_header("org-b"))
        assert resp_b.status_code == 200, f"Unexpected status: {resp_b.status_code}"
        ids_b = [v.get("id") for v in resp_b.json()]
        assert vuln_id not in ids_b, (
            f"DATA LEAK: org-b received org-a vulnerability {vuln_id}"
        )

        # Sanity: org-a can see its own vuln
        resp_a = client.get("/api/v1/vulns/discovered", headers=_org_header("org-a"))
        assert resp_a.status_code == 200
        ids_a = [v.get("id") for v in resp_a.json()]
        assert vuln_id in ids_a, "org-a should see its own vulnerability"
