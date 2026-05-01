"""Tests for ContainerSecurityConnector → /api/v1/cwp/workloads fallback.

Validates the engine fallback added in
``cloud_workload_protection_engine.list_workloads_with_container_fallback``:

1. Org with registered cwp_workloads → returns those rows untouched
   (source="org_registered").
2. Org with no rows + connector unconfigured (no docker/trivy/grype/dockle
   AND no tenant repos) → structured needs_credentials hint (NEVER mocks).
3. Org with no rows + connector has scan history → projects each
   TenantScanResult as a derived workload (workload_type=container,
   cloud_provider=on_prem).
4. Risk-score derivation from severity_breakdown (critical=10pt, high=5pt,
   medium=2pt) — capped at 100, mapped to risk_level.
5. Filters apply against derived rows.
6. Org-registered rows take precedence over derived projection.
7. Multiple scans against the same image → derived row uses the most recent.
"""
from __future__ import annotations

import os
import sys
import uuid
from typing import Any, Dict, List

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _make_engine(tmp_path):
    from core.cloud_workload_protection_engine import CloudWorkloadProtectionEngine
    db = os.path.join(str(tmp_path), f"cwp_{uuid.uuid4().hex}.db")
    return CloudWorkloadProtectionEngine(db_path=db)


class _FakeContainerConnector:
    """Stand-in for ContainerSecurityConnector with controllable state."""

    def __init__(
        self,
        scan_history: List[Dict[str, Any]] = None,
        tools: Dict[str, bool] = None,
        tenants: List[str] = None,
    ):
        self._scan_history = scan_history or []
        self._tools = tools or {"docker": False, "trivy": False,
                                "grype": False, "dockle": False}
        self._tenants = tenants or []

    def get_scan_history(self, org_id: str, limit: int = 50):
        return list(self._scan_history)

    def tool_status(self):
        return dict(self._tools)

    def list_tenants(self):
        return list(self._tenants)


def test_returns_org_registered_when_workloads_exist(tmp_path):
    eng = _make_engine(tmp_path)
    eng.register_workload("acme", {
        "workload_name": "vm-1", "workload_type": "vm",
        "cloud_provider": "aws",
    })
    out = eng.list_workloads_with_container_fallback("acme")
    assert out["source"] == "org_registered"
    assert out["total"] == 1
    assert out["workloads"][0]["workload_name"] == "vm-1"


def test_returns_needs_credentials_when_no_data_and_no_toolchain(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeContainerConnector()  # no tools, no tenants, no scans
    out = eng.list_workloads_with_container_fallback(
        "empty-org", container_connector=fake,
    )
    assert out["workloads"] == []
    assert out["total"] == 0
    assert out["source"] == "needs_credentials"
    assert "FIXOPS_CONTAINER_TENANTS_ROOT" in out["hint"]
    assert out["tool_status"] == {"docker": False, "trivy": False,
                                  "grype": False, "dockle": False}


def test_needs_scan_when_configured_but_no_history(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeContainerConnector(
        tools={"docker": True, "trivy": True, "grype": True, "dockle": True},
        tenants=["juice-shop", "dvwa"],
    )
    out = eng.list_workloads_with_container_fallback(
        "acme", container_connector=fake,
    )
    assert out["source"] == "needs_scan"
    assert out["workloads"] == []
    assert "POST /api/v1/container-security/scan" in out["hint"]


def test_projects_scan_history_as_derived_workloads(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeContainerConnector(
        scan_history=[
            {
                "scan_id": "s1", "tenant": "juice-shop",
                "image": "fixops-test/juice-shop:scan",
                "started_at": "2026-05-02T10:00:00",
                "completed_at": "2026-05-02T10:05:00",
                "findings_recorded": 14,
                "severity_breakdown": {
                    "critical": 1, "high": 3, "medium": 4, "low": 6,
                },
            },
            {
                "scan_id": "s2", "tenant": "dvwa",
                "image": "fixops-test/dvwa:scan",
                "started_at": "2026-05-02T11:00:00",
                "completed_at": "2026-05-02T11:04:00",
                "findings_recorded": 0,
                "severity_breakdown": {"critical": 0, "high": 0, "medium": 0,
                                       "low": 0, "informational": 0},
            },
        ],
        tools={"docker": True, "trivy": True, "grype": True, "dockle": True},
        tenants=["juice-shop", "dvwa"],
    )
    out = eng.list_workloads_with_container_fallback(
        "acme", container_connector=fake,
    )
    assert out["source"] == "container_oss"
    assert out["total"] == 2
    by_image = {w["image"]: w for w in out["workloads"]}
    juice = by_image["fixops-test/juice-shop:scan"]
    assert juice["workload_type"] == "container"
    assert juice["cloud_provider"] == "on_prem"
    assert juice["risk_level"] == "critical"  # 1 crit drives critical bucket
    # 1*10 + 3*5 + 4*2 = 33
    assert juice["risk_score"] == 33.0
    assert juice["protection_status"] == "unprotected"  # has high findings
    dvwa = by_image["fixops-test/dvwa:scan"]
    assert dvwa["risk_level"] == "low"
    assert dvwa["risk_score"] == 0.0
    assert dvwa["protection_status"] == "protected"
    # Provenance
    assert all(w["source"] == "container_oss" for w in out["workloads"])
    assert all("scan_id" in w and "tenant" in w for w in out["workloads"])


def test_filters_against_derived_rows(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeContainerConnector(
        scan_history=[
            {
                "scan_id": "s1", "tenant": "a", "image": "img-a:scan",
                "started_at": "2026-05-02T10:00:00",
                "completed_at": "2026-05-02T10:05:00",
                "findings_recorded": 1,
                "severity_breakdown": {"critical": 1},
            },
            {
                "scan_id": "s2", "tenant": "b", "image": "img-b:scan",
                "started_at": "2026-05-02T11:00:00",
                "findings_recorded": 1,
                "severity_breakdown": {"low": 1},
            },
        ],
        tools={"docker": True, "trivy": True, "grype": True, "dockle": True},
        tenants=["a", "b"],
    )
    crit = eng.list_workloads_with_container_fallback(
        "acme", risk_level="critical", container_connector=fake,
    )
    assert crit["total"] == 1
    assert crit["workloads"][0]["image"] == "img-a:scan"
    # workload_type filter: only "container" matches; "vm" excludes all.
    out_vm = eng.list_workloads_with_container_fallback(
        "acme", workload_type="vm", container_connector=fake,
    )
    assert out_vm["total"] == 0
    # cloud_provider="on_prem" matches everything.
    out_op = eng.list_workloads_with_container_fallback(
        "acme", cloud_provider="on_prem", container_connector=fake,
    )
    assert out_op["total"] == 2


def test_org_rows_take_precedence_over_derived(tmp_path):
    eng = _make_engine(tmp_path)
    eng.register_workload("acme", {
        "workload_name": "real-vm", "workload_type": "vm",
        "cloud_provider": "aws",
    })
    fake = _FakeContainerConnector(
        scan_history=[
            {
                "scan_id": "s1", "tenant": "x", "image": "x:scan",
                "started_at": "2026-05-02T10:00:00",
                "findings_recorded": 5,
                "severity_breakdown": {"critical": 1, "high": 1},
            },
        ],
    )
    out = eng.list_workloads_with_container_fallback(
        "acme", container_connector=fake,
    )
    assert out["source"] == "org_registered"
    assert out["total"] == 1
    assert out["workloads"][0]["workload_name"] == "real-vm"


def test_dedupes_same_image_keeping_most_recent(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeContainerConnector(
        scan_history=[
            {
                "scan_id": "old", "tenant": "x", "image": "x:scan",
                "started_at": "2026-04-01T00:00:00",
                "findings_recorded": 1,
                "severity_breakdown": {"low": 1},
            },
            {
                "scan_id": "new", "tenant": "x", "image": "x:scan",
                "started_at": "2026-05-02T10:00:00",
                "findings_recorded": 5,
                "severity_breakdown": {"critical": 1},
            },
        ],
        tools={"docker": True, "trivy": True, "grype": True, "dockle": True},
        tenants=["x"],
    )
    out = eng.list_workloads_with_container_fallback(
        "acme", container_connector=fake,
    )
    assert out["total"] == 1
    # Most-recent scan wins
    assert out["workloads"][0]["scan_id"] == "new"
    assert out["workloads"][0]["risk_level"] == "critical"


def test_router_wired_to_fallback(tmp_path, monkeypatch):
    """End-to-end through the FastAPI router."""
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.api.cloud_workload_protection_router import router as cwp_router
    from apps.api.auth_deps import api_key_auth

    import apps.api.cloud_workload_protection_router as cwp_module
    cwp_module._engine = None
    monkeypatch.setattr(
        "core.cloud_workload_protection_engine._DEFAULT_DB",
        os.path.join(str(tmp_path), "cwp_router.db"),
        raising=False,
    )

    app = FastAPI()
    app.include_router(cwp_router)
    app.dependency_overrides[api_key_auth] = lambda: True
    client = TestClient(app)

    r = client.get(
        "/api/v1/cwp/workloads?org_id=brand-new-org",
    )
    assert r.status_code == 200, r.text
    body = r.json()
    # Must be the structured envelope, not a bare list.
    assert isinstance(body, dict)
    assert "workloads" in body
    assert "source" in body
