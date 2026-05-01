"""Tests for CSPMConnector → /api/v1/cloud-posture/findings fallback.

Validates the engine fallback added in
``cloud_posture_engine.list_findings_with_cspm_fallback``:

1. Org with recorded cp_findings → returns those rows untouched
   (source="org_recorded").
2. Org with no rows + no SecurityFindingsEngine signal → structured empty
   with needs_credentials hint (NEVER mocks).
3. Org with no rows + SecurityFindingsEngine has cspm_via_* tagged rows →
   projects each as a derived cp_finding (source="cspm_connector").
4. Filters apply against derived rows.
5. Org-recorded rows take precedence over derived projection.
"""
from __future__ import annotations

import os
import sys
import tempfile
import uuid
from typing import Any, Dict, List

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _make_engine(tmp_path):
    from core.cloud_posture_engine import CloudPostureEngine
    db = os.path.join(str(tmp_path), f"cp_{uuid.uuid4().hex}.db")
    return CloudPostureEngine(db_path=db)


class _FakeSF:
    """Stand-in for SecurityFindingsEngine.list_findings()."""

    def __init__(self, rows: List[Dict[str, Any]]):
        self._rows = rows

    def list_findings(self, org_id: str, **_):
        return [r for r in self._rows if r.get("org_id") == org_id]


def test_returns_org_recorded_when_cp_rows_exist(tmp_path):
    eng = _make_engine(tmp_path)
    eng.register_account("acme", {"account_id": "111111111111"})
    eng.record_finding("acme", {
        "cloud_account_id": "111111111111",
        "resource_type": "storage",
        "severity": "high",
        "title": "S3 public bucket",
        "description": "real org-recorded finding",
        "remediation": "block public",
    })
    out = eng.list_findings_with_cspm_fallback("acme")
    assert out["source"] == "org_recorded"
    assert out["total"] == 1
    assert out["findings"][0]["title"] == "S3 public bucket"


def test_returns_needs_credentials_when_no_data_anywhere(tmp_path):
    eng = _make_engine(tmp_path)
    out = eng.list_findings_with_cspm_fallback(
        "empty-org",
        findings_engine=_FakeSF([]),
    )
    assert out["findings"] == []
    assert out["total"] == 0
    assert out["source"] == "needs_credentials"
    assert "/api/v1/cspm/scan" in out["hint"]


def test_projects_cspm_via_findings_as_cp_findings(tmp_path):
    eng = _make_engine(tmp_path)
    fake_sf = _FakeSF([
        {
            "id": "f1", "org_id": "acme",
            "title": "S3 public access", "description": "bucket exposed",
            "remediation": "enable BPA",
            "severity": "critical",
            "asset_id": "my-bucket", "asset_type": "cloud_resource",
            "source_tool": "cspm_via_prowler",
            "first_seen": "2026-05-02T00:00:00",
            "correlation_key": "cspm_via_prowler|s3_pub|my-bucket",
        },
        {
            "id": "f2", "org_id": "acme",
            "title": "RDS unencrypted", "description": "no kms",
            "remediation": "encrypt",
            "severity": "high",
            "asset_id": "my-rds", "asset_type": "cloud_resource",
            "source_tool": "cspm_via_checkov",
            "first_seen": "2026-05-02T00:00:00",
        },
        # Different org — must be filtered out.
        {
            "id": "f3", "org_id": "other",
            "title": "leak", "severity": "high",
            "asset_id": "x", "asset_type": "cloud_resource",
            "source_tool": "cspm_via_prowler",
        },
        # Non-CSPM source — must be filtered out.
        {
            "id": "f4", "org_id": "acme",
            "title": "sast finding", "severity": "high",
            "asset_id": "x", "asset_type": "code",
            "source_tool": "semgrep",
        },
    ])
    out = eng.list_findings_with_cspm_fallback("acme", findings_engine=fake_sf)
    assert out["source"] == "cspm_connector"
    assert out["total"] == 2
    titles = sorted(f["title"] for f in out["findings"])
    assert titles == ["RDS unencrypted", "S3 public access"]
    # Provenance fields preserved
    by_title = {f["title"]: f for f in out["findings"]}
    assert by_title["S3 public access"]["cspm_tool"] == "prowler"
    assert by_title["RDS unencrypted"]["cspm_tool"] == "checkov"
    assert all(f["source"] == "cspm_connector" for f in out["findings"])
    # Severity vocab mapped (no "informational" leakage)
    assert all(f["severity"] in {"critical", "high", "medium", "low", "info"}
               for f in out["findings"])


def test_filters_apply_against_derived_rows(tmp_path):
    eng = _make_engine(tmp_path)
    fake_sf = _FakeSF([
        {
            "id": "a", "org_id": "acme", "title": "crit-bucket",
            "severity": "critical", "asset_id": "b1",
            "asset_type": "cloud_resource", "source_tool": "cspm_via_prowler",
        },
        {
            "id": "b", "org_id": "acme", "title": "med-iam",
            "severity": "medium", "asset_id": "u1",
            "asset_type": "cloud_resource", "source_tool": "cspm_via_prowler",
        },
    ])
    crit = eng.list_findings_with_cspm_fallback(
        "acme", severity="critical", findings_engine=fake_sf,
    )
    assert crit["total"] == 1
    assert crit["findings"][0]["title"] == "crit-bucket"
    med = eng.list_findings_with_cspm_fallback(
        "acme", severity="medium", findings_engine=fake_sf,
    )
    assert med["total"] == 1
    assert med["findings"][0]["title"] == "med-iam"


def test_org_rows_take_precedence_over_derived(tmp_path):
    eng = _make_engine(tmp_path)
    eng.register_account("acme", {"account_id": "1"})
    eng.record_finding("acme", {
        "cloud_account_id": "1", "resource_type": "compute",
        "severity": "low", "title": "real org row",
        "description": "", "remediation": "",
    })
    fake_sf = _FakeSF([
        {
            "id": "a", "org_id": "acme", "title": "should be ignored",
            "severity": "critical", "asset_id": "x",
            "asset_type": "cloud_resource", "source_tool": "cspm_via_prowler",
        },
    ])
    out = eng.list_findings_with_cspm_fallback("acme", findings_engine=fake_sf)
    assert out["source"] == "org_recorded"
    assert out["total"] == 1
    assert out["findings"][0]["title"] == "real org row"


def test_router_wired_to_fallback(tmp_path, monkeypatch):
    """End-to-end through the FastAPI router: list_findings returns the
    fallback envelope (not bare list)."""
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.api.cloud_posture_router import router as cp_router
    from apps.api.auth_deps import api_key_auth

    # Reset engine + point to tmp_path for isolation.
    import apps.api.cloud_posture_router as cp_module
    cp_module._engine = None
    monkeypatch.setattr(
        "core.cloud_posture_engine._DEFAULT_DB",
        os.path.join(str(tmp_path), "cp_router.db"),
        raising=False,
    )

    app = FastAPI()
    app.include_router(cp_router)
    # Bypass auth via dependency_overrides — the engine fallback is what
    # we're testing.
    app.dependency_overrides[api_key_auth] = lambda: True
    client = TestClient(app)

    r = client.get(
        "/api/v1/cloud-posture/findings?org_id=brand-new-org",
    )
    assert r.status_code == 200, r.text
    body = r.json()
    # Must be the structured envelope, not bare list
    assert isinstance(body, dict)
    assert "findings" in body
    assert "source" in body
