"""Regression tests for the four platform gaps surfaced by the
2026-04-27 ALDECI self-scan dogfood (docs/security/aldeci_self_scan_2026-04-27.md).

  Gap 1 — pip-audit JSON normalizer
  Gap 2 — ingest-to-issues promotion
  Gap 3 — /api/v1/risk-scoring/summary endpoint
  Gap 4 — cross-scanner dedup at storage layer ingest path

Run with:
    python -m pytest tests/test_self_scan_gaps_2026_04_27.py -x -q
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

# Make sure suite-core / suite-api are importable when running standalone.
_repo_root = Path(__file__).resolve().parent.parent
for sub in ("suite-core", "suite-api"):
    p = str(_repo_root / sub)
    if p not in sys.path:
        sys.path.insert(0, p)


# ---------------------------------------------------------------------------
# Gap 1 — pip-audit normalizer
# ---------------------------------------------------------------------------


def _pip_audit_sample() -> bytes:
    return json.dumps({
        "dependencies": [
            {"name": "clean-pkg", "version": "1.0.0", "vulns": []},
            {
                "name": "authlib",
                "version": "1.6.9",
                "vulns": [
                    {
                        "id": "GHSA-jj8c-mmj3-mmgv",
                        "fix_versions": ["1.6.11"],
                        "aliases": [],
                        "description": "No CSRF protection on OAuth cache.",
                    }
                ],
            },
            {
                "name": "diskcache",
                "version": "5.6.3",
                "vulns": [
                    {
                        "id": "CVE-2025-69872",
                        "fix_versions": [],
                        "aliases": ["GHSA-w8v5-vhqr-4h9v"],
                        "description": "Pickle RCE via cache directory write.",
                    }
                ],
            },
        ]
    }).encode("utf-8")


def test_gap1_pip_audit_auto_detect_and_parse():
    from core.scanner_parsers import (
        SCANNER_NORMALIZERS,
        auto_detect_scanner,
        parse_scanner_output,
    )

    assert "pip-audit" in SCANNER_NORMALIZERS, "pip-audit must be in normalizer registry"
    content = _pip_audit_sample()
    assert auto_detect_scanner(content) == "pip-audit"
    findings = parse_scanner_output(content=content, scanner_type="pip-audit")
    # 2 vulns across 2 deps; clean-pkg contributes zero findings
    assert len(findings) == 2
    titles = {f.title if hasattr(f, "title") else f.get("title") for f in findings}
    assert any("authlib" in (t or "") for t in titles)
    assert any("diskcache" in (t or "") for t in titles)
    # Verify CVE id is populated when aliases carry it (diskcache case)
    cves = [
        getattr(f, "cve_id", None) or (f.get("cve_id") if isinstance(f, dict) else None)
        for f in findings
    ]
    assert "CVE-2025-69872" in cves


def test_gap1_pip_audit_handles_empty_dependencies():
    from core.scanner_parsers import parse_scanner_output

    findings = parse_scanner_output(
        content=b'{"dependencies": []}',
        scanner_type="pip-audit",
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Gap 2 — ingest-to-issues promotion
# ---------------------------------------------------------------------------


@pytest.fixture()
def isolated_findings_db(tmp_path, monkeypatch):
    """Point SecurityFindingsEngine at a tmp DB so test rows don't pollute."""
    from core import security_findings_engine as sfe

    db = tmp_path / "security_findings_engine.db"
    monkeypatch.setattr(sfe, "_DEFAULT_DB", str(db))
    yield str(db)


def test_gap2_promotion_records_findings_to_issues_table(isolated_findings_db):
    from apps.api.scanner_ingest_router import _promote_findings_to_issues
    from core.security_findings_engine import SecurityFindingsEngine

    findings = [
        {
            "id": "p1",
            "title": "fastmcp shell injection",
            "cve_id": "CVE-2025-64340",
            "package_name": "fastmcp",
            "package_version": "2.14.6",
            "severity": "high",
            "description": "Server names with shell metacharacters.",
            "recommendation": "Upgrade fastmcp to >= 3.2.0",
        },
        {
            "id": "p2",
            "title": "B324 weak SHA1",
            "rule_id": "B324",
            "file_path": "suite-api/apps/api/some_router.py",
            "severity": "high",
        },
    ]
    promoted = _promote_findings_to_issues(findings, "pip-audit", "test-gap2")
    assert promoted == 2

    engine = SecurityFindingsEngine()
    rows = engine.list_findings(org_id="test-gap2")
    assert len(rows) == 2
    titles = {r["title"] for r in rows}
    assert "fastmcp shell injection" in titles
    assert "B324 weak SHA1" in titles
    # correlation_key must be stable for re-ingest dedup
    keys = {r["correlation_key"] for r in rows}
    assert any("CVE-2025-64340" in k for k in keys)
    assert any("B324" in k for k in keys)


def test_gap2_promotion_is_idempotent_via_correlation_key(isolated_findings_db):
    """Re-ingesting the same finding must not create duplicate rows."""
    from apps.api.scanner_ingest_router import _promote_findings_to_issues
    from core.security_findings_engine import SecurityFindingsEngine

    finding = {
        "id": "x1",
        "title": "fastmcp shell injection",
        "cve_id": "CVE-2025-64340",
        "package_name": "fastmcp",
        "package_version": "2.14.6",
        "severity": "high",
    }
    _promote_findings_to_issues([finding], "pip-audit", "test-gap2-idem")
    _promote_findings_to_issues([finding], "pip-audit", "test-gap2-idem")
    rows = SecurityFindingsEngine().list_findings(org_id="test-gap2-idem")
    assert len(rows) == 1, "second ingest should dedup via correlation_key"
    assert rows[0]["occurrence_count"] >= 2


# ---------------------------------------------------------------------------
# Gap 3 — /api/v1/risk-scoring/summary endpoint
# ---------------------------------------------------------------------------


def test_gap3_risk_scoring_summary_endpoint_returns_rollup(monkeypatch):
    monkeypatch.setenv("FIXOPS_API_TOKEN", "test-key-gap3")
    monkeypatch.setenv("FIXOPS_MODE", "test")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Re-import auth_deps + router so they re-read env.
    import importlib

    import apps.api.auth_deps as ad
    importlib.reload(ad)
    import apps.api.risk_scoring_router as rsr
    importlib.reload(rsr)

    app = FastAPI()
    app.include_router(rsr.router)
    client = TestClient(app)

    r = client.get(
        "/api/v1/risk-scoring/summary?org_id=demo",
        headers={"X-API-Key": "test-key-gap3"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    # Required rollup keys for the dashboard
    for key in (
        "exposure_score",
        "rating",
        "weighted_risk_avg",
        "open_findings_count",
        "by_tier",
        "assets_at_risk",
        "patch_velocity_score",
    ):
        assert key in body, f"missing {key}"
    assert set(body["by_tier"].keys()) == {"critical", "high", "medium", "low"}


def test_gap3_router_prefix_is_risk_scoring():
    """Regression — historical prefix was /api/v1/risk and broke the UI."""
    from apps.api.risk_scoring_router import router

    assert router.prefix == "/api/v1/risk-scoring"


# ---------------------------------------------------------------------------
# Gap 4 — cross-scanner dedup at storage layer
# ---------------------------------------------------------------------------


def test_gap4_dedupe_collapses_cross_scanner_cve(tmp_path, monkeypatch):
    from core import smart_dedup as sd
    monkeypatch.setattr(sd, "_DB_PATH", tmp_path / "smart_dedup_test.db")
    from apps.api.scanner_ingest_router import _dedupe_findings

    findings: List[Dict[str, Any]] = [
        {
            "id": "a", "title": "authlib OAuth CSRF",
            "cve_id": "GHSA-jj8c-mmj3-mmgv",
            "source_tool": "pip-audit", "file_path": "requirements.txt",
            "severity": "high",
        },
        {
            "id": "b", "title": "authlib OAuth CSRF",
            "cve_id": "GHSA-jj8c-mmj3-mmgv",
            "source_tool": "snyk", "file_path": "requirements.txt",
            "severity": "high",
        },
        {
            "id": "c", "title": "diskcache pickle RCE",
            "cve_id": "CVE-2025-69872",
            "source_tool": "pip-audit", "severity": "high",
        },
    ]
    out = _dedupe_findings(findings, "test-gap4")
    assert out["duplicate_count"] >= 1
    assert len(out["canonical"]) == 2
    assert out["groups"] >= 1


def test_gap4_dedupe_handles_empty_input(tmp_path, monkeypatch):
    from core import smart_dedup as sd
    monkeypatch.setattr(sd, "_DB_PATH", tmp_path / "smart_dedup_test_empty.db")
    from apps.api.scanner_ingest_router import _dedupe_findings

    out = _dedupe_findings([], "test-gap4-empty")
    assert out["duplicate_count"] == 0
    assert out["canonical"] == []
    assert out["groups"] == 0
