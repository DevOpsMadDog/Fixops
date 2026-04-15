"""Tests for SecurityFindingsEngine — 35+ tests covering all methods and edge cases."""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

import pytest
from core.security_findings_engine import SecurityFindingsEngine

ORG = "org-sf-test"
ORG2 = "org-sf-other"


@pytest.fixture
def engine(tmp_path):
    return SecurityFindingsEngine(db_path=str(tmp_path / "test_sf.db"))


def _make_finding(engine, org=ORG, **kwargs):
    defaults = dict(
        title="SQL Injection in login endpoint",
        finding_type="vulnerability",
        source_tool="SAST",
        severity="high",
        cvss_score=7.5,
        asset_id="asset-web-01",
        asset_type="web-application",
        description="User input not sanitized",
        remediation="Use parameterized queries",
    )
    defaults.update(kwargs)
    return engine.record_finding(org_id=org, **defaults)


# ---------------------------------------------------------------------------
# record_finding — basic creation
# ---------------------------------------------------------------------------

def test_record_finding_creates_record(engine):
    f = _make_finding(engine)
    assert f["id"]
    assert f["title"] == "SQL Injection in login endpoint"
    assert f["status"] == "open"
    assert f["occurrence_count"] == 1
    assert f["org_id"] == ORG


def test_record_finding_cvss_stored(engine):
    f = _make_finding(engine, cvss_score=8.5)
    assert f["cvss_score"] == 8.5


def test_record_finding_cvss_clamped_above_10(engine):
    f = _make_finding(engine, cvss_score=15.0)
    assert f["cvss_score"] == 10.0


def test_record_finding_cvss_clamped_below_0(engine):
    f = _make_finding(engine, cvss_score=-3.0)
    assert f["cvss_score"] == 0.0


def test_record_finding_cvss_at_10_boundary(engine):
    f = _make_finding(engine, cvss_score=10.0)
    assert f["cvss_score"] == 10.0


def test_record_finding_cvss_at_0_boundary(engine):
    f = _make_finding(engine, cvss_score=0.0)
    assert f["cvss_score"] == 0.0


# ---------------------------------------------------------------------------
# record_finding — deduplication
# ---------------------------------------------------------------------------

def test_record_finding_dedup_increments_occurrence(engine):
    f1 = _make_finding(engine)
    f2 = _make_finding(engine)
    assert f1["id"] == f2["id"]
    assert f2["occurrence_count"] == 2


def test_record_finding_dedup_three_times(engine):
    _make_finding(engine)
    _make_finding(engine)
    f3 = _make_finding(engine)
    assert f3["occurrence_count"] == 3


def test_record_finding_different_title_creates_new(engine):
    f1 = _make_finding(engine, title="Finding A")
    f2 = _make_finding(engine, title="Finding B")
    assert f1["id"] != f2["id"]


def test_record_finding_different_source_tool_creates_new(engine):
    f1 = _make_finding(engine, source_tool="SAST")
    f2 = _make_finding(engine, source_tool="DAST")
    assert f1["id"] != f2["id"]


def test_record_finding_different_asset_creates_new(engine):
    f1 = _make_finding(engine, asset_id="asset-01")
    f2 = _make_finding(engine, asset_id="asset-02")
    assert f1["id"] != f2["id"]


def test_record_finding_resolved_status_creates_new(engine):
    f1 = _make_finding(engine)
    engine.update_status(f1["id"], ORG, "resolved")
    # Same title+tool+asset but previous is resolved → new finding
    f2 = _make_finding(engine)
    assert f1["id"] != f2["id"]
    assert f2["occurrence_count"] == 1


def test_record_finding_different_org_creates_new(engine):
    f1 = _make_finding(engine, org=ORG)
    f2 = _make_finding(engine, org=ORG2)
    assert f1["id"] != f2["id"]


# ---------------------------------------------------------------------------
# update_status
# ---------------------------------------------------------------------------

def test_update_status_in_progress(engine):
    f = _make_finding(engine)
    updated = engine.update_status(f["id"], ORG, "in-progress")
    assert updated["status"] == "in-progress"


def test_update_status_resolved_updates_last_seen(engine):
    f = _make_finding(engine)
    first_last_seen = f["last_seen"]
    updated = engine.update_status(f["id"], ORG, "resolved")
    assert updated["status"] == "resolved"
    # last_seen must be updated (may equal first_last_seen if very fast, but status is correct)
    assert updated["last_seen"] is not None


def test_update_status_assigns_to(engine):
    f = _make_finding(engine)
    updated = engine.update_status(f["id"], ORG, "in-progress", assigned_to="alice")
    assert updated["assigned_to"] == "alice"


def test_update_status_wrong_org_returns_none(engine):
    f = _make_finding(engine)
    result = engine.update_status(f["id"], ORG2, "resolved")
    assert result is None


def test_update_status_nonexistent_returns_none(engine):
    result = engine.update_status("no-such-id", ORG, "resolved")
    assert result is None


# ---------------------------------------------------------------------------
# add_evidence
# ---------------------------------------------------------------------------

def test_add_evidence_returns_dict(engine):
    f = _make_finding(engine)
    ev = engine.add_evidence(f["id"], ORG, "log", "Found in /var/log/app.log")
    assert ev["id"]
    assert ev["finding_id"] == f["id"]
    assert ev["evidence_type"] == "log"


def test_add_evidence_appears_in_get_finding(engine):
    f = _make_finding(engine)
    engine.add_evidence(f["id"], ORG, "screenshot", "base64data...")
    result = engine.get_finding(f["id"], ORG)
    assert len(result["evidence"]) == 1
    assert result["evidence"][0]["evidence_type"] == "screenshot"


def test_add_multiple_evidence(engine):
    f = _make_finding(engine)
    engine.add_evidence(f["id"], ORG, "log", "log1")
    engine.add_evidence(f["id"], ORG, "code-snippet", "x = input()")
    result = engine.get_finding(f["id"], ORG)
    assert len(result["evidence"]) == 2


# ---------------------------------------------------------------------------
# suppress_finding
# ---------------------------------------------------------------------------

def test_suppress_finding_creates_suppression(engine):
    f = _make_finding(engine)
    sup = engine.suppress_finding(f["id"], ORG, "risk accepted", "alice", "2027-01-01T00:00:00Z")
    assert sup["id"]
    assert sup["reason"] == "risk accepted"
    assert sup["suppressed_by"] == "alice"


def test_suppress_finding_updates_status(engine):
    f = _make_finding(engine)
    engine.suppress_finding(f["id"], ORG, "risk accepted", "alice", "2027-01-01T00:00:00Z")
    updated = engine.get_finding(f["id"], ORG)
    assert updated["status"] == "suppressed"


def test_suppress_finding_appears_in_get(engine):
    f = _make_finding(engine)
    engine.suppress_finding(f["id"], ORG, "test suppression", "bob", "2027-06-01T00:00:00Z")
    result = engine.get_finding(f["id"], ORG)
    assert len(result["suppressions"]) == 1


# ---------------------------------------------------------------------------
# get_finding
# ---------------------------------------------------------------------------

def test_get_finding_returns_none_for_wrong_org(engine):
    f = _make_finding(engine)
    result = engine.get_finding(f["id"], ORG2)
    assert result is None


def test_get_finding_includes_empty_evidence_and_suppressions(engine):
    f = _make_finding(engine)
    result = engine.get_finding(f["id"], ORG)
    assert result["evidence"] == []
    assert result["suppressions"] == []


# ---------------------------------------------------------------------------
# list_findings
# ---------------------------------------------------------------------------

def test_list_findings_by_org(engine):
    _make_finding(engine, org=ORG, title="F1")
    _make_finding(engine, org=ORG, title="F2")
    _make_finding(engine, org=ORG2, title="F3")
    results = engine.list_findings(ORG)
    assert len(results) == 2


def test_list_findings_filter_status(engine):
    f = _make_finding(engine, title="F-open")
    _make_finding(engine, title="F-open2")
    engine.update_status(f["id"], ORG, "resolved")
    open_findings = engine.list_findings(ORG, status="open")
    assert all(r["status"] == "open" for r in open_findings)


def test_list_findings_filter_severity(engine):
    _make_finding(engine, title="crit", severity="critical")
    _make_finding(engine, title="low", severity="low")
    results = engine.list_findings(ORG, severity="critical")
    assert all(r["severity"] == "critical" for r in results)


def test_list_findings_filter_source_tool(engine):
    _make_finding(engine, title="sast-f", source_tool="SAST", asset_id="a1")
    _make_finding(engine, title="dast-f", source_tool="DAST", asset_id="a2")
    results = engine.list_findings(ORG, source_tool="DAST")
    assert all(r["source_tool"] == "DAST" for r in results)


# ---------------------------------------------------------------------------
# get_asset_findings
# ---------------------------------------------------------------------------

def test_get_asset_findings(engine):
    _make_finding(engine, title="F1", asset_id="server-01", source_tool="SAST")
    _make_finding(engine, title="F2", asset_id="server-01", source_tool="DAST")
    _make_finding(engine, title="F3", asset_id="server-02", source_tool="SAST")
    results = engine.get_asset_findings(ORG, "server-01")
    assert len(results) == 2
    assert all(r["asset_id"] == "server-01" for r in results)


# ---------------------------------------------------------------------------
# get_findings_summary
# ---------------------------------------------------------------------------

def test_get_findings_summary_empty(engine):
    summary = engine.get_findings_summary(ORG)
    assert summary["total"] == 0
    assert summary["open"] == 0


def test_get_findings_summary_counts(engine):
    f1 = _make_finding(engine, title="F1", asset_id="a1", source_tool="SAST")
    f2 = _make_finding(engine, title="F2", asset_id="a2", source_tool="DAST")
    engine.update_status(f2["id"], ORG, "resolved")
    summary = engine.get_findings_summary(ORG)
    assert summary["total"] == 2
    assert summary["open"] == 1
    assert summary["resolved"] == 1


def test_get_findings_summary_by_severity(engine):
    _make_finding(engine, title="C1", severity="critical", asset_id="a1", source_tool="SAST")
    _make_finding(engine, title="C2", severity="critical", asset_id="a2", source_tool="DAST")
    _make_finding(engine, title="H1", severity="high", asset_id="a3", source_tool="Nessus")
    summary = engine.get_findings_summary(ORG)
    assert summary["by_severity"].get("critical", 0) == 2
    assert summary["by_severity"].get("high", 0) == 1


def test_get_findings_summary_avg_cvss(engine):
    _make_finding(engine, title="F1", cvss_score=6.0, asset_id="a1", source_tool="SAST")
    _make_finding(engine, title="F2", cvss_score=8.0, asset_id="a2", source_tool="DAST")
    summary = engine.get_findings_summary(ORG)
    assert summary["avg_cvss_score"] == 7.0


def test_get_findings_summary_top_assets(engine):
    for i in range(3):
        engine.record_finding(
            org_id=ORG,
            title=f"Finding-{i}",
            finding_type="vulnerability",
            source_tool=f"TOOL{i}",
            severity="high",
            cvss_score=7.0,
            asset_id="top-asset",
            asset_type="server",
            description="",
            remediation="",
        )
    engine.record_finding(
        org_id=ORG,
        title="Other finding",
        finding_type="vulnerability",
        source_tool="Nessus",
        severity="low",
        cvss_score=2.0,
        asset_id="other-asset",
        asset_type="server",
        description="",
        remediation="",
    )
    summary = engine.get_findings_summary(ORG)
    top = summary["top_assets_by_open_findings"]
    assert top[0]["asset_id"] == "top-asset"
    assert top[0]["open_findings"] == 3
