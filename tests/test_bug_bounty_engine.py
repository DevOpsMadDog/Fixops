"""Tests for BugBountyEngine — 27 tests covering all methods + org isolation."""

from __future__ import annotations

import pytest
from core.bug_bounty_engine import BugBountyEngine


@pytest.fixture
def engine(tmp_path):
    return BugBountyEngine(org_id="default", db_dir=str(tmp_path))


@pytest.fixture
def org():
    return "org-alpha"


@pytest.fixture
def org2():
    return "org-beta"


def _program(engine, org, name="Main VDP", platform="private"):
    return engine.create_program(org, {"program_name": name, "platform": platform})


def _report(engine, org, program_id, title="SQL Injection in /login"):
    return engine.submit_report(org, program_id, {
        "title": title,
        "vulnerability_class": "sqli",
        "severity": "high",
        "researcher_handle": "h4x0r",
    })


# ---------------------------------------------------------------------------
# create_program
# ---------------------------------------------------------------------------

def test_create_program_returns_record(engine, org):
    prog = _program(engine, org)
    assert prog["program_name"] == "Main VDP"
    assert prog["org_id"] == org
    assert prog["platform"] == "private"
    assert prog["status"] == "active"
    assert "id" in prog


def test_create_program_missing_name_raises(engine, org):
    with pytest.raises(ValueError, match="program_name"):
        engine.create_program(org, {"program_name": ""})


def test_create_program_invalid_platform_raises(engine, org):
    with pytest.raises(ValueError, match="platform"):
        engine.create_program(org, {"program_name": "VDP", "platform": "unknown_platform"})


def test_create_program_all_platforms(engine, org):
    for platform in ("hackerone", "bugcrowd", "intigriti", "yeswehack", "private"):
        p = engine.create_program(org, {"program_name": f"VDP-{platform}", "platform": platform})
        assert p["platform"] == platform


def test_create_program_with_scope_lists(engine, org):
    prog = engine.create_program(org, {
        "program_name": "Scoped VDP",
        "in_scope_assets": ["*.example.com", "api.example.com"],
        "out_of_scope_assets": ["staging.example.com"],
    })
    assert "*.example.com" in prog["in_scope_assets"]
    assert "staging.example.com" in prog["out_of_scope_assets"]


# ---------------------------------------------------------------------------
# list_programs
# ---------------------------------------------------------------------------

def test_list_programs_empty(engine, org):
    assert engine.list_programs(org) == []


def test_list_programs_org_isolation(engine, org, org2):
    _program(engine, org, "Alpha VDP")
    _program(engine, org2, "Beta VDP")
    result = engine.list_programs(org)
    assert len(result) == 1
    assert result[0]["program_name"] == "Alpha VDP"


def test_list_programs_filter_by_status(engine, org):
    engine.create_program(org, {"program_name": "Active VDP", "status": "active"})
    engine.create_program(org, {"program_name": "Paused VDP", "status": "paused"})
    active = engine.list_programs(org, status="active")
    assert len(active) == 1
    assert active[0]["program_name"] == "Active VDP"


# ---------------------------------------------------------------------------
# get_program
# ---------------------------------------------------------------------------

def test_get_program_returns_record_with_stats(engine, org):
    prog = _program(engine, org)
    result = engine.get_program(org, prog["id"])
    assert result is not None
    assert result["id"] == prog["id"]
    assert "reports_by_status" in result
    assert "total_reports" in result


def test_get_program_not_found_returns_none(engine, org):
    assert engine.get_program(org, "nonexistent-id") is None


def test_get_program_org_isolation(engine, org, org2):
    prog = _program(engine, org)
    assert engine.get_program(org2, prog["id"]) is None


# ---------------------------------------------------------------------------
# submit_report
# ---------------------------------------------------------------------------

def test_submit_report_returns_record(engine, org):
    prog = _program(engine, org)
    report = _report(engine, org, prog["id"])
    assert report["title"] == "SQL Injection in /login"
    assert report["status"] == "new"
    assert report["program_id"] == prog["id"]
    assert report["severity"] == "high"
    assert report["payout_usd"] == 0.0


def test_submit_report_missing_title_raises(engine, org):
    prog = _program(engine, org)
    with pytest.raises(ValueError, match="title"):
        engine.submit_report(org, prog["id"], {"title": ""})


def test_submit_report_invalid_vuln_class_raises(engine, org):
    prog = _program(engine, org)
    with pytest.raises(ValueError, match="vulnerability_class"):
        engine.submit_report(org, prog["id"], {"title": "Bug", "vulnerability_class": "invalid_class"})


def test_submit_report_invalid_severity_raises(engine, org):
    prog = _program(engine, org)
    with pytest.raises(ValueError, match="severity"):
        engine.submit_report(org, prog["id"], {"title": "Bug", "severity": "extreme"})


# ---------------------------------------------------------------------------
# list_reports
# ---------------------------------------------------------------------------

def test_list_reports_empty(engine, org):
    prog = _program(engine, org)
    assert engine.list_reports(org, program_id=prog["id"]) == []


def test_list_reports_org_isolation(engine, org, org2):
    prog1 = _program(engine, org, "VDP-Alpha")
    prog2 = _program(engine, org2, "VDP-Beta")
    _report(engine, org, prog1["id"], "Bug in Alpha")
    _report(engine, org2, prog2["id"], "Bug in Beta")
    result = engine.list_reports(org)
    assert len(result) == 1
    assert result[0]["title"] == "Bug in Alpha"


def test_list_reports_filter_by_severity(engine, org):
    prog = _program(engine, org)
    engine.submit_report(org, prog["id"], {"title": "Critical Bug", "vulnerability_class": "rce", "severity": "critical"})
    engine.submit_report(org, prog["id"], {"title": "Info Bug", "vulnerability_class": "info_disclosure", "severity": "info"})
    crits = engine.list_reports(org, severity="critical")
    assert len(crits) == 1
    assert crits[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# get_report
# ---------------------------------------------------------------------------

def test_get_report_returns_record(engine, org):
    prog = _program(engine, org)
    report = _report(engine, org, prog["id"])
    result = engine.get_report(org, report["id"])
    assert result is not None
    assert result["id"] == report["id"]


def test_get_report_not_found_returns_none(engine, org):
    assert engine.get_report(org, "nonexistent-id") is None


# ---------------------------------------------------------------------------
# update_report_status
# ---------------------------------------------------------------------------

def test_update_report_status_triaged(engine, org):
    prog = _program(engine, org)
    report = _report(engine, org, prog["id"])
    updated = engine.update_report_status(org, report["id"], "triaged")
    assert updated["status"] == "triaged"
    assert updated["triaged_at"] is not None


def test_update_report_status_resolved(engine, org):
    prog = _program(engine, org)
    report = _report(engine, org, prog["id"])
    updated = engine.update_report_status(org, report["id"], "resolved")
    assert updated["status"] == "resolved"
    assert updated["resolved_at"] is not None


def test_update_report_status_rewarded_with_payout(engine, org):
    prog = _program(engine, org)
    report = _report(engine, org, prog["id"])
    updated = engine.update_report_status(org, report["id"], "rewarded", payout_usd=500.0)
    assert updated["status"] == "rewarded"
    assert updated["payout_usd"] == 500.0
    assert updated["bounty_decision"] == "approved"


def test_update_report_status_invalid_raises(engine, org):
    prog = _program(engine, org)
    report = _report(engine, org, prog["id"])
    with pytest.raises(ValueError, match="status"):
        engine.update_report_status(org, report["id"], "invalid_status")


def test_update_report_status_not_found_raises(engine, org):
    with pytest.raises(KeyError):
        engine.update_report_status(org, "nonexistent", "triaged")


# ---------------------------------------------------------------------------
# researchers
# ---------------------------------------------------------------------------

def test_add_researcher_returns_record(engine, org):
    researcher = engine.add_researcher(org, {
        "handle": "h4x0r",
        "reputation_score": 95.0,
        "skills": ["xss", "sqli"],
        "country": "US",
    })
    assert researcher["handle"] == "h4x0r"
    assert researcher["reputation_score"] == 95.0
    assert "xss" in researcher["skills"]
    assert researcher["hall_of_fame"] is False


def test_add_researcher_missing_handle_raises(engine, org):
    with pytest.raises(ValueError, match="handle"):
        engine.add_researcher(org, {"handle": ""})


def test_add_researcher_hall_of_fame(engine, org):
    researcher = engine.add_researcher(org, {"handle": "elite", "hall_of_fame": True})
    assert researcher["hall_of_fame"] is True


def test_list_researchers_filter_hof(engine, org):
    engine.add_researcher(org, {"handle": "elite", "hall_of_fame": True})
    engine.add_researcher(org, {"handle": "newbie", "hall_of_fame": False})
    hof = engine.list_researchers(org, hall_of_fame=True)
    assert len(hof) == 1
    assert hof[0]["handle"] == "elite"


# ---------------------------------------------------------------------------
# get_stats
# ---------------------------------------------------------------------------

def test_get_stats_empty(engine, org):
    stats = engine.get_stats(org)
    assert stats["program_count"] == 0
    assert stats["total_reports"] == 0
    assert stats["total_paid_usd"] == 0.0
    assert stats["avg_resolution_days"] == 0.0
    assert stats["reports_by_severity"] == {}
    assert stats["top_researchers"] == []


def test_get_stats_counts_programs_and_reports(engine, org):
    prog = _program(engine, org)
    _report(engine, org, prog["id"], "Bug 1")
    _report(engine, org, prog["id"], "Bug 2")
    stats = engine.get_stats(org)
    assert stats["program_count"] == 1
    assert stats["total_reports"] == 2


def test_get_stats_org_isolation(engine, org, org2):
    _program(engine, org, "Alpha VDP")
    _program(engine, org2, "Beta VDP")
    _program(engine, org2, "Beta VDP 2")
    assert engine.get_stats(org)["program_count"] == 1
    assert engine.get_stats(org2)["program_count"] == 2
