"""Tests for ApplicationSecurityEngine — 27 tests covering all methods + org isolation."""

from __future__ import annotations

import pytest
from core.application_security_engine import ApplicationSecurityEngine


@pytest.fixture
def engine(tmp_path):
    return ApplicationSecurityEngine(org_id="default", db_dir=str(tmp_path))


@pytest.fixture
def org():
    return "org-alpha"


@pytest.fixture
def org2():
    return "org-beta"


def _app(engine, org, name="MyApp", app_type="web"):
    return engine.register_app(org, {"name": name, "app_type": app_type})


# ---------------------------------------------------------------------------
# register_app
# ---------------------------------------------------------------------------

def test_register_app_returns_record(engine, org):
    app = _app(engine, org)
    assert app["name"] == "MyApp"
    assert app["org_id"] == org
    assert app["app_type"] == "web"
    assert app["status"] == "active"
    assert "id" in app


def test_register_app_missing_name_raises(engine, org):
    with pytest.raises(ValueError, match="name"):
        engine.register_app(org, {"name": ""})


def test_register_app_invalid_app_type_raises(engine, org):
    with pytest.raises(ValueError, match="app_type"):
        engine.register_app(org, {"name": "App", "app_type": "invalid"})


def test_register_app_invalid_criticality_raises(engine, org):
    with pytest.raises(ValueError, match="criticality"):
        engine.register_app(org, {"name": "App", "criticality": "extreme"})


def test_register_app_all_types(engine, org):
    for t in ("web", "mobile", "api", "desktop", "microservice"):
        a = engine.register_app(org, {"name": f"App-{t}", "app_type": t})
        assert a["app_type"] == t


# ---------------------------------------------------------------------------
# list_apps
# ---------------------------------------------------------------------------

def test_list_apps_empty(engine, org):
    assert engine.list_apps(org) == []


def test_list_apps_org_isolation(engine, org, org2):
    _app(engine, org, "AppA")
    _app(engine, org2, "AppB")
    result = engine.list_apps(org)
    assert len(result) == 1
    assert result[0]["name"] == "AppA"


def test_list_apps_filter_by_type(engine, org):
    _app(engine, org, "WebApp", "web")
    _app(engine, org, "APIApp", "api")
    webs = engine.list_apps(org, app_type="web")
    assert len(webs) == 1
    assert webs[0]["name"] == "WebApp"


def test_list_apps_filter_by_criticality(engine, org):
    engine.register_app(org, {"name": "CritApp", "criticality": "critical"})
    engine.register_app(org, {"name": "LowApp", "criticality": "low"})
    crits = engine.list_apps(org, criticality="critical")
    assert len(crits) == 1
    assert crits[0]["name"] == "CritApp"


# ---------------------------------------------------------------------------
# get_app
# ---------------------------------------------------------------------------

def test_get_app_returns_record_with_summary(engine, org):
    app = _app(engine, org)
    result = engine.get_app(org, app["id"])
    assert result is not None
    assert result["id"] == app["id"]
    assert "open_sast_by_severity" in result
    assert "open_dast_by_severity" in result


def test_get_app_not_found_returns_none(engine, org):
    assert engine.get_app(org, "nonexistent-id") is None


def test_get_app_org_isolation(engine, org, org2):
    app = _app(engine, org)
    assert engine.get_app(org2, app["id"]) is None


# ---------------------------------------------------------------------------
# SAST findings
# ---------------------------------------------------------------------------

def test_add_sast_finding_returns_record(engine, org):
    app = _app(engine, org)
    finding = engine.add_sast_finding(org, app["id"], {
        "title": "SQL Injection in login",
        "tool": "bandit",
        "severity": "high",
        "category": "injection",
    })
    assert finding["title"] == "SQL Injection in login"
    assert finding["status"] == "open"
    assert finding["app_id"] == app["id"]


def test_add_sast_finding_missing_title_raises(engine, org):
    app = _app(engine, org)
    with pytest.raises(ValueError, match="title"):
        engine.add_sast_finding(org, app["id"], {"title": ""})


def test_add_sast_finding_invalid_severity_raises(engine, org):
    app = _app(engine, org)
    with pytest.raises(ValueError, match="severity"):
        engine.add_sast_finding(org, app["id"], {"title": "X", "severity": "extreme"})


def test_list_sast_findings_filter_severity(engine, org):
    app = _app(engine, org)
    engine.add_sast_finding(org, app["id"], {"title": "High vuln", "severity": "high", "category": "injection"})
    engine.add_sast_finding(org, app["id"], {"title": "Low vuln", "severity": "low", "category": "logging"})
    highs = engine.list_sast_findings(org, app_id=app["id"], severity="high")
    assert len(highs) == 1
    assert highs[0]["severity"] == "high"


def test_update_sast_finding_status(engine, org):
    app = _app(engine, org)
    f = engine.add_sast_finding(org, app["id"], {"title": "XSS", "severity": "medium", "category": "xss"})
    updated = engine.update_finding_status(org, f["id"], "sast", "fixed")
    assert updated["status"] == "fixed"


def test_update_finding_status_invalid_raises(engine, org):
    app = _app(engine, org)
    f = engine.add_sast_finding(org, app["id"], {"title": "Bug", "severity": "low", "category": "logging"})
    with pytest.raises(ValueError, match="status"):
        engine.update_finding_status(org, f["id"], "sast", "invalid_status")


def test_update_finding_not_found_raises(engine, org):
    with pytest.raises(KeyError):
        engine.update_finding_status(org, "nonexistent", "sast", "fixed")


# ---------------------------------------------------------------------------
# DAST findings
# ---------------------------------------------------------------------------

def test_add_dast_finding_returns_record(engine, org):
    app = _app(engine, org)
    finding = engine.add_dast_finding(org, app["id"], {
        "title": "Reflected XSS",
        "tool": "zap",
        "severity": "high",
        "category": "xss",
        "endpoint": "/search",
    })
    assert finding["title"] == "Reflected XSS"
    assert finding["status"] == "open"
    assert finding["tool"] == "zap"


def test_add_dast_finding_invalid_tool_raises(engine, org):
    app = _app(engine, org)
    with pytest.raises(ValueError, match="tool"):
        engine.add_dast_finding(org, app["id"], {"title": "X", "tool": "unknown_tool"})


def test_list_dast_findings_filter_status(engine, org):
    app = _app(engine, org)
    f = engine.add_dast_finding(org, app["id"], {"title": "SSRF", "severity": "critical", "category": "ssrf"})
    engine.update_finding_status(org, f["id"], "dast", "false_positive")
    open_findings = engine.list_dast_findings(org, app_id=app["id"], status="open")
    fp_findings = engine.list_dast_findings(org, app_id=app["id"], status="false_positive")
    assert len(open_findings) == 0
    assert len(fp_findings) == 1


# ---------------------------------------------------------------------------
# scan_runs
# ---------------------------------------------------------------------------

def test_log_scan_run_returns_record(engine, org):
    app = _app(engine, org)
    run = engine.log_scan_run(org, app["id"], {
        "scan_type": "sast",
        "tool": "bandit",
        "status": "completed",
        "findings_count": 5,
        "critical_count": 1,
        "high_count": 2,
    })
    assert run["scan_type"] == "sast"
    assert run["status"] == "completed"
    assert run["findings_count"] == 5


def test_log_scan_run_invalid_type_raises(engine, org):
    app = _app(engine, org)
    with pytest.raises(ValueError, match="scan_type"):
        engine.log_scan_run(org, app["id"], {"scan_type": "fuzz"})


# ---------------------------------------------------------------------------
# get_stats
# ---------------------------------------------------------------------------

def test_get_stats_empty(engine, org):
    stats = engine.get_stats(org)
    assert stats["app_count"] == 0
    assert stats["avg_security_score"] == 0.0
    assert stats["open_sast_by_severity"] == {}
    assert stats["open_dast_by_severity"] == {}
    assert stats["scans_this_week"] == 0
    assert stats["top_vulnerable_apps"] == []


def test_get_stats_counts_active_apps(engine, org):
    _app(engine, org, "App1")
    _app(engine, org, "App2")
    stats = engine.get_stats(org)
    assert stats["app_count"] == 2


def test_get_stats_sast_severity_breakdown(engine, org):
    app = _app(engine, org)
    engine.add_sast_finding(org, app["id"], {"title": "Critical", "severity": "critical", "category": "injection"})
    engine.add_sast_finding(org, app["id"], {"title": "High", "severity": "high", "category": "xss"})
    stats = engine.get_stats(org)
    assert stats["open_sast_by_severity"].get("critical", 0) == 1
    assert stats["open_sast_by_severity"].get("high", 0) == 1


def test_get_stats_org_isolation(engine, org, org2):
    _app(engine, org, "App-Alpha")
    _app(engine, org2, "App-Beta")
    stats_alpha = engine.get_stats(org)
    stats_beta = engine.get_stats(org2)
    assert stats_alpha["app_count"] == 1
    assert stats_beta["app_count"] == 1
