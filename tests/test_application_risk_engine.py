"""Tests for ApplicationRiskEngine — wave 24."""

import pytest
from core.application_risk_engine import ApplicationRiskEngine


@pytest.fixture
def engine(tmp_path):
    return ApplicationRiskEngine(db_path=str(tmp_path / "application_risk.db"))


# ---------------------------------------------------------------------------
# register_application
# ---------------------------------------------------------------------------

def test_register_application_minimal(engine):
    app = engine.register_application("org1", {"name": "MyApp"})
    assert app["name"] == "MyApp"
    assert app["app_type"] == "web"
    assert app["environment"] == "prod"
    assert app["risk_score"] == 50.0
    assert app["risk_level"] == "medium"
    assert app["status"] == "active"
    assert app["assessed_at"] is None
    assert "id" in app
    assert "created_at" in app


def test_register_application_all_types(engine):
    for idx, atype in enumerate(["web", "api", "mobile", "desktop", "microservice"]):
        app = engine.register_application("org1", {"name": f"App{idx}", "app_type": atype})
        assert app["app_type"] == atype


def test_register_application_all_environments(engine):
    for idx, env in enumerate(["prod", "staging", "dev", "test"]):
        app = engine.register_application("org1", {"name": f"App{idx}", "environment": env})
        assert app["environment"] == env


def test_register_application_missing_name_raises(engine):
    with pytest.raises(ValueError, match="name"):
        engine.register_application("org1", {"app_type": "web"})


def test_register_application_empty_name_raises(engine):
    with pytest.raises(ValueError, match="name"):
        engine.register_application("org1", {"name": "  "})


def test_register_application_invalid_app_type_raises(engine):
    with pytest.raises(ValueError, match="app_type"):
        engine.register_application("org1", {"name": "App", "app_type": "mainframe"})


def test_register_application_invalid_environment_raises(engine):
    with pytest.raises(ValueError, match="environment"):
        engine.register_application("org1", {"name": "App", "environment": "live"})


def test_register_application_stores_tech_stack_and_owner(engine):
    app = engine.register_application("org1", {
        "name": "API Gateway",
        "app_type": "api",
        "tech_stack": "Python/FastAPI",
        "owner_team": "platform",
        "environment": "prod",
    })
    assert app["tech_stack"] == "Python/FastAPI"
    assert app["owner_team"] == "platform"


# ---------------------------------------------------------------------------
# list_applications
# ---------------------------------------------------------------------------

def test_list_applications_empty(engine):
    assert engine.list_applications("org1") == []


def test_list_applications_filter_by_app_type(engine):
    engine.register_application("org1", {"name": "WebApp", "app_type": "web"})
    engine.register_application("org1", {"name": "APIApp", "app_type": "api"})
    apis = engine.list_applications("org1", app_type="api")
    assert len(apis) == 1
    assert apis[0]["app_type"] == "api"


def test_list_applications_filter_by_environment(engine):
    engine.register_application("org1", {"name": "Prod", "environment": "prod"})
    engine.register_application("org1", {"name": "Dev", "environment": "dev"})
    devs = engine.list_applications("org1", environment="dev")
    assert len(devs) == 1
    assert devs[0]["environment"] == "dev"


def test_list_applications_org_isolation(engine):
    engine.register_application("org1", {"name": "App"})
    assert engine.list_applications("org2") == []


def test_list_applications_multiple_filters(engine):
    engine.register_application("org1", {"name": "A1", "app_type": "web", "environment": "prod"})
    engine.register_application("org1", {"name": "A2", "app_type": "web", "environment": "dev"})
    engine.register_application("org1", {"name": "A3", "app_type": "api", "environment": "prod"})
    result = engine.list_applications("org1", app_type="web", environment="prod")
    assert len(result) == 1
    assert result[0]["name"] == "A1"


# ---------------------------------------------------------------------------
# get_application
# ---------------------------------------------------------------------------

def test_get_application_found(engine):
    created = engine.register_application("org1", {"name": "MyApp", "app_type": "mobile"})
    fetched = engine.get_application("org1", created["id"])
    assert fetched is not None
    assert fetched["id"] == created["id"]
    assert fetched["name"] == "MyApp"


def test_get_application_not_found_returns_none(engine):
    assert engine.get_application("org1", "nonexistent-id") is None


def test_get_application_org_isolation(engine):
    created = engine.register_application("org1", {"name": "App"})
    assert engine.get_application("org2", created["id"]) is None


# ---------------------------------------------------------------------------
# assess_risk
# ---------------------------------------------------------------------------

def test_assess_risk_base_score_no_controls(engine):
    app = engine.register_application("org1", {"name": "App"})
    result = engine.assess_risk("org1", app["id"], {})
    # base=50, dependency_scan defaults True (no penalty), no findings
    assert result["risk_score"] == 50.0
    assert result["risk_level"] == "medium"
    assert result["app_id"] == app["id"]
    assert "factors" in result


def test_assess_risk_all_controls_reduce_score(engine):
    app = engine.register_application("org1", {"name": "Secure"})
    result = engine.assess_risk("org1", app["id"], {
        "auth_controls": True,
        "input_validation": True,
        "encryption": True,
        "dependency_scan": True,
    })
    # 50 - 10 - 10 - 10 = 20
    assert result["risk_score"] == 20.0
    assert result["risk_level"] == "low"


def test_assess_risk_no_dependency_scan_adds_penalty(engine):
    app = engine.register_application("org1", {"name": "NoDeps"})
    result = engine.assess_risk("org1", app["id"], {"dependency_scan": False})
    # 50 + 10 = 60
    assert result["risk_score"] == 60.0
    assert result["risk_level"] == "high"


def test_assess_risk_sast_findings_capped_at_20(engine):
    app = engine.register_application("org1", {"name": "SastHeavy"})
    result = engine.assess_risk("org1", app["id"], {"sast_findings": 50})
    # 50 + min(100, 20) = 70
    assert result["risk_score"] == 70.0


def test_assess_risk_dast_findings_capped_at_20(engine):
    app = engine.register_application("org1", {"name": "DastHeavy"})
    result = engine.assess_risk("org1", app["id"], {"dast_findings": 15})
    # 50 + min(30, 20) = 70
    assert result["risk_score"] == 70.0


def test_assess_risk_internet_exposed_adds_15(engine):
    app = engine.register_application("org1", {"name": "Public"})
    result = engine.assess_risk("org1", app["id"], {"internet_exposed": True})
    # 50 + 15 = 65
    assert result["risk_score"] == 65.0
    assert result["risk_level"] == "high"


def test_assess_risk_score_clamped_at_100(engine):
    app = engine.register_application("org1", {"name": "Worst"})
    result = engine.assess_risk("org1", app["id"], {
        "dependency_scan": False,
        "sast_findings": 50,
        "dast_findings": 50,
        "internet_exposed": True,
    })
    assert result["risk_score"] == 100.0
    assert result["risk_level"] == "critical"


def test_assess_risk_score_clamped_at_0(engine):
    app = engine.register_application("org1", {"name": "Perfect"})
    # manually set base low: all controls on, no findings
    result = engine.assess_risk("org1", app["id"], {
        "auth_controls": True,
        "input_validation": True,
        "encryption": True,
        "dependency_scan": True,
        "sast_findings": 0,
        "dast_findings": 0,
    })
    assert result["risk_score"] == 20.0  # 50-30 = 20, not negative


def test_assess_risk_updates_db(engine):
    app = engine.register_application("org1", {"name": "App"})
    engine.assess_risk("org1", app["id"], {"auth_controls": True})
    fetched = engine.get_application("org1", app["id"])
    assert fetched["risk_score"] == 40.0
    assert fetched["assessed_at"] is not None


def test_assess_risk_risk_level_boundaries(engine):
    app = engine.register_application("org1", {"name": "BoundaryApp"})
    # score=25 → low (<=25)
    result = engine.assess_risk("org1", app["id"], {
        "auth_controls": True, "input_validation": True, "encryption": True,
        "sast_findings": 2,
    })
    # 50 - 30 + 4 = 24 → low
    assert result["risk_level"] == "low"


# ---------------------------------------------------------------------------
# add_finding
# ---------------------------------------------------------------------------

def test_add_finding_basic(engine):
    app = engine.register_application("org1", {"name": "App"})
    finding = engine.add_finding("org1", app["id"], {
        "title": "SQL Injection",
        "severity": "critical",
        "finding_type": "sast",
        "cve_id": "CVE-2024-0001",
    })
    assert finding["title"] == "SQL Injection"
    assert finding["severity"] == "critical"
    assert finding["finding_type"] == "sast"
    assert finding["status"] == "open"
    assert finding["resolution"] == ""
    assert finding["resolved_at"] is None
    assert "id" in finding


def test_add_finding_all_severities(engine):
    app = engine.register_application("org1", {"name": "App"})
    for sev in ["critical", "high", "medium", "low"]:
        f = engine.add_finding("org1", app["id"], {"severity": sev, "finding_type": "sast"})
        assert f["severity"] == sev


def test_add_finding_all_types(engine):
    app = engine.register_application("org1", {"name": "App"})
    for ftype in ["sast", "dast", "sca", "manual"]:
        f = engine.add_finding("org1", app["id"], {"severity": "low", "finding_type": ftype})
        assert f["finding_type"] == ftype


def test_add_finding_invalid_severity_raises(engine):
    app = engine.register_application("org1", {"name": "App"})
    with pytest.raises(ValueError, match="severity"):
        engine.add_finding("org1", app["id"], {"severity": "extreme", "finding_type": "sast"})


def test_add_finding_invalid_finding_type_raises(engine):
    app = engine.register_application("org1", {"name": "App"})
    with pytest.raises(ValueError, match="finding_type"):
        engine.add_finding("org1", app["id"], {"severity": "high", "finding_type": "fuzzing"})


# ---------------------------------------------------------------------------
# list_findings
# ---------------------------------------------------------------------------

def test_list_findings_empty(engine):
    assert engine.list_findings("org1") == []


def test_list_findings_filter_by_app_id(engine):
    app1 = engine.register_application("org1", {"name": "App1"})
    app2 = engine.register_application("org1", {"name": "App2"})
    engine.add_finding("org1", app1["id"], {"severity": "high", "finding_type": "sast"})
    engine.add_finding("org1", app2["id"], {"severity": "low", "finding_type": "dast"})
    findings = engine.list_findings("org1", app_id=app1["id"])
    assert len(findings) == 1
    assert findings[0]["app_id"] == app1["id"]


def test_list_findings_filter_by_severity(engine):
    app = engine.register_application("org1", {"name": "App"})
    engine.add_finding("org1", app["id"], {"severity": "critical", "finding_type": "sast"})
    engine.add_finding("org1", app["id"], {"severity": "low", "finding_type": "sast"})
    criticals = engine.list_findings("org1", severity="critical")
    assert len(criticals) == 1
    assert criticals[0]["severity"] == "critical"


def test_list_findings_filter_by_status(engine):
    app = engine.register_application("org1", {"name": "App"})
    f = engine.add_finding("org1", app["id"], {"severity": "high", "finding_type": "dast"})
    engine.resolve_finding("org1", f["id"], "Patched")
    open_findings = engine.list_findings("org1", status="open")
    assert len(open_findings) == 0
    resolved = engine.list_findings("org1", status="resolved")
    assert len(resolved) == 1


def test_list_findings_org_isolation(engine):
    app = engine.register_application("org1", {"name": "App"})
    engine.add_finding("org1", app["id"], {"severity": "high", "finding_type": "sast"})
    assert engine.list_findings("org2") == []


# ---------------------------------------------------------------------------
# resolve_finding
# ---------------------------------------------------------------------------

def test_resolve_finding_sets_status(engine):
    app = engine.register_application("org1", {"name": "App"})
    f = engine.add_finding("org1", app["id"], {"severity": "high", "finding_type": "sast"})
    result = engine.resolve_finding("org1", f["id"], "Applied patch CVE-2024-0001")
    assert result["status"] == "resolved"
    assert result["resolution"] == "Applied patch CVE-2024-0001"
    assert result["resolved_at"] is not None


def test_resolve_finding_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.resolve_finding("org1", "ghost-finding-id", "N/A")


def test_resolve_finding_org_isolation(engine):
    app = engine.register_application("org1", {"name": "App"})
    f = engine.add_finding("org1", app["id"], {"severity": "low", "finding_type": "manual"})
    with pytest.raises(KeyError):
        engine.resolve_finding("org2", f["id"], "Fixed")


# ---------------------------------------------------------------------------
# get_app_risk_stats
# ---------------------------------------------------------------------------

def test_get_app_risk_stats_empty(engine):
    stats = engine.get_app_risk_stats("org1")
    assert stats["total_apps"] == 0
    assert stats["critical_apps"] == 0
    assert stats["total_findings"] == 0
    assert stats["open_findings"] == 0
    assert stats["by_severity"] == {}
    assert stats["by_app_type"] == {}


def test_get_app_risk_stats_counts(engine):
    app1 = engine.register_application("org1", {"name": "WebApp", "app_type": "web"})
    app2 = engine.register_application("org1", {"name": "APIApp", "app_type": "api"})
    # Make app1 critical
    engine.assess_risk("org1", app1["id"], {
        "dependency_scan": False, "sast_findings": 50, "dast_findings": 50,
        "internet_exposed": True,
    })
    f1 = engine.add_finding("org1", app1["id"], {"severity": "critical", "finding_type": "sast"})
    engine.add_finding("org1", app1["id"], {"severity": "high", "finding_type": "dast"})
    engine.add_finding("org1", app2["id"], {"severity": "medium", "finding_type": "sca"})
    engine.resolve_finding("org1", f1["id"], "Fixed")

    stats = engine.get_app_risk_stats("org1")
    assert stats["total_apps"] == 2
    assert stats["critical_apps"] == 1
    assert stats["total_findings"] == 3
    assert stats["open_findings"] == 2
    assert stats["by_severity"].get("critical", 0) == 1
    assert stats["by_severity"].get("high", 0) == 1
    assert stats["by_severity"].get("medium", 0) == 1
    assert stats["by_app_type"].get("web", 0) == 1
    assert stats["by_app_type"].get("api", 0) == 1


def test_get_app_risk_stats_org_isolation(engine):
    engine.register_application("org1", {"name": "App"})
    stats = engine.get_app_risk_stats("org2")
    assert stats["total_apps"] == 0
