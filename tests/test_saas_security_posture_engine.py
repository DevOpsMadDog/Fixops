"""Tests for SaasSecurityPostureEngine — 35+ tests covering all major paths."""

from __future__ import annotations

import pytest


@pytest.fixture
def engine(tmp_path):
    from core.saas_security_posture_engine import SaasSecurityPostureEngine
    return SaasSecurityPostureEngine(db_path=str(tmp_path / "sspm.db"))


ORG = "test-org-sspm"
ORG2 = "other-org-sspm"


# ---------------------------------------------------------------------------
# App registration
# ---------------------------------------------------------------------------

def test_register_app_basic(engine):
    app = engine.register_app(ORG, {
        "app_name": "Salesforce",
        "app_category": "crm",
    })
    assert app["id"]
    assert app["app_name"] == "Salesforce"
    assert app["app_category"] == "crm"
    assert app["org_id"] == ORG
    assert app["risk_level"] == "medium"
    assert app["compliance_status"] == "unknown"
    assert app["status"] == "active"
    assert app["last_assessed"] is None
    assert app["endpoint_count"] if "endpoint_count" in app else True  # optional field


def test_register_app_all_categories(engine):
    cats = ("productivity", "crm", "hrm", "finance", "security", "devops", "communication", "storage", "analytics")
    for cat in cats:
        app = engine.register_app(ORG, {"app_name": f"App-{cat}", "app_category": cat})
        assert app["app_category"] == cat


def test_register_app_missing_name(engine):
    with pytest.raises(ValueError, match="app_name"):
        engine.register_app(ORG, {"app_category": "crm"})


def test_register_app_empty_name(engine):
    with pytest.raises(ValueError, match="app_name"):
        engine.register_app(ORG, {"app_name": "  ", "app_category": "crm"})


def test_register_app_invalid_category(engine):
    with pytest.raises(ValueError):
        engine.register_app(ORG, {"app_name": "X", "app_category": "unknown_cat"})


def test_register_app_with_all_fields(engine):
    app = engine.register_app(ORG, {
        "app_name": "GitHub",
        "app_category": "devops",
        "vendor": "Microsoft",
        "user_count": 250,
        "data_sensitivity": "confidential",
        "oauth_scopes": "repo,read:org",
    })
    assert app["vendor"] == "Microsoft"
    assert app["user_count"] == 250
    assert app["data_sensitivity"] == "confidential"
    assert app["oauth_scopes"] == "repo,read:org"


def test_register_app_returns_uuid(engine):
    app = engine.register_app(ORG, {"app_name": "Slack", "app_category": "communication"})
    assert len(app["id"]) == 36  # UUID format


# ---------------------------------------------------------------------------
# List and get apps
# ---------------------------------------------------------------------------

def test_list_apps_empty(engine):
    assert engine.list_apps(ORG) == []


def test_list_apps_multiple(engine):
    engine.register_app(ORG, {"app_name": "A", "app_category": "crm"})
    engine.register_app(ORG, {"app_name": "B", "app_category": "analytics"})
    assert len(engine.list_apps(ORG)) == 2


def test_list_apps_filter_by_category(engine):
    engine.register_app(ORG, {"app_name": "CRM App", "app_category": "crm"})
    engine.register_app(ORG, {"app_name": "Analytics App", "app_category": "analytics"})
    crm = engine.list_apps(ORG, app_category="crm")
    assert len(crm) == 1
    assert crm[0]["app_category"] == "crm"


def test_list_apps_filter_by_risk_level(engine):
    engine.register_app(ORG, {"app_name": "A", "app_category": "crm"})
    # Default risk_level is medium; filter on high should return empty
    highs = engine.list_apps(ORG, risk_level="high")
    assert len(highs) == 0
    mediums = engine.list_apps(ORG, risk_level="medium")
    assert len(mediums) == 1


def test_list_apps_org_isolation(engine):
    engine.register_app(ORG, {"app_name": "A", "app_category": "crm"})
    assert engine.list_apps(ORG2) == []


def test_get_app_found(engine):
    app = engine.register_app(ORG, {"app_name": "Zoom", "app_category": "communication"})
    result = engine.get_app(ORG, app["id"])
    assert result is not None
    assert result["id"] == app["id"]
    assert result["app_name"] == "Zoom"


def test_get_app_not_found(engine):
    assert engine.get_app(ORG, "nonexistent-id") is None


def test_get_app_wrong_org(engine):
    app = engine.register_app(ORG, {"app_name": "Secret", "app_category": "finance"})
    assert engine.get_app(ORG2, app["id"]) is None


# ---------------------------------------------------------------------------
# Assessments — score-driven risk_level update
# ---------------------------------------------------------------------------

def test_assess_app_basic(engine):
    app = engine.register_app(ORG, {"app_name": "Jira", "app_category": "devops"})
    assessment = engine.assess_app(ORG, app["id"], {
        "score": 80.0,
        "findings_count": 2,
        "assessor": "Alice",
        "notes": "Quarterly review",
    })
    assert assessment["id"]
    assert assessment["app_id"] == app["id"]
    assert assessment["score"] == 80.0
    assert assessment["assessor"] == "Alice"
    assert assessment["risk_level"] == "low"  # score > 75


def test_assess_app_updates_last_assessed(engine):
    app = engine.register_app(ORG, {"app_name": "A", "app_category": "crm"})
    assert app["last_assessed"] is None
    engine.assess_app(ORG, app["id"], {"score": 70.0})
    updated = engine.get_app(ORG, app["id"])
    assert updated["last_assessed"] is not None


def test_assess_app_risk_level_critical(engine):
    """score <= 25 → critical."""
    app = engine.register_app(ORG, {"app_name": "A", "app_category": "crm"})
    engine.assess_app(ORG, app["id"], {"score": 20.0})
    updated = engine.get_app(ORG, app["id"])
    assert updated["risk_level"] == "critical"


def test_assess_app_risk_level_high(engine):
    """26 <= score <= 50 → high."""
    app = engine.register_app(ORG, {"app_name": "A", "app_category": "hrm"})
    engine.assess_app(ORG, app["id"], {"score": 40.0})
    updated = engine.get_app(ORG, app["id"])
    assert updated["risk_level"] == "high"


def test_assess_app_risk_level_medium(engine):
    """51 <= score <= 75 → medium."""
    app = engine.register_app(ORG, {"app_name": "A", "app_category": "analytics"})
    engine.assess_app(ORG, app["id"], {"score": 60.0})
    updated = engine.get_app(ORG, app["id"])
    assert updated["risk_level"] == "medium"


def test_assess_app_risk_level_low(engine):
    """score > 75 → low."""
    app = engine.register_app(ORG, {"app_name": "A", "app_category": "storage"})
    engine.assess_app(ORG, app["id"], {"score": 90.0})
    updated = engine.get_app(ORG, app["id"])
    assert updated["risk_level"] == "low"


def test_assess_app_boundary_score_25(engine):
    """Exact boundary: score=25 → critical."""
    app = engine.register_app(ORG, {"app_name": "B", "app_category": "crm"})
    engine.assess_app(ORG, app["id"], {"score": 25.0})
    updated = engine.get_app(ORG, app["id"])
    assert updated["risk_level"] == "critical"


def test_assess_app_boundary_score_50(engine):
    """Exact boundary: score=50 → high."""
    app = engine.register_app(ORG, {"app_name": "C", "app_category": "finance"})
    engine.assess_app(ORG, app["id"], {"score": 50.0})
    updated = engine.get_app(ORG, app["id"])
    assert updated["risk_level"] == "high"


def test_assess_app_boundary_score_75(engine):
    """Exact boundary: score=75 → medium."""
    app = engine.register_app(ORG, {"app_name": "D", "app_category": "security"})
    engine.assess_app(ORG, app["id"], {"score": 75.0})
    updated = engine.get_app(ORG, app["id"])
    assert updated["risk_level"] == "medium"


def test_list_assessments_by_app(engine):
    a1 = engine.register_app(ORG, {"app_name": "A1", "app_category": "crm"})
    a2 = engine.register_app(ORG, {"app_name": "A2", "app_category": "analytics"})
    engine.assess_app(ORG, a1["id"], {"score": 70.0})
    engine.assess_app(ORG, a2["id"], {"score": 80.0})
    a1_assessments = engine.list_assessments(ORG, app_id=a1["id"])
    assert len(a1_assessments) == 1
    assert a1_assessments[0]["app_id"] == a1["id"]


def test_list_assessments_all(engine):
    a1 = engine.register_app(ORG, {"app_name": "A1", "app_category": "crm"})
    a2 = engine.register_app(ORG, {"app_name": "A2", "app_category": "storage"})
    engine.assess_app(ORG, a1["id"], {"score": 60.0})
    engine.assess_app(ORG, a2["id"], {"score": 80.0})
    all_assessments = engine.list_assessments(ORG)
    assert len(all_assessments) == 2


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def test_record_finding_basic(engine):
    app = engine.register_app(ORG, {"app_name": "Dropbox", "app_category": "storage"})
    finding = engine.record_finding(ORG, app["id"], {
        "finding_type": "excessive_permissions",
        "severity": "high",
        "title": "OAuth over-scoped",
        "description": "App has write access to all files",
    })
    assert finding["id"]
    assert finding["app_id"] == app["id"]
    assert finding["severity"] == "high"
    assert finding["status"] == "open"
    assert finding["detected_at"] is not None
    assert finding["resolved_at"] is None


def test_record_finding_invalid_severity(engine):
    app = engine.register_app(ORG, {"app_name": "X", "app_category": "crm"})
    with pytest.raises(ValueError, match="severity"):
        engine.record_finding(ORG, app["id"], {"severity": "extreme"})


def test_record_finding_all_severities(engine):
    app = engine.register_app(ORG, {"app_name": "Multi", "app_category": "devops"})
    for sev in ("critical", "high", "medium", "low"):
        f = engine.record_finding(ORG, app["id"], {"severity": sev, "title": f"Finding-{sev}"})
        assert f["severity"] == sev


def test_list_findings_filter_by_app(engine):
    a1 = engine.register_app(ORG, {"app_name": "A1", "app_category": "crm"})
    a2 = engine.register_app(ORG, {"app_name": "A2", "app_category": "analytics"})
    engine.record_finding(ORG, a1["id"], {"severity": "high", "title": "F1"})
    engine.record_finding(ORG, a2["id"], {"severity": "low", "title": "F2"})
    a1_findings = engine.list_findings(ORG, app_id=a1["id"])
    assert len(a1_findings) == 1
    assert a1_findings[0]["app_id"] == a1["id"]


def test_list_findings_filter_by_severity(engine):
    app = engine.register_app(ORG, {"app_name": "App", "app_category": "finance"})
    engine.record_finding(ORG, app["id"], {"severity": "critical", "title": "Crit"})
    engine.record_finding(ORG, app["id"], {"severity": "low", "title": "Low"})
    crits = engine.list_findings(ORG, severity="critical")
    assert len(crits) == 1
    assert crits[0]["severity"] == "critical"


def test_list_findings_filter_by_status(engine):
    app = engine.register_app(ORG, {"app_name": "App", "app_category": "hrm"})
    engine.record_finding(ORG, app["id"], {"severity": "medium", "title": "Open F"})
    open_findings = engine.list_findings(ORG, status="open")
    assert len(open_findings) == 1
    resolved = engine.list_findings(ORG, status="resolved")
    assert len(resolved) == 0


def test_list_findings_org_isolation(engine):
    app = engine.register_app(ORG, {"app_name": "App", "app_category": "security"})
    engine.record_finding(ORG, app["id"], {"severity": "high", "title": "F"})
    assert engine.list_findings(ORG2) == []


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_sspm_stats_empty(engine):
    stats = engine.get_sspm_stats(ORG)
    assert stats["total_apps"] == 0
    assert stats["high_risk_apps"] == 0
    assert stats["open_findings"] == 0
    assert stats["critical_findings"] == 0
    assert stats["compliance_rate"] == 0.0
    assert stats["by_category"] == {}


def test_get_sspm_stats_high_risk_apps(engine):
    """Apps with risk_level in (critical, high) count as high_risk."""
    a1 = engine.register_app(ORG, {"app_name": "A1", "app_category": "crm"})
    engine.register_app(ORG, {"app_name": "A2", "app_category": "analytics"})
    # Assess a1 with low score → critical risk
    engine.assess_app(ORG, a1["id"], {"score": 15.0})
    stats = engine.get_sspm_stats(ORG)
    assert stats["total_apps"] == 2
    assert stats["high_risk_apps"] == 1


def test_get_sspm_stats_open_findings(engine):
    app = engine.register_app(ORG, {"app_name": "App", "app_category": "devops"})
    engine.record_finding(ORG, app["id"], {"severity": "high", "title": "F1"})
    engine.record_finding(ORG, app["id"], {"severity": "medium", "title": "F2"})
    stats = engine.get_sspm_stats(ORG)
    assert stats["open_findings"] == 2


def test_get_sspm_stats_critical_findings(engine):
    app = engine.register_app(ORG, {"app_name": "App", "app_category": "finance"})
    engine.record_finding(ORG, app["id"], {"severity": "critical", "title": "C1"})
    engine.record_finding(ORG, app["id"], {"severity": "high", "title": "H1"})
    stats = engine.get_sspm_stats(ORG)
    assert stats["critical_findings"] == 1


def test_get_sspm_stats_compliance_rate(engine):
    """compliance_rate = compliant_apps / total_apps * 100."""
    # Apps start with compliance_status='unknown'; compliance_rate should be 0
    engine.register_app(ORG, {"app_name": "A1", "app_category": "crm"})
    engine.register_app(ORG, {"app_name": "A2", "app_category": "storage"})
    stats = engine.get_sspm_stats(ORG)
    assert stats["compliance_rate"] == 0.0


def test_get_sspm_stats_by_category(engine):
    engine.register_app(ORG, {"app_name": "A1", "app_category": "crm"})
    engine.register_app(ORG, {"app_name": "A2", "app_category": "crm"})
    engine.register_app(ORG, {"app_name": "A3", "app_category": "analytics"})
    stats = engine.get_sspm_stats(ORG)
    assert stats["by_category"]["crm"] == 2
    assert stats["by_category"]["analytics"] == 1


def test_stats_org_isolation(engine):
    engine.register_app(ORG, {"app_name": "A", "app_category": "crm"})
    stats = engine.get_sspm_stats(ORG2)
    assert stats["total_apps"] == 0
    assert stats["high_risk_apps"] == 0
    assert stats["by_category"] == {}
