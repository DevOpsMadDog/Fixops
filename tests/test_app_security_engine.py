"""Tests for suite-core/core/app_security_engine.py.

25 tests covering: init, register/list apps, SAST/DAST scans,
findings CRUD, update status, stats, org isolation, OWASP categories.
"""

from __future__ import annotations

import os
import sys
import tempfile

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret-32-chars-minimum!!")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-integrations"))

import pytest
from core.app_security_engine import (
    AppSecurityEngine,
    get_app_security_engine,
    _VULN_TO_OWASP,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    """Fresh engine backed by a temp SQLite DB."""
    db = str(tmp_path / "appsec_test.db")
    return AppSecurityEngine(db_path=db)


@pytest.fixture
def org():
    return "org-test-001"


@pytest.fixture
def other_org():
    return "org-other-999"


@pytest.fixture
def sample_app(engine, org):
    return engine.register_app(org, {
        "name": "My Web App",
        "app_type": "web",
        "repo_url": "https://github.com/acme/webapp",
        "tech_stack": ["python", "fastapi", "react"],
        "risk_rating": "high",
        "compliance_score": 72.5,
    })


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------

def test_init_creates_engine(tmp_path):
    """Engine initialises without errors."""
    db = str(tmp_path / "init_test.db")
    eng = AppSecurityEngine(db_path=db)
    assert eng is not None


def test_init_creates_db_file(tmp_path):
    """SQLite database file is created on init."""
    db = str(tmp_path / "sub" / "appsec.db")
    AppSecurityEngine(db_path=db)
    assert os.path.exists(db)


# ---------------------------------------------------------------------------
# 2. Register app
# ---------------------------------------------------------------------------

def test_register_app_returns_record(engine, org):
    record = engine.register_app(org, {"name": "API Gateway", "app_type": "api"})
    assert record["app_id"]
    assert record["name"] == "API Gateway"
    assert record["app_type"] == "api"
    assert record["org_id"] == org


def test_register_app_defaults(engine, org):
    record = engine.register_app(org, {"name": "Minimal App"})
    assert record["app_type"] == "web"
    assert record["risk_rating"] == "medium"
    assert record["compliance_score"] == 0.0
    assert record["tech_stack"] == []


def test_register_app_invalid_type_defaults_to_web(engine, org):
    record = engine.register_app(org, {"name": "Bad Type", "app_type": "unknown"})
    assert record["app_type"] == "web"


def test_register_app_tech_stack_stored(engine, org):
    record = engine.register_app(org, {
        "name": "Stack App",
        "tech_stack": ["java", "spring", "kubernetes"],
    })
    assert "java" in record["tech_stack"]
    assert "spring" in record["tech_stack"]


# ---------------------------------------------------------------------------
# 3. List apps
# ---------------------------------------------------------------------------

def test_list_apps_empty(engine, org):
    assert engine.list_apps(org) == []


def test_list_apps_returns_registered(engine, org, sample_app):
    apps = engine.list_apps(org)
    assert len(apps) == 1
    assert apps[0]["app_id"] == sample_app["app_id"]


def test_list_apps_multiple(engine, org):
    engine.register_app(org, {"name": "App A"})
    engine.register_app(org, {"name": "App B"})
    assert len(engine.list_apps(org)) == 2


# ---------------------------------------------------------------------------
# 4. Org isolation (apps)
# ---------------------------------------------------------------------------

def test_org_isolation_apps(engine, org, other_org, sample_app):
    """Other org cannot see org's apps."""
    assert engine.list_apps(other_org) == []


# ---------------------------------------------------------------------------
# 5. SAST scans
# ---------------------------------------------------------------------------

def test_create_sast_scan(engine, org, sample_app):
    scan = engine.create_sast_scan(org, sample_app["app_id"], {
        "tool": "semgrep",
        "status": "completed",
        "findings_count": 5,
        "critical_count": 1,
        "high_count": 2,
        "medium_count": 2,
        "low_count": 0,
    })
    assert scan["scan_id"]
    assert scan["scan_type"] == "sast"
    assert scan["tool"] == "semgrep"
    assert scan["findings_count"] == 5


def test_create_sast_scan_invalid_tool_defaults(engine, org, sample_app):
    scan = engine.create_sast_scan(org, sample_app["app_id"], {"tool": "notrealtool"})
    # Should default to first valid SAST tool
    assert scan["tool"] in {"semgrep", "sonarqube", "checkmarx", "bandit", "eslint"}


# ---------------------------------------------------------------------------
# 6. DAST scans
# ---------------------------------------------------------------------------

def test_create_dast_scan(engine, org, sample_app):
    scan = engine.create_dast_scan(org, sample_app["app_id"], {
        "tool": "zap",
        "status": "running",
        "findings_count": 3,
    })
    assert scan["scan_type"] == "dast"
    assert scan["tool"] == "zap"


def test_create_dast_scan_invalid_tool_defaults(engine, org, sample_app):
    scan = engine.create_dast_scan(org, sample_app["app_id"], {"tool": "nmap"})
    assert scan["tool"] in {"zap", "burpsuite", "nikto", "nuclei"}


# ---------------------------------------------------------------------------
# 7. List scans
# ---------------------------------------------------------------------------

def test_list_scans_all(engine, org, sample_app):
    engine.create_sast_scan(org, sample_app["app_id"], {"tool": "bandit"})
    engine.create_dast_scan(org, sample_app["app_id"], {"tool": "nikto"})
    scans = engine.list_scans(org)
    assert len(scans) == 2


def test_list_scans_filter_by_type(engine, org, sample_app):
    engine.create_sast_scan(org, sample_app["app_id"], {"tool": "bandit"})
    engine.create_dast_scan(org, sample_app["app_id"], {"tool": "nuclei"})
    sast = engine.list_scans(org, scan_type="sast")
    dast = engine.list_scans(org, scan_type="dast")
    assert all(s["scan_type"] == "sast" for s in sast)
    assert all(s["scan_type"] == "dast" for s in dast)


def test_list_scans_filter_by_app(engine, org):
    app_a = engine.register_app(org, {"name": "A"})
    app_b = engine.register_app(org, {"name": "B"})
    engine.create_sast_scan(org, app_a["app_id"], {"tool": "semgrep"})
    engine.create_sast_scan(org, app_b["app_id"], {"tool": "eslint"})
    result = engine.list_scans(org, app_id=app_a["app_id"])
    assert len(result) == 1
    assert result[0]["app_id"] == app_a["app_id"]


# ---------------------------------------------------------------------------
# 8. Findings CRUD
# ---------------------------------------------------------------------------

def test_create_finding(engine, org, sample_app):
    finding = engine.create_finding(org, {
        "app_id": sample_app["app_id"],
        "vuln_type": "sqli",
        "severity": "critical",
        "cwe_id": "CWE-89",
        "description": "SQL injection in login form",
        "file_path": "app/routes/auth.py",
        "line_number": 42,
    })
    assert finding["finding_id"]
    assert finding["vuln_type"] == "sqli"
    assert finding["severity"] == "critical"
    assert finding["owasp_category"] == "A03"  # Injection


def test_create_finding_owasp_auto_mapped(engine, org, sample_app):
    for vuln, expected_owasp in _VULN_TO_OWASP.items():
        f = engine.create_finding(org, {
            "app_id": sample_app["app_id"],
            "vuln_type": vuln,
        })
        assert f["owasp_category"] == expected_owasp, f"{vuln} → {f['owasp_category']} (expected {expected_owasp})"


def test_list_findings_empty(engine, org):
    assert engine.list_findings(org) == []


def test_list_findings_filter_severity(engine, org, sample_app):
    engine.create_finding(org, {"app_id": sample_app["app_id"], "vuln_type": "xss", "severity": "high"})
    engine.create_finding(org, {"app_id": sample_app["app_id"], "vuln_type": "misconfig", "severity": "low"})
    highs = engine.list_findings(org, severity="high")
    assert all(f["severity"] == "high" for f in highs)
    assert len(highs) == 1


def test_list_findings_filter_status(engine, org, sample_app):
    f = engine.create_finding(org, {"app_id": sample_app["app_id"], "vuln_type": "ssrf", "status": "open"})
    engine.update_finding_status(org, f["finding_id"], "fixed")
    open_findings = engine.list_findings(org, status="open")
    assert all(x["status"] == "open" for x in open_findings)


# ---------------------------------------------------------------------------
# 9. Update finding status
# ---------------------------------------------------------------------------

def test_update_finding_status_success(engine, org, sample_app):
    f = engine.create_finding(org, {"app_id": sample_app["app_id"], "vuln_type": "rce"})
    result = engine.update_finding_status(org, f["finding_id"], "accepted")
    assert result is True
    updated = engine.list_findings(org, status="accepted")
    assert len(updated) == 1


def test_update_finding_status_invalid_returns_false(engine, org, sample_app):
    f = engine.create_finding(org, {"app_id": sample_app["app_id"], "vuln_type": "idor"})
    result = engine.update_finding_status(org, f["finding_id"], "invalid_status")
    assert result is False


def test_update_finding_status_wrong_org_returns_false(engine, org, other_org, sample_app):
    f = engine.create_finding(org, {"app_id": sample_app["app_id"], "vuln_type": "xss"})
    result = engine.update_finding_status(other_org, f["finding_id"], "fixed")
    assert result is False


# ---------------------------------------------------------------------------
# 10. Org isolation (findings)
# ---------------------------------------------------------------------------

def test_org_isolation_findings(engine, org, other_org, sample_app):
    engine.create_finding(org, {"app_id": sample_app["app_id"], "vuln_type": "sqli"})
    assert engine.list_findings(other_org) == []


# ---------------------------------------------------------------------------
# 11. Stats
# ---------------------------------------------------------------------------

def test_stats_empty_org(engine, org):
    stats = engine.get_appsec_stats(org)
    assert stats["total_apps"] == 0
    assert stats["total_scans"] == 0
    assert stats["open_findings"] == 0
    assert stats["by_severity"] == {}
    assert stats["by_owasp_category"] == {}
    assert stats["avg_compliance_score"] == 0.0


def test_stats_with_data(engine, org, sample_app):
    engine.create_sast_scan(org, sample_app["app_id"], {"tool": "semgrep", "status": "completed"})
    engine.create_dast_scan(org, sample_app["app_id"], {"tool": "zap"})
    engine.create_finding(org, {"app_id": sample_app["app_id"], "vuln_type": "sqli", "severity": "critical"})
    engine.create_finding(org, {"app_id": sample_app["app_id"], "vuln_type": "xss", "severity": "high"})
    f = engine.create_finding(org, {"app_id": sample_app["app_id"], "vuln_type": "misconfig", "severity": "low"})
    engine.update_finding_status(org, f["finding_id"], "fixed")

    stats = engine.get_appsec_stats(org)
    assert stats["total_apps"] == 1
    assert stats["total_scans"] == 2
    assert stats["open_findings"] == 2
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_severity"]["high"] == 1
    assert stats["avg_compliance_score"] == 72.5


# ---------------------------------------------------------------------------
# 12. Singleton
# ---------------------------------------------------------------------------

def test_singleton_returns_same_instance():
    e1 = get_app_security_engine()
    e2 = get_app_security_engine()
    assert e1 is e2
