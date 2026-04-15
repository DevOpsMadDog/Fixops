"""Tests for MobileAppSecurityEngine.

Covers:
- App registration: valid/invalid platform, category, risk_level
- App listing with filters, get by ID (org isolation)
- Finding recording: valid/invalid finding_type, severity, status
- Finding listing with filters and status update
- Scan creation and completion (app.last_scanned updated)
- Scan listing with filters
- Stats correctness: totals, by_platform, by_finding_type, by_severity
- Multi-tenant org_id isolation throughout
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")

from core.mobile_app_security_engine import MobileAppSecurityEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return MobileAppSecurityEngine(db_path=str(tmp_path / "mas.db"))


ORG = "org-mas-test"
ORG2 = "org-mas-other"


def _app(overrides=None):
    base = {
        "app_name": "TestApp",
        "bundle_id": "com.test.app",
        "platform": "android",
        "category": "enterprise",
    }
    if overrides:
        base.update(overrides)
    return base


def _finding(app_id, overrides=None):
    base = {
        "app_id": app_id,
        "finding_type": "insecure_storage",
        "severity": "high",
        "title": "Sensitive data stored in plaintext",
    }
    if overrides:
        base.update(overrides)
    return base


def _scan(app_id, overrides=None):
    base = {"app_id": app_id, "scan_type": "sast"}
    if overrides:
        base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# App Registration
# ---------------------------------------------------------------------------

class TestRegisterApp:
    def test_returns_dict_with_id(self, engine):
        result = engine.register_app(ORG, _app())
        assert "id" in result
        assert len(result["id"]) == 36

    def test_stores_app_name_and_bundle_id(self, engine):
        result = engine.register_app(ORG, _app({"app_name": "MyBank", "bundle_id": "com.mybank.ios"}))
        assert result["app_name"] == "MyBank"
        assert result["bundle_id"] == "com.mybank.ios"

    def test_stores_platform(self, engine):
        result = engine.register_app(ORG, _app({"platform": "ios"}))
        assert result["platform"] == "ios"

    def test_defaults_risk_score_50(self, engine):
        result = engine.register_app(ORG, _app())
        assert result["risk_score"] == 50.0

    def test_defaults_status_active(self, engine):
        result = engine.register_app(ORG, _app())
        assert result["status"] == "active"

    def test_defaults_risk_level_medium(self, engine):
        result = engine.register_app(ORG, _app())
        assert result["risk_level"] == "medium"

    def test_all_valid_platforms(self, engine):
        platforms = ["ios", "android", "react_native", "flutter", "xamarin", "web"]
        for p in platforms:
            result = engine.register_app(ORG, _app({"platform": p, "bundle_id": f"com.test.{p}"}))
            assert result["platform"] == p

    def test_invalid_platform_raises(self, engine):
        with pytest.raises(ValueError, match="platform"):
            engine.register_app(ORG, _app({"platform": "windows_phone"}))

    def test_all_valid_categories(self, engine):
        categories = ["banking", "healthcare", "retail", "enterprise", "social", "gaming", "utility"]
        for c in categories:
            result = engine.register_app(ORG, _app({"category": c, "bundle_id": f"com.test.{c}"}))
            assert result["category"] == c

    def test_invalid_category_raises(self, engine):
        with pytest.raises(ValueError, match="category"):
            engine.register_app(ORG, _app({"category": "unknown_cat"}))

    def test_missing_app_name_raises(self, engine):
        data = _app()
        data.pop("app_name")
        with pytest.raises(ValueError, match="app_name"):
            engine.register_app(ORG, data)

    def test_missing_bundle_id_raises(self, engine):
        data = _app()
        data.pop("bundle_id")
        with pytest.raises(ValueError, match="bundle_id"):
            engine.register_app(ORG, data)

    def test_invalid_risk_level_raises(self, engine):
        with pytest.raises(ValueError, match="risk_level"):
            engine.register_app(ORG, _app({"risk_level": "extreme"}))

    def test_custom_risk_score_stored(self, engine):
        result = engine.register_app(ORG, _app({"risk_score": 75.5}))
        assert result["risk_score"] == 75.5


# ---------------------------------------------------------------------------
# App Listing and Get
# ---------------------------------------------------------------------------

class TestListAndGetApp:
    def test_list_returns_all_for_org(self, engine):
        engine.register_app(ORG, _app({"bundle_id": "com.a.1"}))
        engine.register_app(ORG, _app({"bundle_id": "com.a.2"}))
        results = engine.list_apps(ORG)
        assert len(results) == 2

    def test_list_filter_by_platform(self, engine):
        engine.register_app(ORG, _app({"platform": "ios", "bundle_id": "com.a.ios"}))
        engine.register_app(ORG, _app({"platform": "android", "bundle_id": "com.a.android"}))
        results = engine.list_apps(ORG, platform="ios")
        assert len(results) == 1
        assert results[0]["platform"] == "ios"

    def test_list_filter_by_risk_level(self, engine):
        engine.register_app(ORG, _app({"risk_level": "critical", "bundle_id": "com.a.c"}))
        engine.register_app(ORG, _app({"risk_level": "low", "bundle_id": "com.a.l"}))
        results = engine.list_apps(ORG, risk_level="critical")
        assert len(results) == 1
        assert results[0]["risk_level"] == "critical"

    def test_get_app_returns_correct_record(self, engine):
        app = engine.register_app(ORG, _app())
        fetched = engine.get_app(ORG, app["id"])
        assert fetched["id"] == app["id"]

    def test_get_app_wrong_org_returns_none(self, engine):
        app = engine.register_app(ORG, _app())
        result = engine.get_app(ORG2, app["id"])
        assert result is None

    def test_get_app_not_found_returns_none(self, engine):
        result = engine.get_app(ORG, "nonexistent-id")
        assert result is None


# ---------------------------------------------------------------------------
# Finding Recording
# ---------------------------------------------------------------------------

class TestRecordFinding:
    def test_returns_dict_with_id(self, engine):
        app = engine.register_app(ORG, _app())
        result = engine.record_finding(ORG, _finding(app["id"]))
        assert "id" in result
        assert len(result["id"]) == 36

    def test_defaults_status_open(self, engine):
        app = engine.register_app(ORG, _app())
        result = engine.record_finding(ORG, _finding(app["id"]))
        assert result["status"] == "open"

    def test_stores_finding_type_and_severity(self, engine):
        app = engine.register_app(ORG, _app())
        result = engine.record_finding(ORG, _finding(app["id"], {
            "finding_type": "weak_crypto", "severity": "critical"
        }))
        assert result["finding_type"] == "weak_crypto"
        assert result["severity"] == "critical"

    def test_all_valid_finding_types(self, engine):
        app = engine.register_app(ORG, _app())
        types = [
            "insecure_storage", "weak_crypto", "hardcoded_secret", "improper_auth",
            "insecure_transport", "code_injection", "reverse_engineering",
            "data_leakage", "improper_session", "third_party_lib",
        ]
        for ft in types:
            result = engine.record_finding(ORG, _finding(app["id"], {"finding_type": ft, "title": ft}))
            assert result["finding_type"] == ft

    def test_invalid_finding_type_raises(self, engine):
        app = engine.register_app(ORG, _app())
        with pytest.raises(ValueError, match="finding_type"):
            engine.record_finding(ORG, _finding(app["id"], {"finding_type": "unknown_type"}))

    def test_invalid_severity_raises(self, engine):
        app = engine.register_app(ORG, _app())
        with pytest.raises(ValueError, match="severity"):
            engine.record_finding(ORG, _finding(app["id"], {"severity": "extreme"}))

    def test_missing_title_raises(self, engine):
        app = engine.register_app(ORG, _app())
        data = _finding(app["id"])
        data.pop("title")
        with pytest.raises(ValueError, match="title"):
            engine.record_finding(ORG, data)

    def test_app_cross_org_raises(self, engine):
        app = engine.register_app(ORG, _app())
        with pytest.raises(ValueError):
            engine.record_finding(ORG2, _finding(app["id"]))

    def test_optional_owasp_category_stored(self, engine):
        app = engine.register_app(ORG, _app())
        result = engine.record_finding(ORG, _finding(app["id"], {"owasp_category": "M1: Improper Platform Usage"}))
        assert result["owasp_category"] == "M1: Improper Platform Usage"

    def test_optional_cwe_id_stored(self, engine):
        app = engine.register_app(ORG, _app())
        result = engine.record_finding(ORG, _finding(app["id"], {"cwe_id": "CWE-312"}))
        assert result["cwe_id"] == "CWE-312"


# ---------------------------------------------------------------------------
# Finding Listing and Status Update
# ---------------------------------------------------------------------------

class TestListAndUpdateFinding:
    def test_list_returns_all_findings(self, engine):
        app = engine.register_app(ORG, _app())
        engine.record_finding(ORG, _finding(app["id"]))
        engine.record_finding(ORG, _finding(app["id"], {"finding_type": "weak_crypto", "title": "Weak"}))
        results = engine.list_findings(ORG)
        assert len(results) == 2

    def test_list_filter_by_app_id(self, engine):
        app1 = engine.register_app(ORG, _app({"bundle_id": "com.a.1"}))
        app2 = engine.register_app(ORG, _app({"bundle_id": "com.a.2"}))
        engine.record_finding(ORG, _finding(app1["id"]))
        engine.record_finding(ORG, _finding(app2["id"]))
        results = engine.list_findings(ORG, app_id=app1["id"])
        assert len(results) == 1
        assert results[0]["app_id"] == app1["id"]

    def test_list_filter_by_severity(self, engine):
        app = engine.register_app(ORG, _app())
        engine.record_finding(ORG, _finding(app["id"], {"severity": "critical", "title": "Crit"}))
        engine.record_finding(ORG, _finding(app["id"], {"severity": "low", "title": "Low"}))
        results = engine.list_findings(ORG, severity="critical")
        assert len(results) == 1
        assert results[0]["severity"] == "critical"

    def test_list_filter_by_status(self, engine):
        app = engine.register_app(ORG, _app())
        f = engine.record_finding(ORG, _finding(app["id"]))
        engine.update_finding_status(ORG, f["id"], "fixed")
        open_findings = engine.list_findings(ORG, status="open")
        fixed_findings = engine.list_findings(ORG, status="fixed")
        assert len(open_findings) == 0
        assert len(fixed_findings) == 1

    def test_update_finding_status_all_valid(self, engine):
        app = engine.register_app(ORG, _app())
        for status in ["in_review", "fixed", "accepted_risk", "open"]:
            f = engine.record_finding(ORG, _finding(app["id"], {"title": f"F-{status}"}))
            result = engine.update_finding_status(ORG, f["id"], status)
            assert result["status"] == status

    def test_update_finding_status_invalid_raises(self, engine):
        app = engine.register_app(ORG, _app())
        f = engine.record_finding(ORG, _finding(app["id"]))
        with pytest.raises(ValueError, match="status"):
            engine.update_finding_status(ORG, f["id"], "deleted")

    def test_update_finding_wrong_org_raises(self, engine):
        app = engine.register_app(ORG, _app())
        f = engine.record_finding(ORG, _finding(app["id"]))
        with pytest.raises(ValueError):
            engine.update_finding_status(ORG2, f["id"], "fixed")


# ---------------------------------------------------------------------------
# Scan Management
# ---------------------------------------------------------------------------

class TestScans:
    def test_create_scan_returns_dict(self, engine):
        app = engine.register_app(ORG, _app())
        result = engine.create_scan(ORG, _scan(app["id"]))
        assert "id" in result
        assert len(result["id"]) == 36

    def test_create_scan_defaults_queued(self, engine):
        app = engine.register_app(ORG, _app())
        result = engine.create_scan(ORG, _scan(app["id"]))
        assert result["status"] == "queued"

    def test_create_scan_all_valid_types(self, engine):
        app = engine.register_app(ORG, _app())
        for st in ["sast", "dast", "penetration", "api", "binary"]:
            result = engine.create_scan(ORG, _scan(app["id"], {"scan_type": st}))
            assert result["scan_type"] == st

    def test_create_scan_invalid_type_raises(self, engine):
        app = engine.register_app(ORG, _app())
        with pytest.raises(ValueError, match="scan_type"):
            engine.create_scan(ORG, _scan(app["id"], {"scan_type": "fuzzing"}))

    def test_create_scan_wrong_org_raises(self, engine):
        app = engine.register_app(ORG, _app())
        with pytest.raises(ValueError):
            engine.create_scan(ORG2, _scan(app["id"]))

    def test_complete_scan_updates_status(self, engine):
        app = engine.register_app(ORG, _app())
        scan = engine.create_scan(ORG, _scan(app["id"]))
        result = engine.complete_scan(ORG, scan["id"], 10, 2, 85.0)
        assert result["status"] == "completed"
        assert result["total_findings"] == 10
        assert result["critical_findings"] == 2
        assert result["scan_score"] == 85.0

    def test_complete_scan_updates_app_last_scanned(self, engine):
        app = engine.register_app(ORG, _app())
        scan = engine.create_scan(ORG, _scan(app["id"]))
        assert app["last_scanned"] is None
        engine.complete_scan(ORG, scan["id"], 5, 1, 70.0)
        updated_app = engine.get_app(ORG, app["id"])
        assert updated_app["last_scanned"] is not None

    def test_complete_scan_wrong_org_raises(self, engine):
        app = engine.register_app(ORG, _app())
        scan = engine.create_scan(ORG, _scan(app["id"]))
        with pytest.raises(ValueError):
            engine.complete_scan(ORG2, scan["id"], 0, 0, 0.0)

    def test_list_scans_filter_by_app_id(self, engine):
        app1 = engine.register_app(ORG, _app({"bundle_id": "com.a.1"}))
        app2 = engine.register_app(ORG, _app({"bundle_id": "com.a.2"}))
        engine.create_scan(ORG, _scan(app1["id"]))
        engine.create_scan(ORG, _scan(app2["id"]))
        results = engine.list_scans(ORG, app_id=app1["id"])
        assert len(results) == 1
        assert results[0]["app_id"] == app1["id"]

    def test_list_scans_filter_by_scan_type(self, engine):
        app = engine.register_app(ORG, _app())
        engine.create_scan(ORG, _scan(app["id"], {"scan_type": "sast"}))
        engine.create_scan(ORG, _scan(app["id"], {"scan_type": "dast"}))
        results = engine.list_scans(ORG, scan_type="sast")
        assert len(results) == 1
        assert results[0]["scan_type"] == "sast"


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestMobileStats:
    def test_total_apps_count(self, engine):
        engine.register_app(ORG, _app({"bundle_id": "com.a.1"}))
        engine.register_app(ORG, _app({"bundle_id": "com.a.2"}))
        stats = engine.get_mobile_stats(ORG)
        assert stats["total_apps"] == 2

    def test_active_apps_count(self, engine):
        engine.register_app(ORG, _app({"bundle_id": "com.a.1", "status": "active"}))
        engine.register_app(ORG, _app({"bundle_id": "com.a.2", "status": "archived"}))
        stats = engine.get_mobile_stats(ORG)
        assert stats["active_apps"] == 1

    def test_by_platform_dict(self, engine):
        engine.register_app(ORG, _app({"platform": "ios", "bundle_id": "com.a.ios"}))
        engine.register_app(ORG, _app({"platform": "android", "bundle_id": "com.a.android"}))
        engine.register_app(ORG, _app({"platform": "android", "bundle_id": "com.b.android"}))
        stats = engine.get_mobile_stats(ORG)
        assert stats["by_platform"]["ios"] == 1
        assert stats["by_platform"]["android"] == 2

    def test_findings_totals(self, engine):
        app = engine.register_app(ORG, _app())
        f1 = engine.record_finding(ORG, _finding(app["id"], {"severity": "critical", "title": "C"}))
        engine.record_finding(ORG, _finding(app["id"], {"severity": "high", "title": "H"}))
        engine.update_finding_status(ORG, f1["id"], "fixed")
        stats = engine.get_mobile_stats(ORG)
        assert stats["total_findings"] == 2
        assert stats["open_findings"] == 1
        assert stats["critical_findings"] == 1

    def test_by_finding_type_dict(self, engine):
        app = engine.register_app(ORG, _app())
        engine.record_finding(ORG, _finding(app["id"], {"finding_type": "weak_crypto", "title": "W1"}))
        engine.record_finding(ORG, _finding(app["id"], {"finding_type": "weak_crypto", "title": "W2"}))
        engine.record_finding(ORG, _finding(app["id"], {"finding_type": "data_leakage", "title": "D"}))
        stats = engine.get_mobile_stats(ORG)
        assert stats["by_finding_type"]["weak_crypto"] == 2
        assert stats["by_finding_type"]["data_leakage"] == 1

    def test_by_severity_dict(self, engine):
        app = engine.register_app(ORG, _app())
        engine.record_finding(ORG, _finding(app["id"], {"severity": "critical", "title": "C"}))
        engine.record_finding(ORG, _finding(app["id"], {"severity": "low", "title": "L"}))
        stats = engine.get_mobile_stats(ORG)
        assert stats["by_severity"]["critical"] == 1
        assert stats["by_severity"]["low"] == 1

    def test_avg_risk_score(self, engine):
        engine.register_app(ORG, _app({"risk_score": 40.0, "bundle_id": "com.a.1"}))
        engine.register_app(ORG, _app({"risk_score": 60.0, "bundle_id": "com.a.2"}))
        stats = engine.get_mobile_stats(ORG)
        assert stats["avg_risk_score"] == 50.0

    def test_empty_org_stats(self, engine):
        stats = engine.get_mobile_stats("empty-org")
        assert stats["total_apps"] == 0
        assert stats["active_apps"] == 0
        assert stats["total_findings"] == 0
        assert stats["avg_risk_score"] == 0.0


# ---------------------------------------------------------------------------
# Org Isolation
# ---------------------------------------------------------------------------

class TestOrgIsolation:
    def test_apps_isolated_by_org(self, engine):
        engine.register_app(ORG, _app({"app_name": "App1", "bundle_id": "com.a.1"}))
        engine.register_app(ORG2, _app({"app_name": "App2", "bundle_id": "com.a.2"}))
        org1_apps = engine.list_apps(ORG)
        org2_apps = engine.list_apps(ORG2)
        assert len(org1_apps) == 1
        assert org1_apps[0]["app_name"] == "App1"
        assert len(org2_apps) == 1
        assert org2_apps[0]["app_name"] == "App2"

    def test_findings_isolated_by_org(self, engine):
        app1 = engine.register_app(ORG, _app({"bundle_id": "com.a.1"}))
        app2 = engine.register_app(ORG2, _app({"bundle_id": "com.a.2"}))
        engine.record_finding(ORG, _finding(app1["id"]))
        engine.record_finding(ORG, _finding(app1["id"], {"title": "F2"}))
        engine.record_finding(ORG2, _finding(app2["id"]))
        assert len(engine.list_findings(ORG)) == 2
        assert len(engine.list_findings(ORG2)) == 1

    def test_scans_isolated_by_org(self, engine):
        app1 = engine.register_app(ORG, _app({"bundle_id": "com.a.1"}))
        app2 = engine.register_app(ORG2, _app({"bundle_id": "com.a.2"}))
        engine.create_scan(ORG, _scan(app1["id"]))
        engine.create_scan(ORG2, _scan(app2["id"]))
        assert len(engine.list_scans(ORG)) == 1
        assert len(engine.list_scans(ORG2)) == 1

    def test_stats_isolated_by_org(self, engine):
        engine.register_app(ORG, _app({"bundle_id": "com.a.1"}))
        engine.register_app(ORG, _app({"bundle_id": "com.a.2"}))
        stats1 = engine.get_mobile_stats(ORG)
        stats2 = engine.get_mobile_stats(ORG2)
        assert stats1["total_apps"] == 2
        assert stats2["total_apps"] == 0
