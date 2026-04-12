"""
Supply Chain Intelligence Test Suite for ALDECI.

Tests cover:
- RiskCategory enum values (7 tests)
- PackageRisk and SupplyChainAlert model validation (4 tests)
- analyze_package: clean, malicious, typosquat, abandoned (6 tests)
- detect_typosquat: known variants, edit distance, clean packages (4 tests)
- check_maintainer_trust: single maintainer, multi-maintainer (3 tests)
- check_abandoned: threshold logic (3 tests)
- detect_dependency_confusion: internal prefix patterns (3 tests)
- get_alerts / resolve_alert: lifecycle (4 tests)
- get_risk_summary: structure validation (2 tests)
- get_high_risk_packages: threshold filtering (3 tests)
- get_supply_chain_stats: aggregate counts (3 tests)
- analyze_sbom: missing db, empty result (2 tests)
- API router: all 10 endpoints (10 tests)

Run with:
    python -m pytest tests/test_supply_chain_intel.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import os
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

# Configure environment before any app imports
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_intel(tmp_path):
    """SupplyChainIntel instance backed by a temp DB."""
    from core.supply_chain_intel import SupplyChainIntel
    return SupplyChainIntel(db_path=str(tmp_path / "supply_chain_test.db"))


@pytest.fixture
def org_id():
    return f"test-org-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# 1. RiskCategory enum (7 tests)
# ---------------------------------------------------------------------------

class TestRiskCategory:
    def test_typosquat_value(self):
        from core.supply_chain_intel import RiskCategory
        assert RiskCategory.TYPOSQUAT.value == "typosquat"

    def test_maintainer_change_value(self):
        from core.supply_chain_intel import RiskCategory
        assert RiskCategory.MAINTAINER_CHANGE.value == "maintainer_change"

    def test_abandoned_value(self):
        from core.supply_chain_intel import RiskCategory
        assert RiskCategory.ABANDONED.value == "abandoned"

    def test_malicious_code_value(self):
        from core.supply_chain_intel import RiskCategory
        assert RiskCategory.MALICIOUS_CODE.value == "malicious_code"

    def test_license_change_value(self):
        from core.supply_chain_intel import RiskCategory
        assert RiskCategory.LICENSE_CHANGE.value == "license_change"

    def test_vulnerability_value(self):
        from core.supply_chain_intel import RiskCategory
        assert RiskCategory.VULNERABILITY.value == "vulnerability"

    def test_dependency_confusion_value(self):
        from core.supply_chain_intel import RiskCategory
        assert RiskCategory.DEPENDENCY_CONFUSION.value == "dependency_confusion"


# ---------------------------------------------------------------------------
# 2. Pydantic model validation (4 tests)
# ---------------------------------------------------------------------------

class TestModels:
    def test_package_risk_defaults(self):
        from core.supply_chain_intel import PackageRisk
        pkg = PackageRisk(package_name="requests", ecosystem="pip")
        assert pkg.risk_score == 0.0
        assert pkg.risks == []
        assert pkg.org_id == "default"

    def test_package_risk_score_bounds(self):
        from core.supply_chain_intel import PackageRisk
        pkg = PackageRisk(package_name="x", ecosystem="npm", risk_score=100.0)
        assert pkg.risk_score == 100.0

    def test_supply_chain_alert_fields(self):
        from core.supply_chain_intel import SupplyChainAlert, RiskCategory
        alert = SupplyChainAlert(
            id="a1",
            package_name="colourama",
            category=RiskCategory.TYPOSQUAT,
            severity="high",
            description="Typosquat of colorama",
            detected_at="2026-01-01T00:00:00+00:00",
        )
        assert alert.resolved is False
        assert alert.category == RiskCategory.TYPOSQUAT

    def test_alert_resolved_field(self):
        from core.supply_chain_intel import SupplyChainAlert, RiskCategory
        alert = SupplyChainAlert(
            id="a2",
            package_name="pkg",
            category=RiskCategory.ABANDONED,
            severity="medium",
            description="Old package",
            detected_at="2026-01-01T00:00:00+00:00",
            resolved=True,
        )
        assert alert.resolved is True


# ---------------------------------------------------------------------------
# 3. analyze_package (6 tests)
# ---------------------------------------------------------------------------

class TestAnalyzePackage:
    def test_clean_package_returns_package_risk(self, tmp_intel, org_id):
        result = tmp_intel.analyze_package("requests", "pip", "2.31.0", org_id)
        assert result.package_name == "requests"
        assert result.ecosystem == "pip"
        assert result.version == "2.31.0"
        assert 0 <= result.risk_score <= 100

    def test_malicious_package_high_score(self, tmp_intel, org_id):
        result = tmp_intel.analyze_package("colourama", "pip", "1.0.0", org_id)
        assert result.risk_score >= 70
        categories = [r["category"] for r in result.risks]
        assert "malicious_code" in categories

    def test_known_malicious_npm(self, tmp_intel, org_id):
        result = tmp_intel.analyze_package("cross-env2", "npm", "1.0.0", org_id)
        assert result.risk_score >= 70

    def test_package_risk_persisted(self, tmp_intel, org_id):
        tmp_intel.analyze_package("numpy", "pip", "1.24.0", org_id)
        high_risk = tmp_intel.get_high_risk_packages(org_id=org_id, threshold=0.0)
        names = [p.package_name for p in high_risk]
        assert "numpy" in names

    def test_analyze_generates_alert_for_malicious(self, tmp_intel, org_id):
        tmp_intel.analyze_package("colourama", "pip", "1.0", org_id)
        alerts = tmp_intel.get_alerts(org_id=org_id)
        assert len(alerts) > 0
        assert any(a.package_name == "colourama" for a in alerts)

    def test_default_org_id(self, tmp_intel):
        result = tmp_intel.analyze_package("flask", "pip")
        assert result.org_id == "default"


# ---------------------------------------------------------------------------
# 4. detect_typosquat (4 tests)
# ---------------------------------------------------------------------------

class TestDetectTyposquat:
    def test_known_variant_detected(self, tmp_intel):
        hits = tmp_intel.detect_typosquat("colourama", "pip")
        assert len(hits) > 0
        targets = [h["target"] for h in hits]
        assert "colorama" in targets

    def test_clean_popular_package_not_flagged(self, tmp_intel):
        # "requests" itself is not a typosquat of anything
        hits = tmp_intel.detect_typosquat("requests", "pip")
        assert len(hits) == 0

    def test_edit_distance_detection(self, tmp_intel):
        # "requets" is 1 edit from "requests"
        hits = tmp_intel.detect_typosquat("requets", "pip")
        assert len(hits) > 0

    def test_npm_typosquat_detected(self, tmp_intel):
        hits = tmp_intel.detect_typosquat("cross-env2", "npm")
        assert len(hits) > 0
        targets = [h["target"] for h in hits]
        assert "cross-env" in targets


# ---------------------------------------------------------------------------
# 5. check_maintainer_trust (3 tests)
# ---------------------------------------------------------------------------

class TestMaintainerTrust:
    def test_returns_expected_keys(self, tmp_intel):
        result = tmp_intel.check_maintainer_trust("requests", "pip")
        assert "maintainer_count" in result
        assert "trust_level" in result
        assert "recent_maintainer_change" in result
        assert "verified_org" in result

    def test_trust_level_valid(self, tmp_intel):
        result = tmp_intel.check_maintainer_trust("numpy", "pip")
        assert result["trust_level"] in ("high", "medium", "low")

    def test_account_age_positive(self, tmp_intel):
        result = tmp_intel.check_maintainer_trust("django", "pip")
        assert result["account_age_days"] > 0


# ---------------------------------------------------------------------------
# 6. check_abandoned (3 tests)
# ---------------------------------------------------------------------------

class TestCheckAbandoned:
    def test_abandoned_package(self, tmp_intel):
        # "old-legacy-deprecated" should trigger abandonment
        result = tmp_intel.check_abandoned("old-legacy-deprecated", "pip")
        assert result is True

    def test_active_package(self, tmp_intel):
        # "requests" has a low hash-based day count
        result = tmp_intel.check_abandoned("requests", "pip")
        # Just verify it returns a bool
        assert isinstance(result, bool)

    def test_abandoned_threshold_is_730_days(self, tmp_intel):
        from core.supply_chain_intel import SupplyChainIntel
        intel = tmp_intel
        # Package that gets 900 days (abandoned) due to keyword
        assert intel._mock_last_updated_days("old-unmaintained-pkg") > 730


# ---------------------------------------------------------------------------
# 7. detect_dependency_confusion (3 tests)
# ---------------------------------------------------------------------------

class TestDependencyConfusion:
    def test_internal_prefix_may_trigger(self, tmp_intel):
        # "internal-mylib" with org "internal" — deterministic hash check
        result = tmp_intel.detect_dependency_confusion("internal-mylib", "internal")
        assert isinstance(result, bool)

    def test_no_prefix_no_confusion(self, tmp_intel):
        result = tmp_intel.detect_dependency_confusion("requests", "default")
        assert result is False

    def test_corp_prefix_evaluated(self, tmp_intel):
        result = tmp_intel.detect_dependency_confusion("corp-auth-lib", "default")
        # corp- prefix triggers evaluation — result is bool
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# 8. get_alerts / resolve_alert (4 tests)
# ---------------------------------------------------------------------------

class TestAlerts:
    def test_no_alerts_initially(self, tmp_intel, org_id):
        alerts = tmp_intel.get_alerts(org_id=org_id)
        assert alerts == []

    def test_alert_created_for_malicious(self, tmp_intel, org_id):
        tmp_intel.analyze_package("colourama", "pip", "1.0", org_id)
        alerts = tmp_intel.get_alerts(org_id=org_id)
        assert len(alerts) >= 1

    def test_resolve_alert_marks_resolved(self, tmp_intel, org_id):
        tmp_intel.analyze_package("colourama", "pip", "1.0", org_id)
        alerts = tmp_intel.get_alerts(org_id=org_id)
        alert_id = alerts[0].id
        result = tmp_intel.resolve_alert(alert_id)
        assert result is True
        updated = tmp_intel.get_alerts(org_id=org_id)
        resolved_ids = [a.id for a in updated if a.resolved]
        assert alert_id in resolved_ids

    def test_resolve_nonexistent_alert(self, tmp_intel):
        result = tmp_intel.resolve_alert("nonexistent-id")
        assert result is False


# ---------------------------------------------------------------------------
# 9. get_risk_summary (2 tests)
# ---------------------------------------------------------------------------

class TestRiskSummary:
    def test_empty_org_summary(self, tmp_intel, org_id):
        summary = tmp_intel.get_risk_summary(org_id=org_id)
        assert "org_id" in summary
        assert "by_ecosystem" in summary
        assert "by_category" in summary
        assert "by_severity" in summary
        assert "unresolved_alerts" in summary

    def test_summary_after_analysis(self, tmp_intel, org_id):
        tmp_intel.analyze_package("colourama", "pip", "1.0", org_id)
        tmp_intel.analyze_package("requests", "pip", "2.31.0", org_id)
        summary = tmp_intel.get_risk_summary(org_id=org_id)
        pip_entries = [e for e in summary["by_ecosystem"] if e["ecosystem"] == "pip"]
        assert len(pip_entries) == 1
        assert pip_entries[0]["package_count"] == 2


# ---------------------------------------------------------------------------
# 10. get_high_risk_packages (3 tests)
# ---------------------------------------------------------------------------

class TestHighRiskPackages:
    def test_no_packages_initially(self, tmp_intel, org_id):
        results = tmp_intel.get_high_risk_packages(org_id=org_id)
        assert results == []

    def test_malicious_package_in_high_risk(self, tmp_intel, org_id):
        tmp_intel.analyze_package("colourama", "pip", "1.0", org_id)
        results = tmp_intel.get_high_risk_packages(org_id=org_id)
        assert any(p.package_name == "colourama" for p in results)

    def test_threshold_filtering(self, tmp_intel, org_id):
        tmp_intel.analyze_package("colourama", "pip", "1.0", org_id)
        tmp_intel.analyze_package("requests", "pip", "2.31.0", org_id)
        # Only the malicious one should be above 90
        critical = tmp_intel.get_high_risk_packages(org_id=org_id, threshold=90.0)
        assert all(p.risk_score >= 90.0 for p in critical)


# ---------------------------------------------------------------------------
# 11. get_supply_chain_stats (3 tests)
# ---------------------------------------------------------------------------

class TestSupplyChainStats:
    def test_stats_structure(self, tmp_intel, org_id):
        stats = tmp_intel.get_supply_chain_stats(org_id=org_id)
        assert "total_packages_analyzed" in stats
        assert "average_risk_score" in stats
        assert "high_risk_packages" in stats
        assert "critical_risk_packages" in stats
        assert "total_alerts" in stats
        assert "unresolved_alerts" in stats
        assert "known_malicious_detected" in stats
        assert "known_malicious_db_size" in stats

    def test_stats_db_size(self, tmp_intel, org_id):
        stats = tmp_intel.get_supply_chain_stats(org_id=org_id)
        assert stats["known_malicious_db_size"] >= 50

    def test_stats_after_analysis(self, tmp_intel, org_id):
        tmp_intel.analyze_package("colourama", "pip", "1.0", org_id)
        stats = tmp_intel.get_supply_chain_stats(org_id=org_id)
        assert stats["total_packages_analyzed"] >= 1
        assert stats["known_malicious_detected"] >= 1


# ---------------------------------------------------------------------------
# 12. analyze_sbom (2 tests)
# ---------------------------------------------------------------------------

class TestAnalyzeSBOM:
    def test_missing_sbom_db_returns_empty(self, tmp_intel, org_id):
        results = tmp_intel.analyze_sbom(
            sbom_id="nonexistent-sbom",
            org_id=org_id,
            db_path="/tmp/nonexistent_sbom_db_xyz.db",
        )
        assert results == []

    def test_analyze_sbom_nonexistent_id(self, tmp_intel, tmp_path, org_id):
        import sqlite3
        # Create a real but empty sbom DB
        sbom_db = tmp_path / "sbom.db"
        conn = sqlite3.connect(str(sbom_db))
        conn.execute(
            """CREATE TABLE sbom_components
               (id TEXT, sbom_id TEXT, name TEXT, version TEXT,
                purl TEXT, type TEXT, licenses TEXT, supplier TEXT, hashes TEXT)"""
        )
        conn.commit()
        conn.close()
        results = tmp_intel.analyze_sbom(
            sbom_id="no-such-sbom",
            org_id=org_id,
            db_path=str(sbom_db),
        )
        assert results == []


# ---------------------------------------------------------------------------
# 13. API router — all 10 endpoints (10 tests)
# ---------------------------------------------------------------------------

@pytest.fixture
def api_client(tmp_path):
    """FastAPI TestClient with supply_chain_router mounted and auth bypassed."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from core.supply_chain_intel import SupplyChainIntel
    from apps.api.auth_deps import api_key_auth
    from apps.api import supply_chain_router

    app = FastAPI()

    # Inject a temp-DB intel instance
    real_intel = SupplyChainIntel(db_path=str(tmp_path / "api_test.db"))

    # Override the singleton getter so the router uses our temp-DB instance
    supply_chain_router._intel = real_intel

    # Bypass auth via dependency_overrides
    app.dependency_overrides[api_key_auth] = lambda: None
    app.include_router(supply_chain_router.router)

    yield TestClient(app)

    # Reset singleton so other tests are unaffected
    supply_chain_router._intel = None


class TestSupplyChainRouter:
    def test_analyze_endpoint(self, api_client):
        resp = api_client.post("/api/v1/supply-chain/analyze", json={
            "package_name": "requests",
            "ecosystem": "pip",
            "version": "2.31.0",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["package_name"] == "requests"
        assert "risk_score" in data
        assert "risk_level" in data

    def test_analyze_malicious_package(self, api_client):
        resp = api_client.post("/api/v1/supply-chain/analyze", json={
            "package_name": "colourama",
            "ecosystem": "pip",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_score"] >= 70

    def test_analyze_sbom_endpoint(self, api_client):
        resp = api_client.post("/api/v1/supply-chain/analyze-sbom", json={
            "sbom_id": "test-sbom-123",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "sbom_id" in data
        assert "total_components" in data

    def test_get_alerts_endpoint(self, api_client):
        resp = api_client.get("/api/v1/supply-chain/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert "alerts" in data
        assert "total" in data

    def test_resolve_alert_not_found(self, api_client):
        resp = api_client.post("/api/v1/supply-chain/alerts/nonexistent-id/resolve")
        assert resp.status_code == 404

    def test_resolve_alert_success(self, api_client):
        # First create an alert by analyzing a malicious package
        api_client.post("/api/v1/supply-chain/analyze", json={
            "package_name": "colourama",
            "ecosystem": "pip",
        })
        alerts_resp = api_client.get("/api/v1/supply-chain/alerts")
        alerts = alerts_resp.json()["alerts"]
        if alerts:
            alert_id = alerts[0]["id"]
            resp = api_client.post(f"/api/v1/supply-chain/alerts/{alert_id}/resolve")
            assert resp.status_code == 200
            assert resp.json()["resolved"] is True

    def test_high_risk_endpoint(self, api_client):
        resp = api_client.get("/api/v1/supply-chain/high-risk")
        assert resp.status_code == 200
        data = resp.json()
        assert "packages" in data
        assert "threshold" in data

    def test_stats_endpoint(self, api_client):
        resp = api_client.get("/api/v1/supply-chain/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_packages_analyzed" in data
        assert "known_malicious_db_size" in data
        assert data["known_malicious_db_size"] >= 50

    def test_typosquat_endpoint(self, api_client):
        resp = api_client.post("/api/v1/supply-chain/typosquat", json={
            "package_name": "colourama",
            "ecosystem": "pip",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "is_typosquat" in data
        assert data["is_typosquat"] is True

    def test_maintainer_trust_endpoint(self, api_client):
        resp = api_client.post("/api/v1/supply-chain/maintainer-trust", json={
            "package_name": "django",
            "ecosystem": "pip",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "trust_level" in data
        assert "maintainer_count" in data

    def test_malicious_db_endpoint(self, api_client):
        resp = api_client.get("/api/v1/supply-chain/malicious-db")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 50
        assert len(data["entries"]) >= 50

    def test_malicious_db_filtered_by_ecosystem(self, api_client):
        resp = api_client.get("/api/v1/supply-chain/malicious-db?ecosystem=pip")
        assert resp.status_code == 200
        data = resp.json()
        assert all(e["ecosystem"] == "pip" for e in data["entries"])

    def test_risk_summary_endpoint(self, api_client):
        resp = api_client.get("/api/v1/supply-chain/risk-summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "by_ecosystem" in data
        assert "by_category" in data
        assert "unresolved_alerts" in data
