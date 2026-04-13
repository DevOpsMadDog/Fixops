"""
Tests for SupplyChainAnalyzer — typosquat detection, malicious package DB,
requirements parsing, persistence, and risk scoring.

All tests use a temporary SQLite DB. No network calls.
"""

from __future__ import annotations

import sys
import os
import pytest

# Ensure suite-core is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.supply_chain_analyzer import SupplyChainAnalyzer, _KNOWN_MALICIOUS, _POPULAR_PACKAGES


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def analyzer(tmp_path):
    """Fresh SupplyChainAnalyzer backed by a temp SQLite DB."""
    db = str(tmp_path / "supply_chain_test.db")
    return SupplyChainAnalyzer(db_path=db)


# ---------------------------------------------------------------------------
# Instantiation
# ---------------------------------------------------------------------------


def test_instantiation(tmp_path):
    """SupplyChainAnalyzer instantiates without errors."""
    db = str(tmp_path / "test.db")
    analyzer = SupplyChainAnalyzer(db_path=db)
    assert analyzer is not None
    assert analyzer.db_path == db


def test_db_file_created(tmp_path):
    """SQLite DB file is created on init."""
    db = str(tmp_path / "subdir" / "sc.db")
    SupplyChainAnalyzer(db_path=db)
    assert os.path.exists(db)


# ---------------------------------------------------------------------------
# analyze_package — return shape
# ---------------------------------------------------------------------------


def test_analyze_package_returns_dict(analyzer):
    """analyze_package returns a dict with expected keys."""
    result = analyzer.analyze_package("requests", "2.31.0", "pypi")
    for key in ("package", "version", "ecosystem", "risk_score", "risks",
                "is_typosquat", "similar_packages", "is_known_malicious",
                "days_since_last_release", "is_abandoned"):
        assert key in result, f"Missing key: {key}"


def test_analyze_package_safe_package_low_risk(analyzer):
    """A clean, well-known package gets a low risk score."""
    result = analyzer.analyze_package("requests", "2.31.0", "pypi")
    assert isinstance(result["risk_score"], float)
    assert result["risk_score"] < 70.0


def test_analyze_package_known_malicious_ctx(analyzer):
    """'ctx' (any version) is flagged as known malicious with high risk score."""
    result = analyzer.analyze_package("ctx", None, "pypi")
    assert result["is_known_malicious"] is True
    assert result["risk_score"] >= 90.0


def test_analyze_package_malicious_specific_version(analyzer):
    """event-stream@3.3.6 is flagged as malicious."""
    result = analyzer.analyze_package("event-stream", "3.3.6", "npm")
    assert result["is_known_malicious"] is True
    assert result["risk_score"] >= 90.0


def test_analyze_package_malicious_wrong_version_not_flagged(analyzer):
    """event-stream@3.3.5 (safe version) is NOT flagged as malicious."""
    result = analyzer.analyze_package("event-stream", "3.3.5", "npm")
    assert result["is_known_malicious"] is False


def test_analyze_package_typosquat_detected(analyzer):
    """'colourama' is flagged as a typosquat of colorama."""
    result = analyzer.analyze_package("colourama", None, "pypi")
    assert result["is_typosquat"] is True
    assert result["risk_score"] >= 70.0
    assert any("colorama" in pkg.lower() for pkg in result["similar_packages"])


def test_analyze_package_exact_match_not_typosquat(analyzer):
    """Exact match 'requests' is NOT flagged as a typosquat."""
    result = analyzer.analyze_package("requests", None, "pypi")
    # 'requests' should not match itself
    assert "requests" not in result["similar_packages"]


def test_analyze_package_risk_score_is_float(analyzer):
    """risk_score is always a float."""
    result = analyzer.analyze_package("numpy", "1.24.0", "pypi")
    assert isinstance(result["risk_score"], float)


def test_analyze_package_no_version(analyzer):
    """analyze_package works without a version argument."""
    result = analyzer.analyze_package("somepackage", None, "pypi")
    assert result["version"] is None
    assert "risk_score" in result


# ---------------------------------------------------------------------------
# check_known_malicious
# ---------------------------------------------------------------------------


def test_check_known_malicious_returns_bool(analyzer):
    """check_known_malicious returns a bool."""
    result = analyzer.check_known_malicious("ctx")
    assert isinstance(result, bool)


def test_check_known_malicious_known_package_any_version(analyzer):
    """ctx is malicious regardless of version."""
    assert analyzer.check_known_malicious("ctx") is True
    assert analyzer.check_known_malicious("ctx", "1.0.0") is True


def test_check_known_malicious_case_insensitive(analyzer):
    """Malicious check is case-insensitive."""
    assert analyzer.check_known_malicious("CTX") is True
    assert analyzer.check_known_malicious("Ctx", None) is True


def test_check_known_malicious_safe_package(analyzer):
    """A safe package returns False."""
    assert analyzer.check_known_malicious("requests") is False
    assert analyzer.check_known_malicious("numpy", "1.24.0") is False


def test_check_known_malicious_version_specific_match(analyzer):
    """colors@1.4.44-liberty-2 is malicious; other versions are not."""
    assert analyzer.check_known_malicious("colors", "1.4.44-liberty-2") is True
    assert analyzer.check_known_malicious("colors", "1.4.0") is False


# ---------------------------------------------------------------------------
# detect_typosquats
# ---------------------------------------------------------------------------


def test_detect_typosquats_returns_list(analyzer):
    """detect_typosquats returns a list."""
    result = analyzer.detect_typosquats("requestss", "pypi")
    assert isinstance(result, list)


def test_detect_typosquats_finds_match(analyzer):
    """'requestss' is a typosquat candidate for 'requests'."""
    matches = analyzer.detect_typosquats("requestss", "pypi")
    assert "requests" in matches


def test_detect_typosquats_exact_match_excluded(analyzer):
    """Exact package name is not a typosquat of itself."""
    matches = analyzer.detect_typosquats("requests", "pypi")
    assert "requests" not in matches


def test_detect_typosquats_npm_ecosystem(analyzer):
    """detect_typosquats works for npm ecosystem."""
    matches = analyzer.detect_typosquats("lodahs", "npm")
    assert "lodash" in matches


def test_detect_typosquats_unknown_ecosystem_falls_back(analyzer):
    """Unknown ecosystem falls back to pypi list."""
    result = analyzer.detect_typosquats("requestss", "unknown")
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# analyze_requirements
# ---------------------------------------------------------------------------


SIMPLE_REQUIREMENTS = """\
requests==2.31.0
numpy>=1.24.0
flask==3.0.0
"""


def test_analyze_requirements_returns_dict(analyzer):
    """analyze_requirements returns a dict with total_packages key."""
    result = analyzer.analyze_requirements(SIMPLE_REQUIREMENTS, "pypi")
    assert isinstance(result, dict)
    assert "total_packages" in result


def test_analyze_requirements_total_packages_count(analyzer):
    """total_packages matches the number of parsed packages."""
    result = analyzer.analyze_requirements(SIMPLE_REQUIREMENTS, "pypi")
    assert result["total_packages"] == 3


def test_analyze_requirements_has_packages_list(analyzer):
    """Result contains 'packages' list with individual analyses."""
    result = analyzer.analyze_requirements(SIMPLE_REQUIREMENTS, "pypi")
    assert "packages" in result
    assert len(result["packages"]) == 3


def test_analyze_requirements_has_overall_risk(analyzer):
    """Result includes overall_risk field."""
    result = analyzer.analyze_requirements(SIMPLE_REQUIREMENTS, "pypi")
    assert "overall_risk" in result
    assert result["overall_risk"] in ("low", "medium", "high", "critical")


def test_analyze_requirements_high_risk_count(analyzer):
    """high_risk_count is present and is an integer."""
    result = analyzer.analyze_requirements(SIMPLE_REQUIREMENTS, "pypi")
    assert "high_risk_count" in result
    assert isinstance(result["high_risk_count"], int)


def test_analyze_requirements_malicious_package_raises_overall_risk(analyzer):
    """A malicious package in requirements makes overall_risk critical."""
    content = "ctx==0.1.0\nrequests==2.31.0\n"
    result = analyzer.analyze_requirements(content, "pypi")
    assert result["overall_risk"] == "critical"


def test_analyze_requirements_empty_content(analyzer):
    """Empty requirements content returns zero packages."""
    result = analyzer.analyze_requirements("", "pypi")
    assert result["total_packages"] == 0
    assert result["overall_risk"] == "low"


def test_analyze_requirements_npm_package_json(analyzer):
    """parse npm package.json format."""
    pkg_json = '{"dependencies": {"lodash": "^4.17.21", "axios": "^1.6.0"}}'
    result = analyzer.analyze_requirements(pkg_json, "npm")
    assert result["total_packages"] == 2


# ---------------------------------------------------------------------------
# store_analysis / get_analysis / list_analyses
# ---------------------------------------------------------------------------


def test_store_analysis_returns_string_id(analyzer):
    """store_analysis returns a non-empty string ID."""
    pkg_result = analyzer.analyze_package("requests", "2.31.0", "pypi")
    analysis_id = analyzer.store_analysis(pkg_result)
    assert isinstance(analysis_id, str)
    assert len(analysis_id) > 0


def test_get_analysis_retrieves_stored_result(analyzer):
    """get_analysis retrieves what was stored."""
    pkg_result = analyzer.analyze_package("numpy", "1.24.0", "pypi")
    analysis_id = analyzer.store_analysis(pkg_result)
    retrieved = analyzer.get_analysis(analysis_id)
    assert retrieved is not None
    assert retrieved["package"] == "numpy"


def test_get_analysis_returns_none_for_unknown_id(analyzer):
    """get_analysis returns None for a non-existent ID."""
    result = analyzer.get_analysis("00000000-0000-0000-0000-000000000000")
    assert result is None


def test_list_analyses_returns_list(analyzer):
    """list_analyses returns a list."""
    result = analyzer.list_analyses()
    assert isinstance(result, list)


def test_list_analyses_shows_stored_items(analyzer):
    """list_analyses shows items that were stored."""
    pkg_result = analyzer.analyze_package("flask", "3.0.0", "pypi")
    analyzer.store_analysis(pkg_result)
    items = analyzer.list_analyses()
    assert len(items) >= 1


def test_list_analyses_org_isolation(analyzer):
    """list_analyses respects org_id isolation."""
    pkg_result = analyzer.analyze_package("flask", "3.0.0", "pypi")
    analyzer.store_analysis(pkg_result, org_id="org-A")
    items_b = analyzer.list_analyses(org_id="org-B")
    # org-B should have no items
    assert all(item.get("org_id", "org-B") != "org-A" for item in items_b)


# ---------------------------------------------------------------------------
# get_risk_summary
# ---------------------------------------------------------------------------


def test_get_risk_summary_returns_dict(analyzer):
    """get_risk_summary returns a dict with expected keys."""
    summary = analyzer.get_risk_summary()
    assert isinstance(summary, dict)
    assert "total_analyzed" in summary
    assert "high_risk_packages" in summary
    assert "known_malicious_detected" in summary


def test_get_risk_summary_counts_stored(analyzer):
    """get_risk_summary counts reflect stored analyses."""
    pkg = analyzer.analyze_package("requests", "2.31.0", "pypi")
    analyzer.store_analysis(pkg)
    summary = analyzer.get_risk_summary()
    assert summary["total_analyzed"] >= 1


def test_get_risk_summary_malicious_count(analyzer):
    """known_malicious_detected increments for malicious packages."""
    malicious = analyzer.analyze_package("ctx", None, "pypi")
    analyzer.store_analysis(malicious)
    summary = analyzer.get_risk_summary()
    assert summary["known_malicious_detected"] >= 1
