"""
Tests for suite-core/core/license_auditor.py

Covers:
- LicenseCategory enum values
- classify_license: permissive, copyleft, proprietary, unknown
- fetch_pypi_license: success and network failure (mocked)
- audit_requirements: valid file, missing file, empty file
- audit_package_json: valid file, missing file
- _build_result: enrichment logic, high-risk flagging
- audit_summary: counts, risk_score, high_risk_packages list
- Risk flagging for copyleft and proprietary licenses
- UNKNOWN license handling
- Multiple dependency sections in package.json
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.license_auditor import (
    LicenseAuditor,
    LicenseAuditResult,
    LicenseCategory,
    _normalize_license,
    _parse_requirements_txt,
    _parse_package_json_deps,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def auditor() -> LicenseAuditor:
    """LicenseAuditor with PyPI fetching disabled (no network in tests)."""
    return LicenseAuditor(fetch_pypi=False)


@pytest.fixture
def tmp_requirements(tmp_path) -> Path:
    content = (
        "requests==2.28.2\n"
        "flask>=2.0\n"
        "# comment\n"
        "numpy==1.24.0\n"
    )
    p = tmp_path / "requirements.txt"
    p.write_text(content)
    return p


@pytest.fixture
def tmp_package_json(tmp_path) -> Path:
    data = {
        "name": "my-app",
        "version": "1.0.0",
        "dependencies": {"lodash": "^4.17.21", "express": "4.18.2"},
        "devDependencies": {"jest": "^29.0.0"},
    }
    p = tmp_path / "package.json"
    p.write_text(json.dumps(data))
    return p


@pytest.fixture
def copyleft_requirements(tmp_path) -> Path:
    content = "some-gpl-lib==1.0\nrequests==2.28.2\n"
    p = tmp_path / "requirements.txt"
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# LicenseCategory enum
# ---------------------------------------------------------------------------


def test_license_category_values():
    assert LicenseCategory.PERMISSIVE == "PERMISSIVE"
    assert LicenseCategory.COPYLEFT == "COPYLEFT"
    assert LicenseCategory.PROPRIETARY == "PROPRIETARY"
    assert LicenseCategory.UNKNOWN == "UNKNOWN"


# ---------------------------------------------------------------------------
# classify_license
# ---------------------------------------------------------------------------


def test_classify_mit_is_permissive(auditor):
    assert auditor.classify_license("MIT") == LicenseCategory.PERMISSIVE


def test_classify_apache_is_permissive(auditor):
    assert auditor.classify_license("Apache-2.0") == LicenseCategory.PERMISSIVE


def test_classify_bsd_is_permissive(auditor):
    assert auditor.classify_license("BSD-3-Clause") == LicenseCategory.PERMISSIVE


def test_classify_gpl_is_copyleft(auditor):
    assert auditor.classify_license("GPL-3.0") == LicenseCategory.COPYLEFT


def test_classify_lgpl_is_copyleft(auditor):
    assert auditor.classify_license("LGPL-2.1") == LicenseCategory.COPYLEFT


def test_classify_agpl_is_copyleft(auditor):
    assert auditor.classify_license("AGPL-3.0") == LicenseCategory.COPYLEFT


def test_classify_mpl_is_copyleft(auditor):
    assert auditor.classify_license("MPL-2.0") == LicenseCategory.COPYLEFT


def test_classify_proprietary(auditor):
    assert auditor.classify_license("Proprietary") == LicenseCategory.PROPRIETARY


def test_classify_commercial(auditor):
    assert auditor.classify_license("commercial") == LicenseCategory.PROPRIETARY


def test_classify_unknown_empty(auditor):
    assert auditor.classify_license("") == LicenseCategory.UNKNOWN


def test_classify_unknown_noassertion(auditor):
    assert auditor.classify_license("NOASSERTION") == LicenseCategory.UNKNOWN


def test_classify_unknown_random_string(auditor):
    # An unrecognised string should return UNKNOWN
    assert auditor.classify_license("XYZ-Custom-License-v9") == LicenseCategory.UNKNOWN


# ---------------------------------------------------------------------------
# fetch_pypi_license (mocked)
# ---------------------------------------------------------------------------


def test_fetch_pypi_license_success():
    auditor = LicenseAuditor(fetch_pypi=True)
    fake_response = {"info": {"license": "MIT"}}
    with patch("core.license_auditor._fetch_url_json", return_value=fake_response):
        result = auditor.fetch_pypi_license("requests")
    assert result == "MIT"


def test_fetch_pypi_license_network_failure():
    auditor = LicenseAuditor(fetch_pypi=True)
    with patch("core.license_auditor._fetch_url_json", return_value=None):
        result = auditor.fetch_pypi_license("requests")
    assert result == "UNKNOWN"


def test_fetch_pypi_license_empty_field():
    auditor = LicenseAuditor(fetch_pypi=True)
    fake_response = {"info": {"license": ""}}
    with patch("core.license_auditor._fetch_url_json", return_value=fake_response):
        result = auditor.fetch_pypi_license("somepackage")
    assert result == "UNKNOWN"


# ---------------------------------------------------------------------------
# audit_requirements
# ---------------------------------------------------------------------------


def test_audit_requirements_returns_results(auditor, tmp_requirements):
    results = auditor.audit_requirements(str(tmp_requirements))
    assert len(results) == 3  # requests, flask, numpy (comment skipped)
    names = [r.name for r in results]
    assert "requests" in names
    assert "flask" in names
    assert "numpy" in names


def test_audit_requirements_result_fields(auditor, tmp_requirements):
    results = auditor.audit_requirements(str(tmp_requirements))
    r = results[0]
    assert isinstance(r, LicenseAuditResult)
    assert r.ecosystem == "pypi"
    assert isinstance(r.category, LicenseCategory)
    assert isinstance(r.is_high_risk, bool)


def test_audit_requirements_file_not_found(auditor):
    with pytest.raises(FileNotFoundError):
        auditor.audit_requirements("/nonexistent/requirements.txt")


def test_audit_requirements_empty_file(auditor, tmp_path):
    p = tmp_path / "requirements.txt"
    p.write_text("# nothing here\n")
    results = auditor.audit_requirements(str(p))
    assert results == []


def test_audit_requirements_with_pypi_fetch(tmp_requirements):
    """Verify PyPI enrichment path is exercised without actual network."""
    auditor = LicenseAuditor(fetch_pypi=True)
    with patch("core.license_auditor._fetch_url_json", return_value={"info": {"license": "MIT"}}):
        results = auditor.audit_requirements(str(tmp_requirements))
    assert len(results) == 3
    # With MIT returned from PyPI, all should be PERMISSIVE
    for r in results:
        assert r.category == LicenseCategory.PERMISSIVE
        assert not r.is_high_risk


# ---------------------------------------------------------------------------
# audit_package_json
# ---------------------------------------------------------------------------


def test_audit_package_json_returns_results(auditor, tmp_package_json):
    results = auditor.audit_package_json(str(tmp_package_json))
    names = [r.name for r in results]
    assert "lodash" in names
    assert "express" in names
    assert "jest" in names


def test_audit_package_json_ecosystem(auditor, tmp_package_json):
    results = auditor.audit_package_json(str(tmp_package_json))
    for r in results:
        assert r.ecosystem == "npm"


def test_audit_package_json_file_not_found(auditor):
    with pytest.raises(FileNotFoundError):
        auditor.audit_package_json("/nonexistent/package.json")


# ---------------------------------------------------------------------------
# High-risk flagging
# ---------------------------------------------------------------------------


def test_copyleft_flagged_as_high_risk(auditor):
    result = auditor._build_result(
        name="gpl-lib", version="1.0", ecosystem="pypi",
        license_id="GPL-3.0"
    )
    assert result.is_high_risk is True
    assert result.category == LicenseCategory.COPYLEFT
    assert "copyleft" in result.risk_reason.lower() or "source code" in result.risk_reason.lower()


def test_proprietary_flagged_as_high_risk(auditor):
    result = auditor._build_result(
        name="closed-lib", version="2.0", ecosystem="pypi",
        license_id="Proprietary"
    )
    assert result.is_high_risk is True
    assert result.category == LicenseCategory.PROPRIETARY


def test_permissive_not_high_risk(auditor):
    result = auditor._build_result(
        name="requests", version="2.28.2", ecosystem="pypi",
        license_id="MIT"
    )
    assert result.is_high_risk is False
    assert result.category == LicenseCategory.PERMISSIVE
    assert result.risk_reason == ""


# ---------------------------------------------------------------------------
# audit_summary
# ---------------------------------------------------------------------------


def test_audit_summary_counts(auditor, tmp_requirements):
    results = auditor.audit_requirements(str(tmp_requirements))
    summary = auditor.audit_summary(results)
    assert summary["total"] == 3
    assert "permissive" in summary
    assert "copyleft" in summary
    assert "proprietary" in summary
    assert "unknown" in summary
    assert "high_risk_count" in summary
    assert "high_risk_packages" in summary
    assert "risk_score" in summary


def test_audit_summary_risk_score_range(auditor):
    results = [
        auditor._build_result("a", "1.0", "pypi", "GPL-3.0"),
        auditor._build_result("b", "1.0", "pypi", "MIT"),
    ]
    summary = auditor.audit_summary(results)
    assert 0.0 <= summary["risk_score"] <= 100.0


def test_audit_summary_high_risk_packages_list(auditor):
    results = [
        auditor._build_result("gpl-lib", "1.0", "pypi", "GPL-3.0"),
        auditor._build_result("requests", "2.28.2", "pypi", "MIT"),
    ]
    summary = auditor.audit_summary(results)
    assert summary["high_risk_count"] == 1
    assert summary["high_risk_packages"][0]["name"] == "gpl-lib"


def test_audit_summary_empty_results(auditor):
    summary = auditor.audit_summary([])
    assert summary["total"] == 0
    assert summary["high_risk_count"] == 0
    assert summary["high_risk_packages"] == []
