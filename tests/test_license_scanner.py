"""Tests for suite-core/core/license_scanner.py and the license_scanner_router.

Covers:
- LicenseRisk enum values
- LicensePolicy enum values
- LicenseResult Pydantic model creation
- LicenseScanner.scan_requirements()
- LicenseScanner.scan_package_json()
- LicenseScanner.evaluate_policy()
- LicenseScanner.get_license_summary()
- LicenseScanner.set_policy()
- LicenseScanner.get_violations()
- Built-in package license database (100+ packages)
- SPDX → risk level mapping
- FastAPI router endpoints (6 endpoints)

No network access required. SQLite is in-memory (tmp dir).
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[1]
_SUITE_CORE = str(_REPO_ROOT / "suite-core")
if _SUITE_CORE not in sys.path:
    sys.path.insert(0, _SUITE_CORE)

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")

from core.license_scanner import (
    LicensePolicy,
    LicenseResult,
    LicenseRisk,
    LicenseScanner,
    _PACKAGE_LICENSE_DB,
    _SPDX_RISK_MAP,
    _normalize_license,
    _parse_package_name,
    _parse_version_from_requirement,
    _spdx_to_risk,
)


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def tmp_scanner(tmp_path):
    """LicenseScanner backed by a temp SQLite DB."""
    db = tmp_path / "license_test.db"
    return LicenseScanner(db_path=str(db))


@pytest.fixture
def sample_requirements():
    return """\
# ALDECI dependencies
flask==2.3.2
requests==2.31.0
fastapi==0.104.0
pydantic==2.4.2
# comment line
mysqlclient==2.1.1
"""


@pytest.fixture
def sample_package_json():
    return json.dumps({
        "name": "aldeci-ui",
        "version": "1.0.0",
        "dependencies": {
            "react": "^18.2.0",
            "axios": "^1.4.0",
            "lodash": "^4.17.21",
        },
        "devDependencies": {
            "vite": "^4.4.5",
            "eslint": "^8.45.0",
        },
    })


# ===========================================================================
# LicenseRisk enum
# ===========================================================================


class TestLicenseRiskEnum:
    def test_permissive_value(self):
        assert LicenseRisk.PERMISSIVE.value == "permissive"

    def test_weak_copyleft_value(self):
        assert LicenseRisk.WEAK_COPYLEFT.value == "weak_copyleft"

    def test_strong_copyleft_value(self):
        assert LicenseRisk.STRONG_COPYLEFT.value == "strong_copyleft"

    def test_network_copyleft_value(self):
        assert LicenseRisk.NETWORK_COPYLEFT.value == "network_copyleft"

    def test_commercial_value(self):
        assert LicenseRisk.COMMERCIAL.value == "commercial"

    def test_unknown_value(self):
        assert LicenseRisk.UNKNOWN.value == "unknown"

    def test_all_six_variants_present(self):
        assert len(LicenseRisk) == 6


# ===========================================================================
# LicensePolicy enum
# ===========================================================================


class TestLicensePolicyEnum:
    def test_allow_value(self):
        assert LicensePolicy.ALLOW.value == "allow"

    def test_warn_value(self):
        assert LicensePolicy.WARN.value == "warn"

    def test_block_value(self):
        assert LicensePolicy.BLOCK.value == "block"

    def test_all_three_variants_present(self):
        assert len(LicensePolicy) == 3


# ===========================================================================
# LicenseResult Pydantic model
# ===========================================================================


class TestLicenseResult:
    def test_create_basic(self):
        r = LicenseResult(
            package="flask",
            version="2.3.2",
            license_name="MIT",
            risk_level=LicenseRisk.PERMISSIVE,
            policy_action=LicensePolicy.ALLOW,
            spdx_id="MIT",
        )
        assert r.package == "flask"
        assert r.version == "2.3.2"
        assert r.license_name == "MIT"
        assert r.risk_level == LicenseRisk.PERMISSIVE
        assert r.policy_action == LicensePolicy.ALLOW
        assert r.spdx_id == "MIT"
        assert r.org_id == "default"
        assert r.id is not None
        assert r.scanned_at is not None

    def test_custom_org_id(self):
        r = LicenseResult(
            package="p",
            version="1.0",
            license_name="Apache-2.0",
            risk_level=LicenseRisk.PERMISSIVE,
            policy_action=LicensePolicy.ALLOW,
            spdx_id="Apache-2.0",
            org_id="acme-corp",
        )
        assert r.org_id == "acme-corp"

    def test_unique_ids(self):
        make = lambda: LicenseResult(  # noqa: E731
            package="x",
            version="1",
            license_name="MIT",
            risk_level=LicenseRisk.PERMISSIVE,
            policy_action=LicensePolicy.ALLOW,
            spdx_id="MIT",
        )
        assert make().id != make().id

    def test_blocked_result(self):
        r = LicenseResult(
            package="agpl-lib",
            version="3.0",
            license_name="AGPL-3.0-only",
            risk_level=LicenseRisk.NETWORK_COPYLEFT,
            policy_action=LicensePolicy.BLOCK,
            spdx_id="AGPL-3.0-only",
        )
        assert r.policy_action == LicensePolicy.BLOCK


# ===========================================================================
# Helpers
# ===========================================================================


class TestHelpers:
    def test_normalize_license_mit(self):
        assert _normalize_license("MIT") == "MIT"
        assert _normalize_license("mit") == "MIT"
        assert _normalize_license("MIT License") == "MIT"

    def test_normalize_license_apache(self):
        assert _normalize_license("Apache-2.0") == "Apache-2.0"
        assert _normalize_license("apache 2.0") == "Apache-2.0"
        assert _normalize_license("Apache License 2.0") == "Apache-2.0"

    def test_normalize_license_gpl(self):
        assert _normalize_license("GPL-3.0") == "GPL-3.0-only"
        assert _normalize_license("gpl-3.0") == "GPL-3.0-only"

    def test_normalize_license_agpl(self):
        assert _normalize_license("AGPL-3.0") == "AGPL-3.0-only"

    def test_normalize_license_unknown_passthrough(self):
        result = _normalize_license("SomeWeirdLicense")
        assert result == "SomeWeirdLicense"

    def test_spdx_to_risk_permissive(self):
        assert _spdx_to_risk("MIT") == LicenseRisk.PERMISSIVE
        assert _spdx_to_risk("Apache-2.0") == LicenseRisk.PERMISSIVE
        assert _spdx_to_risk("BSD-3-Clause") == LicenseRisk.PERMISSIVE

    def test_spdx_to_risk_weak_copyleft(self):
        assert _spdx_to_risk("LGPL-2.1-or-later") == LicenseRisk.WEAK_COPYLEFT
        assert _spdx_to_risk("MPL-2.0") == LicenseRisk.WEAK_COPYLEFT

    def test_spdx_to_risk_strong_copyleft(self):
        assert _spdx_to_risk("GPL-3.0-only") == LicenseRisk.STRONG_COPYLEFT
        assert _spdx_to_risk("GPL-2.0-only") == LicenseRisk.STRONG_COPYLEFT

    def test_spdx_to_risk_network_copyleft(self):
        assert _spdx_to_risk("AGPL-3.0-only") == LicenseRisk.NETWORK_COPYLEFT
        assert _spdx_to_risk("SSPL-1.0") == LicenseRisk.NETWORK_COPYLEFT

    def test_spdx_to_risk_commercial(self):
        assert _spdx_to_risk("LicenseRef-Proprietary") == LicenseRisk.COMMERCIAL

    def test_spdx_to_risk_unknown(self):
        assert _spdx_to_risk("SomeRandomLicense-99") == LicenseRisk.UNKNOWN

    def test_parse_package_name_simple(self):
        assert _parse_package_name("flask==2.3.2") == "flask"

    def test_parse_package_name_with_extras(self):
        assert _parse_package_name("requests>=2.0") == "requests"

    def test_parse_package_name_empty(self):
        assert _parse_package_name("") == ""

    def test_parse_version_from_requirement(self):
        assert _parse_version_from_requirement("flask==2.3.2") == "2.3.2"

    def test_parse_version_missing(self):
        assert _parse_version_from_requirement("flask>=2.0") == "unknown"


# ===========================================================================
# Built-in package database
# ===========================================================================


class TestPackageLicenseDB:
    def test_db_has_100_plus_entries(self):
        assert len(_PACKAGE_LICENSE_DB) >= 100

    def test_flask_is_mit(self):
        spdx, risk = _PACKAGE_LICENSE_DB["flask"]
        assert spdx == "MIT"
        assert risk == LicenseRisk.PERMISSIVE

    def test_requests_is_apache(self):
        spdx, risk = _PACKAGE_LICENSE_DB["requests"]
        assert spdx == "Apache-2.0"
        assert risk == LicenseRisk.PERMISSIVE

    def test_mysqlclient_is_strong_copyleft(self):
        spdx, risk = _PACKAGE_LICENSE_DB["mysqlclient"]
        assert risk == LicenseRisk.STRONG_COPYLEFT

    def test_psycopg2_is_weak_copyleft(self):
        spdx, risk = _PACKAGE_LICENSE_DB["psycopg2"]
        assert risk == LicenseRisk.WEAK_COPYLEFT

    def test_react_is_mit(self):
        spdx, risk = _PACKAGE_LICENSE_DB["react"]
        assert spdx == "MIT"
        assert risk == LicenseRisk.PERMISSIVE

    def test_spdx_map_size(self):
        assert len(_SPDX_RISK_MAP) >= 30


# ===========================================================================
# LicenseScanner.scan_requirements
# ===========================================================================


class TestScanRequirements:
    def test_returns_list(self, tmp_scanner, sample_requirements):
        results = tmp_scanner.scan_requirements(sample_requirements)
        assert isinstance(results, list)

    def test_parses_known_packages(self, tmp_scanner, sample_requirements):
        results = tmp_scanner.scan_requirements(sample_requirements)
        packages = [r.package for r in results]
        assert "flask" in packages
        assert "requests" in packages

    def test_skips_comment_lines(self, tmp_scanner):
        content = "# this is a comment\nflask==2.0.0\n"
        results = tmp_scanner.scan_requirements(content)
        assert len(results) == 1

    def test_skips_blank_lines(self, tmp_scanner):
        content = "\n\nflask==2.0.0\n\nrequests==2.31.0\n"
        results = tmp_scanner.scan_requirements(content)
        assert len(results) == 2

    def test_version_captured(self, tmp_scanner):
        content = "flask==2.3.2\n"
        results = tmp_scanner.scan_requirements(content)
        assert results[0].version == "2.3.2"

    def test_known_permissive_package(self, tmp_scanner):
        content = "fastapi==0.104.0\n"
        results = tmp_scanner.scan_requirements(content)
        assert results[0].risk_level == LicenseRisk.PERMISSIVE

    def test_known_strong_copyleft_package(self, tmp_scanner):
        content = "mysqlclient==2.1.1\n"
        results = tmp_scanner.scan_requirements(content)
        assert results[0].risk_level == LicenseRisk.STRONG_COPYLEFT

    def test_unknown_package_gets_unknown_risk(self, tmp_scanner):
        content = "some-obscure-package==99.0\n"
        results = tmp_scanner.scan_requirements(content)
        assert results[0].risk_level == LicenseRisk.UNKNOWN

    def test_results_persisted(self, tmp_scanner):
        content = "flask==2.3.2\n"
        tmp_scanner.scan_requirements(content, org_id="testorg")
        summary = tmp_scanner.get_license_summary("testorg")
        assert summary["total"] >= 1

    def test_org_id_assigned(self, tmp_scanner):
        content = "flask==2.3.2\n"
        results = tmp_scanner.scan_requirements(content, org_id="my-org")
        assert all(r.org_id == "my-org" for r in results)

    def test_empty_content_returns_empty(self, tmp_scanner):
        results = tmp_scanner.scan_requirements("")
        assert results == []

    def test_skips_git_plus_lines(self, tmp_scanner):
        content = "git+https://github.com/foo/bar.git\nflask==2.0\n"
        results = tmp_scanner.scan_requirements(content)
        assert len(results) == 1


# ===========================================================================
# LicenseScanner.scan_package_json
# ===========================================================================


class TestScanPackageJson:
    def test_returns_list(self, tmp_scanner, sample_package_json):
        results = tmp_scanner.scan_package_json(sample_package_json)
        assert isinstance(results, list)

    def test_parses_dependencies(self, tmp_scanner, sample_package_json):
        results = tmp_scanner.scan_package_json(sample_package_json)
        packages = [r.package for r in results]
        assert "react" in packages
        assert "axios" in packages

    def test_parses_dev_dependencies(self, tmp_scanner, sample_package_json):
        results = tmp_scanner.scan_package_json(sample_package_json)
        packages = [r.package for r in results]
        assert "vite" in packages
        assert "eslint" in packages

    def test_total_count(self, tmp_scanner, sample_package_json):
        results = tmp_scanner.scan_package_json(sample_package_json)
        # 3 deps + 2 devDeps
        assert len(results) == 5

    def test_version_stripped_of_caret(self, tmp_scanner):
        content = json.dumps({"dependencies": {"react": "^18.2.0"}})
        results = tmp_scanner.scan_package_json(content)
        assert results[0].version == "18.2.0"

    def test_invalid_json_returns_empty(self, tmp_scanner):
        results = tmp_scanner.scan_package_json("not json at all")
        assert results == []

    def test_empty_json_object_returns_empty(self, tmp_scanner):
        results = tmp_scanner.scan_package_json("{}")
        assert results == []

    def test_react_is_permissive(self, tmp_scanner):
        content = json.dumps({"dependencies": {"react": "^18.2.0"}})
        results = tmp_scanner.scan_package_json(content)
        assert results[0].risk_level == LicenseRisk.PERMISSIVE

    def test_org_id_assigned(self, tmp_scanner, sample_package_json):
        results = tmp_scanner.scan_package_json(sample_package_json, org_id="ui-team")
        assert all(r.org_id == "ui-team" for r in results)


# ===========================================================================
# LicenseScanner.evaluate_policy
# ===========================================================================


class TestEvaluatePolicy:
    def _make_result(self, spdx_id: str, risk: LicenseRisk) -> LicenseResult:
        return LicenseResult(
            package="test-pkg",
            version="1.0",
            license_name=spdx_id,
            risk_level=risk,
            policy_action=LicensePolicy.ALLOW,
            spdx_id=spdx_id,
        )

    def test_block_overrides_allow(self, tmp_scanner):
        r = self._make_result("GPL-3.0-only", LicenseRisk.STRONG_COPYLEFT)
        policy = {"blocked_licenses": ["GPL-3.0-only"]}
        updated = tmp_scanner.evaluate_policy([r], policy)
        assert updated[0].policy_action == LicensePolicy.BLOCK

    def test_allowed_list_warns_others(self, tmp_scanner):
        r = self._make_result("BSD-3-Clause", LicenseRisk.PERMISSIVE)
        policy = {"allowed_licenses": ["MIT", "Apache-2.0"]}
        updated = tmp_scanner.evaluate_policy([r], policy)
        assert updated[0].policy_action == LicensePolicy.WARN

    def test_allowed_list_permits_listed(self, tmp_scanner):
        r = self._make_result("MIT", LicenseRisk.PERMISSIVE)
        policy = {"allowed_licenses": ["MIT", "Apache-2.0"]}
        updated = tmp_scanner.evaluate_policy([r], policy)
        assert updated[0].policy_action == LicensePolicy.ALLOW

    def test_empty_policy_uses_defaults(self, tmp_scanner):
        r = self._make_result("MIT", LicenseRisk.PERMISSIVE)
        updated = tmp_scanner.evaluate_policy([r], {})
        assert updated[0].policy_action == LicensePolicy.ALLOW

    def test_network_copyleft_blocked_by_default(self, tmp_scanner):
        r = self._make_result("AGPL-3.0-only", LicenseRisk.NETWORK_COPYLEFT)
        updated = tmp_scanner.evaluate_policy([r], {})
        assert updated[0].policy_action == LicensePolicy.BLOCK

    def test_returns_same_count(self, tmp_scanner):
        results = [
            self._make_result("MIT", LicenseRisk.PERMISSIVE),
            self._make_result("GPL-3.0-only", LicenseRisk.STRONG_COPYLEFT),
            self._make_result("AGPL-3.0-only", LicenseRisk.NETWORK_COPYLEFT),
        ]
        updated = tmp_scanner.evaluate_policy(results, {})
        assert len(updated) == 3

    def test_original_not_mutated(self, tmp_scanner):
        r = self._make_result("MIT", LicenseRisk.PERMISSIVE)
        original_action = r.policy_action
        tmp_scanner.evaluate_policy([r], {"blocked_licenses": ["MIT"]})
        assert r.policy_action == original_action


# ===========================================================================
# LicenseScanner.get_license_summary
# ===========================================================================


class TestGetLicenseSummary:
    def test_empty_org_returns_zero(self, tmp_scanner):
        summary = tmp_scanner.get_license_summary("nonexistent-org")
        assert summary["total"] == 0
        assert summary["by_risk"] == {}
        assert summary["by_policy"] == {}

    def test_summary_after_scan(self, tmp_scanner):
        tmp_scanner.scan_requirements("flask==2.3.2\nmysqlclient==2.1.1\n", org_id="s-org")
        summary = tmp_scanner.get_license_summary("s-org")
        assert summary["total"] == 2
        assert "permissive" in summary["by_risk"] or "strong_copyleft" in summary["by_risk"]

    def test_summary_org_id_in_response(self, tmp_scanner):
        summary = tmp_scanner.get_license_summary("my-org")
        assert summary["org_id"] == "my-org"

    def test_summary_has_generated_at(self, tmp_scanner):
        summary = tmp_scanner.get_license_summary("x")
        assert "generated_at" in summary

    def test_by_policy_counts(self, tmp_scanner):
        tmp_scanner.scan_requirements("flask==2.0\n", org_id="pol-org")
        summary = tmp_scanner.get_license_summary("pol-org")
        assert "allow" in summary["by_policy"]


# ===========================================================================
# LicenseScanner.set_policy / get_violations
# ===========================================================================


class TestPolicyAndViolations:
    def test_set_policy_persists(self, tmp_scanner):
        tmp_scanner.set_policy("acme", {"blocked_licenses": ["GPL-3.0-only"]})
        policy = tmp_scanner._get_org_policy("acme")
        assert "blocked_licenses" in policy
        assert "GPL-3.0-only" in policy["blocked_licenses"]

    def test_set_policy_multiple_rules(self, tmp_scanner):
        tmp_scanner.set_policy("corp", {
            "blocked_licenses": ["AGPL-3.0-only"],
            "allowed_licenses": ["MIT", "Apache-2.0"],
        })
        policy = tmp_scanner._get_org_policy("corp")
        assert len(policy) == 2

    def test_set_policy_overwrite(self, tmp_scanner):
        tmp_scanner.set_policy("org1", {"blocked_licenses": ["GPL-3.0-only"]})
        tmp_scanner.set_policy("org1", {"blocked_licenses": ["AGPL-3.0-only"]})
        policy = tmp_scanner._get_org_policy("org1")
        assert "AGPL-3.0-only" in policy["blocked_licenses"]

    def test_violations_empty_without_blocks(self, tmp_scanner):
        tmp_scanner.scan_requirements("flask==2.0\n", org_id="v-org")
        violations = tmp_scanner.get_violations("v-org")
        # flask is permissive → ALLOW by default, no violations
        assert violations == []

    def test_violations_returned_after_blocked_scan(self, tmp_scanner):
        # Set policy to block network copyleft, then scan an unknown package
        # Use a package that returns NETWORK_COPYLEFT via the DB by setting policy
        tmp_scanner.set_policy("vio-org", {"blocked_licenses": ["GPL-2.0-only"]})
        tmp_scanner.scan_requirements("mysqlclient==2.1.1\n", org_id="vio-org")
        violations = tmp_scanner.get_violations("vio-org")
        assert len(violations) >= 1
        assert all(v.policy_action == LicensePolicy.BLOCK for v in violations)

    def test_violations_returns_list(self, tmp_scanner):
        result = tmp_scanner.get_violations("empty-org")
        assert isinstance(result, list)

    def test_violations_have_correct_org_id(self, tmp_scanner):
        tmp_scanner.set_policy("vorg2", {"blocked_licenses": ["GPL-2.0-only"]})
        tmp_scanner.scan_requirements("mysqlclient==2.1\n", org_id="vorg2")
        violations = tmp_scanner.get_violations("vorg2")
        assert all(v.org_id == "vorg2" for v in violations)


# ===========================================================================
# FastAPI router endpoint tests
# ===========================================================================


@pytest.fixture
def client(tmp_path):
    """TestClient for the license_scanner_router with isolated DB."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Patch the scanner to use tmp db
    db_file = str(tmp_path / "router_test.db")

    app = FastAPI()

    # Patch before importing router
    with patch("core.license_scanner._db_path", return_value=Path(db_file)):
        from apps.api.license_scanner_router import router
        app.include_router(router)
        yield TestClient(app)


class TestRouterScanRequirements:
    def test_200_with_valid_content(self, client):
        resp = client.post(
            "/api/v1/license-scanner/scan-requirements",
            json={"content": "flask==2.3.2\n"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert isinstance(data["results"], list)

    def test_400_on_empty_content(self, client):
        resp = client.post(
            "/api/v1/license-scanner/scan-requirements",
            json={"content": "   "},
        )
        assert resp.status_code == 400

    def test_response_shape(self, client):
        resp = client.post(
            "/api/v1/license-scanner/scan-requirements",
            json={"content": "requests==2.31.0\n", "org_id": "test-org"},
        )
        assert resp.status_code == 200
        item = resp.json()["results"][0]
        assert "package" in item
        assert "risk_level" in item
        assert "policy_action" in item
        assert "spdx_id" in item

    def test_org_id_in_response(self, client):
        resp = client.post(
            "/api/v1/license-scanner/scan-requirements",
            json={"content": "flask==2.0\n", "org_id": "acme"},
        )
        assert resp.json()["org_id"] == "acme"


class TestRouterScanPackageJson:
    def test_200_with_valid_json(self, client):
        pkg = json.dumps({"dependencies": {"react": "^18.0.0"}})
        resp = client.post(
            "/api/v1/license-scanner/scan-package-json",
            json={"content": pkg},
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_400_on_empty_content(self, client):
        resp = client.post(
            "/api/v1/license-scanner/scan-package-json",
            json={"content": ""},
        )
        assert resp.status_code == 400

    def test_invalid_json_returns_zero(self, client):
        resp = client.post(
            "/api/v1/license-scanner/scan-package-json",
            json={"content": "not-json-at-all"},
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 0


class TestRouterEvaluatePolicy:
    def test_200_with_packages(self, client):
        resp = client.post(
            "/api/v1/license-scanner/evaluate-policy",
            json={
                "packages": [{"package": "flask", "version": "2.3.2"}],
                "policy": {},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

    def test_block_policy_reflected(self, client):
        resp = client.post(
            "/api/v1/license-scanner/evaluate-policy",
            json={
                "packages": [{"package": "mysqlclient", "version": "2.1.1"}],
                "policy": {"blocked_licenses": ["GPL-2.0-only"]},
            },
        )
        assert resp.status_code == 200
        items = resp.json()["results"]
        blocked = [i for i in items if i["policy_action"] == "block"]
        assert len(blocked) >= 1


class TestRouterSummary:
    def test_200_empty_org(self, client):
        resp = client.get("/api/v1/license-scanner/summary?org_id=new-org")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["org_id"] == "new-org"

    def test_default_org_id(self, client):
        resp = client.get("/api/v1/license-scanner/summary")
        assert resp.status_code == 200
        assert resp.json()["org_id"] == "default"


class TestRouterSetPolicy:
    def test_200_with_valid_rules(self, client):
        resp = client.post(
            "/api/v1/license-scanner/policy",
            json={
                "org_id": "my-org",
                "rules": {"blocked_licenses": ["AGPL-3.0-only"]},
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["rules_saved"] == 1
        assert data["status"] == "ok"

    def test_400_on_empty_rules(self, client):
        resp = client.post(
            "/api/v1/license-scanner/policy",
            json={"org_id": "my-org", "rules": {}},
        )
        assert resp.status_code == 400


class TestRouterViolations:
    def test_200_empty_violations(self, client):
        resp = client.get("/api/v1/license-scanner/violations?org_id=clean-org")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_violations"] == 0
        assert data["violations"] == []

    def test_default_org_id(self, client):
        resp = client.get("/api/v1/license-scanner/violations")
        assert resp.status_code == 200
        assert resp.json()["org_id"] == "default"
