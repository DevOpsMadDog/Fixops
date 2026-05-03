"""Tests for GHSA advisory search — importer helpers + API router.

Covers:
  - parse_advisory: field extraction, CVE alias, severity, affected rows
  - list_advisories: empty store, filters (id, cve_id, ecosystem, package, severity, high+critical alias)
  - GET /api/v1/ghsa/advisories: 200, filter params, pagination fields

Usage:
    pytest tests/test_ghsa_advisory_search.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Path setup — mirrors other test files
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).parent.parent
_FEEDS_PATH = str(_REPO_ROOT / "suite-feeds")
_CORE_PATH = str(_REPO_ROOT / "suite-core")
_API_PATH = str(_REPO_ROOT / "suite-api")

for _p in (_FEEDS_PATH, _CORE_PATH, _API_PATH):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from feeds.ghsa.importer import (
    _extract_cve_alias,
    _extract_severity,
    _flatten_range,
    _is_reviewed_advisory,
    list_advisories,
    parse_advisory,
)


# ---------------------------------------------------------------------------
# Sample OSV advisory fixture
# ---------------------------------------------------------------------------

def _make_osv(
    ghsa_id: str = "GHSA-test-0001-abcd",
    cve: str = "CVE-2024-99999",
    severity_label: str = "HIGH",
    ecosystem: str = "PyPI",
    package_name: str = "requests",
    fixed: str = "2.32.0",
    summary: str = "Test advisory summary",
) -> Dict[str, Any]:
    return {
        "id": ghsa_id,
        "summary": summary,
        "details": "Detailed description here.",
        "aliases": [cve],
        "database_specific": {"severity": severity_label},
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": package_name},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": fixed}],
                    }
                ],
            }
        ],
        "references": [{"url": f"https://github.com/advisories/{ghsa_id}"}],
        "published": "2024-01-01T00:00:00Z",
        "modified": "2024-01-02T00:00:00Z",
        "schema_version": "1.4.0",
    }


# ===========================================================================
# 1. _extract_cve_alias
# ===========================================================================

class TestExtractCveAlias:
    def test_extracts_cve_from_aliases(self):
        assert _extract_cve_alias(["CVE-2024-12345"]) == "CVE-2024-12345"

    def test_returns_first_cve(self):
        assert _extract_cve_alias(["GHSA-xxxx", "CVE-2023-00001"]) == "CVE-2023-00001"

    def test_normalises_to_uppercase(self):
        assert _extract_cve_alias(["cve-2024-11111"]) == "CVE-2024-11111"

    def test_no_cve_returns_empty(self):
        assert _extract_cve_alias(["GHSA-only"]) == ""

    def test_non_list_returns_empty(self):
        assert _extract_cve_alias(None) == ""
        assert _extract_cve_alias("CVE-2024-12345") == ""

    def test_empty_list_returns_empty(self):
        assert _extract_cve_alias([]) == ""


# ===========================================================================
# 2. _extract_severity
# ===========================================================================

class TestExtractSeverity:
    def test_reads_database_specific_severity(self):
        doc = {"database_specific": {"severity": "CRITICAL"}}
        assert _extract_severity(doc) == "critical"

    def test_moderate_is_preserved(self):
        doc = {"database_specific": {"severity": "MODERATE"}}
        assert _extract_severity(doc) == "moderate"

    def test_falls_back_to_unknown(self):
        assert _extract_severity({}) == "unknown"

    def test_strips_whitespace(self):
        doc = {"database_specific": {"severity": "  HIGH  "}}
        assert _extract_severity(doc) == "high"


# ===========================================================================
# 3. _flatten_range
# ===========================================================================

class TestFlattenRange:
    def test_extracts_fixed_version(self):
        ranges = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]
        vuln, fixed = _flatten_range(ranges)
        assert "1.2.3" in fixed
        assert "fixed=1.2.3" in vuln

    def test_empty_ranges_returns_empty_strings(self):
        assert _flatten_range([]) == ("", "")
        assert _flatten_range(None) == ("", "")

    def test_introduced_appears_in_vuln(self):
        ranges = [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}]}]
        vuln, _ = _flatten_range(ranges)
        assert "introduced=2.0.0" in vuln


# ===========================================================================
# 4. _is_reviewed_advisory
# ===========================================================================

class TestIsReviewedAdvisory:
    def test_valid_path_returns_true(self):
        p = "advisories/github-reviewed/2024/01/GHSA-xxxx-yyyy-zzzz/GHSA-xxxx-yyyy-zzzz.json"
        assert _is_reviewed_advisory(p) is True

    def test_non_json_returns_false(self):
        p = "advisories/github-reviewed/2024/01/GHSA-xxxx-yyyy-zzzz/GHSA-xxxx-yyyy-zzzz.txt"
        assert _is_reviewed_advisory(p) is False

    def test_non_ghsa_json_returns_false(self):
        p = "advisories/github-reviewed/2024/01/other/other.json"
        assert _is_reviewed_advisory(p) is False

    def test_unreviewed_path_returns_false(self):
        p = "advisories/unreviewed/2024/01/GHSA-xxxx-yyyy-zzzz/GHSA-xxxx-yyyy-zzzz.json"
        assert _is_reviewed_advisory(p) is False


# ===========================================================================
# 5. parse_advisory
# ===========================================================================

class TestParseAdvisory:
    def test_returns_dict_for_valid_osv(self):
        result = parse_advisory(_make_osv())
        assert isinstance(result, dict)

    def test_ghsa_id_preserved(self):
        result = parse_advisory(_make_osv(ghsa_id="GHSA-abcd-1234-wxyz"))
        assert result["ghsa_id"] == "GHSA-abcd-1234-wxyz"

    def test_cve_alias_extracted(self):
        result = parse_advisory(_make_osv(cve="CVE-2024-11111"))
        assert result["cve_alias"] == "CVE-2024-11111"

    def test_severity_lowercased(self):
        result = parse_advisory(_make_osv(severity_label="CRITICAL"))
        assert result["severity"] == "critical"

    def test_ecosystems_list(self):
        result = parse_advisory(_make_osv(ecosystem="npm"))
        assert "npm" in result["ecosystems"]

    def test_packages_list(self):
        result = parse_advisory(_make_osv(package_name="lodash"))
        assert "lodash" in result["packages"]

    def test_affected_contains_package_entry(self):
        result = parse_advisory(_make_osv(package_name="pillow"))
        assert any(a["package_name"] == "pillow" for a in result["affected"])

    def test_fixed_version_in_affected(self):
        result = parse_advisory(_make_osv(fixed="3.0.0"))
        affected = result["affected"]
        assert any("3.0.0" in a.get("patched_versions", "") for a in affected)

    def test_summary_preserved(self):
        result = parse_advisory(_make_osv(summary="Heap overflow in libfoo"))
        assert result["summary"] == "Heap overflow in libfoo"

    def test_references_extracted(self):
        result = parse_advisory(_make_osv(ghsa_id="GHSA-ref-test-1234"))
        assert any("GHSA-ref-test-1234" in r for r in result["references"])

    def test_returns_none_for_non_ghsa_id(self):
        doc = _make_osv()
        doc["id"] = "CVE-2024-99999"
        assert parse_advisory(doc) is None

    def test_returns_none_for_missing_id(self):
        doc = _make_osv()
        del doc["id"]
        assert parse_advisory(doc) is None

    def test_returns_none_for_non_dict(self):
        assert parse_advisory("not a dict") is None
        assert parse_advisory(None) is None

    def test_imported_at_set(self):
        result = parse_advisory(_make_osv())
        assert "imported_at" in result
        assert result["imported_at"]


# ===========================================================================
# 6. list_advisories — in-memory store injection
# ===========================================================================

def _make_store(records: list) -> dict:
    """Return a simple dict keyed by ghsa_id."""
    return {r["ghsa_id"]: r for r in records}


def _sample_records():
    return [
        parse_advisory(_make_osv(
            ghsa_id="GHSA-aaaa-0001-xxxx", cve="CVE-2024-00001",
            severity_label="HIGH", ecosystem="PyPI", package_name="requests",
        )),
        parse_advisory(_make_osv(
            ghsa_id="GHSA-bbbb-0002-yyyy", cve="CVE-2024-00002",
            severity_label="CRITICAL", ecosystem="npm", package_name="lodash",
        )),
        parse_advisory(_make_osv(
            ghsa_id="GHSA-cccc-0003-zzzz", cve="CVE-2024-00003",
            severity_label="LOW", ecosystem="PyPI", package_name="flask",
        )),
        parse_advisory(_make_osv(
            ghsa_id="GHSA-dddd-0004-wwww", cve="CVE-2024-00004",
            severity_label="MODERATE", ecosystem="Maven", package_name="log4j",
        )),
    ]


class TestListAdvisories:
    def setup_method(self):
        self._records = _sample_records()
        self._store = _make_store(self._records)

    def _run(self, **kwargs):
        with patch("feeds.ghsa.importer._get_store", return_value=self._store):
            return list_advisories(**kwargs)

    def test_returns_all_when_no_filters(self):
        results = self._run()
        assert len(results) == 4

    def test_filter_by_exact_ghsa_id(self):
        results = self._run(id="GHSA-aaaa-0001-xxxx")
        assert len(results) == 1
        assert results[0]["ghsa_id"] == "GHSA-aaaa-0001-xxxx"

    def test_filter_by_ghsa_id_case_insensitive(self):
        results = self._run(id="ghsa-aaaa-0001-xxxx")
        assert len(results) == 1

    def test_filter_by_cve_id(self):
        results = self._run(cve_id="CVE-2024-00002")
        assert len(results) == 1
        assert results[0]["ghsa_id"] == "GHSA-bbbb-0002-yyyy"

    def test_filter_by_cve_id_case_insensitive(self):
        results = self._run(cve_id="cve-2024-00002")
        assert len(results) == 1

    def test_filter_by_ecosystem(self):
        results = self._run(ecosystem="PyPI")
        assert len(results) == 2
        for r in results:
            assert "PyPI" in r["ecosystems"]

    def test_filter_by_ecosystem_case_insensitive(self):
        results = self._run(ecosystem="pypi")
        assert len(results) == 2

    def test_filter_by_package(self):
        results = self._run(package="lodash")
        assert len(results) == 1
        assert results[0]["ghsa_id"] == "GHSA-bbbb-0002-yyyy"

    def test_filter_by_severity_single(self):
        results = self._run(severity="high")
        assert len(results) == 1
        assert results[0]["severity"] == "high"

    def test_filter_by_severity_critical(self):
        results = self._run(severity="critical")
        assert len(results) == 1
        assert results[0]["severity"] == "critical"

    def test_filter_by_severity_comma_list(self):
        results = self._run(severity="high,critical")
        assert len(results) == 2
        sevs = {r["severity"] for r in results}
        assert sevs == {"high", "critical"}

    def test_filter_by_severity_high_plus_critical_alias(self):
        results = self._run(severity="high+critical")
        assert len(results) == 2

    def test_filter_by_severity_low(self):
        results = self._run(severity="low")
        assert len(results) == 1
        assert results[0]["severity"] == "low"

    def test_limit_applied(self):
        results = self._run(limit=2)
        assert len(results) == 2

    def test_offset_applied(self):
        all_results = self._run()
        offset_results = self._run(offset=2)
        assert len(offset_results) == 2
        assert offset_results[0] == all_results[2]

    def test_limit_and_offset_combined(self):
        results = self._run(limit=1, offset=1)
        assert len(results) == 1

    def test_empty_store_returns_empty_list(self):
        with patch("feeds.ghsa.importer._get_store", return_value={}):
            results = list_advisories()
        assert results == []

    def test_no_match_returns_empty_list(self):
        results = self._run(id="GHSA-zzzz-9999-xxxx")
        assert results == []

    def test_combined_filters_ecosystem_and_severity(self):
        results = self._run(ecosystem="PyPI", severity="high")
        assert len(results) == 1
        assert results[0]["ghsa_id"] == "GHSA-aaaa-0001-xxxx"

    def test_non_dict_values_in_store_skipped(self):
        store = dict(self._store)
        store["bad_key"] = "not a dict"
        with patch("feeds.ghsa.importer._get_store", return_value=store):
            results = list_advisories()
        assert len(results) == 4


# ===========================================================================
# 7. GHSA router — GET /api/v1/ghsa/advisories
# ===========================================================================

try:
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    _TESTCLIENT_AVAILABLE = True
except ImportError:
    _TESTCLIENT_AVAILABLE = False


def _make_ghsa_app():
    suite_api_path = str(_REPO_ROOT / "suite-api")
    if suite_api_path not in sys.path:
        sys.path.insert(0, suite_api_path)

    from apps.api.ghsa_router import router
    import apps.api.auth_deps as auth_deps

    app = FastAPI()

    async def no_auth():
        return None

    app.dependency_overrides[auth_deps.api_key_auth] = no_auth
    app.include_router(router)
    return app


def _mock_advisories():
    return [
        {
            "ghsa_id": "GHSA-aaaa-0001-xxxx",
            "cve_alias": "CVE-2024-00001",
            "summary": "Test high advisory",
            "severity": "high",
            "ecosystems": ["PyPI"],
            "packages": ["requests"],
        },
        {
            "ghsa_id": "GHSA-bbbb-0002-yyyy",
            "cve_alias": "CVE-2024-00002",
            "summary": "Test critical advisory",
            "severity": "critical",
            "ecosystems": ["npm"],
            "packages": ["lodash"],
        },
    ]


@pytest.mark.skipif(not _TESTCLIENT_AVAILABLE, reason="fastapi not available")
class TestGhsaAdvisorySearchRouter:
    @pytest.fixture(autouse=True)
    def setup(self):
        app = _make_ghsa_app()
        self.http = TestClient(app)

    def _patch_list(self, advisories=None):
        if advisories is None:
            advisories = _mock_advisories()
        return patch(
            "apps.api.ghsa_router._get_importer",
            return_value=(MagicMock(), lambda **kw: advisories, MagicMock()),
        )

    def test_advisories_returns_200(self):
        with self._patch_list():
            resp = self.http.get("/api/v1/ghsa/advisories")
        assert resp.status_code == 200

    def test_advisories_response_has_required_keys(self):
        with self._patch_list():
            resp = self.http.get("/api/v1/ghsa/advisories")
        data = resp.json()
        assert "advisories" in data
        assert "total" in data
        assert "offset" in data
        assert "limit" in data

    def test_advisories_list_is_list(self):
        with self._patch_list():
            resp = self.http.get("/api/v1/ghsa/advisories")
        assert isinstance(resp.json()["advisories"], list)

    def test_advisories_total_matches_list_length(self):
        with self._patch_list():
            resp = self.http.get("/api/v1/ghsa/advisories")
        data = resp.json()
        assert data["total"] == len(data["advisories"])

    def test_advisories_filter_by_severity_param(self):
        filtered = [_mock_advisories()[0]]  # high only
        with patch(
            "apps.api.ghsa_router._get_importer",
            return_value=(MagicMock(), lambda **kw: filtered, MagicMock()),
        ):
            resp = self.http.get("/api/v1/ghsa/advisories?severity=high")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1

    def test_advisories_filter_by_ecosystem_param(self):
        filtered = [_mock_advisories()[0]]
        with patch(
            "apps.api.ghsa_router._get_importer",
            return_value=(MagicMock(), lambda **kw: filtered, MagicMock()),
        ):
            resp = self.http.get("/api/v1/ghsa/advisories?ecosystem=PyPI")
        assert resp.status_code == 200

    def test_advisories_empty_store_returns_200_with_empty_list(self):
        with patch(
            "apps.api.ghsa_router._get_importer",
            return_value=(MagicMock(), lambda **kw: [], MagicMock()),
        ):
            resp = self.http.get("/api/v1/ghsa/advisories")
        assert resp.status_code == 200
        data = resp.json()
        assert data["advisories"] == []
        assert data["total"] == 0

    def test_advisories_offset_reflected_in_response(self):
        with self._patch_list():
            resp = self.http.get("/api/v1/ghsa/advisories?offset=10")
        assert resp.json()["offset"] == 10

    def test_advisories_limit_reflected_in_response(self):
        with self._patch_list():
            resp = self.http.get("/api/v1/ghsa/advisories?limit=50")
        assert resp.json()["limit"] == 50

    def test_advisories_limit_below_1_returns_422(self):
        resp = self.http.get("/api/v1/ghsa/advisories?limit=0")
        assert resp.status_code == 422

    def test_advisories_limit_above_5000_returns_422(self):
        resp = self.http.get("/api/v1/ghsa/advisories?limit=5001")
        assert resp.status_code == 422

    def test_advisories_offset_below_0_returns_422(self):
        resp = self.http.get("/api/v1/ghsa/advisories?offset=-1")
        assert resp.status_code == 422

    def test_advisories_500_on_importer_exception(self):
        def _boom(**kw):
            raise RuntimeError("DB corrupted")

        with patch(
            "apps.api.ghsa_router._get_importer",
            return_value=(MagicMock(), _boom, MagicMock()),
        ):
            resp = self.http.get("/api/v1/ghsa/advisories")
        assert resp.status_code == 500
