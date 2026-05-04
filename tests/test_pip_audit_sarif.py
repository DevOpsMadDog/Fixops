"""Tests for scanner_parsers.pip_audit_to_sarif.

Covers:
- Valid pip-audit JSON → SARIF v2.1.0 schema shape
- rules[] populated: one rule per unique vuln id
- results[] populated: one result per (package, vuln) pair
- level=error for all results
- CVE alias captured in rule properties.cves
- Empty dependencies list → valid empty SARIF (zero rules, zero results)
- Malformed JSON bytes → valid empty SARIF (no crash)
- Empty bytes → valid empty SARIF (no crash)
- Package with multiple vulns → multiple results, deduplicated rules
- Rule deduplication: same vuln id across two packages → one rule, two results
- helpUri for GHSA vuln points at github.com/advisories
- helpUri for CVE-only vuln points at nvd.nist.gov
- fix_versions captured in rule properties
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_CORE = _ROOT / "suite-core" / "core"
if str(_CORE.parent) not in sys.path:
    sys.path.insert(0, str(_CORE.parent))

from core.scanner_parsers import pip_audit_to_sarif  # noqa: E402

# ---------------------------------------------------------------------------
# Schema constants (must match the converter)
# ---------------------------------------------------------------------------
_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
_SARIF_VERSION = "2.1.0"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _encode(obj: Any) -> bytes:
    return json.dumps(obj).encode()


def _valid_pip_audit(deps: list | None = None, version: str = "2.4.0") -> bytes:
    payload: Dict[str, Any] = {"pip_audit_version": version}
    if deps is not None:
        payload["dependencies"] = deps
    return _encode(payload)


def _single_vuln_dep(
    name: str = "requests",
    version: str = "2.28.0",
    vid: str = "GHSA-j8r2-6x86-q33q",
    aliases: list | None = None,
    description: str = "Sensitive information disclosure",
    fix_versions: list | None = None,
) -> dict:
    return {
        "name": name,
        "version": version,
        "vulns": [
            {
                "id": vid,
                "description": description,
                "fix_versions": fix_versions or ["2.31.0"],
                "aliases": aliases or ["CVE-2023-32681"],
            }
        ],
    }


def _assert_empty_sarif(sarif: dict) -> None:
    assert sarif["$schema"] == _SARIF_SCHEMA
    assert sarif["version"] == _SARIF_VERSION
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPipAuditToSarif:

    def test_sarif_schema_and_version(self):
        sarif = pip_audit_to_sarif(_valid_pip_audit([_single_vuln_dep()]))
        assert sarif["$schema"] == _SARIF_SCHEMA
        assert sarif["version"] == _SARIF_VERSION

    def test_runs_array_present(self):
        sarif = pip_audit_to_sarif(_valid_pip_audit([_single_vuln_dep()]))
        assert isinstance(sarif.get("runs"), list)
        assert len(sarif["runs"]) == 1

    def test_single_vuln_one_rule_one_result(self):
        sarif = pip_audit_to_sarif(_valid_pip_audit([_single_vuln_dep()]))
        run = sarif["runs"][0]
        assert len(run["tool"]["driver"]["rules"]) == 1
        assert len(run["results"]) == 1

    def test_result_level_is_error(self):
        sarif = pip_audit_to_sarif(_valid_pip_audit([_single_vuln_dep()]))
        result = sarif["runs"][0]["results"][0]
        assert result["level"] == "error"

    def test_rule_default_level_is_error(self):
        sarif = pip_audit_to_sarif(_valid_pip_audit([_single_vuln_dep()]))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"]["level"] == "error"

    def test_cve_alias_captured(self):
        dep = _single_vuln_dep(aliases=["CVE-2023-32681"])
        sarif = pip_audit_to_sarif(_valid_pip_audit([dep]))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "CVE-2023-32681" in rule["properties"]["cves"]

    def test_ghsa_help_uri(self):
        dep = _single_vuln_dep(vid="GHSA-j8r2-6x86-q33q", aliases=[])
        sarif = pip_audit_to_sarif(_valid_pip_audit([dep]))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "github.com/advisories" in rule["helpUri"]

    def test_cve_only_help_uri(self):
        dep = _single_vuln_dep(vid="CVE-2022-0001", aliases=[], fix_versions=["1.0.1"])
        sarif = pip_audit_to_sarif(_valid_pip_audit([dep]))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "nvd.nist.gov" in rule["helpUri"]

    def test_fix_versions_in_rule_properties(self):
        dep = _single_vuln_dep(fix_versions=["2.31.0", "3.0.0"])
        sarif = pip_audit_to_sarif(_valid_pip_audit([dep]))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "2.31.0" in rule["properties"]["fix_versions"]

    def test_package_with_multiple_vulns(self):
        dep = {
            "name": "flask",
            "version": "2.0.0",
            "vulns": [
                {"id": "GHSA-aaaa-bbbb-cccc", "description": "XSS",
                 "fix_versions": ["2.3.0"], "aliases": ["CVE-2023-0001"]},
                {"id": "GHSA-dddd-eeee-ffff", "description": "CSRF",
                 "fix_versions": ["2.3.0"], "aliases": ["CVE-2023-0002"]},
            ],
        }
        sarif = pip_audit_to_sarif(_valid_pip_audit([dep]))
        run = sarif["runs"][0]
        assert len(run["tool"]["driver"]["rules"]) == 2
        assert len(run["results"]) == 2

    def test_same_vuln_two_packages_one_rule_two_results(self):
        """Same vuln id in two different packages → one rule, two results."""
        dep1 = _single_vuln_dep(name="requests", version="2.28.0",
                                vid="GHSA-j8r2-6x86-q33q", aliases=[])
        dep2 = _single_vuln_dep(name="requests2", version="1.0.0",
                                vid="GHSA-j8r2-6x86-q33q", aliases=[])
        sarif = pip_audit_to_sarif(_valid_pip_audit([dep1, dep2]))
        run = sarif["runs"][0]
        assert len(run["tool"]["driver"]["rules"]) == 1
        assert len(run["results"]) == 2

    def test_empty_dependencies(self):
        sarif = pip_audit_to_sarif(_valid_pip_audit([]))
        _assert_empty_sarif(sarif)

    def test_missing_dependencies_key(self):
        sarif = pip_audit_to_sarif(_encode({"pip_audit_version": "2.4.0"}))
        _assert_empty_sarif(sarif)

    def test_malformed_json_no_crash(self):
        sarif = pip_audit_to_sarif(b"not-json-at-all!!!")
        _assert_empty_sarif(sarif)

    def test_empty_bytes_no_crash(self):
        sarif = pip_audit_to_sarif(b"")
        _assert_empty_sarif(sarif)

    def test_null_bytes_no_crash(self):
        sarif = pip_audit_to_sarif(b"null")
        _assert_empty_sarif(sarif)

    def test_json_array_root_no_crash(self):
        """If someone passes a JSON array (wrong format) → empty SARIF, no crash."""
        sarif = pip_audit_to_sarif(_encode([{"name": "x", "version": "1"}]))
        _assert_empty_sarif(sarif)

    def test_dep_missing_vulns_key(self):
        """Dependency with no 'vulns' key is skipped gracefully."""
        dep = {"name": "safe-package", "version": "1.0.0"}
        sarif = pip_audit_to_sarif(_valid_pip_audit([dep]))
        run = sarif["runs"][0]
        assert len(run["results"]) == 0

    def test_result_rule_index_consistent(self):
        """ruleIndex in result must match index of ruleId in rules array."""
        dep = _single_vuln_dep()
        sarif = pip_audit_to_sarif(_valid_pip_audit([dep]))
        run = sarif["runs"][0]
        result = run["results"][0]
        rule_id = result["ruleId"]
        rule_idx = result["ruleIndex"]
        assert run["tool"]["driver"]["rules"][rule_idx]["id"] == rule_id

    def test_result_message_contains_package_name(self):
        dep = _single_vuln_dep(name="urllib3", version="1.26.4")
        sarif = pip_audit_to_sarif(_valid_pip_audit([dep]))
        msg = sarif["runs"][0]["results"][0]["message"]["text"]
        assert "urllib3" in msg or "1.26.4" in msg

    def test_result_has_locations(self):
        dep = _single_vuln_dep()
        sarif = pip_audit_to_sarif(_valid_pip_audit([dep]))
        locs = sarif["runs"][0]["results"][0]["locations"]
        assert len(locs) >= 1

    def test_pip_audit_version_preserved(self):
        sarif = pip_audit_to_sarif(_valid_pip_audit([], version="2.7.3"))
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["version"] == "2.7.3"

    def test_tags_include_supply_chain(self):
        dep = _single_vuln_dep()
        sarif = pip_audit_to_sarif(_valid_pip_audit([dep]))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "supply-chain" in rule["properties"]["tags"]

    def test_aliases_stored_in_result_properties(self):
        dep = _single_vuln_dep(aliases=["CVE-2023-32681"])
        sarif = pip_audit_to_sarif(_valid_pip_audit([dep]))
        props = sarif["runs"][0]["results"][0]["properties"]
        assert "CVE-2023-32681" in props["aliases"]
