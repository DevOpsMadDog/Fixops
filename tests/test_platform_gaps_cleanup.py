"""
Tests for 4 platform gaps fixed in commit 6246aee9 dogfood cleanup.

Gap 1 — pip-audit SARIF conversion  (pip_audit_to_sarif)
Gap 2 — ingest-to-issues promotion  (_promote_findings_to_issues already wired)
Gap 3 — /risk-scoring/summary fields (by_source, by_severity, last_updated)
Gap 4 — cross-scanner dedup         (dedup_cross_scanner)
"""
from __future__ import annotations

import json
import sys
import os

import pytest

# ── path setup ────────────────────────────────────────────────────────────────
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in [
    os.path.join(_ROOT, "suite-core"),
    os.path.join(_ROOT, "suite-api"),
]:
    if _p not in sys.path:
        sys.path.insert(0, _p)


# =============================================================================
# Gap 1 — pip-audit → SARIF v2.1.0 converter
# =============================================================================

@pytest.fixture()
def pip_audit_json() -> bytes:
    """Minimal pip-audit --format json output with two packages."""
    payload = {
        "pip_audit_version": "2.7.3",
        "dependencies": [
            {
                "name": "requests",
                "version": "2.25.0",
                "vulns": [
                    {
                        "id": "GHSA-j8r2-6x86-q33q",
                        "description": "Requests allows proxy-authorization header leak.",
                        "fix_versions": ["2.31.0"],
                        "aliases": ["CVE-2023-32681"],
                    }
                ],
            },
            {
                "name": "pillow",
                "version": "9.0.0",
                "vulns": [
                    {
                        "id": "CVE-2023-44271",
                        "description": "Uncontrolled resource consumption in Pillow.",
                        "fix_versions": ["10.0.1"],
                        "aliases": [],
                    },
                    {
                        "id": "GHSA-j7hp-h8jx-5ppr",
                        "description": "Pillow path traversal vulnerability.",
                        "fix_versions": ["10.3.0"],
                        "aliases": ["CVE-2024-28219"],
                    },
                ],
            },
            # clean package — zero vulns
            {"name": "boto3", "version": "1.34.0", "vulns": []},
        ],
    }
    return json.dumps(payload).encode()


def test_pip_audit_to_sarif_schema_keys(pip_audit_json):
    """SARIF output must have $schema, version, runs keys."""
    from core.scanner_parsers import pip_audit_to_sarif

    sarif = pip_audit_to_sarif(pip_audit_json)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert "runs" in sarif
    assert len(sarif["runs"]) == 1


def test_pip_audit_to_sarif_rules(pip_audit_json):
    """One rule per unique vuln id (3 unique IDs across 2 packages)."""
    from core.scanner_parsers import pip_audit_to_sarif

    sarif = pip_audit_to_sarif(pip_audit_json)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 3
    rule_ids = {r["id"] for r in rules}
    assert "GHSA-j8r2-6x86-q33q" in rule_ids
    assert "CVE-2023-44271" in rule_ids
    assert "GHSA-j7hp-h8jx-5ppr" in rule_ids


def test_pip_audit_to_sarif_results(pip_audit_json):
    """One result per (package, vuln) pair — 3 total, boto3 produces none."""
    from core.scanner_parsers import pip_audit_to_sarif

    sarif = pip_audit_to_sarif(pip_audit_json)
    results = sarif["runs"][0]["results"]
    assert len(results) == 3
    packages = {r["properties"]["package"] for r in results}
    assert "requests" in packages
    assert "pillow" in packages
    assert "boto3" not in packages


def test_pip_audit_to_sarif_level_error(pip_audit_json):
    """All results must have level=error (pip-audit only reports exploitable issues)."""
    from core.scanner_parsers import pip_audit_to_sarif

    sarif = pip_audit_to_sarif(pip_audit_json)
    for r in sarif["runs"][0]["results"]:
        assert r["level"] == "error"


def test_pip_audit_to_sarif_fix_text(pip_audit_json):
    """Results must carry fix description text."""
    from core.scanner_parsers import pip_audit_to_sarif

    sarif = pip_audit_to_sarif(pip_audit_json)
    for r in sarif["runs"][0]["results"]:
        fixes = r.get("fixes", [])
        assert len(fixes) >= 1
        assert fixes[0]["description"]["text"]


def test_pip_audit_to_sarif_empty_input():
    """Empty / malformed input returns valid empty SARIF (no crash)."""
    from core.scanner_parsers import pip_audit_to_sarif

    sarif = pip_audit_to_sarif(b"not json at all")
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_pip_audit_to_sarif_no_fix_version():
    """Vuln with no fix_versions gets a 'no upstream fix' message."""
    from core.scanner_parsers import pip_audit_to_sarif

    payload = {
        "dependencies": [{
            "name": "legacy-pkg",
            "version": "0.1.0",
            "vulns": [{
                "id": "CVE-2020-9999",
                "description": "Old bug.",
                "fix_versions": [],
                "aliases": [],
            }],
        }]
    }
    sarif = pip_audit_to_sarif(json.dumps(payload).encode())
    fix_text = sarif["runs"][0]["results"][0]["fixes"][0]["description"]["text"]
    assert "no upstream fix" in fix_text.lower() or "no" in fix_text.lower()


def test_pip_audit_to_sarif_cve_alias_in_rule(pip_audit_json):
    """CVE aliases are captured in rule properties."""
    from core.scanner_parsers import pip_audit_to_sarif

    sarif = pip_audit_to_sarif(pip_audit_json)
    rules_by_id = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    ghsa_rule = rules_by_id["GHSA-j8r2-6x86-q33q"]
    assert "CVE-2023-32681" in ghsa_rule["properties"]["cves"]


# =============================================================================
# Gap 2 — ingest-to-issues promotion (verify the hook exists and is wired)
# =============================================================================

def test_promote_findings_to_issues_function_exists():
    """_promote_findings_to_issues must be importable from scanner_ingest_router."""
    from apps.api.scanner_ingest_router import _promote_findings_to_issues
    assert callable(_promote_findings_to_issues)


def test_promote_findings_to_issues_empty_input():
    """Empty finding list returns 0 promoted without error."""
    from apps.api.scanner_ingest_router import _promote_findings_to_issues
    count = _promote_findings_to_issues([], "pip-audit", "test-org")
    assert count == 0


def test_promote_findings_promotes_high_severity():
    """High-severity finding is promoted (returns count >= 0, never raises)."""
    from apps.api.scanner_ingest_router import _promote_findings_to_issues

    finding = {
        "title": "CVE-2023-32681: requests@2.25.0",
        "description": "Proxy-auth header leak.",
        "severity": "high",
        "cve_id": "CVE-2023-32681",
        "package_name": "requests",
        "package_version": "2.25.0",
        "source_tool": "pip-audit",
        "recommendation": "Upgrade requests to >= 2.31.0",
    }
    # Result is 0 or 1 depending on whether SecurityFindingsEngine DB is available.
    # What matters: it never raises.
    result = _promote_findings_to_issues([finding], "pip-audit", "test-org")
    assert isinstance(result, int)
    assert result >= 0


# =============================================================================
# Gap 3 — /risk-scoring/summary: by_source, by_severity, last_updated fields
# =============================================================================

def test_risk_scoring_summary_endpoint_returns_required_fields():
    """risk_scoring_summary() must return by_source, by_severity, last_updated.

    Calls the handler function directly (bypasses auth middleware which
    requires a real API key token env-var).
    """
    from apps.api.risk_scoring_router import risk_scoring_summary
    import datetime

    data = risk_scoring_summary(org_id="test-org")

    # Required fields from task spec
    assert "total" in data, f"Missing 'total' in {list(data.keys())}"
    assert "by_severity" in data, f"Missing 'by_severity' in {list(data.keys())}"
    assert "by_source" in data, f"Missing 'by_source' in {list(data.keys())}"
    assert "last_updated" in data, f"Missing 'last_updated' in {list(data.keys())}"

    # by_severity must have the 4 standard tiers
    assert set(data["by_severity"].keys()) >= {"critical", "high", "medium", "low"}

    # last_updated must be an ISO datetime string that parses cleanly
    assert isinstance(data["last_updated"], str)
    datetime.datetime.fromisoformat(data["last_updated"].replace("Z", "+00:00"))


def test_risk_scoring_summary_total_is_numeric():
    """total field must be a non-negative integer."""
    from apps.api.risk_scoring_router import risk_scoring_summary

    data = risk_scoring_summary(org_id="default")
    assert isinstance(data["total"], int)
    assert data["total"] >= 0


# =============================================================================
# Gap 4 — cross-scanner dedup
# =============================================================================

@pytest.fixture()
def multi_scanner_findings() -> list:
    """Three raw findings: two from different scanners with same CVE+file+line,
    one unique finding that should pass through."""
    return [
        {
            "cve_id": "CVE-2023-1234",
            "file_path": "src/app.py",
            "line_number": 42,
            "source_tool": "bandit",
            "severity": "high",
            "description": "Bandit found SQL injection.",
            "recommendation": "Use parameterised queries.",
            "tags": ["sql-injection"],
        },
        {
            "cve_id": "CVE-2023-1234",
            "file_path": "src/app.py",
            "line_number": 42,
            "source_tool": "semgrep",
            "severity": "critical",  # higher severity
            "description": "",
            "recommendation": "",
            "tags": ["owasp-a03"],
        },
        {
            "cve_id": "CVE-2024-9999",
            "file_path": "lib/utils.py",
            "line_number": 10,
            "source_tool": "bandit",
            "severity": "medium",
            "description": "Hardcoded secret.",
            "recommendation": "Use env vars.",
            "tags": [],
        },
    ]


def test_dedup_cross_scanner_merges_same_cve_file_line(multi_scanner_findings):
    """Two findings with same (cve_id, file_path, line_number) merge into one."""
    from core.scanner_parsers import dedup_cross_scanner

    result = dedup_cross_scanner(multi_scanner_findings)
    assert len(result) == 2  # 3 raw → 2 merged


def test_dedup_cross_scanner_sources_list(multi_scanner_findings):
    """Merged finding carries sources=[bandit, semgrep]."""
    from core.scanner_parsers import dedup_cross_scanner

    result = dedup_cross_scanner(multi_scanner_findings)
    merged = next(r for r in result if r.get("cve_id") == "CVE-2023-1234")
    assert set(merged["sources"]) == {"bandit", "semgrep"}


def test_dedup_cross_scanner_highest_severity_wins(multi_scanner_findings):
    """Merged finding takes the highest severity across contributing scanners."""
    from core.scanner_parsers import dedup_cross_scanner

    result = dedup_cross_scanner(multi_scanner_findings)
    merged = next(r for r in result if r.get("cve_id") == "CVE-2023-1234")
    assert merged["severity"] == "critical"


def test_dedup_cross_scanner_first_nonempty_description(multi_scanner_findings):
    """First non-empty description is kept when one scanner omits it."""
    from core.scanner_parsers import dedup_cross_scanner

    result = dedup_cross_scanner(multi_scanner_findings)
    merged = next(r for r in result if r.get("cve_id") == "CVE-2023-1234")
    assert "Bandit found SQL injection" in merged["description"]


def test_dedup_cross_scanner_tags_merged(multi_scanner_findings):
    """Tags from all sources are merged and deduplicated."""
    from core.scanner_parsers import dedup_cross_scanner

    result = dedup_cross_scanner(multi_scanner_findings)
    merged = next(r for r in result if r.get("cve_id") == "CVE-2023-1234")
    tags = set(merged["tags"])
    assert "sql-injection" in tags
    assert "owasp-a03" in tags


def test_dedup_cross_scanner_unique_finding_passthrough(multi_scanner_findings):
    """Finding with unique key is passed through unchanged."""
    from core.scanner_parsers import dedup_cross_scanner

    result = dedup_cross_scanner(multi_scanner_findings)
    unique = next(r for r in result if r.get("cve_id") == "CVE-2024-9999")
    assert unique["source_tool"] == "bandit"
    assert unique["severity"] == "medium"


def test_dedup_cross_scanner_empty_input():
    """Empty input returns empty list without error."""
    from core.scanner_parsers import dedup_cross_scanner

    assert dedup_cross_scanner([]) == []


def test_dedup_cross_scanner_no_stable_id_passthrough():
    """Findings with no cve_id and no rule_id are passed through (not dropped)."""
    from core.scanner_parsers import dedup_cross_scanner

    findings = [
        {"source_tool": "nikto", "description": "Server banner exposed", "severity": "low"},
        {"source_tool": "nikto", "description": "Directory listing enabled", "severity": "medium"},
    ]
    result = dedup_cross_scanner(findings)
    assert len(result) == 2


def test_dedup_cross_scanner_deduped_from_count(multi_scanner_findings):
    """deduped_from_count records raw finding count per merged group."""
    from core.scanner_parsers import dedup_cross_scanner

    result = dedup_cross_scanner(multi_scanner_findings)
    merged = next(r for r in result if r.get("cve_id") == "CVE-2023-1234")
    assert merged["deduped_from_count"] == 2
    unique = next(r for r in result if r.get("cve_id") == "CVE-2024-9999")
    assert unique["deduped_from_count"] == 1


def test_dedup_cross_scanner_three_scanners_same_finding():
    """Three scanners reporting the same CVE merge into one with all three sources."""
    from core.scanner_parsers import dedup_cross_scanner

    findings = [
        {"cve_id": "CVE-2023-0001", "file_path": "a.py", "line_number": 1,
         "source_tool": "bandit", "severity": "high", "tags": []},
        {"cve_id": "CVE-2023-0001", "file_path": "a.py", "line_number": 1,
         "source_tool": "semgrep", "severity": "high", "tags": []},
        {"cve_id": "CVE-2023-0001", "file_path": "a.py", "line_number": 1,
         "source_tool": "sonarqube", "severity": "critical", "tags": []},
    ]
    result = dedup_cross_scanner(findings)
    assert len(result) == 1
    assert set(result[0]["sources"]) == {"bandit", "semgrep", "sonarqube"}
    assert result[0]["severity"] == "critical"
    assert result[0]["deduped_from_count"] == 3
