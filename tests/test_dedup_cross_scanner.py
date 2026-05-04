"""Tests for scanner_parsers.dedup_cross_scanner.

Covers:
- Empty input passthrough
- Single finding passthrough (sources list set)
- 2-scanner merge on identical (cve_id, file_path, line) key
- 3-scanner merge
- No-duplicate passthrough (different keys remain separate)
- Missing cve_id passthrough (no stable identifier)
- Severity hoisting: high beats medium, critical beats high
- Tags merged and sorted
- First non-empty description wins
- deduped_from_count correct
- Rule/vuln_id field used as fallback when cve_id absent
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_CORE = _ROOT / "suite-core" / "core"
if str(_CORE.parent) not in sys.path:
    sys.path.insert(0, str(_CORE.parent))

from core.scanner_parsers import dedup_cross_scanner  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _finding(
    cve_id: str | None = "CVE-2021-44228",
    file_path: str = "src/app.py",
    line_number: int = 42,
    severity: str = "medium",
    source_tool: str = "bandit",
    description: str = "",
    tags: list | None = None,
    **extra,
) -> Dict[str, Any]:
    f: Dict[str, Any] = {
        "source_tool": source_tool,
        "severity": severity,
        "file_path": file_path,
        "line_number": line_number,
        "description": description,
        "tags": tags or [],
    }
    if cve_id is not None:
        f["cve_id"] = cve_id
    f.update(extra)
    return f


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestDedupCrossScanner:

    def test_empty_input(self):
        assert dedup_cross_scanner([]) == []

    def test_single_finding_passthrough(self):
        findings = [_finding(source_tool="bandit")]
        result = dedup_cross_scanner(findings)
        assert len(result) == 1
        assert result[0]["deduped_from_count"] == 1
        assert "bandit" in result[0]["sources"]

    def test_two_scanner_merge(self):
        """Two findings with identical key from different scanners merge into one."""
        f1 = _finding(source_tool="bandit", severity="medium", description="First")
        f2 = _finding(source_tool="semgrep", severity="medium", description="")
        result = dedup_cross_scanner([f1, f2])
        assert len(result) == 1
        assert result[0]["deduped_from_count"] == 2
        assert set(result[0]["sources"]) == {"bandit", "semgrep"}

    def test_three_scanner_merge(self):
        f1 = _finding(source_tool="bandit")
        f2 = _finding(source_tool="semgrep")
        f3 = _finding(source_tool="sonarqube")
        result = dedup_cross_scanner([f1, f2, f3])
        assert len(result) == 1
        assert result[0]["deduped_from_count"] == 3
        assert len(result[0]["sources"]) == 3

    def test_no_duplicate_passthrough(self):
        """Different CVE ids produce separate output findings."""
        f1 = _finding(cve_id="CVE-2021-44228", source_tool="bandit")
        f2 = _finding(cve_id="CVE-2022-12345", source_tool="semgrep")
        result = dedup_cross_scanner([f1, f2])
        assert len(result) == 2

    def test_different_file_path_no_merge(self):
        """Same CVE but different file paths must NOT merge."""
        f1 = _finding(file_path="src/a.py", source_tool="bandit")
        f2 = _finding(file_path="src/b.py", source_tool="semgrep")
        result = dedup_cross_scanner([f1, f2])
        assert len(result) == 2

    def test_different_line_no_merge(self):
        """Same CVE + file but different line numbers must NOT merge."""
        f1 = _finding(line_number=10, source_tool="bandit")
        f2 = _finding(line_number=99, source_tool="semgrep")
        result = dedup_cross_scanner([f1, f2])
        assert len(result) == 2

    def test_missing_cve_id_passthrough(self):
        """Finding with no cve_id/rule_id/vuln_id passes through as-is."""
        f = {"source_tool": "manual", "severity": "high", "description": "hand-written note"}
        result = dedup_cross_scanner([f])
        assert len(result) == 1
        assert result[0]["deduped_from_count"] == 1

    def test_two_no_id_findings_not_merged(self):
        """Two findings with no stable id must NOT collapse into one."""
        f1 = {"source_tool": "manual", "severity": "high"}
        f2 = {"source_tool": "manual", "severity": "low"}
        result = dedup_cross_scanner([f1, f2])
        assert len(result) == 2

    def test_severity_hoisting_high_beats_medium(self):
        f1 = _finding(severity="medium", source_tool="bandit")
        f2 = _finding(severity="high", source_tool="semgrep")
        result = dedup_cross_scanner([f1, f2])
        assert result[0]["severity"] == "high"

    def test_severity_hoisting_critical_beats_high(self):
        f1 = _finding(severity="high", source_tool="bandit")
        f2 = _finding(severity="critical", source_tool="semgrep")
        result = dedup_cross_scanner([f1, f2])
        assert result[0]["severity"] == "critical"

    def test_severity_not_downgraded(self):
        """Higher severity scanner came first — must stay high."""
        f1 = _finding(severity="high", source_tool="bandit")
        f2 = _finding(severity="low", source_tool="semgrep")
        result = dedup_cross_scanner([f1, f2])
        assert result[0]["severity"] == "high"

    def test_tags_merged_and_sorted(self):
        f1 = _finding(source_tool="bandit", tags=["sast", "injection"])
        f2 = _finding(source_tool="semgrep", tags=["injection", "owasp-a03"])
        result = dedup_cross_scanner([f1, f2])
        tags = result[0]["tags"]
        assert sorted(tags) == tags  # deterministically sorted
        assert "sast" in tags
        assert "owasp-a03" in tags
        assert tags.count("injection") == 1  # deduplicated

    def test_first_non_empty_description_wins(self):
        f1 = _finding(description="", source_tool="bandit")
        f2 = _finding(description="Second scanner description", source_tool="semgrep")
        result = dedup_cross_scanner([f1, f2])
        assert result[0]["description"] == "Second scanner description"

    def test_first_description_preserved_when_set(self):
        f1 = _finding(description="First scanner description", source_tool="bandit")
        f2 = _finding(description="Second scanner description", source_tool="semgrep")
        result = dedup_cross_scanner([f1, f2])
        assert result[0]["description"] == "First scanner description"

    def test_rule_id_used_as_fallback_key(self):
        """rule_id is used as dedup key when cve_id is absent."""
        f1 = {"rule_id": "B101", "file_path": "app.py", "line_number": 5,
              "severity": "low", "source_tool": "bandit", "description": ""}
        f2 = {"rule_id": "B101", "file_path": "app.py", "line_number": 5,
              "severity": "medium", "source_tool": "semgrep", "description": ""}
        result = dedup_cross_scanner([f1, f2])
        assert len(result) == 1
        assert result[0]["deduped_from_count"] == 2

    def test_cve_id_case_insensitive_key(self):
        """cve-2021-44228 and CVE-2021-44228 should merge (normalised to upper)."""
        f1 = _finding(cve_id="cve-2021-44228", source_tool="bandit")
        f2 = _finding(cve_id="CVE-2021-44228", source_tool="semgrep")
        result = dedup_cross_scanner([f1, f2])
        assert len(result) == 1

    def test_windows_path_normalised(self):
        """Windows backslash path treated same as forward-slash path."""
        f1 = _finding(file_path="src\\app.py", source_tool="bandit")
        f2 = _finding(file_path="src/app.py", source_tool="semgrep")
        result = dedup_cross_scanner([f1, f2])
        assert len(result) == 1

    def test_sources_list_always_present_single(self):
        """Single finding with source_tool set must have sources list."""
        f = _finding(source_tool="trivy")
        result = dedup_cross_scanner([f])
        assert "sources" in result[0]
        assert "trivy" in result[0]["sources"]

    def test_mixed_id_and_no_id_findings(self):
        """Mix of identifiable and unidentifiable findings handled correctly."""
        f_id = _finding(cve_id="CVE-2023-9999", source_tool="bandit")
        f_no_id = {"source_tool": "manual", "severity": "info"}
        result = dedup_cross_scanner([f_id, f_no_id])
        assert len(result) == 2
