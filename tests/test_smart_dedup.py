"""
Tests for SmartDedup — Cross-Scanner Vulnerability Deduplication Engine.

Covers:
- DedupStrategy enum values
- DedupGroup model construction and validation
- find_exact_cve_matches
- find_fuzzy_title_matches (various thresholds)
- find_same_location (file + line overlap)
- find_cross_scanner
- _find_component_version_matches
- deduplicate (all strategies combined)
- merge_group
- get_dedup_stats
- get_noise_reduction
- list_groups / get_group
- alert_fatigue_score calculation
- Edge cases: empty input, single finding, no duplicates

Run with:
    python -m pytest tests/test_smart_dedup.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.smart_dedup import (
    DedupGroup,
    DedupStrategy,
    SmartDedup,
    _extract_cves,
    _extract_component_version,
    _extract_file,
    _extract_line_range,
    _extract_scanner,
    _extract_title,
    _fid,
    _levenshtein_ratio,
    _lines_overlap,
    _pick_canonical,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    *,
    fid: Optional[str] = None,
    title: str = "Test finding",
    severity: str = "medium",
    cve: Optional[str] = None,
    scanner: Optional[str] = None,
    file_path: Optional[str] = None,
    line: Optional[int] = None,
    end_line: Optional[int] = None,
    package: Optional[str] = None,
    version: Optional[str] = None,
    **extra: Any,
) -> Dict[str, Any]:
    f: Dict[str, Any] = {
        "id": fid or str(uuid.uuid4()),
        "title": title,
        "severity": severity,
    }
    if cve:
        f["cve_id"] = cve
    if scanner:
        f["scanner"] = scanner
    if file_path:
        f["file_path"] = file_path
    if line is not None:
        f["line"] = line
    if end_line is not None:
        f["end_line"] = end_line
    if package:
        f["package"] = package
    if version:
        f["version"] = version
    f.update(extra)
    return f


@pytest.fixture
def engine(tmp_path):
    db = tmp_path / "test_smart_dedup.db"
    return SmartDedup(db_path=db)


@pytest.fixture
def engine2(tmp_path):
    """Second engine sharing the same tmp_path DB."""
    db = tmp_path / "test_smart_dedup2.db"
    return SmartDedup(db_path=db)


# ---------------------------------------------------------------------------
# 1. Enum values
# ---------------------------------------------------------------------------


def test_dedup_strategy_values():
    assert DedupStrategy.EXACT_CVE == "exact_cve"
    assert DedupStrategy.FUZZY_TITLE == "fuzzy_title"
    assert DedupStrategy.SAME_FILE_LINE == "same_file_line"
    assert DedupStrategy.CROSS_SCANNER == "cross_scanner"
    assert DedupStrategy.COMPONENT_VERSION == "component_version"


def test_dedup_strategy_count():
    assert len(list(DedupStrategy)) == 5


# ---------------------------------------------------------------------------
# 2. DedupGroup model
# ---------------------------------------------------------------------------


def test_dedup_group_defaults():
    g = DedupGroup(
        canonical_finding_id="f1",
        strategy=DedupStrategy.EXACT_CVE,
        confidence=0.95,
    )
    assert g.id is not None
    assert g.duplicate_ids == []
    assert g.org_id == ""
    assert g.created_at is not None


def test_dedup_group_confidence_range():
    g = DedupGroup(
        canonical_finding_id="f1",
        strategy=DedupStrategy.FUZZY_TITLE,
        confidence=1.0,
        duplicate_ids=["f2"],
        org_id="acme",
    )
    assert g.confidence == 1.0


def test_dedup_group_invalid_confidence():
    with pytest.raises(Exception):
        DedupGroup(
            canonical_finding_id="f1",
            strategy=DedupStrategy.CROSS_SCANNER,
            confidence=1.5,  # > 1.0
        )


# ---------------------------------------------------------------------------
# 3. Private helpers
# ---------------------------------------------------------------------------


def test_extract_cves_from_cve_id_field():
    f = {"cve_id": "CVE-2023-1234"}
    assert "CVE-2023-1234" in _extract_cves(f)


def test_extract_cves_from_title():
    f = {"title": "Vulnerability CVE-2021-44228 in log4j"}
    assert "CVE-2021-44228" in _extract_cves(f)


def test_extract_cves_none():
    f = {"title": "No CVE here"}
    assert _extract_cves(f) == []


def test_extract_cves_list_field():
    f = {"cves": ["CVE-2020-1111", "CVE-2020-2222"]}
    cves = _extract_cves(f)
    assert "CVE-2020-1111" in cves
    assert "CVE-2020-2222" in cves


def test_extract_title_various_fields():
    assert _extract_title({"title": "SQL Injection"}) == "sql injection"
    assert _extract_title({"rule_id": "RULE-001"}) == "rule-001"
    assert _extract_title({}) == ""


def test_extract_file_paths():
    assert _extract_file({"file_path": "/src/main.py"}) == "/src/main.py"
    assert _extract_file({"path": "/etc/config"}) == "/etc/config"
    assert _extract_file({}) is None


def test_extract_line_range_defaults():
    start, end = _extract_line_range({})
    assert start == 0
    assert end == 0


def test_extract_line_range_with_data():
    f = {"line": 10, "end_line": 20}
    start, end = _extract_line_range(f)
    assert start == 10
    assert end == 20


def test_extract_scanner_fields():
    assert _extract_scanner({"scanner": "Trivy"}) == "trivy"
    assert _extract_scanner({"tool": "Semgrep"}) == "semgrep"
    assert _extract_scanner({}) is None


def test_extract_component_version():
    f = {"package": "lodash", "version": "4.17.15"}
    assert _extract_component_version(f) == "lodash@4.17.15"


def test_extract_component_no_version():
    f = {"package": "requests"}
    assert _extract_component_version(f) == "requests"


def test_extract_component_missing():
    assert _extract_component_version({}) is None


def test_levenshtein_ratio_identical():
    assert _levenshtein_ratio("hello", "hello") == 1.0


def test_levenshtein_ratio_empty():
    assert _levenshtein_ratio("", "") == 1.0
    assert _levenshtein_ratio("abc", "") == 0.0


def test_levenshtein_ratio_similar():
    ratio = _levenshtein_ratio("sql injection in login", "sql injection in signup")
    assert ratio > 0.7


def test_levenshtein_ratio_different():
    ratio = _levenshtein_ratio("sql injection", "memory overflow in kernel")
    assert ratio < 0.5


def test_lines_overlap_direct():
    assert _lines_overlap((10, 20), (15, 25)) is True


def test_lines_overlap_within_tolerance():
    assert _lines_overlap((10, 20), (23, 30), tolerance=5) is True


def test_lines_overlap_no_overlap():
    assert _lines_overlap((10, 20), (30, 40), tolerance=0) is False


def test_pick_canonical_prefers_critical():
    findings_map = {
        "f1": {"severity": "low"},
        "f2": {"severity": "critical"},
        "f3": {"severity": "medium"},
    }
    assert _pick_canonical(["f1", "f2", "f3"], findings_map) == "f2"


def test_fid_uses_id_field():
    assert _fid({"id": "abc-123"}) == "abc-123"
    assert _fid({"finding_id": "xyz"}) == "xyz"


# ---------------------------------------------------------------------------
# 4. find_exact_cve_matches
# ---------------------------------------------------------------------------


def test_exact_cve_matches_two_scanners(engine):
    findings = [
        _finding(fid="f1", cve="CVE-2021-44228", scanner="trivy"),
        _finding(fid="f2", cve="CVE-2021-44228", scanner="snyk"),
        _finding(fid="f3", title="Unrelated finding", scanner="semgrep"),
    ]
    groups = engine.find_exact_cve_matches(findings)
    assert len(groups) == 1
    fids, conf = groups[0]
    assert "f1" in fids
    assert "f2" in fids
    assert conf >= 0.95


def test_exact_cve_no_duplicates(engine):
    findings = [
        _finding(fid="f1", cve="CVE-2021-1111", scanner="trivy"),
        _finding(fid="f2", cve="CVE-2022-2222", scanner="snyk"),
    ]
    groups = engine.find_exact_cve_matches(findings)
    assert len(groups) == 0


def test_exact_cve_multiple_cves(engine):
    findings = [
        _finding(fid="f1", cve="CVE-2020-1234", scanner="a"),
        _finding(fid="f2", cve="CVE-2020-1234", scanner="b"),
        _finding(fid="f3", cve="CVE-2019-9999", scanner="a"),
        _finding(fid="f4", cve="CVE-2019-9999", scanner="c"),
    ]
    groups = engine.find_exact_cve_matches(findings)
    assert len(groups) == 2


def test_exact_cve_same_scanner_deduped(engine):
    """Same CVE from same scanner should not create a group."""
    findings = [
        _finding(fid="f1", cve="CVE-2021-1000", scanner="trivy"),
        _finding(fid="f2", cve="CVE-2021-1000", scanner="trivy"),
    ]
    groups = engine.find_exact_cve_matches(findings)
    # same scanner → only one entry per scanner, so ≤1 fid per group
    # The engine de-dupes scanner→fid, so same scanner = 1 fid = no group
    assert len(groups) == 0


# ---------------------------------------------------------------------------
# 5. find_fuzzy_title_matches
# ---------------------------------------------------------------------------


def test_fuzzy_title_matches_similar(engine):
    findings = [
        _finding(fid="f1", title="SQL Injection in login endpoint"),
        _finding(fid="f2", title="SQL Injection in login form"),
        _finding(fid="f3", title="Remote code execution via deserialization"),
    ]
    groups = engine.find_fuzzy_title_matches(findings, threshold=0.7)
    fid_sets = [set(g[0]) for g in groups]
    assert any({"f1", "f2"}.issubset(s) for s in fid_sets)


def test_fuzzy_title_no_match_high_threshold(engine):
    findings = [
        _finding(fid="f1", title="SQL Injection"),
        _finding(fid="f2", title="Cross Site Scripting"),
    ]
    groups = engine.find_fuzzy_title_matches(findings, threshold=0.99)
    assert len(groups) == 0


def test_fuzzy_title_identical_titles(engine):
    findings = [
        _finding(fid="f1", title="Buffer overflow in libssl"),
        _finding(fid="f2", title="Buffer overflow in libssl"),
    ]
    groups = engine.find_fuzzy_title_matches(findings, threshold=0.9)
    assert len(groups) == 1
    fids, conf = groups[0]
    assert conf == 1.0


def test_fuzzy_title_empty_titles_excluded(engine):
    findings = [
        _finding(fid="f1"),  # title defaults to "test finding"
        {"id": "f2"},  # no title at all
    ]
    # Should not crash with empty titles
    groups = engine.find_fuzzy_title_matches(findings, threshold=0.99)
    # f2 has no title, so only f1 in pool — no groups
    assert len(groups) == 0


# ---------------------------------------------------------------------------
# 6. find_same_location
# ---------------------------------------------------------------------------


def test_same_location_overlapping_lines(engine):
    findings = [
        _finding(fid="f1", file_path="/src/app.py", line=10, end_line=20),
        _finding(fid="f2", file_path="/src/app.py", line=15, end_line=25),
    ]
    groups = engine.find_same_location(findings)
    assert len(groups) == 1
    fids, conf = groups[0]
    assert "f1" in fids
    assert "f2" in fids
    assert conf > 0.8


def test_same_location_different_files(engine):
    findings = [
        _finding(fid="f1", file_path="/src/a.py", line=10),
        _finding(fid="f2", file_path="/src/b.py", line=10),
    ]
    groups = engine.find_same_location(findings)
    assert len(groups) == 0


def test_same_location_within_tolerance(engine):
    findings = [
        _finding(fid="f1", file_path="/src/main.go", line=100, end_line=110),
        _finding(fid="f2", file_path="/src/main.go", line=113, end_line=120),
    ]
    # tolerance=5 → 110+5=115 >= 113, so they overlap
    groups = engine.find_same_location(findings)
    assert len(groups) == 1


def test_same_location_no_file(engine):
    findings = [
        _finding(fid="f1", title="No file finding"),
        _finding(fid="f2", title="Also no file"),
    ]
    groups = engine.find_same_location(findings)
    assert len(groups) == 0


# ---------------------------------------------------------------------------
# 7. find_cross_scanner
# ---------------------------------------------------------------------------


def test_cross_scanner_same_cve(engine):
    findings = [
        _finding(fid="f1", cve="CVE-2022-1234", scanner="trivy"),
        _finding(fid="f2", cve="CVE-2022-1234", scanner="grype"),
        _finding(fid="f3", cve="CVE-2022-1234", scanner="snyk"),
    ]
    groups = engine.find_cross_scanner(findings)
    assert len(groups) == 1
    fids, conf = groups[0]
    assert len(fids) == 3
    # 3 scanners → conf >= 0.75 + 3*0.05 = 0.90, capped at 0.95
    assert conf >= 0.90


def test_cross_scanner_same_title_diff_scanners(engine):
    findings = [
        _finding(fid="f1", title="Path traversal vulnerability", scanner="semgrep"),
        _finding(fid="f2", title="Path traversal vulnerability", scanner="codeql"),
    ]
    groups = engine.find_cross_scanner(findings)
    assert len(groups) == 1


def test_cross_scanner_single_scanner_no_group(engine):
    findings = [
        _finding(fid="f1", title="XSS vulnerability", scanner="semgrep"),
        _finding(fid="f2", title="XSS vulnerability", scanner="semgrep"),
    ]
    groups = engine.find_cross_scanner(findings)
    assert len(groups) == 0


def test_cross_scanner_no_scanner_field(engine):
    findings = [
        _finding(fid="f1", title="SSRF vulnerability"),
        _finding(fid="f2", title="SSRF vulnerability"),
    ]
    # no scanner field → excluded
    groups = engine.find_cross_scanner(findings)
    assert len(groups) == 0


# ---------------------------------------------------------------------------
# 8. Component + version matching
# ---------------------------------------------------------------------------


def test_component_version_same_package_version(engine):
    findings = [
        _finding(fid="f1", package="lodash", version="4.17.15", scanner="trivy"),
        _finding(fid="f2", package="lodash", version="4.17.15", scanner="snyk"),
    ]
    groups = engine._find_component_version_matches(findings)
    assert len(groups) == 1
    fids, conf = groups[0]
    assert "f1" in fids
    assert "f2" in fids


def test_component_version_different_versions(engine):
    findings = [
        _finding(fid="f1", package="requests", version="2.25.0"),
        _finding(fid="f2", package="requests", version="2.26.0"),
    ]
    groups = engine._find_component_version_matches(findings)
    # different versions → no group (package@version differs)
    assert len(groups) == 0


def test_component_no_version_groups_by_package(engine):
    findings = [
        _finding(fid="f1", package="django"),
        _finding(fid="f2", package="django"),
    ]
    groups = engine._find_component_version_matches(findings)
    assert len(groups) == 1


# ---------------------------------------------------------------------------
# 9. deduplicate (integration)
# ---------------------------------------------------------------------------


def test_deduplicate_empty_input(engine):
    result = engine.deduplicate([], org_id="test")
    assert result["groups"] == []
    assert result["canonical_findings"] == []
    assert result["duplicate_count"] == 0
    assert result["alert_fatigue_score"] == 0.0


def test_deduplicate_no_duplicates(engine):
    findings = [
        _finding(fid="f1", title="XSS in header", file_path="/a.py", scanner="s1"),
        _finding(fid="f2", title="Buffer overflow", file_path="/b.py", scanner="s2"),
        _finding(fid="f3", title="SSRF via redirect", file_path="/c.py", scanner="s3"),
    ]
    result = engine.deduplicate(findings, org_id="acme")
    assert result["duplicate_count"] == 0
    assert len(result["canonical_findings"]) == 3
    assert result["alert_fatigue_score"] == 0.0


def test_deduplicate_exact_cve_reduces_findings(engine):
    findings = [
        _finding(fid="f1", cve="CVE-2021-44228", scanner="trivy", severity="high"),
        _finding(fid="f2", cve="CVE-2021-44228", scanner="snyk", severity="critical"),
        _finding(fid="f3", title="Unrelated", scanner="semgrep"),
    ]
    result = engine.deduplicate(findings, org_id="org1")
    assert result["duplicate_count"] == 1
    assert len(result["canonical_findings"]) == 2
    assert result["alert_fatigue_score"] > 0


def test_deduplicate_fuzzy_title_grouping(engine):
    findings = [
        _finding(fid="f1", title="SQL injection via user input parameter"),
        _finding(fid="f2", title="SQL injection via user input value"),
        _finding(fid="f3", title="Remote code execution in parser"),
    ]
    result = engine.deduplicate(findings, org_id="org2", fuzzy_threshold=0.75)
    assert result["duplicate_count"] >= 1
    assert len(result["canonical_findings"]) == 2


def test_deduplicate_persists_groups(engine):
    findings = [
        _finding(fid="f1", cve="CVE-2020-9999", scanner="a"),
        _finding(fid="f2", cve="CVE-2020-9999", scanner="b"),
    ]
    engine.deduplicate(findings, org_id="persist-test")
    groups = engine.list_groups(org_id="persist-test")
    assert len(groups) >= 1


def test_deduplicate_alert_fatigue_score_full_dedup(engine):
    """100% duplicates → score = 100."""
    findings = [
        _finding(fid="f1", cve="CVE-2021-1234", scanner="a"),
        _finding(fid="f2", cve="CVE-2021-1234", scanner="b"),
        _finding(fid="f3", cve="CVE-2021-1234", scanner="c"),
    ]
    result = engine.deduplicate(findings, org_id="full")
    # 3 in, 1 canonical → 2 duplicates → score = 2/3 * 100 ≈ 66.67
    assert result["alert_fatigue_score"] > 60.0


def test_deduplicate_canonical_is_highest_severity(engine):
    findings = [
        _finding(fid="f1", cve="CVE-2022-5555", scanner="a", severity="low"),
        _finding(fid="f2", cve="CVE-2022-5555", scanner="b", severity="critical"),
    ]
    result = engine.deduplicate(findings, org_id="sev-test")
    groups = result["groups"]
    assert len(groups) >= 1
    # canonical should be f2 (critical)
    canonicals = {g.canonical_finding_id for g in groups}
    assert "f2" in canonicals


def test_deduplicate_cross_strategy_merge(engine):
    """A finding matched by both EXACT_CVE and CROSS_SCANNER ends up in one group."""
    findings = [
        _finding(fid="f1", cve="CVE-2023-1111", scanner="trivy", severity="high"),
        _finding(fid="f2", cve="CVE-2023-1111", scanner="grype", severity="medium"),
    ]
    result = engine.deduplicate(findings, org_id="merge-test")
    # Should not produce 2 separate groups for the same pair
    assert result["duplicate_count"] == 1
    assert len(result["canonical_findings"]) == 1


def test_deduplicate_single_finding(engine):
    findings = [_finding(fid="f1", title="Only finding")]
    result = engine.deduplicate(findings, org_id="solo")
    assert result["duplicate_count"] == 0
    assert len(result["canonical_findings"]) == 1


# ---------------------------------------------------------------------------
# 10. merge_group
# ---------------------------------------------------------------------------


def test_merge_group_returns_summary(engine):
    findings = [
        _finding(fid="f1", cve="CVE-2021-9999", scanner="x"),
        _finding(fid="f2", cve="CVE-2021-9999", scanner="y"),
    ]
    result = engine.deduplicate(findings, org_id="merge-org")
    groups = engine.list_groups(org_id="merge-org")
    assert len(groups) >= 1
    merge_result = engine.merge_group(groups[0].id)
    assert merge_result is not None
    assert merge_result["canonical_finding_id"] is not None
    assert isinstance(merge_result["merged_count"], int)
    assert isinstance(merge_result["merged_duplicate_ids"], list)


def test_merge_group_not_found(engine):
    result = engine.merge_group("nonexistent-id")
    assert result is None


def test_merge_group_confidence_returned(engine):
    findings = [
        _finding(fid="f1", cve="CVE-2021-7777", scanner="a"),
        _finding(fid="f2", cve="CVE-2021-7777", scanner="b"),
    ]
    engine.deduplicate(findings, org_id="conf-org")
    groups = engine.list_groups(org_id="conf-org")
    merge_result = engine.merge_group(groups[0].id)
    assert "confidence" in merge_result
    assert 0.0 <= merge_result["confidence"] <= 1.0


# ---------------------------------------------------------------------------
# 11. get_dedup_stats
# ---------------------------------------------------------------------------


def test_get_dedup_stats_empty(engine):
    stats = engine.get_dedup_stats("no-org")
    assert stats["total_groups"] == 0
    assert stats["total_duplicates_removed"] == 0
    assert stats["reduction_ratio"] == 0.0


def test_get_dedup_stats_after_dedup(engine):
    findings = [
        _finding(fid="f1", cve="CVE-2021-0001", scanner="a"),
        _finding(fid="f2", cve="CVE-2021-0001", scanner="b"),
        _finding(fid="f3", cve="CVE-2021-0002", scanner="d"),
        _finding(fid="f4", cve="CVE-2021-0002", scanner="e"),
    ]
    engine.deduplicate(findings, org_id="stats-org")
    stats = engine.get_dedup_stats("stats-org")
    assert stats["total_groups"] >= 1
    assert stats["total_duplicates_removed"] >= 2
    assert len(stats["strategies_used"]) >= 1
    assert "by_strategy" in stats


def test_get_dedup_stats_by_strategy_breakdown(engine):
    findings = [
        _finding(fid="f1", cve="CVE-2021-4444", scanner="x"),
        _finding(fid="f2", cve="CVE-2021-4444", scanner="y"),
    ]
    engine.deduplicate(findings, org_id="strat-org")
    stats = engine.get_dedup_stats("strat-org")
    assert "exact_cve" in stats["by_strategy"] or "cross_scanner" in stats["by_strategy"]


# ---------------------------------------------------------------------------
# 12. get_noise_reduction
# ---------------------------------------------------------------------------


def test_get_noise_reduction_empty(engine):
    result = engine.get_noise_reduction("ghost-org")
    assert result["total_runs"] == 0
    assert result["total_input_findings"] == 0
    assert result["alert_fatigue_score"] == 0.0


def test_get_noise_reduction_after_runs(engine):
    for i in range(3):
        findings = [
            _finding(fid=f"run{i}-f1", cve=f"CVE-2020-{i:04d}", scanner="a"),
            _finding(fid=f"run{i}-f2", cve=f"CVE-2020-{i:04d}", scanner="b"),
            _finding(fid=f"run{i}-f3", title=f"Unique finding {i}", scanner="c"),
        ]
        engine.deduplicate(findings, org_id="noise-org")

    result = engine.get_noise_reduction("noise-org")
    assert result["total_runs"] == 3
    assert result["total_input_findings"] == 9
    assert result["total_output_findings"] < 9
    assert result["total_duplicates_removed"] > 0
    assert result["alert_fatigue_score"] > 0.0
    assert len(result["runs"]) == 3


def test_get_noise_reduction_run_structure(engine):
    findings = [
        _finding(fid="a1", cve="CVE-2021-3333", scanner="s1"),
        _finding(fid="a2", cve="CVE-2021-3333", scanner="s2"),
    ]
    engine.deduplicate(findings, org_id="struct-org")
    result = engine.get_noise_reduction("struct-org")
    run = result["runs"][0]
    assert "id" in run
    assert "input_count" in run
    assert "output_count" in run
    assert "group_count" in run
    assert "strategies_used" in run
    assert "created_at" in run


# ---------------------------------------------------------------------------
# 13. list_groups / get_group
# ---------------------------------------------------------------------------


def test_list_groups_empty(engine):
    groups = engine.list_groups(org_id="empty-org")
    assert groups == []


def test_list_groups_filters_by_org(engine):
    f_a = [
        _finding(fid="a1", cve="CVE-2022-0001", scanner="x"),
        _finding(fid="a2", cve="CVE-2022-0001", scanner="y"),
    ]
    f_b = [
        _finding(fid="b1", cve="CVE-2022-0002", scanner="x"),
        _finding(fid="b2", cve="CVE-2022-0002", scanner="y"),
    ]
    engine.deduplicate(f_a, org_id="org-a")
    engine.deduplicate(f_b, org_id="org-b")
    groups_a = engine.list_groups(org_id="org-a")
    groups_b = engine.list_groups(org_id="org-b")
    assert all(g.org_id == "org-a" for g in groups_a)
    assert all(g.org_id == "org-b" for g in groups_b)


def test_get_group_found(engine):
    findings = [
        _finding(fid="g1", cve="CVE-2023-8888", scanner="a"),
        _finding(fid="g2", cve="CVE-2023-8888", scanner="b"),
    ]
    engine.deduplicate(findings, org_id="get-org")
    groups = engine.list_groups(org_id="get-org")
    group_id = groups[0].id
    fetched = engine.get_group(group_id)
    assert fetched is not None
    assert fetched.id == group_id


def test_get_group_not_found(engine):
    fetched = engine.get_group("does-not-exist")
    assert fetched is None


def test_list_groups_limit(engine):
    for i in range(5):
        findings = [
            _finding(fid=f"lim{i}a", cve=f"CVE-2020-{i+100}", scanner="a"),
            _finding(fid=f"lim{i}b", cve=f"CVE-2020-{i+100}", scanner="b"),
        ]
        engine.deduplicate(findings, org_id="limit-org")
    groups = engine.list_groups(org_id="limit-org", limit=3)
    assert len(groups) == 3


# ---------------------------------------------------------------------------
# 14. Alert fatigue score
# ---------------------------------------------------------------------------


def test_alert_fatigue_score_zero():
    score = SmartDedup._calc_fatigue_score(0, 0)
    assert score == 0.0


def test_alert_fatigue_score_half():
    score = SmartDedup._calc_fatigue_score(10, 5)
    assert score == 50.0


def test_alert_fatigue_score_full():
    score = SmartDedup._calc_fatigue_score(10, 1)
    assert score == 90.0


def test_alert_fatigue_score_no_reduction():
    score = SmartDedup._calc_fatigue_score(5, 5)
    assert score == 0.0
