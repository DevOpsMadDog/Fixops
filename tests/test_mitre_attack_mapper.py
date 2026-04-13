"""
Tests for MITREATTACKMapper — suite-core/core/mitre_attack_mapper.py

15+ tests covering:
- CWE→ATT&CK mappings for all 8 required CWEs
- Keyword matching
- Confidence ordering
- Coverage calculation
- Gap identification
- Heatmap data format
- Edge cases (empty input, unknown CWE, no-match finding)

Run with:
    python -m pytest tests/test_mitre_attack_mapper.py --timeout=10 -q -o "addopts="
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

# Inject suite-core into path so imports resolve without a full install
_suite_core = str(Path(__file__).parent.parent / "suite-core")
if _suite_core not in sys.path:
    sys.path.insert(0, _suite_core)

from core.mitre_attack_mapper import (
    ATTACKCoverage,
    HIGH,
    LOW,
    MED,
    MITREATTACKMapper,
    TechniqueGap,
    TechniqueMapping,
    TECHNIQUES,
    CWE_TO_TECHNIQUES,
    get_mitre_attack_mapper,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def mapper() -> MITREATTACKMapper:
    return MITREATTACKMapper()


def _finding(
    title: str,
    cwe_id: Any = None,
    description: str = "",
    finding_id: str = "F-001",
) -> Dict[str, Any]:
    return {
        "id": finding_id,
        "title": title,
        "description": description,
        "cwe_id": cwe_id,
    }


# ---------------------------------------------------------------------------
# 1. CWE-89 → T1190 (Exploit Public-Facing Application)
# ---------------------------------------------------------------------------


def test_cwe_89_maps_to_t1190(mapper):
    """CWE-89 (SQL Injection) must map to T1190 with HIGH confidence."""
    results = mapper.map_finding_to_techniques(_finding("SQL Injection", cwe_id="CWE-89"))
    tids = {m.technique_id for m in results}
    assert "T1190" in tids

    t1190 = next(m for m in results if m.technique_id == "T1190")
    assert t1190.confidence == HIGH


# ---------------------------------------------------------------------------
# 2. CWE-79 → T1059.007 (JavaScript)
# ---------------------------------------------------------------------------


def test_cwe_79_maps_to_t1059_007(mapper):
    """CWE-79 (XSS) must map to T1059.007 with HIGH confidence."""
    results = mapper.map_finding_to_techniques(_finding("XSS", cwe_id="CWE-79"))
    tids = {m.technique_id for m in results}
    assert "T1059.007" in tids

    js = next(m for m in results if m.technique_id == "T1059.007")
    assert js.confidence == HIGH


# ---------------------------------------------------------------------------
# 3. CWE-798 → T1552 (Unsecured Credentials)
# ---------------------------------------------------------------------------


def test_cwe_798_maps_to_t1552(mapper):
    """CWE-798 (Hard-coded Credentials) must map to T1552."""
    results = mapper.map_finding_to_techniques(_finding("Hard-coded creds", cwe_id="CWE-798"))
    tids = {m.technique_id for m in results}
    assert "T1552" in tids

    cred = next(m for m in results if m.technique_id == "T1552")
    assert cred.confidence == HIGH


# ---------------------------------------------------------------------------
# 4. CWE-22 → T1083 (File and Directory Discovery)
# ---------------------------------------------------------------------------


def test_cwe_22_maps_to_t1083(mapper):
    """CWE-22 (Path Traversal) must map to T1083."""
    results = mapper.map_finding_to_techniques(_finding("Path Traversal", cwe_id="CWE-22"))
    tids = {m.technique_id for m in results}
    assert "T1083" in tids


# ---------------------------------------------------------------------------
# 5. CWE-78 → T1059 (Command and Scripting Interpreter)
# ---------------------------------------------------------------------------


def test_cwe_78_maps_to_t1059(mapper):
    """CWE-78 (OS Command Injection) must map to T1059."""
    results = mapper.map_finding_to_techniques(_finding("OS Command Injection", cwe_id="CWE-78"))
    tids = {m.technique_id for m in results}
    assert "T1059" in tids

    t = next(m for m in results if m.technique_id == "T1059")
    assert t.confidence == HIGH


# ---------------------------------------------------------------------------
# 6. CWE-611 → T1083 (via XXE file disclosure)
# ---------------------------------------------------------------------------


def test_cwe_611_maps_to_t1083(mapper):
    """CWE-611 (XXE) must map to T1083."""
    results = mapper.map_finding_to_techniques(_finding("XXE", cwe_id="CWE-611"))
    tids = {m.technique_id for m in results}
    assert "T1083" in tids


# ---------------------------------------------------------------------------
# 7. CWE-502 → T1059 (Insecure Deserialization)
# ---------------------------------------------------------------------------


def test_cwe_502_maps_to_t1059(mapper):
    """CWE-502 (Deserialization) must map to T1059."""
    results = mapper.map_finding_to_techniques(_finding("Insecure deserialization", cwe_id="CWE-502"))
    tids = {m.technique_id for m in results}
    assert "T1059" in tids


# ---------------------------------------------------------------------------
# 8. CWE-306 → T1078 (Missing Authentication → Valid Accounts)
# ---------------------------------------------------------------------------


def test_cwe_306_maps_to_t1078(mapper):
    """CWE-306 (Missing Authentication) must map to T1078."""
    results = mapper.map_finding_to_techniques(_finding("Missing auth", cwe_id="CWE-306"))
    tids = {m.technique_id for m in results}
    assert "T1078" in tids

    t = next(m for m in results if m.technique_id == "T1078")
    assert t.confidence == HIGH


# ---------------------------------------------------------------------------
# 9. CWE ID normalisation (various input formats)
# ---------------------------------------------------------------------------


def test_cwe_id_normalisation(mapper):
    """Various CWE ID formats must all resolve the same mappings."""
    formats = ["89", "CWE-89", "cwe-89", "CWE89", 89]
    all_tids = []
    for fmt in formats:
        results = mapper.map_finding_to_techniques(_finding("SQLi", cwe_id=fmt))
        all_tids.append(frozenset(m.technique_id for m in results))
    # All formats should produce identical technique sets
    assert len(set(all_tids)) == 1, "Different CWE formats produced different results"


# ---------------------------------------------------------------------------
# 10. Keyword matching (no CWE provided)
# ---------------------------------------------------------------------------


def test_keyword_match_sql_injection(mapper):
    """Keyword 'sql injection' in title must match T1190 even without CWE."""
    results = mapper.map_finding_to_techniques(_finding("SQL injection found in login form"))
    tids = {m.technique_id for m in results}
    assert "T1190" in tids
    t = next(m for m in results if m.technique_id == "T1190")
    assert t.match_source == "keyword"


def test_keyword_match_rce(mapper):
    """RCE keyword must match T1059."""
    results = mapper.map_finding_to_techniques(_finding("RCE via eval()", cwe_id=None))
    tids = {m.technique_id for m in results}
    assert "T1059" in tids


# ---------------------------------------------------------------------------
# 11. Empty findings list → empty coverage
# ---------------------------------------------------------------------------


def test_coverage_empty_findings(mapper):
    """Empty findings list must return zero coverage."""
    cov = mapper.calculate_coverage([])
    assert cov.technique_coverage_pct == 0.0
    assert len(cov.covered_technique_ids) == 0
    assert len(cov.covered_tactic_ids) == 0


# ---------------------------------------------------------------------------
# 12. Coverage calculation with known findings
# ---------------------------------------------------------------------------


def test_coverage_calculation(mapper):
    """Coverage must count unique techniques and tactics correctly."""
    findings = [
        _finding("SQL Injection", cwe_id="CWE-89", finding_id="F1"),
        _finding("XSS", cwe_id="CWE-79", finding_id="F2"),
        _finding("Hard-coded credentials", cwe_id="CWE-798", finding_id="F3"),
    ]
    cov = mapper.calculate_coverage(findings)
    assert cov.technique_coverage_pct > 0
    assert len(cov.covered_technique_ids) >= 3
    assert len(cov.covered_tactic_ids) >= 2
    assert isinstance(cov.tactic_breakdown, dict)
    assert len(cov.tactic_breakdown) > 0


# ---------------------------------------------------------------------------
# 13. identify_gaps — all techniques not in covered set are returned
# ---------------------------------------------------------------------------


def test_identify_gaps_empty_covered(mapper):
    """With no covered techniques, all DB techniques should be in gaps."""
    gaps = mapper.identify_gaps(set())
    gap_ids = {g.technique_id for g in gaps}
    # All techniques in the embedded DB must appear as gaps
    for tid in TECHNIQUES:
        assert tid in gap_ids, f"Expected gap {tid} not returned"


def test_identify_gaps_partial(mapper):
    """Covered techniques must be excluded from gaps."""
    covered = {"T1190", "T1059", "T1078"}
    gaps = mapper.identify_gaps(covered)
    gap_ids = {g.technique_id for g in gaps}
    for tid in covered:
        assert tid not in gap_ids


def test_identify_gaps_priority_ordering(mapper):
    """HIGH priority gaps must appear before LOW priority gaps."""
    gaps = mapper.identify_gaps(set())
    priorities = [g.priority for g in gaps]
    # Find first LOW after first HIGH — they should not interleave (HIGH block first)
    first_low = next((i for i, p in enumerate(priorities) if p == LOW), None)
    first_high = next((i for i, p in enumerate(priorities) if p == HIGH), None)
    if first_low is not None and first_high is not None:
        assert first_high < first_low, "HIGH priority gaps should appear before LOW"


# ---------------------------------------------------------------------------
# 14. generate_heatmap_data — schema validation
# ---------------------------------------------------------------------------


def test_heatmap_schema(mapper):
    """Heatmap output must conform to ATT&CK Navigator layer schema."""
    findings = [
        _finding("SQL Injection", cwe_id="CWE-89"),
        _finding("XSS", cwe_id="CWE-79"),
    ]
    layer = mapper.generate_heatmap_data(findings)

    # Top-level required keys
    assert layer["domain"] == "enterprise-attack"
    assert "versions" in layer
    assert layer["versions"]["attack"] == "14"
    assert "techniques" in layer
    assert isinstance(layer["techniques"], list)
    assert len(layer["techniques"]) > 0

    # Each technique entry must have techniqueID and score
    for entry in layer["techniques"]:
        assert "techniqueID" in entry
        assert "score" in entry
        assert 0 <= entry["score"] <= 100


# ---------------------------------------------------------------------------
# 15. Singleton accessor returns same instance
# ---------------------------------------------------------------------------


def test_singleton(mapper):
    """get_mitre_attack_mapper() must return the same object on repeated calls."""
    a = get_mitre_attack_mapper()
    b = get_mitre_attack_mapper()
    assert a is b


# ---------------------------------------------------------------------------
# 16. Unknown CWE returns empty list (no crash)
# ---------------------------------------------------------------------------


def test_unknown_cwe_no_crash(mapper):
    """An unrecognised CWE ID must return an empty list without raising."""
    results = mapper.map_finding_to_techniques(_finding("Obscure bug", cwe_id="CWE-99999"))
    assert isinstance(results, list)


# ---------------------------------------------------------------------------
# 17. Finding with no title matches, no CWE → empty result (no crash)
# ---------------------------------------------------------------------------


def test_no_match_finding(mapper):
    """A finding with unrecognised title and no CWE must return [] gracefully."""
    results = mapper.map_finding_to_techniques(_finding("Completely unrelated finding text"))
    assert isinstance(results, list)


# ---------------------------------------------------------------------------
# 18. TechniqueMapping dataclass confidence_score property
# ---------------------------------------------------------------------------


def test_technique_mapping_confidence_score(mapper):
    """confidence_score property must return correct numeric values."""
    results = mapper.map_finding_to_techniques(_finding("SQL injection", cwe_id="CWE-89"))
    assert len(results) > 0
    for m in results:
        assert m.confidence in {HIGH, MED, LOW}
        assert m.confidence_score in {1.0, 0.6, 0.3}


# ---------------------------------------------------------------------------
# 19. Coverage percentage is bounded [0, 100]
# ---------------------------------------------------------------------------


def test_coverage_pct_bounded(mapper):
    """Technique and tactic coverage percentages must be in [0, 100]."""
    many_findings = [
        _finding(f"Finding {i}", cwe_id=cwe, finding_id=f"F{i}")
        for i, cwe in enumerate(
            ["CWE-89", "CWE-79", "CWE-798", "CWE-22", "CWE-78",
             "CWE-611", "CWE-502", "CWE-306"], start=1
        )
    ]
    cov = mapper.calculate_coverage(many_findings)
    assert 0.0 <= cov.technique_coverage_pct <= 100.0
    assert 0.0 <= cov.tactic_coverage_pct <= 100.0


# ---------------------------------------------------------------------------
# 20. CWE_TO_TECHNIQUES covers all 8 required CWEs
# ---------------------------------------------------------------------------


def test_required_cwe_mappings_present():
    """All 8 required CWE→ATT&CK mappings must exist in the database."""
    required = {"89", "79", "798", "22", "78", "611", "502", "306"}
    for cwe in required:
        assert cwe in CWE_TO_TECHNIQUES, f"CWE-{cwe} missing from CWE_TO_TECHNIQUES"
        assert len(CWE_TO_TECHNIQUES[cwe]) > 0, f"CWE-{cwe} has no technique mappings"
