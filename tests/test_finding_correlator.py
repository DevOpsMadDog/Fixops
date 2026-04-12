"""
Tests for FindingCorrelator — Finding Correlation Engine.

Covers:
- CVE correlation
- Component correlation
- File correlation
- Attack chain detection
- Scanner overlap detection
- Exposure case building
- Stats calculation
- Status management
- Edge cases

Run with:
    python -m pytest tests/test_finding_correlator.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.finding_correlator import (
    CaseStatus,
    Correlation,
    CorrelationType,
    ExposureCase,
    FindingCorrelator,
    _extract_cve_ids,
    _extract_component,
    _extract_file_path,
    _extract_scanner,
    _finding_tags,
    _max_severity,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_correlator(tmp_path):
    """FindingCorrelator backed by a temp SQLite DB."""
    db = tmp_path / "test_correlator.db"
    return FindingCorrelator(db_path=db)


def _finding(
    *,
    fid: str = None,
    title: str = "Test finding",
    severity: str = "high",
    cve: str = None,
    package: str = None,
    file_path: str = None,
    scanner: str = None,
    tags: List[str] = None,
    **extra,
) -> Dict[str, Any]:
    f: Dict[str, Any] = {
        "id": fid or str(uuid.uuid4()),
        "title": title,
        "severity": severity,
    }
    if cve:
        f["cve_id"] = cve
    if package:
        f["package"] = package
    if file_path:
        f["file_path"] = file_path
    if scanner:
        f["scanner"] = scanner
    if tags:
        f["tags"] = tags
    f.update(extra)
    return f


# ---------------------------------------------------------------------------
# Helper extraction tests
# ---------------------------------------------------------------------------


def test_extract_cve_ids_from_field():
    f = {"cve_id": "CVE-2023-44487"}
    assert _extract_cve_ids(f) == ["CVE-2023-44487"]


def test_extract_cve_ids_from_title():
    f = {"title": "Vuln CVE-2021-44228 in log4j"}
    assert "CVE-2021-44228" in _extract_cve_ids(f)


def test_extract_cve_ids_multiple():
    f = {"description": "Affects CVE-2021-44228 and CVE-2022-22965"}
    ids = _extract_cve_ids(f)
    assert "CVE-2021-44228" in ids
    assert "CVE-2022-22965" in ids


def test_extract_cve_ids_none():
    f = {"title": "No CVE here"}
    assert _extract_cve_ids(f) == []


def test_extract_component():
    f = {"package": "log4j-core"}
    assert _extract_component(f) == "log4j-core"


def test_extract_component_fallback_fields():
    f = {"library": "lodash"}
    assert _extract_component(f) == "lodash"


def test_extract_file_path():
    f = {"file_path": "/src/main.py"}
    assert _extract_file_path(f) == "/src/main.py"


def test_extract_scanner():
    f = {"scanner": "Trivy"}
    assert _extract_scanner(f) == "trivy"


def test_max_severity_critical_wins():
    assert _max_severity(["low", "critical", "high"]) == "critical"


def test_max_severity_fallback():
    assert _max_severity([]) == "medium"


# ---------------------------------------------------------------------------
# CVE correlation
# ---------------------------------------------------------------------------


def test_cve_correlation_groups_same_cve(tmp_correlator):
    findings = [
        _finding(fid="f1", cve="CVE-2023-44487"),
        _finding(fid="f2", cve="CVE-2023-44487"),
        _finding(fid="f3", cve="CVE-2021-44228"),
    ]
    corrs = tmp_correlator._correlate_by_cve(findings)
    cve_corrs = [c for c in corrs if c.type == CorrelationType.CVE_MATCH]
    # Should group f1+f2 together
    group_44487 = next(c for c in cve_corrs if "CVE-2023-44487" in c.description)
    assert "f1" in group_44487.finding_ids
    assert "f2" in group_44487.finding_ids
    assert "f3" not in group_44487.finding_ids


def test_cve_correlation_no_group_for_single(tmp_correlator):
    findings = [_finding(fid="f1", cve="CVE-2023-99999")]
    corrs = tmp_correlator._correlate_by_cve(findings)
    assert len(corrs) == 0


def test_cve_correlation_high_confidence(tmp_correlator):
    findings = [
        _finding(fid="a", cve="CVE-2023-1234"),
        _finding(fid="b", cve="CVE-2023-1234"),
    ]
    corrs = tmp_correlator._correlate_by_cve(findings)
    assert corrs[0].confidence >= 0.90


def test_cve_correlation_three_findings_same_cve(tmp_correlator):
    findings = [
        _finding(fid="x1", cve="CVE-2024-0001"),
        _finding(fid="x2", cve="CVE-2024-0001"),
        _finding(fid="x3", cve="CVE-2024-0001"),
    ]
    corrs = tmp_correlator._correlate_by_cve(findings)
    assert len(corrs) == 1
    assert set(corrs[0].finding_ids) == {"x1", "x2", "x3"}


# ---------------------------------------------------------------------------
# Component correlation
# ---------------------------------------------------------------------------


def test_component_correlation_same_package(tmp_correlator):
    findings = [
        _finding(fid="c1", package="lodash"),
        _finding(fid="c2", package="lodash"),
        _finding(fid="c3", package="axios"),
    ]
    corrs = tmp_correlator._correlate_by_component(findings)
    lodash_corr = next(c for c in corrs if "lodash" in c.description)
    assert "c1" in lodash_corr.finding_ids
    assert "c2" in lodash_corr.finding_ids
    assert "c3" not in lodash_corr.finding_ids


def test_component_correlation_no_group_when_different(tmp_correlator):
    findings = [
        _finding(fid="p1", package="react"),
        _finding(fid="p2", package="vue"),
    ]
    corrs = tmp_correlator._correlate_by_component(findings)
    assert len(corrs) == 0


def test_component_correlation_type(tmp_correlator):
    findings = [
        _finding(fid="d1", package="express"),
        _finding(fid="d2", package="express"),
    ]
    corrs = tmp_correlator._correlate_by_component(findings)
    assert corrs[0].type == CorrelationType.COMPONENT_MATCH


# ---------------------------------------------------------------------------
# File correlation
# ---------------------------------------------------------------------------


def test_file_correlation_same_path(tmp_correlator):
    findings = [
        _finding(fid="f1", file_path="/app/src/auth.py"),
        _finding(fid="f2", file_path="/app/src/auth.py"),
        _finding(fid="f3", file_path="/app/src/main.py"),
    ]
    corrs = tmp_correlator._correlate_by_file(findings)
    auth_corr = next(c for c in corrs if "auth.py" in c.description)
    assert "f1" in auth_corr.finding_ids
    assert "f2" in auth_corr.finding_ids
    assert "f3" not in auth_corr.finding_ids


def test_file_correlation_type(tmp_correlator):
    findings = [
        _finding(fid="g1", file_path="/x/y.js"),
        _finding(fid="g2", file_path="/x/y.js"),
    ]
    corrs = tmp_correlator._correlate_by_file(findings)
    assert corrs[0].type == CorrelationType.FILE_MATCH


# ---------------------------------------------------------------------------
# Attack chain detection
# ---------------------------------------------------------------------------


def test_attack_chain_exposed_vuln(tmp_correlator):
    findings = [
        _finding(fid="e1", title="Public endpoint with CVE", tags=["external", "internet-facing"]),
        _finding(fid="e2", title="Known CVE in service", tags=["cve", "vulnerability"]),
    ]
    corrs = tmp_correlator._detect_attack_chains(findings)
    chain_corrs = [c for c in corrs if c.type == CorrelationType.ATTACK_CHAIN]
    assert len(chain_corrs) >= 1
    exposed = next((c for c in chain_corrs if "EXPOSED_VULN" in c.description), None)
    assert exposed is not None
    assert exposed.confidence >= 0.85


def test_attack_chain_auth_bypass(tmp_correlator):
    findings = [
        _finding(fid="a1", title="Broken authentication on /login", tags=["authentication"]),
        _finding(fid="a2", title="Privilege escalation", tags=["authorization"]),
    ]
    corrs = tmp_correlator._detect_attack_chains(findings)
    auth_corrs = [c for c in corrs if "AUTH_BYPASS" in c.description]
    assert len(auth_corrs) >= 1


def test_attack_chain_supply_chain(tmp_correlator):
    findings = [
        _finding(fid="s1", title="Unpinned dependency", tags=["dependency", "npm"]),
        _finding(fid="s2", title="No version pin", tags=["unpinned"]),
    ]
    corrs = tmp_correlator._detect_attack_chains(findings)
    supply = [c for c in corrs if "SUPPLY_CHAIN" in c.description]
    assert len(supply) >= 1


def test_attack_chain_no_false_positive(tmp_correlator):
    """Single-tag findings should not trigger multi-tag pattern."""
    findings = [
        _finding(fid="n1", title="Random finding", tags=["external"]),
    ]
    corrs = tmp_correlator._detect_attack_chains(findings)
    exposed = [c for c in corrs if "EXPOSED_VULN" in c.description]
    assert len(exposed) == 0


# ---------------------------------------------------------------------------
# Scanner overlap
# ---------------------------------------------------------------------------


def test_scanner_overlap_same_cve_diff_scanner(tmp_correlator):
    findings = [
        _finding(fid="o1", cve="CVE-2023-44487", scanner="trivy"),
        _finding(fid="o2", cve="CVE-2023-44487", scanner="snyk"),
    ]
    corrs = tmp_correlator._detect_scanner_overlap(findings)
    assert len(corrs) == 1
    assert corrs[0].type == CorrelationType.SCANNER_OVERLAP
    assert "trivy" in corrs[0].description
    assert "snyk" in corrs[0].description


def test_scanner_overlap_same_title_diff_scanner(tmp_correlator):
    findings = [
        _finding(fid="t1", title="SQL Injection", scanner="semgrep"),
        _finding(fid="t2", title="SQL Injection", scanner="bandit"),
    ]
    corrs = tmp_correlator._detect_scanner_overlap(findings)
    overlap = [c for c in corrs if c.type == CorrelationType.SCANNER_OVERLAP]
    assert len(overlap) >= 1


def test_scanner_overlap_same_scanner_no_group(tmp_correlator):
    findings = [
        _finding(fid="s1", cve="CVE-2023-1111", scanner="trivy"),
        _finding(fid="s2", cve="CVE-2023-1111", scanner="trivy"),
    ]
    corrs = tmp_correlator._detect_scanner_overlap(findings)
    # Same scanner — should not be flagged as overlap
    assert len(corrs) == 0


# ---------------------------------------------------------------------------
# Full correlate_findings pipeline
# ---------------------------------------------------------------------------


def test_correlate_findings_returns_all_types(tmp_correlator):
    findings = [
        _finding(fid="r1", cve="CVE-2023-44487", scanner="trivy", file_path="/a.py"),
        _finding(fid="r2", cve="CVE-2023-44487", scanner="snyk", file_path="/a.py"),
    ]
    corrs = tmp_correlator.correlate_findings(findings)
    types_found = {c.type for c in corrs}
    assert CorrelationType.CVE_MATCH in types_found
    assert CorrelationType.FILE_MATCH in types_found
    assert CorrelationType.SCANNER_OVERLAP in types_found


def test_correlate_findings_sorted_by_confidence(tmp_correlator):
    findings = [
        _finding(fid="z1", cve="CVE-2024-9999", scanner="trivy"),
        _finding(fid="z2", cve="CVE-2024-9999", scanner="snyk"),
    ]
    corrs = tmp_correlator.correlate_findings(findings)
    confidences = [c.confidence for c in corrs]
    assert confidences == sorted(confidences, reverse=True)


# ---------------------------------------------------------------------------
# Exposure case building
# ---------------------------------------------------------------------------


def test_build_exposure_cases_groups_correlated(tmp_correlator):
    findings = [
        _finding(fid="b1", cve="CVE-2023-44487", severity="critical"),
        _finding(fid="b2", cve="CVE-2023-44487", severity="high"),
        _finding(fid="b3", cve="CVE-2023-9999", severity="low"),
    ]
    cases = tmp_correlator.build_exposure_cases(findings, org_id="acme")
    # b1+b2 should be in the same case, b3 alone (or grouped by other strategy)
    b1_case = next((c for c in cases if any(f["id"] == "b1" for f in c.findings)), None)
    assert b1_case is not None
    b2_in_same = any(f["id"] == "b2" for f in b1_case.findings)
    assert b2_in_same


def test_build_exposure_cases_severity_propagated(tmp_correlator):
    findings = [
        _finding(fid="sv1", cve="CVE-2023-1234", severity="low"),
        _finding(fid="sv2", cve="CVE-2023-1234", severity="critical"),
    ]
    cases = tmp_correlator.build_exposure_cases(findings)
    # The case containing these findings should be critical
    sv_case = next((c for c in cases if any(f["id"] == "sv1" for f in c.findings)), None)
    assert sv_case is not None
    assert sv_case.severity == "critical"


def test_build_exposure_cases_persisted(tmp_correlator):
    findings = [
        _finding(fid="p1", cve="CVE-2023-0001"),
        _finding(fid="p2", cve="CVE-2023-0001"),
    ]
    cases = tmp_correlator.build_exposure_cases(findings, org_id="org-test")
    # Should be retrievable from DB
    retrieved = tmp_correlator.list_exposure_cases(org_id="org-test")
    assert len(retrieved) >= 1


def test_build_exposure_cases_risk_score_non_zero(tmp_correlator):
    findings = [
        _finding(fid="rs1", cve="CVE-2023-5555", severity="critical"),
        _finding(fid="rs2", cve="CVE-2023-5555", severity="critical"),
    ]
    cases = tmp_correlator.build_exposure_cases(findings)
    rs_case = next((c for c in cases if any(f["id"] == "rs1" for f in c.findings)), None)
    assert rs_case is not None
    assert rs_case.risk_score > 0.0


# ---------------------------------------------------------------------------
# CRUD operations
# ---------------------------------------------------------------------------


def test_get_exposure_case(tmp_correlator):
    findings = [
        _finding(fid="gc1", cve="CVE-2023-7777"),
        _finding(fid="gc2", cve="CVE-2023-7777"),
    ]
    cases = tmp_correlator.build_exposure_cases(findings, org_id="test-org")
    case_id = cases[0].id
    retrieved = tmp_correlator.get_exposure_case(case_id)
    assert retrieved is not None
    assert retrieved.id == case_id


def test_get_exposure_case_not_found(tmp_correlator):
    result = tmp_correlator.get_exposure_case("nonexistent-id")
    assert result is None


def test_update_case_status(tmp_correlator):
    findings = [
        _finding(fid="us1", cve="CVE-2023-8888"),
        _finding(fid="us2", cve="CVE-2023-8888"),
    ]
    cases = tmp_correlator.build_exposure_cases(findings)
    case_id = cases[0].id

    updated = tmp_correlator.update_case_status(case_id, "investigating")
    assert updated is True

    retrieved = tmp_correlator.get_exposure_case(case_id)
    assert retrieved.status == CaseStatus.INVESTIGATING


def test_update_case_status_invalid(tmp_correlator):
    with pytest.raises(ValueError, match="Invalid status"):
        tmp_correlator.update_case_status("any-id", "not_a_valid_status")


def test_list_exposure_cases_filter_by_org(tmp_correlator):
    findings_a = [
        _finding(fid="la1", cve="CVE-2023-0011"),
        _finding(fid="la2", cve="CVE-2023-0011"),
    ]
    findings_b = [
        _finding(fid="lb1", cve="CVE-2023-0022"),
        _finding(fid="lb2", cve="CVE-2023-0022"),
    ]
    tmp_correlator.build_exposure_cases(findings_a, org_id="org-alpha")
    tmp_correlator.build_exposure_cases(findings_b, org_id="org-beta")

    alpha_cases = tmp_correlator.list_exposure_cases(org_id="org-alpha")
    beta_cases = tmp_correlator.list_exposure_cases(org_id="org-beta")

    # org-alpha findings should not appear in org-beta results
    alpha_ids = {c.org_id for c in alpha_cases}
    beta_ids = {c.org_id for c in beta_cases}
    assert alpha_ids == {"org-alpha"}
    assert beta_ids == {"org-beta"}


def test_list_exposure_cases_filter_by_status(tmp_correlator):
    findings = [
        _finding(fid="fs1", cve="CVE-2023-0033"),
        _finding(fid="fs2", cve="CVE-2023-0033"),
    ]
    cases = tmp_correlator.build_exposure_cases(findings, org_id="org-filter")
    case_id = cases[0].id
    tmp_correlator.update_case_status(case_id, "resolved")

    resolved = tmp_correlator.list_exposure_cases(status="resolved")
    open_cases = tmp_correlator.list_exposure_cases(status="open")

    resolved_ids = {c.id for c in resolved}
    open_ids = {c.id for c in open_cases}

    assert case_id in resolved_ids
    assert case_id not in open_ids


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_get_correlation_stats_reduction_ratio(tmp_correlator):
    # 4 findings → should collapse into fewer cases
    findings = [
        _finding(fid="st1", cve="CVE-2023-1001", severity="high"),
        _finding(fid="st2", cve="CVE-2023-1001", severity="high"),
        _finding(fid="st3", cve="CVE-2023-2002", severity="medium"),
        _finding(fid="st4", cve="CVE-2023-2002", severity="medium"),
    ]
    tmp_correlator.build_exposure_cases(findings, org_id="stats-org")
    stats = tmp_correlator.get_correlation_stats(org_id="stats-org")

    assert stats["total_findings"] >= 4
    assert stats["total_cases"] <= stats["total_findings"]
    assert stats["reduction_ratio"] >= 0.0
    assert stats["avg_findings_per_case"] > 0.0


def test_get_correlation_stats_empty(tmp_correlator):
    stats = tmp_correlator.get_correlation_stats(org_id="empty-org")
    assert stats["total_findings"] == 0
    assert stats["total_cases"] == 0
    assert stats["reduction_ratio"] == 0.0


def test_get_correlation_stats_by_severity(tmp_correlator):
    findings = [
        _finding(fid="bsv1", cve="CVE-2023-7001", severity="critical"),
        _finding(fid="bsv2", cve="CVE-2023-7001", severity="critical"),
    ]
    tmp_correlator.build_exposure_cases(findings, org_id="sev-org")
    stats = tmp_correlator.get_correlation_stats(org_id="sev-org")
    assert "critical" in stats["by_severity"]
