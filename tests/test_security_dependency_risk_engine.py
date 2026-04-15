"""Tests for SecurityDependencyRiskEngine — ALDECI.

Coverage: dependency registration, risk_score formula, vuln_count/critical recompute,
patch_vuln recompute, license conflict detection, transitive graph, org isolation.
"""

from __future__ import annotations

import pytest

from core.security_dependency_risk_engine import SecurityDependencyRiskEngine


@pytest.fixture
def engine(tmp_path):
    return SecurityDependencyRiskEngine(db_path=str(tmp_path / "sdr.db"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reg(engine, org="org1", pkg="requests", ver="2.28.0", ecosystem="pypi", lic="MIT"):
    return engine.register_dependency(org, pkg, ver, ecosystem, lic)


def _add_vuln(engine, dep_id, org="org1", cve="CVE-2023-1234", severity="high",
              cvss=7.5, fixed="2.29.0"):
    return engine.add_vuln(dep_id, org, cve, severity, cvss, fixed)


# ---------------------------------------------------------------------------
# register_dependency
# ---------------------------------------------------------------------------

def test_register_dependency_basic(engine):
    r = _reg(engine)
    assert r["package_name"] == "requests"
    assert r["version"] == "2.28.0"
    assert r["ecosystem"] == "pypi"
    assert r["license"] == "MIT"
    assert r["direct"] == 1
    assert r["depth"] == 0
    assert r["risk_score"] == 0.0
    assert r["vuln_count"] == 0
    assert r["status"] == "active"


def test_register_dependency_idempotent(engine):
    r1 = _reg(engine)
    r2 = _reg(engine)
    assert r1["id"] == r2["id"]  # INSERT OR IGNORE, same record returned


def test_register_dependency_transitive(engine):
    r = engine.register_dependency(
        "org1", "urllib3", "1.26.0", "pypi", "MIT",
        direct=False, depth=1, parent_package="requests"
    )
    assert r["direct"] == 0
    assert r["depth"] == 1
    assert r["parent_package"] == "requests"


def test_register_all_valid_ecosystems(engine):
    ecosystems = ["npm", "pypi", "maven", "nuget", "cargo", "go", "gem", "composer", "hex"]
    for i, eco in enumerate(ecosystems):
        r = engine.register_dependency("org1", f"pkg-{i}", "1.0.0", eco, "MIT")
        assert r["ecosystem"] == eco


def test_register_unknown_ecosystem_defaults_npm(engine):
    r = engine.register_dependency("org1", "pkg", "1.0.0", "unknown_eco", "MIT")
    assert r["ecosystem"] == "npm"


# ---------------------------------------------------------------------------
# add_vuln
# ---------------------------------------------------------------------------

def test_add_vuln_creates_record(engine):
    dep = _reg(engine)
    vuln = _add_vuln(engine, dep["id"])
    assert vuln["cve_id"] == "CVE-2023-1234"
    assert vuln["severity"] == "high"
    assert vuln["cvss_score"] == 7.5
    assert vuln["patched"] == 0
    assert vuln["dependency_id"] == dep["id"]


def test_add_vuln_increments_vuln_count(engine):
    dep = _reg(engine)
    _add_vuln(engine, dep["id"], cve="CVE-2023-0001")
    _add_vuln(engine, dep["id"], cve="CVE-2023-0002")
    dep_updated = engine.get_risky_dependencies("org1", min_risk=0.0)
    row = next(d for d in dep_updated if d["id"] == dep["id"])
    assert row["vuln_count"] == 2


def test_add_vuln_increments_critical_count(engine):
    dep = _reg(engine)
    _add_vuln(engine, dep["id"], cve="CVE-A", severity="critical", cvss=9.8)
    _add_vuln(engine, dep["id"], cve="CVE-B", severity="high", cvss=7.5)
    deps = engine.get_risky_dependencies("org1", min_risk=0.0)
    row = next(d for d in deps if d["id"] == dep["id"])
    assert row["critical_vuln_count"] == 1


def test_add_vuln_risk_score_formula(engine):
    """risk_score = min(10, avg_cvss_unpatched + critical_count * 0.5)"""
    dep = _reg(engine)
    _add_vuln(engine, dep["id"], cve="CVE-A", severity="critical", cvss=8.0)
    _add_vuln(engine, dep["id"], cve="CVE-B", severity="high", cvss=6.0)
    deps = engine.get_risky_dependencies("org1", min_risk=0.0)
    row = next(d for d in deps if d["id"] == dep["id"])
    # avg_cvss = (8.0+6.0)/2 = 7.0; critical_count=1 → 7.0 + 0.5 = 7.5
    assert abs(row["risk_score"] - 7.5) < 1e-6


def test_add_vuln_risk_score_capped_at_10(engine):
    dep = _reg(engine)
    for i in range(5):
        _add_vuln(engine, dep["id"], cve=f"CVE-{i}", severity="critical", cvss=9.9)
    deps = engine.get_risky_dependencies("org1", min_risk=0.0)
    row = next(d for d in deps if d["id"] == dep["id"])
    assert row["risk_score"] <= 10.0


def test_add_vuln_unknown_severity_defaults_medium(engine):
    dep = _reg(engine)
    vuln = engine.add_vuln(dep["id"], "org1", "CVE-X", "unknown_sev", 5.0, "")
    assert vuln["severity"] == "medium"


# ---------------------------------------------------------------------------
# patch_vuln
# ---------------------------------------------------------------------------

def test_patch_vuln_sets_patched(engine):
    dep = _reg(engine)
    vuln = _add_vuln(engine, dep["id"])
    result = engine.patch_vuln(vuln["id"], "org1")
    assert result["patched"] == 1


def test_patch_vuln_recomputes_risk_score(engine):
    dep = _reg(engine)
    v1 = _add_vuln(engine, dep["id"], cve="CVE-A", severity="critical", cvss=9.0)
    v2 = _add_vuln(engine, dep["id"], cve="CVE-B", severity="high", cvss=7.0)
    # Before patch: avg=(9+7)/2=8.0, critical=1 → 8.5
    engine.patch_vuln(v1["id"], "org1")
    # After patching CVE-A: only CVE-B unpatched, avg=7.0, critical=0 → 7.0
    deps = engine.get_risky_dependencies("org1", min_risk=0.0)
    row = next(d for d in deps if d["id"] == dep["id"])
    assert abs(row["risk_score"] - 7.0) < 1e-6


def test_patch_all_vulns_zeroes_risk_score(engine):
    dep = _reg(engine)
    v1 = _add_vuln(engine, dep["id"], cve="CVE-A", severity="high", cvss=7.0)
    engine.patch_vuln(v1["id"], "org1")
    deps = engine.get_risky_dependencies("org1", min_risk=0.0)
    row = next(d for d in deps if d["id"] == dep["id"])
    assert row["risk_score"] == 0.0


def test_patch_vuln_not_found_returns_error(engine):
    result = engine.patch_vuln("nonexistent", "org1")
    assert result.get("error") == "not_found"


# ---------------------------------------------------------------------------
# flag_license_risk
# ---------------------------------------------------------------------------

def test_flag_license_risk_creates(engine):
    r = engine.flag_license_risk("org1", "GPL-3.0", "high", True, False, "Strong copyleft")
    assert r["license_name"] == "GPL-3.0"
    assert r["risk_level"] == "high"
    assert r["copyleft"] == 1
    assert r["commercial_use_allowed"] == 0


def test_flag_license_risk_idempotent_replace(engine):
    engine.flag_license_risk("org1", "GPL-3.0", "high", True, False, "note1")
    r2 = engine.flag_license_risk("org1", "GPL-3.0", "critical", True, False, "note2")
    assert r2["risk_level"] == "critical"
    assert r2["notes"] == "note2"


def test_flag_license_unknown_risk_level_defaults_low(engine):
    r = engine.flag_license_risk("org1", "FOO", "unknown_level", False, True)
    assert r["risk_level"] == "low"


# ---------------------------------------------------------------------------
# get_dependency_summary
# ---------------------------------------------------------------------------

def test_summary_empty(engine):
    s = engine.get_dependency_summary("org1")
    assert s["total_deps"] == 0
    assert s["direct_count"] == 0
    assert s["transitive_count"] == 0
    assert s["total_vulns"] == 0
    assert s["critical_vulns"] == 0
    assert s["high_risk_deps"] == 0
    assert s["by_ecosystem"] == {}


def test_summary_direct_vs_transitive(engine):
    _reg(engine, pkg="direct1")
    engine.register_dependency("org1", "trans1", "1.0", "pypi", "MIT",
                               direct=False, depth=1)
    s = engine.get_dependency_summary("org1")
    assert s["direct_count"] == 1
    assert s["transitive_count"] == 1
    assert s["total_deps"] == 2


def test_summary_by_ecosystem(engine):
    _reg(engine, pkg="p1", ecosystem="pypi")
    engine.register_dependency("org1", "p2", "1.0", "npm", "MIT")
    engine.register_dependency("org1", "p3", "1.0", "npm", "MIT")
    s = engine.get_dependency_summary("org1")
    assert s["by_ecosystem"]["pypi"] == 1
    assert s["by_ecosystem"]["npm"] == 2


def test_summary_high_risk_deps(engine):
    dep = _reg(engine)
    _add_vuln(engine, dep["id"], severity="critical", cvss=9.5)
    s = engine.get_dependency_summary("org1")
    assert s["high_risk_deps"] >= 1


def test_summary_critical_vulns(engine):
    dep = _reg(engine)
    _add_vuln(engine, dep["id"], cve="CVE-C", severity="critical", cvss=9.0)
    _add_vuln(engine, dep["id"], cve="CVE-H", severity="high", cvss=7.0)
    s = engine.get_dependency_summary("org1")
    assert s["critical_vulns"] == 1
    assert s["total_vulns"] == 2


# ---------------------------------------------------------------------------
# get_risky_dependencies
# ---------------------------------------------------------------------------

def test_risky_deps_ordered(engine):
    d1 = _reg(engine, pkg="low-risk")
    d2 = engine.register_dependency("org1", "high-risk", "1.0", "npm", "MIT")
    _add_vuln(engine, d2["id"], severity="critical", cvss=9.8)
    result = engine.get_risky_dependencies("org1", min_risk=0.0)
    scores = [r["risk_score"] for r in result]
    assert scores == sorted(scores, reverse=True)


def test_risky_deps_threshold(engine):
    d1 = _reg(engine, pkg="safe")
    d2 = engine.register_dependency("org1", "risky", "1.0", "npm", "MIT")
    _add_vuln(engine, d2["id"], severity="critical", cvss=9.0)
    result = engine.get_risky_dependencies("org1", min_risk=5.0)
    names = [r["package_name"] for r in result]
    assert "risky" in names
    assert "safe" not in names


# ---------------------------------------------------------------------------
# get_license_conflicts
# ---------------------------------------------------------------------------

def test_license_conflict_high_risk(engine):
    engine.register_dependency("org1", "gpl-pkg", "1.0", "pypi", "GPL-3.0")
    engine.flag_license_risk("org1", "GPL-3.0", "high", True, False)
    conflicts = engine.get_license_conflicts("org1")
    pkgs = [c["package_name"] for c in conflicts]
    assert "gpl-pkg" in pkgs


def test_license_conflict_copyleft_no_commercial(engine):
    engine.register_dependency("org1", "agpl-pkg", "1.0", "pypi", "AGPL-3.0")
    engine.flag_license_risk("org1", "AGPL-3.0", "medium", True, False)
    conflicts = engine.get_license_conflicts("org1")
    pkgs = [c["package_name"] for c in conflicts]
    assert "agpl-pkg" in pkgs


def test_no_conflict_permissive(engine):
    engine.register_dependency("org1", "mit-pkg", "1.0", "pypi", "MIT")
    engine.flag_license_risk("org1", "MIT", "low", False, True)
    conflicts = engine.get_license_conflicts("org1")
    pkgs = [c["package_name"] for c in conflicts]
    assert "mit-pkg" not in pkgs


def test_license_conflict_no_flag_no_conflict(engine):
    engine.register_dependency("org1", "unknown-lic", "1.0", "pypi", "Custom-1.0")
    conflicts = engine.get_license_conflicts("org1")
    assert conflicts == []


# ---------------------------------------------------------------------------
# get_vuln_list
# ---------------------------------------------------------------------------

def test_get_vuln_list_all(engine):
    dep = _reg(engine)
    _add_vuln(engine, dep["id"], cve="CVE-A")
    _add_vuln(engine, dep["id"], cve="CVE-B")
    vulns = engine.get_vuln_list("org1")
    assert len(vulns) == 2
    cves = {v["cve_id"] for v in vulns}
    assert "CVE-A" in cves
    assert "CVE-B" in cves


def test_get_vuln_list_includes_package_name(engine):
    dep = _reg(engine, pkg="requests")
    _add_vuln(engine, dep["id"])
    vulns = engine.get_vuln_list("org1")
    assert vulns[0]["package_name"] == "requests"


def test_get_vuln_list_filter_patched(engine):
    dep = _reg(engine)
    v1 = _add_vuln(engine, dep["id"], cve="CVE-A")
    v2 = _add_vuln(engine, dep["id"], cve="CVE-B")
    engine.patch_vuln(v1["id"], "org1")
    patched = engine.get_vuln_list("org1", patched=True)
    unpatched = engine.get_vuln_list("org1", patched=False)
    assert len(patched) == 1
    assert len(unpatched) == 1
    assert patched[0]["cve_id"] == "CVE-A"


# ---------------------------------------------------------------------------
# get_transitive_graph
# ---------------------------------------------------------------------------

def test_transitive_graph_returns_children(engine):
    engine.register_dependency("org1", "parent", "1.0", "pypi", "MIT")
    engine.register_dependency("org1", "child1", "1.0", "pypi", "MIT",
                               direct=False, depth=1, parent_package="parent")
    engine.register_dependency("org1", "child2", "1.0", "pypi", "MIT",
                               direct=False, depth=1, parent_package="parent")
    children = engine.get_transitive_graph("org1", "parent")
    names = {c["package_name"] for c in children}
    assert names == {"child1", "child2"}


def test_transitive_graph_empty_if_no_children(engine):
    _reg(engine, pkg="leaf")
    result = engine.get_transitive_graph("org1", "leaf")
    assert result == []


def test_transitive_graph_1_level_only(engine):
    # Register grandchild — should NOT appear in parent's graph
    engine.register_dependency("org1", "parent", "1.0", "pypi", "MIT")
    engine.register_dependency("org1", "child", "1.0", "pypi", "MIT",
                               direct=False, depth=1, parent_package="parent")
    engine.register_dependency("org1", "grandchild", "1.0", "pypi", "MIT",
                               direct=False, depth=2, parent_package="child")
    children = engine.get_transitive_graph("org1", "parent")
    names = {c["package_name"] for c in children}
    assert "grandchild" not in names


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_register(engine):
    engine.register_dependency("org1", "shared-pkg", "1.0", "pypi", "MIT")
    engine.register_dependency("org2", "shared-pkg", "1.0", "pypi", "MIT")
    s1 = engine.get_dependency_summary("org1")
    s2 = engine.get_dependency_summary("org2")
    assert s1["total_deps"] == 1
    assert s2["total_deps"] == 1


def test_org_isolation_vulns(engine):
    d1 = engine.register_dependency("org1", "pkg", "1.0", "pypi", "MIT")
    d2 = engine.register_dependency("org2", "pkg", "1.0", "pypi", "MIT")
    engine.add_vuln(d1["id"], "org1", "CVE-A", "high", 7.0, "")
    v2 = engine.get_vuln_list("org2")
    assert v2 == []


def test_org_isolation_license_risks(engine):
    engine.register_dependency("org1", "gpl-pkg", "1.0", "pypi", "GPL-3.0")
    engine.flag_license_risk("org1", "GPL-3.0", "high", True, False)
    conflicts = engine.get_license_conflicts("org2")
    assert conflicts == []


def test_org_isolation_risky_deps(engine):
    d1 = engine.register_dependency("org1", "risky", "1.0", "npm", "MIT")
    engine.add_vuln(d1["id"], "org1", "CVE-A", "critical", 9.0, "")
    risky = engine.get_risky_dependencies("org2", min_risk=0.0)
    assert risky == []
