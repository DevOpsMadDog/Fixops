"""Tests for SupplyChainIntelEngine — 27 tests covering all methods + org isolation."""

from __future__ import annotations

import pytest
from core.supply_chain_intel_engine import SupplyChainIntelEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "sci_test.db")
    return SupplyChainIntelEngine(db_path=db)


@pytest.fixture
def org():
    return "org-alpha"


@pytest.fixture
def org2():
    return "org-beta"


def _pkg(engine, org, name="requests", ecosystem="pypi", risk_level="safe"):
    return engine.track_package(org, {
        "name": name,
        "ecosystem": ecosystem,
        "risk_level": risk_level,
    })


# ---------------------------------------------------------------------------
# track_package
# ---------------------------------------------------------------------------

def test_track_package_returns_record(engine, org):
    pkg = _pkg(engine, org)
    assert pkg["name"] == "requests"
    assert pkg["ecosystem"] == "pypi"
    assert pkg["org_id"] == org
    assert "pkg_id" in pkg


def test_track_package_missing_name_raises(engine, org):
    with pytest.raises(ValueError, match="name"):
        engine.track_package(org, {"name": "", "ecosystem": "pypi"})


def test_track_package_invalid_ecosystem_raises(engine, org):
    with pytest.raises(ValueError, match="ecosystem"):
        engine.track_package(org, {"name": "foo", "ecosystem": "perl"})


def test_track_package_invalid_risk_level_raises(engine, org):
    with pytest.raises(ValueError, match="risk_level"):
        engine.track_package(org, {"name": "foo", "ecosystem": "pypi", "risk_level": "extreme"})


def test_track_package_all_ecosystems(engine, org):
    for eco in ("npm", "pypi", "maven", "go", "ruby", "cargo", "nuget"):
        pkg = engine.track_package(org, {"name": f"pkg-{eco}", "ecosystem": eco})
        assert pkg["ecosystem"] == eco


# ---------------------------------------------------------------------------
# list_packages
# ---------------------------------------------------------------------------

def test_list_packages_empty(engine, org):
    assert engine.list_packages(org) == []


def test_list_packages_org_isolation(engine, org, org2):
    _pkg(engine, org, "requests")
    _pkg(engine, org2, "flask")
    assert len(engine.list_packages(org)) == 1
    assert engine.list_packages(org)[0]["name"] == "requests"


def test_list_packages_filter_ecosystem(engine, org):
    _pkg(engine, org, "requests", ecosystem="pypi")
    _pkg(engine, org, "lodash", ecosystem="npm")
    pypi = engine.list_packages(org, ecosystem="pypi")
    assert len(pypi) == 1
    assert pypi[0]["name"] == "requests"


def test_list_packages_filter_risk_level(engine, org):
    _pkg(engine, org, "safe-pkg", risk_level="safe")
    _pkg(engine, org, "evil-pkg", risk_level="critical")
    critical = engine.list_packages(org, risk_level="critical")
    assert len(critical) == 1
    assert critical[0]["name"] == "evil-pkg"


# ---------------------------------------------------------------------------
# add_vulnerability + list_vulnerabilities
# ---------------------------------------------------------------------------

def test_add_vulnerability_returns_record(engine, org):
    pkg = _pkg(engine, org)
    vuln = engine.add_vulnerability(org, pkg["pkg_id"], {
        "cve_id": "CVE-2024-0001",
        "severity": "critical",
        "cvss_score": 9.8,
        "fixed_in_version": "2.0.0",
    })
    assert vuln["cve_id"] == "CVE-2024-0001"
    assert vuln["severity"] == "critical"
    assert vuln["vuln_id"] is not None


def test_add_vulnerability_invalid_severity_raises(engine, org):
    pkg = _pkg(engine, org)
    with pytest.raises(ValueError, match="severity"):
        engine.add_vulnerability(org, pkg["pkg_id"], {"severity": "unknown"})


def test_list_vulnerabilities_unpatched_only(engine, org):
    pkg = _pkg(engine, org)
    engine.add_vulnerability(org, pkg["pkg_id"], {"cve_id": "CVE-A", "severity": "high"})
    engine.add_vulnerability(org, pkg["pkg_id"], {"cve_id": "CVE-B", "severity": "low", "patched": True})
    unpatched = engine.list_vulnerabilities(org)
    assert len(unpatched) == 1
    assert unpatched[0]["cve_id"] == "CVE-A"


def test_list_vulnerabilities_include_patched(engine, org):
    pkg = _pkg(engine, org)
    engine.add_vulnerability(org, pkg["pkg_id"], {"cve_id": "CVE-A", "severity": "high"})
    engine.add_vulnerability(org, pkg["pkg_id"], {"cve_id": "CVE-B", "severity": "low", "patched": True})
    all_vulns = engine.list_vulnerabilities(org, patched=True)
    assert len(all_vulns) == 2


def test_list_vulnerabilities_filter_severity(engine, org):
    pkg = _pkg(engine, org)
    engine.add_vulnerability(org, pkg["pkg_id"], {"severity": "critical"})
    engine.add_vulnerability(org, pkg["pkg_id"], {"severity": "low"})
    critical = engine.list_vulnerabilities(org, severity="critical")
    assert len(critical) == 1


def test_list_vulnerabilities_org_isolation(engine, org, org2):
    pkg = _pkg(engine, org)
    pkg2 = _pkg(engine, org2, "flask")
    engine.add_vulnerability(org, pkg["pkg_id"], {"severity": "high"})
    engine.add_vulnerability(org2, pkg2["pkg_id"], {"severity": "medium"})
    assert len(engine.list_vulnerabilities(org)) == 1
    assert len(engine.list_vulnerabilities(org2)) == 1


# ---------------------------------------------------------------------------
# flag_malicious + list_malicious
# ---------------------------------------------------------------------------

def test_flag_malicious_returns_record(engine, org):
    mal = engine.flag_malicious(org, {
        "name": "reque5ts",
        "ecosystem": "pypi",
        "malware_type": "typosquat",
        "confidence": 0.95,
        "source": "osv",
    })
    assert mal["name"] == "reque5ts"
    assert mal["malware_type"] == "typosquat"
    assert mal["mal_id"] is not None


def test_flag_malicious_missing_name_raises(engine, org):
    with pytest.raises(ValueError, match="name"):
        engine.flag_malicious(org, {"name": "", "ecosystem": "pypi"})


def test_flag_malicious_invalid_malware_type_raises(engine, org):
    with pytest.raises(ValueError, match="malware_type"):
        engine.flag_malicious(org, {"name": "evil", "ecosystem": "pypi", "malware_type": "virus"})


def test_list_malicious_org_isolation(engine, org, org2):
    engine.flag_malicious(org, {"name": "evil-a", "ecosystem": "npm", "malware_type": "backdoor"})
    engine.flag_malicious(org2, {"name": "evil-b", "ecosystem": "pypi", "malware_type": "backdoor"})
    assert len(engine.list_malicious(org)) == 1
    assert len(engine.list_malicious(org2)) == 1


def test_list_malicious_filter_ecosystem(engine, org):
    engine.flag_malicious(org, {"name": "evil-npm", "ecosystem": "npm", "malware_type": "cryptominer"})
    engine.flag_malicious(org, {"name": "evil-py", "ecosystem": "pypi", "malware_type": "backdoor"})
    npm = engine.list_malicious(org, ecosystem="npm")
    assert len(npm) == 1
    assert npm[0]["name"] == "evil-npm"


# ---------------------------------------------------------------------------
# check_package
# ---------------------------------------------------------------------------

def test_check_package_not_tracked(engine, org):
    result = engine.check_package(org, "unknown-pkg", "pypi")
    assert result["is_tracked"] is False
    assert result["is_malicious"] is False
    assert result["vulnerability_count"] == 0
    assert result["recommendation"] == "safe to use"


def test_check_package_is_malicious(engine, org):
    engine.flag_malicious(org, {"name": "evil-pkg", "ecosystem": "npm", "malware_type": "backdoor"})
    result = engine.check_package(org, "evil-pkg", "npm")
    assert result["is_malicious"] is True
    assert "block" in result["recommendation"]


def test_check_package_has_critical_vuln(engine, org):
    pkg = _pkg(engine, org, "vulnerable-pkg", "pypi")
    engine.add_vulnerability(org, pkg["pkg_id"], {"severity": "critical", "cvss_score": 9.9})
    result = engine.check_package(org, "vulnerable-pkg", "pypi")
    assert result["highest_severity"] == "critical"
    assert "block" in result["recommendation"]


def test_check_package_has_high_vuln(engine, org):
    pkg = _pkg(engine, org, "high-vuln-pkg", "pypi")
    engine.add_vulnerability(org, pkg["pkg_id"], {"severity": "high"})
    result = engine.check_package(org, "high-vuln-pkg", "pypi")
    assert result["highest_severity"] == "high"
    assert "warn" in result["recommendation"]


# ---------------------------------------------------------------------------
# create_sbom_snapshot + list_snapshots
# ---------------------------------------------------------------------------

def test_create_sbom_snapshot_empty(engine, org):
    snap = engine.create_sbom_snapshot(org, "my-project", [])
    assert snap["total_deps"] == 0
    assert snap["risk_score"] == 0.0
    assert snap["project_name"] == "my-project"


def test_create_sbom_snapshot_with_vulns(engine, org):
    packages = [
        {"name": "pkg-a", "ecosystem": "pypi", "is_direct": True, "license_ok": True,
         "cve_ids": [{"cve_id": "CVE-A", "severity": "critical"}]},
        {"name": "pkg-b", "ecosystem": "npm", "is_direct": False, "license_ok": False, "cve_ids": []},
    ]
    snap = engine.create_sbom_snapshot(org, "proj-x", packages)
    assert snap["total_deps"] == 2
    assert snap["direct_deps"] == 1
    assert snap["vulnerable_deps"] == 1
    assert snap["critical_vulns"] == 1
    assert snap["license_violations"] == 1
    assert snap["risk_score"] > 0


def test_create_sbom_snapshot_detects_malicious(engine, org):
    engine.flag_malicious(org, {"name": "evil-dep", "ecosystem": "npm", "malware_type": "backdoor"})
    packages = [
        {"name": "evil-dep", "ecosystem": "npm", "is_direct": True, "license_ok": True, "cve_ids": []},
    ]
    snap = engine.create_sbom_snapshot(org, "compromised-project", packages)
    assert snap["malicious_flags"] == 1
    assert snap["risk_score"] > 0


def test_list_snapshots_org_isolation(engine, org, org2):
    engine.create_sbom_snapshot(org, "proj-a", [])
    engine.create_sbom_snapshot(org2, "proj-b", [])
    assert len(engine.list_snapshots(org)) == 1
    assert len(engine.list_snapshots(org2)) == 1


def test_list_snapshots_filter_project(engine, org):
    engine.create_sbom_snapshot(org, "proj-1", [])
    engine.create_sbom_snapshot(org, "proj-2", [])
    proj1 = engine.list_snapshots(org, project_name="proj-1")
    assert len(proj1) == 1


# ---------------------------------------------------------------------------
# get_supply_chain_stats
# ---------------------------------------------------------------------------

def test_get_supply_chain_stats_empty(engine, org):
    stats = engine.get_supply_chain_stats(org)
    assert stats["total_packages"] == 0
    assert stats["malicious_flags"] == 0
    assert stats["highest_risk_packages"] == []


def test_get_supply_chain_stats_populated(engine, org):
    pkg = _pkg(engine, org, "django", risk_level="critical")
    _pkg(engine, org, "flask", risk_level="medium")
    engine.add_vulnerability(org, pkg["pkg_id"], {"severity": "critical"})
    engine.flag_malicious(org, {"name": "evil", "ecosystem": "pypi", "malware_type": "backdoor"})
    engine.create_sbom_snapshot(org, "proj-a", [])
    engine.create_sbom_snapshot(org, "proj-b", [])
    stats = engine.get_supply_chain_stats(org)
    assert stats["total_packages"] == 2
    assert stats["critical_packages"] == 1
    assert stats["malicious_flags"] == 1
    assert stats["critical_vulns"] == 1
    assert stats["projects_count"] == 2
    assert "django" in stats["highest_risk_packages"]


def test_get_supply_chain_stats_org_isolation(engine, org, org2):
    _pkg(engine, org)
    _pkg(engine, org2, "flask")
    _pkg(engine, org2, "django")
    assert engine.get_supply_chain_stats(org)["total_packages"] == 1
    assert engine.get_supply_chain_stats(org2)["total_packages"] == 2
