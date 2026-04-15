"""Tests for SoftwareCompositionAnalysisEngine — 33 tests covering all methods + org isolation."""

from __future__ import annotations

import pytest
from core.software_composition_analysis_engine import SoftwareCompositionAnalysisEngine


@pytest.fixture
def engine(tmp_path):
    return SoftwareCompositionAnalysisEngine(db_path=str(tmp_path / "sca.db"))


@pytest.fixture
def org():
    return "org-alpha"


@pytest.fixture
def org2():
    return "org-beta"


def _project(engine, org, name="backend-api", language="python"):
    return engine.register_project(org, {
        "name": name,
        "language": language,
        "repo_url": f"https://github.com/example/{name}",
    })


def _scan(engine, org, project_id, deps=None):
    if deps is None:
        deps = [
            {"name": "requests", "version": "2.28.0", "license": "Apache-2.0"},
            {"name": "flask", "version": "2.3.0", "license": "BSD-3-Clause"},
            {"name": "log4j", "version": "2.14.1", "license": "Apache-2.0"},
        ]
    return engine.submit_scan(org, project_id, {
        "dependencies": deps,
        "direct_count": 2,
        "transitive_count": 1,
    })


# ---------------------------------------------------------------------------
# register_project
# ---------------------------------------------------------------------------

def test_register_project_returns_record(engine, org):
    proj = _project(engine, org)
    assert proj["name"] == "backend-api"
    assert proj["language"] == "python"
    assert proj["org_id"] == org
    assert "id" in proj
    assert "created_at" in proj


def test_register_project_missing_name_raises(engine, org):
    with pytest.raises(ValueError, match="name"):
        engine.register_project(org, {"name": "", "language": "python"})


def test_register_project_invalid_language_raises(engine, org):
    with pytest.raises(ValueError, match="language"):
        engine.register_project(org, {"name": "app", "language": "cobol"})


def test_register_project_all_languages(engine, org):
    for lang in ("python", "java", "js", "go", "rust"):
        p = engine.register_project(org, {"name": f"app-{lang}", "language": lang})
        assert p["language"] == lang


def test_register_project_stores_repo_url(engine, org):
    proj = engine.register_project(org, {
        "name": "myapp",
        "language": "go",
        "repo_url": "https://github.com/acme/myapp",
    })
    assert proj["repo_url"] == "https://github.com/acme/myapp"


# ---------------------------------------------------------------------------
# list_projects / get_project
# ---------------------------------------------------------------------------

def test_list_projects_empty(engine, org):
    assert engine.list_projects(org) == []


def test_list_projects_returns_all(engine, org):
    _project(engine, org, "P1")
    _project(engine, org, "P2")
    assert len(engine.list_projects(org)) == 2


def test_list_projects_org_isolation(engine, org, org2):
    _project(engine, org, "P-alpha")
    _project(engine, org2, "P-beta")
    assert len(engine.list_projects(org)) == 1
    assert len(engine.list_projects(org2)) == 1


def test_get_project_returns_record(engine, org):
    proj = _project(engine, org)
    fetched = engine.get_project(org, proj["id"])
    assert fetched["id"] == proj["id"]
    assert fetched["name"] == proj["name"]


def test_get_project_wrong_org_returns_none(engine, org, org2):
    proj = _project(engine, org)
    assert engine.get_project(org2, proj["id"]) is None


# ---------------------------------------------------------------------------
# submit_scan
# ---------------------------------------------------------------------------

def test_submit_scan_returns_record(engine, org):
    proj = _project(engine, org)
    scan = _scan(engine, org, proj["id"])
    assert scan["project_id"] == proj["id"]
    assert scan["direct_count"] == 2
    assert scan["transitive_count"] == 1
    assert isinstance(scan["dependencies"], list)
    assert len(scan["dependencies"]) == 3


def test_submit_scan_detects_known_vulnerability(engine, org):
    proj = _project(engine, org)
    scan = engine.submit_scan(org, proj["id"], {
        "dependencies": [
            {"name": "log4j", "version": "2.14.1", "license": "Apache-2.0"},
        ],
        "direct_count": 1,
        "transitive_count": 0,
    })
    assert scan["vulnerable_count"] == 1
    dep = scan["dependencies"][0]
    assert dep["is_vulnerable"] is True
    assert len(dep["cves"]) > 0
    assert dep["cves"][0]["cve_id"] == "CVE-2021-44228"


def test_submit_scan_detects_risky_license(engine, org):
    proj = _project(engine, org)
    scan = engine.submit_scan(org, proj["id"], {
        "dependencies": [
            {"name": "some-lib", "version": "1.0", "license": "GPL-3.0"},
        ],
        "direct_count": 1,
        "transitive_count": 0,
    })
    assert scan["license_risk"] is True


def test_submit_scan_clean_deps(engine, org):
    proj = _project(engine, org)
    scan = engine.submit_scan(org, proj["id"], {
        "dependencies": [
            {"name": "pure-lib", "version": "1.0", "license": "MIT"},
        ],
        "direct_count": 1,
        "transitive_count": 0,
    })
    assert scan["vulnerable_count"] == 0
    assert scan["license_risk"] is False


def test_submit_scan_spring4shell_detected(engine, org):
    proj = _project(engine, org, language="java")
    scan = engine.submit_scan(org, proj["id"], {
        "dependencies": [
            {"name": "spring-core", "version": "5.3.17", "license": "Apache-2.0"},
        ],
        "direct_count": 1,
        "transitive_count": 0,
    })
    assert scan["vulnerable_count"] == 1


# ---------------------------------------------------------------------------
# list_scans / get_scan
# ---------------------------------------------------------------------------

def test_list_scans_empty(engine, org):
    assert engine.list_scans(org) == []


def test_list_scans_returns_all(engine, org):
    proj = _project(engine, org)
    _scan(engine, org, proj["id"])
    _scan(engine, org, proj["id"])
    assert len(engine.list_scans(org)) == 2


def test_list_scans_filter_by_project(engine, org):
    p1 = _project(engine, org, "P1")
    p2 = _project(engine, org, "P2")
    _scan(engine, org, p1["id"])
    _scan(engine, org, p2["id"])
    assert len(engine.list_scans(org, project_id=p1["id"])) == 1


def test_list_scans_org_isolation(engine, org, org2):
    p1 = _project(engine, org)
    p2 = _project(engine, org2)
    _scan(engine, org, p1["id"])
    assert len(engine.list_scans(org)) == 1
    assert len(engine.list_scans(org2)) == 0


def test_get_scan_returns_record(engine, org):
    proj = _project(engine, org)
    scan = _scan(engine, org, proj["id"])
    fetched = engine.get_scan(org, scan["id"])
    assert fetched["id"] == scan["id"]


def test_get_scan_wrong_org_returns_none(engine, org, org2):
    proj = _project(engine, org)
    scan = _scan(engine, org, proj["id"])
    assert engine.get_scan(org2, scan["id"]) is None


# ---------------------------------------------------------------------------
# get_vulnerable_dependencies
# ---------------------------------------------------------------------------

def test_get_vulnerable_dependencies_returns_only_vulnerable(engine, org):
    proj = _project(engine, org)
    scan = engine.submit_scan(org, proj["id"], {
        "dependencies": [
            {"name": "log4j", "version": "2.14.1", "license": "Apache-2.0"},
            {"name": "safe-lib", "version": "1.0", "license": "MIT"},
        ],
        "direct_count": 2,
        "transitive_count": 0,
    })
    vuln_deps = engine.get_vulnerable_dependencies(org, scan["id"])
    assert len(vuln_deps) == 1
    assert vuln_deps[0]["name"] == "log4j"
    assert vuln_deps[0]["is_vulnerable"] is True


def test_get_vulnerable_dependencies_empty_when_clean(engine, org):
    proj = _project(engine, org)
    scan = engine.submit_scan(org, proj["id"], {
        "dependencies": [{"name": "clean-lib", "version": "1.0", "license": "MIT"}],
        "direct_count": 1,
        "transitive_count": 0,
    })
    assert engine.get_vulnerable_dependencies(org, scan["id"]) == []


def test_get_vulnerable_dependencies_scan_not_found_raises(engine, org):
    with pytest.raises(KeyError):
        engine.get_vulnerable_dependencies(org, "nonexistent")


# ---------------------------------------------------------------------------
# get_license_report
# ---------------------------------------------------------------------------

def test_get_license_report_returns_distribution(engine, org):
    proj = _project(engine, org)
    scan = engine.submit_scan(org, proj["id"], {
        "dependencies": [
            {"name": "lib-a", "version": "1.0", "license": "MIT"},
            {"name": "lib-b", "version": "2.0", "license": "MIT"},
            {"name": "lib-c", "version": "3.0", "license": "Apache-2.0"},
            {"name": "lib-d", "version": "4.0", "license": "GPL-3.0"},
        ],
        "direct_count": 4,
        "transitive_count": 0,
    })
    report = engine.get_license_report(org, scan["id"])
    assert report["licenses"]["MIT"] == 2
    assert report["licenses"]["Apache-2.0"] == 1
    assert report["licenses"]["GPL-3.0"] == 1
    assert report["risky_count"] == 1
    assert any(r["license"] == "GPL-3.0" for r in report["risky_licenses"])


def test_get_license_report_no_risky_licenses(engine, org):
    proj = _project(engine, org)
    scan = engine.submit_scan(org, proj["id"], {
        "dependencies": [
            {"name": "safe-a", "version": "1.0", "license": "MIT"},
            {"name": "safe-b", "version": "2.0", "license": "Apache-2.0"},
        ],
        "direct_count": 2,
        "transitive_count": 0,
    })
    report = engine.get_license_report(org, scan["id"])
    assert report["risky_count"] == 0
    assert report["risky_licenses"] == []


def test_get_license_report_scan_not_found_raises(engine, org):
    with pytest.raises(KeyError):
        engine.get_license_report(org, "nonexistent")


# ---------------------------------------------------------------------------
# get_sca_stats
# ---------------------------------------------------------------------------

def test_get_sca_stats_empty(engine, org):
    stats = engine.get_sca_stats(org)
    assert stats["projects"] == 0
    assert stats["scans"] == 0
    assert stats["vulnerable_deps"] == 0
    assert stats["license_violations"] == 0


def test_get_sca_stats_populated(engine, org):
    p1 = _project(engine, org, "P1")
    p2 = _project(engine, org, "P2")
    engine.submit_scan(org, p1["id"], {
        "dependencies": [{"name": "log4j", "version": "2.14.1", "license": "Apache-2.0"}],
        "direct_count": 1,
        "transitive_count": 0,
    })
    engine.submit_scan(org, p2["id"], {
        "dependencies": [{"name": "safe-lib", "version": "1.0", "license": "GPL-3.0"}],
        "direct_count": 1,
        "transitive_count": 0,
    })
    stats = engine.get_sca_stats(org)
    assert stats["projects"] == 2
    assert stats["scans"] == 2
    assert stats["vulnerable_deps"] == 1
    assert stats["license_violations"] == 1


def test_get_sca_stats_org_isolation(engine, org, org2):
    p1 = _project(engine, org)
    p2 = _project(engine, org2)
    _scan(engine, org, p1["id"])
    stats1 = engine.get_sca_stats(org)
    stats2 = engine.get_sca_stats(org2)
    assert stats1["projects"] == 1
    assert stats1["scans"] == 1
    assert stats2["projects"] == 1
    assert stats2["scans"] == 0
