"""Tests for SBOMExportEngine — ALDECI.

Covers:
- register_component dedup (INSERT OR IGNORE)
- vuln_count recompute on add_vuln
- generate_cyclonedx structure: bomFormat, specVersion, components, vulnerabilities
- generate_spdx structure: spdxVersion, packages, documentNamespace
- export record inserted on each generate call
- project_summary aggregation: component_count, total_vulns, critical_vulns, by_ecosystem, by_license
- list_projects with component_count
- get_export_history ordering
- search_component by name and purl
- org isolation: org_a data not visible to org_b
- invalid component_type raises ValueError
- invalid severity raises ValueError
- 38+ tests
"""

from __future__ import annotations

import sys
import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.sbom_export_engine import SBOMExportEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return SBOMExportEngine(db_path=str(tmp_path / "sbom_export.db"))


def _comp(
    engine,
    org_id="org1",
    project_name="myapp",
    component_name="requests",
    component_version="2.28.0",
    component_type="library",
    ecosystem="pypi",
    license="Apache-2.0",
    purl="pkg:pypi/requests@2.28.0",
    cpe="",
    supplier="Kenneth Reitz",
    hash_sha256="abc123",
):
    return engine.register_component(
        org_id=org_id,
        project_name=project_name,
        component_name=component_name,
        component_version=component_version,
        component_type=component_type,
        ecosystem=ecosystem,
        license=license,
        purl=purl,
        cpe=cpe,
        supplier=supplier,
        hash_sha256=hash_sha256,
    )


# ---------------------------------------------------------------------------
# register_component
# ---------------------------------------------------------------------------


def test_register_component_basic(engine):
    c = _comp(engine)
    assert c["id"]
    assert c["org_id"] == "org1"
    assert c["project_name"] == "myapp"
    assert c["component_name"] == "requests"
    assert c["component_version"] == "2.28.0"
    assert c["component_type"] == "library"
    assert c["ecosystem"] == "pypi"
    assert c["license"] == "Apache-2.0"
    assert c["purl"] == "pkg:pypi/requests@2.28.0"
    assert c["supplier"] == "Kenneth Reitz"
    assert c["hash_sha256"] == "abc123"
    assert c["vuln_count"] == 0


def test_register_component_dedup_returns_existing(engine):
    c1 = _comp(engine)
    c2 = _comp(engine)  # same org+project+name+version
    assert c1["id"] == c2["id"]


def test_register_component_different_version_not_deduped(engine):
    c1 = _comp(engine, component_version="2.28.0")
    c2 = _comp(engine, component_version="2.29.0")
    assert c1["id"] != c2["id"]


def test_register_component_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="component_type"):
        engine.register_component(
            org_id="org1",
            project_name="myapp",
            component_name="foo",
            component_version="1.0",
            component_type="invalid_type",
            ecosystem="pypi",
            license="MIT",
        )


def test_register_all_valid_types(engine):
    types = ["library", "framework", "application", "container",
             "device", "firmware", "file", "operating-system"]
    for i, t in enumerate(types):
        c = engine.register_component(
            org_id="org1",
            project_name="myapp",
            component_name=f"comp_{i}",
            component_version="1.0",
            component_type=t,
            ecosystem="npm",
            license="MIT",
        )
        assert c["component_type"] == t


def test_register_component_no_purl_defaults_empty(engine):
    c = engine.register_component(
        org_id="org1",
        project_name="myapp",
        component_name="nopurl",
        component_version="1.0",
        component_type="library",
        ecosystem="npm",
        license="MIT",
    )
    assert c["purl"] == ""


# ---------------------------------------------------------------------------
# add_vuln + vuln_count recompute
# ---------------------------------------------------------------------------


def test_add_vuln_basic(engine):
    c = _comp(engine)
    v = engine.add_vuln(
        component_id=c["id"],
        org_id="org1",
        cve_id="CVE-2023-1234",
        severity="high",
        cvss_score=7.5,
        affects_version="2.28.0",
        fixed_in="2.29.0",
    )
    assert v["id"]
    assert v["cve_id"] == "CVE-2023-1234"
    assert v["severity"] == "high"
    assert v["cvss_score"] == 7.5


def test_vuln_count_recomputed(engine):
    c = _comp(engine)
    assert c["vuln_count"] == 0
    engine.add_vuln(c["id"], "org1", "CVE-2023-0001", "high", 7.5, "2.28.0")
    engine.add_vuln(c["id"], "org1", "CVE-2023-0002", "critical", 9.8, "2.28.0")
    updated = engine.get_component(c["id"], "org1")
    assert updated["vuln_count"] == 2


def test_add_vuln_invalid_severity(engine):
    c = _comp(engine)
    with pytest.raises(ValueError, match="severity"):
        engine.add_vuln(c["id"], "org1", "CVE-2023-9999", "unknown", 5.0, "2.28.0")


def test_add_vuln_all_severities(engine):
    c = _comp(engine)
    for i, sev in enumerate(["critical", "high", "medium", "low", "informational"]):
        v = engine.add_vuln(c["id"], "org1", f"CVE-2023-{i:04d}", sev, float(i), "2.28.0")
        assert v["severity"] == sev
    updated = engine.get_component(c["id"], "org1")
    assert updated["vuln_count"] == 5


# ---------------------------------------------------------------------------
# generate_cyclonedx
# ---------------------------------------------------------------------------


def test_generate_cyclonedx_structure(engine):
    c = _comp(engine)
    bom = engine.generate_cyclonedx("org1", "myapp", version_tag="1.0")
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["version"] == 1
    assert "metadata" in bom
    assert bom["metadata"]["component"]["name"] == "myapp"
    assert bom["metadata"]["component"]["version"] == "1.0"
    assert "components" in bom
    assert len(bom["components"]) == 1
    assert "vulnerabilities" in bom


def test_generate_cyclonedx_component_fields(engine):
    c = _comp(engine)
    bom = engine.generate_cyclonedx("org1", "myapp")
    comp = bom["components"][0]
    assert comp["type"] == "library"
    assert comp["name"] == "requests"
    assert comp["version"] == "2.28.0"
    assert comp["purl"] == "pkg:pypi/requests@2.28.0"
    assert comp["licenses"][0]["license"]["id"] == "Apache-2.0"
    assert comp["supplier"]["name"] == "Kenneth Reitz"
    assert comp["hashes"][0]["alg"] == "SHA-256"
    assert comp["hashes"][0]["content"] == "abc123"


def test_generate_cyclonedx_no_hash_empty_hashes(engine):
    engine.register_component(
        org_id="org1", project_name="proj2", component_name="nohash",
        component_version="1.0", component_type="library",
        ecosystem="npm", license="MIT", hash_sha256="",
    )
    bom = engine.generate_cyclonedx("org1", "proj2")
    assert bom["components"][0]["hashes"] == []


def test_generate_cyclonedx_with_vulns(engine):
    c = _comp(engine)
    engine.add_vuln(c["id"], "org1", "CVE-2023-1234", "high", 7.5, "2.28.0")
    bom = engine.generate_cyclonedx("org1", "myapp")
    assert len(bom["vulnerabilities"]) == 1
    v = bom["vulnerabilities"][0]
    assert v["id"] == "CVE-2023-1234"
    assert v["ratings"][0]["severity"] == "high"
    assert v["ratings"][0]["score"] == 7.5


def test_generate_cyclonedx_records_export(engine):
    _comp(engine)
    bom = engine.generate_cyclonedx("org1", "myapp", exported_by="alice")
    history = engine.get_export_history("org1", "myapp")
    assert len(history) == 1
    assert history[0]["format"] == "cyclonedx"
    assert history[0]["exported_by"] == "alice"
    assert history[0]["component_count"] == 1


def test_generate_cyclonedx_org_isolation(engine):
    _comp(engine, org_id="org1")
    _comp(engine, org_id="org2", component_name="other", purl="pkg:pypi/other@1.0")
    bom = engine.generate_cyclonedx("org1", "myapp")
    assert len(bom["components"]) == 1
    assert bom["components"][0]["name"] == "requests"


# ---------------------------------------------------------------------------
# generate_spdx
# ---------------------------------------------------------------------------


def test_generate_spdx_structure(engine):
    _comp(engine)
    doc = engine.generate_spdx("org1", "myapp", version_tag="2.0")
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["dataLicense"] == "CC0-1.0"
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert doc["name"] == "myapp"
    assert doc["documentNamespace"] == "https://aldeci.io/sbom/myapp/2.0"
    assert "packages" in doc
    assert len(doc["packages"]) == 1


def test_generate_spdx_package_fields(engine):
    _comp(engine)
    doc = engine.generate_spdx("org1", "myapp")
    pkg = doc["packages"][0]
    assert pkg["SPDXID"] == "SPDXRef-requests-2.28.0"
    assert pkg["name"] == "requests"
    assert pkg["versionInfo"] == "2.28.0"
    assert pkg["licenseConcluded"] == "Apache-2.0"
    assert pkg["supplier"] == "Organization: Kenneth Reitz"
    assert len(pkg["externalRefs"]) == 1
    assert pkg["externalRefs"][0]["referenceType"] == "purl"
    assert pkg["externalRefs"][0]["referenceLocator"] == "pkg:pypi/requests@2.28.0"


def test_generate_spdx_no_supplier_noassertion(engine):
    engine.register_component(
        org_id="org1", project_name="proj2", component_name="nosup",
        component_version="1.0", component_type="library",
        ecosystem="npm", license="MIT", supplier="",
    )
    doc = engine.generate_spdx("org1", "proj2")
    assert doc["packages"][0]["supplier"] == "NOASSERTION"


def test_generate_spdx_no_purl_empty_external_refs(engine):
    engine.register_component(
        org_id="org1", project_name="proj3", component_name="nopurl",
        component_version="1.0", component_type="library",
        ecosystem="npm", license="MIT", purl="",
    )
    doc = engine.generate_spdx("org1", "proj3")
    assert doc["packages"][0]["externalRefs"] == []


def test_generate_spdx_records_export(engine):
    _comp(engine)
    engine.generate_spdx("org1", "myapp", exported_by="bob")
    history = engine.get_export_history("org1", "myapp")
    spdx_exports = [h for h in history if h["format"] == "spdx"]
    assert len(spdx_exports) == 1
    assert spdx_exports[0]["exported_by"] == "bob"


def test_multiple_exports_recorded(engine):
    _comp(engine)
    engine.generate_cyclonedx("org1", "myapp")
    engine.generate_spdx("org1", "myapp")
    history = engine.get_export_history("org1", "myapp")
    assert len(history) == 2
    formats = {h["format"] for h in history}
    assert "cyclonedx" in formats
    assert "spdx" in formats


# ---------------------------------------------------------------------------
# project_summary
# ---------------------------------------------------------------------------


def test_project_summary_basic(engine):
    c = _comp(engine)
    engine.add_vuln(c["id"], "org1", "CVE-2023-0001", "critical", 9.8, "2.28.0")
    engine.add_vuln(c["id"], "org1", "CVE-2023-0002", "high", 7.5, "2.28.0")
    summary = engine.get_project_summary("org1", "myapp")
    assert summary["component_count"] == 1
    assert summary["total_vulns"] == 2
    assert summary["critical_vulns"] == 1
    assert "pypi" in summary["by_ecosystem"]
    assert "Apache-2.0" in summary["by_license"]


def test_project_summary_latest_export(engine):
    _comp(engine)
    engine.generate_cyclonedx("org1", "myapp")
    summary = engine.get_project_summary("org1", "myapp")
    assert summary["latest_export"] is not None
    assert summary["latest_export"]["format"] == "cyclonedx"


def test_project_summary_no_export(engine):
    _comp(engine)
    summary = engine.get_project_summary("org1", "myapp")
    assert summary["latest_export"] is None


def test_project_summary_org_isolation(engine):
    _comp(engine, org_id="org1")
    _comp(engine, org_id="org2", component_name="other", purl="pkg:pypi/other@1.0")
    summary = engine.get_project_summary("org1", "myapp")
    assert summary["component_count"] == 1


# ---------------------------------------------------------------------------
# list_projects
# ---------------------------------------------------------------------------


def test_list_projects(engine):
    _comp(engine, project_name="proj1")
    _comp(engine, project_name="proj2", component_name="flask", purl="pkg:pypi/flask@2.0")
    projects = engine.list_projects("org1")
    names = [p["project_name"] for p in projects]
    assert "proj1" in names
    assert "proj2" in names


def test_list_projects_component_count(engine):
    _comp(engine, project_name="proj1", component_name="a", purl="pkg:pypi/a@1.0")
    engine.register_component(
        org_id="org1", project_name="proj1", component_name="b",
        component_version="1.0", component_type="library",
        ecosystem="pypi", license="MIT", purl="pkg:pypi/b@1.0",
    )
    projects = engine.list_projects("org1")
    proj1 = next(p for p in projects if p["project_name"] == "proj1")
    assert proj1["component_count"] == 2


def test_list_projects_org_isolation(engine):
    _comp(engine, org_id="org1", project_name="proj1")
    _comp(engine, org_id="org2", project_name="proj2", component_name="x", purl="pkg:pypi/x@1.0")
    projects = engine.list_projects("org1")
    names = [p["project_name"] for p in projects]
    assert "proj1" in names
    assert "proj2" not in names


# ---------------------------------------------------------------------------
# search_component
# ---------------------------------------------------------------------------


def test_search_by_name(engine):
    _comp(engine, component_name="requests")
    _comp(engine, component_name="flask", component_version="2.0", purl="pkg:pypi/flask@2.0")
    results = engine.search_component("org1", "requ")
    assert len(results) == 1
    assert results[0]["component_name"] == "requests"


def test_search_by_purl(engine):
    _comp(engine, purl="pkg:pypi/requests@2.28.0")
    results = engine.search_component("org1", "pypi/requests")
    assert len(results) == 1


def test_search_no_results(engine):
    _comp(engine)
    results = engine.search_component("org1", "nonexistent_package")
    assert results == []


def test_search_org_isolation(engine):
    _comp(engine, org_id="org1")
    results = engine.search_component("org2", "requests")
    assert results == []


# ---------------------------------------------------------------------------
# export history ordering
# ---------------------------------------------------------------------------


def test_export_history_ordered_desc(engine):
    _comp(engine)
    engine.generate_cyclonedx("org1", "myapp", version_tag="1.0")
    engine.generate_cyclonedx("org1", "myapp", version_tag="2.0")
    history = engine.get_export_history("org1", "myapp")
    assert len(history) == 2
    # Most recent first
    assert history[0]["generated_at"] >= history[1]["generated_at"]


# ---------------------------------------------------------------------------
# CycloneDX 1.6 new fields
# ---------------------------------------------------------------------------


def test_generate_cyclonedx_16_spec_version(engine):
    _comp(engine)
    bom = engine.generate_cyclonedx("org1", "myapp")
    assert bom["specVersion"] == "1.6"


def test_generate_cyclonedx_16_lifecycles_present(engine):
    _comp(engine)
    bom = engine.generate_cyclonedx("org1", "myapp")
    assert "lifecycles" in bom["metadata"]
    lifecycles = bom["metadata"]["lifecycles"]
    assert isinstance(lifecycles, list)
    assert len(lifecycles) == 6


def test_generate_cyclonedx_16_lifecycles_phases(engine):
    _comp(engine)
    bom = engine.generate_cyclonedx("org1", "myapp")
    phases = {lc["phase"] for lc in bom["metadata"]["lifecycles"]}
    assert phases == {"design", "build", "post-build", "operations", "discovery", "decommission"}


def test_generate_cyclonedx_16_formulation_present(engine):
    _comp(engine)
    bom = engine.generate_cyclonedx("org1", "myapp")
    assert "formulation" in bom
    formulation = bom["formulation"]
    assert "components" in formulation
    assert len(formulation["components"]) == 1
    assert formulation["components"][0]["name"] == "ALDECI SBOM Engine"


def test_generate_cyclonedx_16_formulation_type(engine):
    _comp(engine)
    bom = engine.generate_cyclonedx("org1", "myapp")
    assert bom["formulation"]["components"][0]["type"] == "platform"


def test_generate_cyclonedx_16_vuln_source_field(engine):
    c = _comp(engine)
    engine.add_vuln(c["id"], "org1", "CVE-2024-0001", "critical", 9.8, "2.28.0")
    bom = engine.generate_cyclonedx("org1", "myapp")
    vuln = bom["vulnerabilities"][0]
    assert "source" in vuln
    assert vuln["source"]["name"] == "ALDECI"
    assert "url" in vuln["source"]


def test_generate_cyclonedx_16_vuln_analysis_field(engine):
    c = _comp(engine)
    engine.add_vuln(c["id"], "org1", "CVE-2024-0002", "high", 7.5, "2.28.0")
    bom = engine.generate_cyclonedx("org1", "myapp")
    vuln = bom["vulnerabilities"][0]
    assert "analysis" in vuln
    assert vuln["analysis"]["state"] == "in_triage"


def test_generate_cyclonedx_16_no_vulns_empty_vulnerabilities(engine):
    _comp(engine)
    bom = engine.generate_cyclonedx("org1", "myapp")
    assert bom["vulnerabilities"] == []
    # formulation and lifecycles still present even with no vulns
    assert "formulation" in bom
    assert "lifecycles" in bom["metadata"]
