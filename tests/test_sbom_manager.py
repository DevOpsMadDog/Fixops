"""
Tests for SBOM Manager — import/export, vulnerability mapping,
license classification, diffing, risk scoring, CRUD.

All tests use an in-memory SQLite database (:memory: via tmp_path).
No external dependencies required.
"""

from __future__ import annotations

import json
import os
import sys
import pytest

# Ensure suite paths are available
os.environ.setdefault("FIXOPS_MODE", "dev")
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops")

from core.sbom_manager import (
    Component,
    LicenseRisk,
    SBOM,
    SBOMFormat,
    SBOMManager,
    VulnerableComponent,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def manager(tmp_path):
    """SBOMManager backed by a temp SQLite file."""
    return SBOMManager(db_path=str(tmp_path / "sbom_test.db"))


CYCLONEDX_SAMPLE = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "my-app",
                "version": "2.0.0",
            }
        },
        "components": [
            {
                "type": "library",
                "name": "log4j-core",
                "version": "2.14.1",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "supplier": {"name": "Apache Software Foundation"},
                "hashes": [{"alg": "SHA-256", "content": "abc123def456"}],
            },
            {
                "type": "library",
                "name": "spring-core",
                "version": "5.3.15",
                "purl": "pkg:maven/org.springframework/spring-core@5.3.15",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "hashes": [],
            },
            {
                "type": "library",
                "name": "commons-lang3",
                "version": "3.12.0",
                "purl": "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "hashes": [],
            },
        ],
    }
)

SPDX_SAMPLE = json.dumps(
    {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "my-node-app",
        "documentNamespace": "https://spdx.org/spdxdocs/my-node-app-1.0.0",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-0",
                "name": "lodash",
                "versionInfo": "4.17.20",
                "downloadLocation": "https://registry.npmjs.org/lodash",
                "filesAnalyzed": False,
                "licenseDeclared": "MIT",
                "licenseConcluded": "MIT",
                "copyrightText": "NOASSERTION",
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": "deadbeef"}
                ],
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:npm/lodash@4.17.20",
                    }
                ],
            },
            {
                "SPDXID": "SPDXRef-Package-1",
                "name": "axios",
                "versionInfo": "0.27.2",
                "downloadLocation": "https://registry.npmjs.org/axios",
                "filesAnalyzed": False,
                "licenseDeclared": "MIT",
                "licenseConcluded": "MIT",
                "copyrightText": "NOASSERTION",
                "checksums": [],
                "externalRefs": [],
            },
        ],
    }
)


# ---------------------------------------------------------------------------
# Import — CycloneDX
# ---------------------------------------------------------------------------

class TestImportCycloneDX:
    def test_import_returns_sbom(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "my-app")
        assert isinstance(sbom, SBOM)
        assert sbom.format == SBOMFormat.CYCLONEDX

    def test_import_component_count(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "my-app")
        assert len(sbom.components) == 3

    def test_import_component_names(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "my-app")
        names = {c.name for c in sbom.components}
        assert "log4j-core" in names
        assert "spring-core" in names
        assert "commons-lang3" in names

    def test_import_component_version(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "my-app")
        log4j = next(c for c in sbom.components if c.name == "log4j-core")
        assert log4j.version == "2.14.1"

    def test_import_component_purl(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "my-app")
        log4j = next(c for c in sbom.components if c.name == "log4j-core")
        assert log4j.purl == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"

    def test_import_component_licenses(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "my-app")
        log4j = next(c for c in sbom.components if c.name == "log4j-core")
        assert "Apache-2.0" in log4j.licenses

    def test_import_component_hashes(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "my-app")
        log4j = next(c for c in sbom.components if c.name == "log4j-core")
        assert log4j.hashes.get("SHA-256") == "abc123def456"

    def test_import_spec_version(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "my-app")
        assert sbom.spec_version == "1.4"

    def test_import_invalid_json_raises(self, manager):
        with pytest.raises(ValueError, match="Invalid JSON"):
            manager.import_sbom("not-json", SBOMFormat.CYCLONEDX, "proj")


# ---------------------------------------------------------------------------
# Import — SPDX
# ---------------------------------------------------------------------------

class TestImportSPDX:
    def test_import_returns_sbom(self, manager):
        sbom = manager.import_sbom(SPDX_SAMPLE, SBOMFormat.SPDX, "my-node-app")
        assert isinstance(sbom, SBOM)
        assert sbom.format == SBOMFormat.SPDX

    def test_import_component_count(self, manager):
        sbom = manager.import_sbom(SPDX_SAMPLE, SBOMFormat.SPDX, "my-node-app")
        assert len(sbom.components) == 2

    def test_import_component_names(self, manager):
        sbom = manager.import_sbom(SPDX_SAMPLE, SBOMFormat.SPDX, "my-node-app")
        names = {c.name for c in sbom.components}
        assert "lodash" in names
        assert "axios" in names

    def test_import_component_version(self, manager):
        sbom = manager.import_sbom(SPDX_SAMPLE, SBOMFormat.SPDX, "my-node-app")
        lodash = next(c for c in sbom.components if c.name == "lodash")
        assert lodash.version == "4.17.20"

    def test_import_component_purl(self, manager):
        sbom = manager.import_sbom(SPDX_SAMPLE, SBOMFormat.SPDX, "my-node-app")
        lodash = next(c for c in sbom.components if c.name == "lodash")
        assert lodash.purl == "pkg:npm/lodash@4.17.20"

    def test_import_component_license(self, manager):
        sbom = manager.import_sbom(SPDX_SAMPLE, SBOMFormat.SPDX, "my-node-app")
        lodash = next(c for c in sbom.components if c.name == "lodash")
        assert "MIT" in lodash.licenses

    def test_import_checksums(self, manager):
        sbom = manager.import_sbom(SPDX_SAMPLE, SBOMFormat.SPDX, "my-node-app")
        lodash = next(c for c in sbom.components if c.name == "lodash")
        assert lodash.hashes.get("SHA1") == "deadbeef"

    def test_import_spdx_version(self, manager):
        sbom = manager.import_sbom(SPDX_SAMPLE, SBOMFormat.SPDX, "my-node-app")
        assert sbom.spec_version == "SPDX-2.3"


# ---------------------------------------------------------------------------
# Export round-trip
# ---------------------------------------------------------------------------

class TestExport:
    def test_export_cyclonedx_structure(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "my-app")
        exported = manager.export_sbom(sbom.id, SBOMFormat.CYCLONEDX)
        doc = json.loads(exported)
        assert doc["bomFormat"] == "CycloneDX"
        assert "components" in doc
        assert len(doc["components"]) == 3

    def test_export_cyclonedx_has_purl(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "my-app")
        exported = manager.export_sbom(sbom.id, SBOMFormat.CYCLONEDX)
        doc = json.loads(exported)
        purls = [c.get("purl") for c in doc["components"] if c.get("purl")]
        assert any("log4j-core" in p for p in purls)

    def test_export_spdx_structure(self, manager):
        sbom = manager.import_sbom(SPDX_SAMPLE, SBOMFormat.SPDX, "my-node-app")
        exported = manager.export_sbom(sbom.id, SBOMFormat.SPDX)
        doc = json.loads(exported)
        assert "spdxVersion" in doc
        assert "packages" in doc
        assert len(doc["packages"]) == 2

    def test_export_spdx_preserves_names(self, manager):
        sbom = manager.import_sbom(SPDX_SAMPLE, SBOMFormat.SPDX, "my-node-app")
        exported = manager.export_sbom(sbom.id, SBOMFormat.SPDX)
        doc = json.loads(exported)
        names = {p["name"] for p in doc["packages"]}
        assert "lodash" in names

    def test_export_not_found_raises(self, manager):
        with pytest.raises(KeyError):
            manager.export_sbom("nonexistent-id", SBOMFormat.CYCLONEDX)


# ---------------------------------------------------------------------------
# CRUD operations
# ---------------------------------------------------------------------------

class TestCRUD:
    def test_get_sbom(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "proj")
        fetched = manager.get_sbom(sbom.id)
        assert fetched.id == sbom.id
        assert fetched.project_name == "proj"

    def test_get_sbom_not_found(self, manager):
        with pytest.raises(KeyError):
            manager.get_sbom("does-not-exist")

    def test_list_sboms_empty(self, manager):
        assert manager.list_sboms() == []

    def test_list_sboms_returns_all(self, manager):
        manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "proj-a")
        manager.import_sbom(SPDX_SAMPLE, SBOMFormat.SPDX, "proj-b")
        result = manager.list_sboms()
        assert len(result) == 2

    def test_list_sboms_filter_org(self, manager):
        manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "proj", org_id="org1")
        manager.import_sbom(SPDX_SAMPLE, SBOMFormat.SPDX, "proj", org_id="org2")
        result = manager.list_sboms(org_id="org1")
        assert len(result) == 1
        assert result[0].org_id == "org1"

    def test_list_sboms_filter_project(self, manager):
        manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "alpha")
        manager.import_sbom(SPDX_SAMPLE, SBOMFormat.SPDX, "beta")
        result = manager.list_sboms(project_name="alpha")
        assert len(result) == 1
        assert result[0].project_name == "alpha"

    def test_get_components(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "proj")
        comps = manager.get_components(sbom.id)
        assert len(comps) == 3

    def test_delete_sbom(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "proj")
        manager.delete_sbom(sbom.id)
        with pytest.raises(KeyError):
            manager.get_sbom(sbom.id)

    def test_delete_cascades_components(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "proj")
        manager.delete_sbom(sbom.id)
        # After delete, list should be empty
        assert manager.list_sboms() == []

    def test_delete_not_found_raises(self, manager):
        with pytest.raises(KeyError):
            manager.delete_sbom("ghost-id")


# ---------------------------------------------------------------------------
# Vulnerability mapping
# ---------------------------------------------------------------------------

class TestVulnerabilityMapping:
    def test_map_vulnerabilities_finds_log4j(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "proj")
        vulns = manager.map_vulnerabilities(sbom.id)
        names = {v.component.name for v in vulns}
        assert "log4j-core" in names

    def test_map_vulnerabilities_finds_spring(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "proj")
        vulns = manager.map_vulnerabilities(sbom.id)
        names = {v.component.name for v in vulns}
        assert "spring-core" in names

    def test_map_vulnerabilities_cve_ids(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "proj")
        vulns = manager.map_vulnerabilities(sbom.id)
        log4j_vuln = next(v for v in vulns if v.component.name == "log4j-core")
        assert "CVE-2021-44228" in log4j_vuln.cve_ids

    def test_map_vulnerabilities_severity(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "proj")
        vulns = manager.map_vulnerabilities(sbom.id)
        log4j_vuln = next(v for v in vulns if v.component.name == "log4j-core")
        assert log4j_vuln.severity == "critical"

    def test_map_vulnerabilities_risk_score(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "proj")
        vulns = manager.map_vulnerabilities(sbom.id)
        log4j_vuln = next(v for v in vulns if v.component.name == "log4j-core")
        assert log4j_vuln.risk_score > 0

    def test_map_vulnerabilities_clean_component(self, manager):
        sbom = manager.import_sbom(CYCLONEDX_SAMPLE, SBOMFormat.CYCLONEDX, "proj")
        vulns = manager.map_vulnerabilities(sbom.id)
        vuln_names = {v.component.name for v in vulns}
        # commons-lang3 has no known CVEs in mock data
        assert "commons-lang3" not in vuln_names

    def test_map_vulnerabilities_lodash(self, manager):
        sbom = manager.import_sbom(SPDX_SAMPLE, SBOMFormat.SPDX, "node-proj")
        vulns = manager.map_vulnerabilities(sbom.id)
        lodash_vuln = next((v for v in vulns if v.component.name == "lodash"), None)
        assert lodash_vuln is not None
        assert "CVE-2021-23337" in lodash_vuln.cve_ids


# ---------------------------------------------------------------------------
# License classification
# ---------------------------------------------------------------------------

class TestLicenseClassification:
    def test_permissive_mit(self, manager):
        assert manager.classify_license("MIT") == LicenseRisk.PERMISSIVE

    def test_permissive_apache(self, manager):
        assert manager.classify_license("Apache-2.0") == LicenseRisk.PERMISSIVE

    def test_permissive_bsd_2(self, manager):
        assert manager.classify_license("BSD-2-Clause") == LicenseRisk.PERMISSIVE

    def test_permissive_bsd_3(self, manager):
        assert manager.classify_license("BSD-3-Clause") == LicenseRisk.PERMISSIVE

    def test_permissive_isc(self, manager):
        assert manager.classify_license("ISC") == LicenseRisk.PERMISSIVE

    def test_weak_copyleft_lgpl(self, manager):
        assert manager.classify_license("LGPL-2.1") == LicenseRisk.WEAK_COPYLEFT

    def test_weak_copyleft_mpl(self, manager):
        assert manager.classify_license("MPL-2.0") == LicenseRisk.WEAK_COPYLEFT

    def test_strong_copyleft_gpl2(self, manager):
        assert manager.classify_license("GPL-2.0") == LicenseRisk.STRONG_COPYLEFT

    def test_strong_copyleft_gpl3(self, manager):
        assert manager.classify_license("GPL-3.0") == LicenseRisk.STRONG_COPYLEFT

    def test_strong_copyleft_agpl(self, manager):
        assert manager.classify_license("AGPL-3.0") == LicenseRisk.STRONG_COPYLEFT

    def test_commercial(self, manager):
        assert manager.classify_license("commercial") == LicenseRisk.COMMERCIAL

    def test_proprietary(self, manager):
        assert manager.classify_license("proprietary") == LicenseRisk.COMMERCIAL

    def test_unknown(self, manager):
        assert manager.classify_license("LicenseRef-SomeWeirdLicense") == LicenseRisk.UNKNOWN

    def test_empty_string(self, manager):
        assert manager.classify_license("") == LicenseRisk.UNKNOWN

    def test_check_licenses_flags_copyleft(self, manager):
        content = json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {
                    "type": "library",
                    "name": "some-lib",
                    "version": "1.0",
                    "licenses": [{"license": {"id": "GPL-3.0"}}],
                }
            ],
        })
        sbom = manager.import_sbom(content, SBOMFormat.CYCLONEDX, "proj")
        report = manager.check_licenses(sbom.id)
        assert any(r["flagged"] for r in report)

    def test_check_licenses_permissive_not_flagged(self, manager):
        content = json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {
                    "type": "library",
                    "name": "clean-lib",
                    "version": "1.0",
                    "licenses": [{"license": {"id": "MIT"}}],
                }
            ],
        })
        sbom = manager.import_sbom(content, SBOMFormat.CYCLONEDX, "proj")
        report = manager.check_licenses(sbom.id)
        assert not any(r["flagged"] for r in report)


# ---------------------------------------------------------------------------
# SBOM diff
# ---------------------------------------------------------------------------

class TestSBOMDiff:
    def _make_sbom(self, manager, components_list, project="proj"):
        content = json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": components_list,
        })
        return manager.import_sbom(content, SBOMFormat.CYCLONEDX, project)

    def test_diff_added(self, manager):
        sbom_a = self._make_sbom(manager, [
            {"type": "library", "name": "lib-a", "version": "1.0", "licenses": []}
        ])
        sbom_b = self._make_sbom(manager, [
            {"type": "library", "name": "lib-a", "version": "1.0", "licenses": []},
            {"type": "library", "name": "lib-new", "version": "2.0", "licenses": []},
        ])
        diff = manager.diff_sboms(sbom_a.id, sbom_b.id)
        added_names = {c["name"] for c in diff["added"]}
        assert "lib-new" in added_names

    def test_diff_removed(self, manager):
        sbom_a = self._make_sbom(manager, [
            {"type": "library", "name": "lib-a", "version": "1.0", "licenses": []},
            {"type": "library", "name": "lib-old", "version": "0.9", "licenses": []},
        ])
        sbom_b = self._make_sbom(manager, [
            {"type": "library", "name": "lib-a", "version": "1.0", "licenses": []}
        ])
        diff = manager.diff_sboms(sbom_a.id, sbom_b.id)
        removed_names = {c["name"] for c in diff["removed"]}
        assert "lib-old" in removed_names

    def test_diff_updated(self, manager):
        sbom_a = self._make_sbom(manager, [
            {"type": "library", "name": "lib-a", "version": "1.0", "licenses": []}
        ])
        sbom_b = self._make_sbom(manager, [
            {"type": "library", "name": "lib-a", "version": "1.1", "licenses": []}
        ])
        diff = manager.diff_sboms(sbom_a.id, sbom_b.id)
        assert len(diff["updated"]) == 1
        assert diff["updated"][0]["old_version"] == "1.0"
        assert diff["updated"][0]["new_version"] == "1.1"

    def test_diff_summary_counts(self, manager):
        sbom_a = self._make_sbom(manager, [
            {"type": "library", "name": "lib-keep", "version": "1.0", "licenses": []},
            {"type": "library", "name": "lib-remove", "version": "2.0", "licenses": []},
        ])
        sbom_b = self._make_sbom(manager, [
            {"type": "library", "name": "lib-keep", "version": "1.0", "licenses": []},
            {"type": "library", "name": "lib-add", "version": "3.0", "licenses": []},
        ])
        diff = manager.diff_sboms(sbom_a.id, sbom_b.id)
        assert diff["summary"]["added_count"] == 1
        assert diff["summary"]["removed_count"] == 1
        assert diff["summary"]["updated_count"] == 0

    def test_diff_identical_sboms(self, manager):
        sbom_a = self._make_sbom(manager, [
            {"type": "library", "name": "lib-a", "version": "1.0", "licenses": []}
        ])
        sbom_b = self._make_sbom(manager, [
            {"type": "library", "name": "lib-a", "version": "1.0", "licenses": []}
        ])
        diff = manager.diff_sboms(sbom_a.id, sbom_b.id)
        assert diff["summary"]["added_count"] == 0
        assert diff["summary"]["removed_count"] == 0
        assert diff["summary"]["updated_count"] == 0

    def test_diff_not_found_raises(self, manager):
        with pytest.raises(KeyError):
            manager.diff_sboms("ghost-a", "ghost-b")


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

class TestRiskScoring:
    def test_vulnerable_component_has_high_score(self, manager):
        comp = Component(name="log4j-core", version="2.14.1", licenses=["Apache-2.0"])
        score = manager.get_component_risk_score(comp)
        assert score > 5.0

    def test_clean_permissive_component_low_score(self, manager):
        comp = Component(name="commons-lang3", version="3.12.0", licenses=["Apache-2.0"])
        score = manager.get_component_risk_score(comp)
        assert score < 2.0

    def test_missing_purl_increases_score(self, manager):
        comp_with = Component(name="mylib", version="1.0", purl="pkg:npm/mylib@1.0", licenses=["MIT"])
        comp_without = Component(name="mylib", version="1.0", purl=None, licenses=["MIT"])
        assert manager.get_component_risk_score(comp_without) > manager.get_component_risk_score(comp_with)

    def test_gpl_license_increases_score(self, manager):
        comp_mit = Component(name="safe-lib", version="1.0", licenses=["MIT"])
        comp_gpl = Component(name="safe-lib", version="1.0", licenses=["GPL-3.0"])
        assert manager.get_component_risk_score(comp_gpl) > manager.get_component_risk_score(comp_mit)

    def test_score_capped_at_10(self, manager):
        comp = Component(
            name="log4j-core",
            version="2.14.1",
            licenses=["AGPL-3.0", "GPL-3.0"],
            purl=None,
        )
        score = manager.get_component_risk_score(comp)
        assert score <= 10.0
