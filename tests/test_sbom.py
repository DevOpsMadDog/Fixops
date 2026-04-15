"""
Tests for SBOM Engine, SBOM Manager, and SBOM Generator.

Covers:
- SBOMEngine: generate_sbom, list_sboms, get_sbom, import_sbom,
  get_vulnerable_components, get_license_summary, get_dependency_graph
- SBOMManager: import/export CycloneDX + SPDX, CRUD, diff, license compliance,
  vulnerability mapping, risk scoring
- SBOMGenerator: requirements.txt / package.json / go.mod parsing,
  CycloneDX + SPDX generation, directory scan, storage, diff
"""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

# ---------------------------------------------------------------------------
# Fixtures — all use isolated temp DBs so tests never share state
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_db(tmp_path):
    return str(tmp_path / "sbom_test.db")


@pytest.fixture()
def engine(tmp_db):
    from core.sbom_engine import SBOMEngine
    return SBOMEngine(db_path=tmp_db)


@pytest.fixture()
def manager(tmp_db):
    from core.sbom_manager import SBOMManager
    return SBOMManager(db_path=tmp_db)


@pytest.fixture()
def generator(tmp_db):
    from core.sbom_generator import SBOMGenerator
    return SBOMGenerator(project_name="test-project", project_version="1.0.0", db_path=tmp_db)


# ---------------------------------------------------------------------------
# Minimal valid SBOM fixtures
# ---------------------------------------------------------------------------

CYCLONEDX_JSON = json.dumps({
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "metadata": {"component": {"type": "application", "name": "myapp", "version": "2.0.0"}},
    "components": [
        {"type": "library", "name": "requests", "version": "2.28.0",
         "purl": "pkg:pypi/requests@2.28.0",
         "licenses": [{"license": {"id": "Apache-2.0"}}]},
        {"type": "library", "name": "log4j-core", "version": "2.14.0",
         "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
         "licenses": [{"license": {"id": "Apache-2.0"}}]},
    ],
})

SPDX_JSON = json.dumps({
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "myapp-spdx",
    "documentNamespace": "https://example.com/sbom/1",
    "packages": [
        {
            "SPDXID": "SPDXRef-Package-0",
            "name": "lodash",
            "versionInfo": "4.17.20",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseDeclared": "MIT",
            "licenseConcluded": "MIT",
            "copyrightText": "NOASSERTION",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                               "referenceType": "purl",
                               "referenceLocator": "pkg:npm/lodash@4.17.20"}],
        },
        {
            "SPDXID": "SPDXRef-Package-1",
            "name": "axios",
            "versionInfo": "0.21.0",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseDeclared": "MIT",
            "licenseConcluded": "MIT",
            "copyrightText": "NOASSERTION",
        },
    ],
})

REQUIREMENTS_TXT = """\
requests==2.28.0
flask>=2.0.0
# this is a comment
-r other.txt
pyyaml~=6.0
"""

PACKAGE_JSON = json.dumps({
    "name": "my-frontend",
    "version": "1.2.3",
    "dependencies": {"lodash": "^4.17.21", "axios": "^1.5.0"},
    "devDependencies": {"jest": "^29.0.0"},
})

GO_MOD = """\
module github.com/example/myapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/stretchr/testify v1.8.4 // indirect
)

require github.com/spf13/cobra v1.7.0
"""

# ===========================================================================
# SBOMEngine tests
# ===========================================================================

class TestSBOMEngineGenerateCycloneDX:
    def test_returns_cyclonedx_format(self, engine):
        sbom = engine.generate_sbom("org1", "asset1", fmt="cyclonedx",
                                    requirements_path="nonexistent_req.txt")
        assert sbom.get("bomFormat") == "CycloneDX"

    def test_sbom_has_components(self, engine):
        sbom = engine.generate_sbom("org1", "asset1", fmt="cyclonedx",
                                    requirements_path="nonexistent_req.txt")
        assert "components" in sbom
        assert isinstance(sbom["components"], list)

    def test_sbom_id_injected(self, engine):
        sbom = engine.generate_sbom("org1", "asset1")
        assert "_sbom_id" in sbom

    def test_generates_spdx_format(self, engine):
        sbom = engine.generate_sbom("org1", "asset1", fmt="spdx",
                                    requirements_path="nonexistent_req.txt")
        assert sbom.get("spdxVersion", "").startswith("SPDX-")

    def test_invalid_format_raises(self, engine):
        with pytest.raises(ValueError, match="Unsupported format"):
            engine.generate_sbom("org1", "asset1", fmt="xml")


class TestSBOMEngineListAndGet:
    def test_list_empty_initially(self, engine):
        assert engine.list_sboms("org1") == []

    def test_list_returns_generated_sboms(self, engine):
        engine.generate_sbom("org1", "asset1")
        engine.generate_sbom("org1", "asset2")
        sboms = engine.list_sboms("org1")
        assert len(sboms) == 2

    def test_list_filters_by_org(self, engine):
        engine.generate_sbom("org1", "asset1")
        engine.generate_sbom("org2", "asset1")
        assert len(engine.list_sboms("org1")) == 1
        assert len(engine.list_sboms("org2")) == 1

    def test_get_sbom_returns_full_doc(self, engine):
        sbom = engine.generate_sbom("org1", "asset1")
        sbom_id = sbom["_sbom_id"]
        result = engine.get_sbom(sbom_id, "org1")
        assert result is not None
        assert result["_sbom_id"] == sbom_id

    def test_get_sbom_wrong_org_returns_none(self, engine):
        sbom = engine.generate_sbom("org1", "asset1")
        sbom_id = sbom["_sbom_id"]
        assert engine.get_sbom(sbom_id, "org_other") is None

    def test_get_sbom_unknown_id_returns_none(self, engine):
        assert engine.get_sbom("does-not-exist", "org1") is None


class TestSBOMEngineImport:
    def test_import_cyclonedx(self, engine):
        cdx_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {"component": {"name": "app", "version": "1.0"}},
            "components": [
                {"type": "library", "name": "flask", "version": "2.3.0",
                 "purl": "pkg:pypi/flask@2.3.0",
                 "licenses": [{"license": {"id": "BSD-3-Clause"}}]},
            ],
        }
        sbom_id = engine.import_sbom("org1", cdx_data)
        assert isinstance(sbom_id, str)
        assert len(sbom_id) > 0

    def test_import_spdx(self, engine):
        spdx_data = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test-app",
            "documentNamespace": "https://example.com/1",
            "packages": [
                {"SPDXID": "SPDXRef-0", "name": "lodash", "versionInfo": "4.17.21",
                 "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                 "licenseDeclared": "MIT", "licenseConcluded": "MIT",
                 "copyrightText": "NOASSERTION"},
            ],
        }
        sbom_id = engine.import_sbom("org1", spdx_data)
        assert isinstance(sbom_id, str)

    def test_import_unknown_format_raises(self, engine):
        with pytest.raises(ValueError, match="Unrecognised SBOM format"):
            engine.import_sbom("org1", {"notSBOM": True})

    def test_imported_sbom_appears_in_list(self, engine):
        cdx_data = {
            "bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
            "metadata": {"component": {"name": "x", "version": "1"}},
            "components": [],
        }
        engine.import_sbom("org1", cdx_data)
        sboms = engine.list_sboms("org1")
        assert len(sboms) == 1
        assert sboms[0]["source"] == "imported"


class TestSBOMEngineLicenseAndVulnerable:
    def test_license_summary_returns_dict(self, engine):
        engine.generate_sbom("org1", "asset1", requirements_path="nonexistent_req.txt")
        summary = engine.get_license_summary("org1")
        assert isinstance(summary, dict)

    def test_vulnerable_components_returns_list(self, engine):
        cdx_data = {
            "bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
            "metadata": {"component": {"name": "app", "version": "1"}},
            "components": [
                {"type": "library", "name": "log4j-core", "version": "2.14.0",
                 "purl": "pkg:maven/log4j-core@2.14.0",
                 "licenses": []},
            ],
        }
        engine.import_sbom("org1", cdx_data)
        vulns = engine.get_vulnerable_components("org1")
        assert isinstance(vulns, list)

    def test_dependency_graph_empty_when_no_sbom(self, engine):
        graph = engine.get_dependency_graph("org1", "no-asset")
        assert graph["nodes"] == []
        assert graph["edges"] == []


# ===========================================================================
# SBOMManager tests
# ===========================================================================

class TestSBOMManagerImportCycloneDX:
    def test_import_cyclonedx_creates_sbom(self, manager):
        from core.sbom_manager import SBOMFormat
        sbom = manager.import_sbom(CYCLONEDX_JSON, SBOMFormat.CYCLONEDX, "myapp", org_id="org1")
        assert sbom.id
        assert sbom.format.value == "cyclonedx"
        assert sbom.project_name == "myapp"
        assert len(sbom.components) == 2

    def test_import_cyclonedx_component_names(self, manager):
        from core.sbom_manager import SBOMFormat
        sbom = manager.import_sbom(CYCLONEDX_JSON, SBOMFormat.CYCLONEDX, "myapp")
        names = {c.name for c in sbom.components}
        assert "requests" in names
        assert "log4j-core" in names

    def test_import_cyclonedx_purl_preserved(self, manager):
        from core.sbom_manager import SBOMFormat
        sbom = manager.import_sbom(CYCLONEDX_JSON, SBOMFormat.CYCLONEDX, "myapp")
        purls = {c.purl for c in sbom.components}
        assert "pkg:pypi/requests@2.28.0" in purls

    def test_import_invalid_json_raises(self, manager):
        from core.sbom_manager import SBOMFormat
        with pytest.raises(ValueError, match="Invalid JSON"):
            manager.import_sbom("not-json{{", SBOMFormat.CYCLONEDX, "myapp")


class TestSBOMManagerImportSPDX:
    def test_import_spdx_creates_sbom(self, manager):
        from core.sbom_manager import SBOMFormat
        sbom = manager.import_sbom(SPDX_JSON, SBOMFormat.SPDX, "myapp-spdx")
        assert sbom.format.value == "spdx"
        assert len(sbom.components) == 2

    def test_import_spdx_component_names(self, manager):
        from core.sbom_manager import SBOMFormat
        sbom = manager.import_sbom(SPDX_JSON, SBOMFormat.SPDX, "myapp-spdx")
        names = {c.name for c in sbom.components}
        assert "lodash" in names
        assert "axios" in names


class TestSBOMManagerCRUD:
    def test_get_sbom_returns_stored(self, manager):
        from core.sbom_manager import SBOMFormat
        sbom = manager.import_sbom(CYCLONEDX_JSON, SBOMFormat.CYCLONEDX, "myapp")
        fetched = manager.get_sbom(sbom.id)
        assert fetched.id == sbom.id
        assert len(fetched.components) == 2

    def test_get_sbom_missing_raises_key_error(self, manager):
        with pytest.raises(KeyError):
            manager.get_sbom("nonexistent-id")

    def test_list_sboms_empty_initially(self, manager):
        assert manager.list_sboms() == []

    def test_list_sboms_filters_by_org(self, manager):
        from core.sbom_manager import SBOMFormat
        manager.import_sbom(CYCLONEDX_JSON, SBOMFormat.CYCLONEDX, "app1", org_id="orgA")
        manager.import_sbom(CYCLONEDX_JSON, SBOMFormat.CYCLONEDX, "app2", org_id="orgB")
        assert len(manager.list_sboms(org_id="orgA")) == 1
        assert len(manager.list_sboms(org_id="orgB")) == 1

    def test_list_sboms_filters_by_project_name(self, manager):
        from core.sbom_manager import SBOMFormat
        manager.import_sbom(CYCLONEDX_JSON, SBOMFormat.CYCLONEDX, "app-alpha")
        manager.import_sbom(CYCLONEDX_JSON, SBOMFormat.CYCLONEDX, "app-beta")
        assert len(manager.list_sboms(project_name="app-alpha")) == 1

    def test_get_components_returns_list(self, manager):
        from core.sbom_manager import SBOMFormat
        sbom = manager.import_sbom(CYCLONEDX_JSON, SBOMFormat.CYCLONEDX, "myapp")
        components = manager.get_components(sbom.id)
        assert len(components) == 2

    def test_delete_sbom_removes_it(self, manager):
        from core.sbom_manager import SBOMFormat
        sbom = manager.import_sbom(CYCLONEDX_JSON, SBOMFormat.CYCLONEDX, "myapp")
        manager.delete_sbom(sbom.id)
        with pytest.raises(KeyError):
            manager.get_sbom(sbom.id)

    def test_delete_nonexistent_raises(self, manager):
        with pytest.raises(KeyError):
            manager.delete_sbom("ghost-id")


class TestSBOMManagerExport:
    def test_export_cyclonedx_roundtrip(self, manager):
        from core.sbom_manager import SBOMFormat
        sbom = manager.import_sbom(CYCLONEDX_JSON, SBOMFormat.CYCLONEDX, "myapp")
        exported = manager.export_sbom(sbom.id, SBOMFormat.CYCLONEDX)
        doc = json.loads(exported)
        assert doc["bomFormat"] == "CycloneDX"
        assert len(doc["components"]) == 2

    def test_export_spdx_roundtrip(self, manager):
        from core.sbom_manager import SBOMFormat
        # Import a native SPDX doc so spec_version is "SPDX-2.3"
        sbom = manager.import_sbom(SPDX_JSON, SBOMFormat.SPDX, "myapp-spdx")
        exported = manager.export_sbom(sbom.id, SBOMFormat.SPDX)
        doc = json.loads(exported)
        assert doc["spdxVersion"].startswith("SPDX-")
        assert len(doc["packages"]) == 2


class TestSBOMManagerLicense:
    def test_classify_permissive(self, manager):
        from core.sbom_manager import LicenseRisk
        assert manager.classify_license("MIT") == LicenseRisk.PERMISSIVE
        assert manager.classify_license("Apache-2.0") == LicenseRisk.PERMISSIVE

    def test_classify_strong_copyleft(self, manager):
        from core.sbom_manager import LicenseRisk
        assert manager.classify_license("GPL-3.0") == LicenseRisk.STRONG_COPYLEFT

    def test_classify_unknown(self, manager):
        from core.sbom_manager import LicenseRisk
        assert manager.classify_license("SOME-RANDOM-UNKNOWN-LICENSE") == LicenseRisk.UNKNOWN

    def test_check_licenses_flags_copyleft(self, manager):
        from core.sbom_manager import SBOMFormat
        gpl_sbom = json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
            "metadata": {"component": {"name": "app", "version": "1"}},
            "components": [
                {"type": "library", "name": "gpl-lib", "version": "1.0",
                 "licenses": [{"license": {"id": "GPL-3.0"}}]},
                {"type": "library", "name": "mit-lib", "version": "1.0",
                 "licenses": [{"license": {"id": "MIT"}}]},
            ],
        })
        sbom = manager.import_sbom(gpl_sbom, SBOMFormat.CYCLONEDX, "test-app")
        report = manager.check_licenses(sbom.id)
        flagged = [r for r in report if r["flagged"]]
        assert any(r["component"] == "gpl-lib" for r in flagged)


class TestSBOMManagerVulnerabilities:
    def test_map_vulnerabilities_finds_log4j(self, manager):
        from core.sbom_manager import SBOMFormat
        sbom = manager.import_sbom(CYCLONEDX_JSON, SBOMFormat.CYCLONEDX, "myapp")
        vulns = manager.map_vulnerabilities(sbom.id)
        names = {v.component.name for v in vulns}
        assert "log4j-core" in names

    def test_map_vulnerabilities_includes_cve_ids(self, manager):
        from core.sbom_manager import SBOMFormat
        sbom = manager.import_sbom(CYCLONEDX_JSON, SBOMFormat.CYCLONEDX, "myapp")
        vulns = manager.map_vulnerabilities(sbom.id)
        log4j = next(v for v in vulns if v.component.name == "log4j-core")
        assert "CVE-2021-44228" in log4j.cve_ids

    def test_risk_score_higher_with_vulns(self, manager):
        from core.sbom_manager import Component
        clean = Component(name="requests", version="2.28.0", purl="pkg:pypi/requests@2.28.0",
                          licenses=["MIT"])
        vuln = Component(name="log4j-core", version="2.14.0",
                         purl="pkg:maven/log4j-core@2.14.0", licenses=["Apache-2.0"])
        assert manager.get_component_risk_score(vuln) > manager.get_component_risk_score(clean)


class TestSBOMManagerDiff:
    def test_diff_detects_added_component(self, manager):
        from core.sbom_manager import SBOMFormat
        sbom_a = manager.import_sbom(CYCLONEDX_JSON, SBOMFormat.CYCLONEDX, "app-v1")
        cdx_v2 = json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
            "metadata": {"component": {"name": "app-v2", "version": "2"}},
            "components": [
                {"type": "library", "name": "requests", "version": "2.28.0",
                 "purl": "pkg:pypi/requests@2.28.0", "licenses": [{"license": {"id": "Apache-2.0"}}]},
                {"type": "library", "name": "log4j-core", "version": "2.14.0",
                 "purl": "pkg:maven/log4j-core@2.14.0", "licenses": [{"license": {"id": "Apache-2.0"}}]},
                {"type": "library", "name": "newlib", "version": "1.0",
                 "purl": "pkg:pypi/newlib@1.0", "licenses": []},
            ],
        })
        sbom_b = manager.import_sbom(cdx_v2, SBOMFormat.CYCLONEDX, "app-v2")
        diff = manager.diff_sboms(sbom_a.id, sbom_b.id)
        added_names = {c["name"] for c in diff["added"]}
        assert "newlib" in added_names

    def test_diff_detects_version_change(self, manager):
        from core.sbom_manager import SBOMFormat
        cdx_v1 = json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
            "metadata": {"component": {"name": "app", "version": "1"}},
            "components": [
                {"type": "library", "name": "requests", "version": "2.27.0",
                 "purl": "pkg:pypi/requests@2.27.0", "licenses": []},
            ],
        })
        cdx_v2 = json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
            "metadata": {"component": {"name": "app", "version": "2"}},
            "components": [
                {"type": "library", "name": "requests", "version": "2.28.0",
                 "purl": "pkg:pypi/requests@2.28.0", "licenses": []},
            ],
        })
        sbom_a = manager.import_sbom(cdx_v1, SBOMFormat.CYCLONEDX, "app-v1")
        sbom_b = manager.import_sbom(cdx_v2, SBOMFormat.CYCLONEDX, "app-v2")
        diff = manager.diff_sboms(sbom_a.id, sbom_b.id)
        updated = diff["updated"]
        assert any(u["name"] == "requests" for u in updated)


# ===========================================================================
# SBOMGenerator tests
# ===========================================================================

class TestSBOMGeneratorParsing:
    def test_parse_requirements_txt(self, generator):
        components = generator.parse_requirements_txt(REQUIREMENTS_TXT)
        names = {c["name"] for c in components}
        assert "requests" in names
        assert "flask" in names
        assert "pyyaml" in names

    def test_parse_requirements_txt_versions(self, generator):
        components = generator.parse_requirements_txt(REQUIREMENTS_TXT)
        req = next(c for c in components if c["name"] == "requests")
        assert req["version"] == "2.28.0"

    def test_parse_requirements_txt_purls(self, generator):
        components = generator.parse_requirements_txt(REQUIREMENTS_TXT)
        purls = {c["purl"] for c in components}
        assert "pkg:pypi/requests@2.28.0" in purls

    def test_parse_package_json(self, generator):
        components = generator.parse_package_json(PACKAGE_JSON)
        names = {c["name"] for c in components}
        assert "lodash" in names
        assert "axios" in names
        assert "jest" in names

    def test_parse_package_json_invalid_returns_empty(self, generator):
        assert generator.parse_package_json("{{not json}}") == []

    def test_parse_go_mod(self, generator):
        components = generator.parse_go_mod(GO_MOD)
        names = {c["name"] for c in components}
        assert "github.com/gin-gonic/gin" in names
        assert "github.com/stretchr/testify" in names

    def test_parse_go_mod_single_require(self, generator):
        components = generator.parse_go_mod(GO_MOD)
        names = {c["name"] for c in components}
        assert "github.com/spf13/cobra" in names


class TestSBOMGeneratorDocuments:
    def test_generate_cyclonedx_format(self, generator):
        components = generator.parse_requirements_txt(REQUIREMENTS_TXT)
        sbom = generator.generate_cyclonedx(components)
        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.4"
        assert len(sbom["components"]) == len(components)

    def test_generate_spdx_format(self, generator):
        components = generator.parse_requirements_txt(REQUIREMENTS_TXT)
        sbom = generator.generate_spdx(components)
        assert sbom["spdxVersion"].startswith("SPDX-")
        assert len(sbom["packages"]) == len(components)

    def test_generate_cyclonedx_from_package_json(self, generator):
        components = generator.parse_package_json(PACKAGE_JSON)
        sbom = generator.generate_cyclonedx(components)
        names = {c["name"] for c in sbom["components"]}
        assert "lodash" in names

    def test_generate_cyclonedx_with_metadata(self, generator):
        components = generator.parse_requirements_txt(REQUIREMENTS_TXT)
        sbom = generator.generate_cyclonedx(components, metadata={"project_name": "custom-app"})
        assert sbom["metadata"]["component"]["name"] == "custom-app"


class TestSBOMGeneratorStorage:
    def test_store_and_retrieve_sbom(self, generator):
        components = generator.parse_requirements_txt(REQUIREMENTS_TXT)
        sbom = generator.generate_cyclonedx(components)
        sbom_id = generator.store_sbom(sbom, "cyclonedx", "test-target", "org1")
        retrieved = generator.get_sbom(sbom_id)
        assert retrieved is not None
        assert retrieved["bomFormat"] == "CycloneDX"

    def test_get_sbom_missing_returns_none(self, generator):
        assert generator.get_sbom("nonexistent") is None

    def test_list_sboms_by_org(self, generator):
        components = generator.parse_requirements_txt(REQUIREMENTS_TXT)
        sbom = generator.generate_cyclonedx(components)
        generator.store_sbom(sbom, "cyclonedx", "target", "org1")
        generator.store_sbom(sbom, "cyclonedx", "target", "org2")
        assert len(generator.list_sboms("org1")) == 1
        assert len(generator.list_sboms("org2")) == 1

    def test_diff_sboms_detects_changes(self, generator):
        c1 = generator.parse_requirements_txt("requests==2.27.0\n")
        c2 = generator.parse_requirements_txt("requests==2.28.0\nflask==2.3.0\n")
        s1 = generator.generate_cyclonedx(c1)
        s2 = generator.generate_cyclonedx(c2)
        id1 = generator.store_sbom(s1, "cyclonedx", "v1", "org1")
        id2 = generator.store_sbom(s2, "cyclonedx", "v2", "org1")
        diff = generator.diff_sboms(id1, id2)
        added_names = {a["name"] for a in diff["added"]}
        assert "flask" in added_names


class TestSBOMGeneratorDirectoryScan:
    def test_scan_directory_finds_requirements(self, generator, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.28.0\nflask==2.3.0\n")
        components = generator.scan_directory(str(tmp_path))
        names = {c["name"] for c in components}
        assert "requests" in names
        assert "flask" in names

    def test_scan_directory_deduplicates(self, generator, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "requirements.txt").write_text("requests==2.28.0\n")
        components = generator.scan_directory(str(tmp_path))
        purls = [c["purl"] for c in components]
        assert purls.count("pkg:pypi/requests@2.28.0") == 1


class TestSBOMGeneratorFromFile:
    def test_generate_from_requirements_file(self, generator, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.28.0\nflask==2.3.0\n")
        sbom = generator.generate_from_requirements(str(req_file))
        assert sbom["bomFormat"] == "CycloneDX"
        names = {c["name"] for c in sbom["components"]}
        assert "requests" in names

    def test_generate_from_requirements_missing_file_raises(self, generator):
        with pytest.raises(FileNotFoundError):
            generator.generate_from_requirements("/nonexistent/requirements.txt")

    def test_generate_from_package_json_file(self, generator, tmp_path):
        pkg_file = tmp_path / "package.json"
        pkg_file.write_text(PACKAGE_JSON)
        sbom = generator.generate_from_package_json(str(pkg_file))
        assert sbom["bomFormat"] == "CycloneDX"
        names = {c["name"] for c in sbom["components"]}
        assert "lodash" in names
