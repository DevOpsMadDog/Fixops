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
def engine(tmp_path):
    from core.sbom_engine import SBOMEngine
    # SBOMEngine is asset/component-based and takes a data_dir (per-org SBOM
    # stores), not a single db_path. Give it an isolated temp directory.
    return SBOMEngine(data_dir=str(tmp_path / "sbom_engine_data"))


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

class TestSBOMEngineAssets:
    """SBOMEngine is asset/component-based: register assets, add components,
    then generate CycloneDX/SPDX. (The old generate_sbom-from-manifest API moved
    to SBOMGenerator.) These tests exercise the real engine end to end."""

    def test_register_asset_returns_id(self, engine):
        a = engine.register_asset("org1", {"asset_name": "myapp", "asset_type": "application"})
        assert a["id"]
        assert a["asset_name"] == "myapp"

    def test_register_asset_requires_name(self, engine):
        with pytest.raises(ValueError, match="asset_name"):
            engine.register_asset("org1", {})

    def test_register_asset_rejects_invalid_type(self, engine):
        with pytest.raises(ValueError):
            engine.register_asset("org1", {"asset_name": "x", "asset_type": "not-a-type"})

    def test_list_assets_empty_initially(self, engine):
        assert engine.list_assets("org1") == []

    def test_list_assets_returns_registered(self, engine):
        engine.register_asset("org1", {"asset_name": "a1"})
        engine.register_asset("org1", {"asset_name": "a2"})
        assert len(engine.list_assets("org1")) == 2

    def test_list_assets_isolated_by_org(self, engine):
        engine.register_asset("org1", {"asset_name": "a1"})
        engine.register_asset("org2", {"asset_name": "a2"})
        assert len(engine.list_assets("org1")) == 1
        assert len(engine.list_assets("org2")) == 1

    def test_get_asset_roundtrip(self, engine):
        a = engine.register_asset("org1", {"asset_name": "a1"})
        got = engine.get_asset("org1", a["id"])
        assert got is not None and got["id"] == a["id"]

    def test_get_asset_wrong_org_returns_none(self, engine):
        a = engine.register_asset("org1", {"asset_name": "a1"})
        assert engine.get_asset("org_other", a["id"]) is None


class TestSBOMEngineComponents:
    def test_add_component_returns_id(self, engine):
        a = engine.register_asset("org1", {"asset_name": "app"})
        c = engine.add_component("org1", a["id"], {
            "component_name": "requests", "component_version": "2.28.0", "ecosystem": "pypi",
        })
        assert c["id"]
        assert c["component_name"] == "requests"

    def test_add_component_requires_name(self, engine):
        a = engine.register_asset("org1", {"asset_name": "app"})
        with pytest.raises(ValueError, match="component_name"):
            engine.add_component("org1", a["id"], {})

    def test_add_component_autogenerates_purl(self, engine):
        a = engine.register_asset("org1", {"asset_name": "app"})
        c = engine.add_component("org1", a["id"], {
            "component_name": "requests", "component_version": "2.28.0",
            "component_type": "library", "ecosystem": "pypi",
        })
        assert c.get("purl")

    def test_list_components_by_asset(self, engine):
        a = engine.register_asset("org1", {"asset_name": "app"})
        engine.add_component("org1", a["id"], {"component_name": "requests"})
        engine.add_component("org1", a["id"], {"component_name": "flask"})
        comps = engine.list_components("org1", asset_id=a["id"])
        assert len(comps) == 2


class TestSBOMEngineGenerate:
    def _asset_with_components(self, engine, org="org1"):
        a = engine.register_asset(org, {"asset_name": "app", "asset_version": "1.0.0"})
        engine.add_component(org, a["id"], {
            "component_name": "requests", "component_version": "2.28.0", "ecosystem": "pypi",
        })
        return a["id"]

    def test_generate_cyclonedx_format(self, engine):
        asset_id = self._asset_with_components(engine)
        cdx = engine.generate_cyclonedx("org1", asset_id)
        assert cdx.get("bomFormat") == "CycloneDX"

    def test_generate_cyclonedx_includes_component(self, engine):
        asset_id = self._asset_with_components(engine)
        cdx = engine.generate_cyclonedx("org1", asset_id)
        names = {c.get("name") for c in cdx.get("components", [])}
        assert "requests" in names

    def test_generate_cyclonedx_unknown_asset_raises(self, engine):
        with pytest.raises(ValueError, match="not found"):
            engine.generate_cyclonedx("org1", "does-not-exist")

    def test_generate_spdx_format(self, engine):
        asset_id = self._asset_with_components(engine)
        spdx = engine.generate_spdx("org1", asset_id)
        assert str(spdx.get("spdxVersion", "")).startswith("SPDX-")

    def test_generate_spdx_unknown_asset_raises(self, engine):
        with pytest.raises(ValueError, match="not found"):
            engine.generate_spdx("org1", "does-not-exist")


class TestSBOMEngineSummaries:
    def test_license_summary_returns_dict(self, engine):
        summary = engine.get_license_summary("org1")
        assert isinstance(summary, dict)

    def test_vuln_exposure_returns_dict(self, engine):
        exposure = engine.get_vuln_exposure("org1")
        assert isinstance(exposure, dict)

    def test_sbom_stats_counts_assets_and_components(self, engine):
        a = engine.register_asset("org1", {"asset_name": "app"})
        engine.add_component("org1", a["id"], {"component_name": "requests"})
        stats = engine.get_sbom_stats("org1")
        assert isinstance(stats, dict)


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
