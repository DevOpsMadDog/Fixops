"""Tests for SBOMEngine — 32 tests covering all public methods, formats, and org isolation."""

from __future__ import annotations

import json
import re
import pytest

from core.sbom_engine import SBOMEngine, _build_purl, _license_risk


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return SBOMEngine(data_dir=str(tmp_path))


@pytest.fixture
def org():
    return "org-alpha"


@pytest.fixture
def org2():
    return "org-beta"


def _make_asset(engine, org, name="my-app", asset_type="application"):
    return engine.register_asset(org, {
        "asset_name": name,
        "asset_type": asset_type,
        "asset_version": "1.0.0",
        "description": "Test asset",
        "team_owner": "security-team",
    })


def _make_component(engine, org, asset_id, name="lodash", version="4.17.21",
                    ecosystem="npm", known_vulns=None):
    data = {
        "component_name": name,
        "component_version": version,
        "component_type": "library",
        "ecosystem": ecosystem,
        "license": "MIT",
        "supplier": "Acme Corp",
    }
    if known_vulns is not None:
        data["known_vulns"] = known_vulns
    return engine.add_component(org, asset_id, data)


# ---------------------------------------------------------------------------
# _build_purl helper
# ---------------------------------------------------------------------------

def test_purl_npm():
    purl = _build_purl("library", "lodash", "4.17.21", "npm")
    assert purl == "pkg:npm/lodash@4.17.21"


def test_purl_pypi():
    purl = _build_purl("library", "requests", "2.28.0", "pypi")
    assert purl == "pkg:pypi/requests@2.28.0"


def test_purl_no_version():
    purl = _build_purl("library", "openssl", "", "")
    assert purl.startswith("pkg:")
    assert "openssl" in purl
    assert "@" not in purl


def test_purl_format_regex():
    purl = _build_purl("library", "lodash", "4.17.21", "npm")
    assert re.match(r"pkg:[a-z]+/[\w\-\.]+@[\d\.]+", purl)


# ---------------------------------------------------------------------------
# _license_risk helper
# ---------------------------------------------------------------------------

def test_license_risk_gpl_high():
    assert _license_risk("GPL-3.0") == "high"
    assert _license_risk("GPL-2.0") == "high"
    assert _license_risk("AGPL-3.0") == "high"


def test_license_risk_mit_low():
    assert _license_risk("MIT") == "low"
    assert _license_risk("Apache-2.0") == "low"
    assert _license_risk("BSD-3-Clause") == "low"


def test_license_risk_unknown_medium():
    assert _license_risk("UNKNOWN-LICENSE") == "medium"
    assert _license_risk("") == "medium"


# ---------------------------------------------------------------------------
# register_asset
# ---------------------------------------------------------------------------

def test_register_asset(engine, org):
    asset = _make_asset(engine, org)
    assert "id" in asset
    assert asset["asset_name"] == "my-app"
    assert asset["org_id"] == org
    assert asset["component_count"] == 0


def test_register_asset_missing_name_raises(engine, org):
    with pytest.raises(ValueError, match="asset_name"):
        engine.register_asset(org, {"asset_name": ""})


def test_register_asset_invalid_type_raises(engine, org):
    with pytest.raises(ValueError, match="asset_type"):
        engine.register_asset(org, {"asset_name": "app", "asset_type": "invalid"})


# ---------------------------------------------------------------------------
# list_assets
# ---------------------------------------------------------------------------

def test_list_assets_empty(engine, org):
    assert engine.list_assets(org) == []


def test_list_assets_returns_created(engine, org):
    _make_asset(engine, org, "app-a")
    _make_asset(engine, org, "app-b")
    assets = engine.list_assets(org)
    assert len(assets) == 2
    names = {a["asset_name"] for a in assets}
    assert names == {"app-a", "app-b"}


# ---------------------------------------------------------------------------
# get_asset
# ---------------------------------------------------------------------------

def test_get_asset(engine, org):
    created = _make_asset(engine, org)
    fetched = engine.get_asset(org, created["id"])
    assert fetched is not None
    assert fetched["id"] == created["id"]
    assert fetched["asset_name"] == "my-app"


def test_get_asset_not_found(engine, org):
    assert engine.get_asset(org, "nonexistent-id") is None


def test_get_asset_has_component_summary(engine, org):
    asset = _make_asset(engine, org)
    _make_component(engine, org, asset["id"])
    fetched = engine.get_asset(org, asset["id"])
    assert fetched["component_count"] == 1


# ---------------------------------------------------------------------------
# add_component
# ---------------------------------------------------------------------------

def test_add_component_npm(engine, org):
    asset = _make_asset(engine, org)
    comp = _make_component(engine, org, asset["id"], name="lodash", version="4.17.21", ecosystem="npm")
    assert comp["purl"] == "pkg:npm/lodash@4.17.21"
    assert comp["component_name"] == "lodash"


def test_add_component_python(engine, org):
    asset = _make_asset(engine, org)
    comp = _make_component(engine, org, asset["id"], name="requests", version="2.28.0", ecosystem="pypi")
    assert comp["purl"] == "pkg:pypi/requests@2.28.0"


def test_add_component_purl_auto_generated(engine, org):
    asset = _make_asset(engine, org)
    comp = engine.add_component(org, asset["id"], {
        "component_name": "openssl",
        "component_version": "3.0.0",
        "component_type": "library",
    })
    assert comp["purl"].startswith("pkg:")
    assert "openssl" in comp["purl"]


def test_add_component_missing_name_raises(engine, org):
    asset = _make_asset(engine, org)
    with pytest.raises(ValueError, match="component_name"):
        engine.add_component(org, asset["id"], {"component_name": ""})


def test_add_component_invalid_type_raises(engine, org):
    asset = _make_asset(engine, org)
    with pytest.raises(ValueError, match="component_type"):
        engine.add_component(org, asset["id"], {
            "component_name": "pkg",
            "component_type": "invalid",
        })


def test_add_component_with_known_vulns(engine, org):
    asset = _make_asset(engine, org)
    comp = engine.add_component(org, asset["id"], {
        "component_name": "log4j-core",
        "component_version": "2.14.1",
        "component_type": "library",
        "known_vulns": ["CVE-2021-44228"],
        "risk_score": 10.0,
    })
    assert "CVE-2021-44228" in comp["known_vulns"]
    assert comp["risk_score"] == 10.0


# ---------------------------------------------------------------------------
# list_components
# ---------------------------------------------------------------------------

def test_list_components(engine, org):
    asset = _make_asset(engine, org)
    _make_component(engine, org, asset["id"], name="pkg-a")
    _make_component(engine, org, asset["id"], name="pkg-b")
    comps = engine.list_components(org, asset_id=asset["id"])
    assert len(comps) == 2


def test_list_components_filter_vulns(engine, org):
    asset = _make_asset(engine, org)
    _make_component(engine, org, asset["id"], name="safe-pkg")
    engine.add_component(org, asset["id"], {
        "component_name": "vuln-pkg",
        "component_version": "1.0",
        "component_type": "library",
        "known_vulns": ["CVE-2021-99999"],
    })
    vuln_comps = engine.list_components(org, asset_id=asset["id"], has_vulns=True)
    safe_comps = engine.list_components(org, asset_id=asset["id"], has_vulns=False)
    assert len(vuln_comps) == 1
    assert vuln_comps[0]["component_name"] == "vuln-pkg"
    assert len(safe_comps) == 1
    assert safe_comps[0]["component_name"] == "safe-pkg"


# ---------------------------------------------------------------------------
# generate_cyclonedx
# ---------------------------------------------------------------------------

def test_generate_cyclonedx_format(engine, org):
    asset = _make_asset(engine, org)
    _make_component(engine, org, asset["id"])
    sbom = engine.generate_cyclonedx(org, asset["id"])
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.4"
    assert sbom["serialNumber"].startswith("urn:uuid:")
    assert sbom["version"] == 1


def test_cyclonedx_has_components(engine, org):
    asset = _make_asset(engine, org)
    _make_component(engine, org, asset["id"], name="lodash")
    _make_component(engine, org, asset["id"], name="axios")
    sbom = engine.generate_cyclonedx(org, asset["id"])
    assert len(sbom["components"]) == 2
    names = {c["name"] for c in sbom["components"]}
    assert names == {"lodash", "axios"}


def test_cyclonedx_has_vulns(engine, org):
    asset = _make_asset(engine, org)
    engine.add_component(org, asset["id"], {
        "component_name": "log4j-core",
        "component_version": "2.14.1",
        "component_type": "library",
        "known_vulns": ["CVE-2021-44228"],
        "risk_score": 10.0,
    })
    sbom = engine.generate_cyclonedx(org, asset["id"])
    assert len(sbom["vulnerabilities"]) == 1
    assert sbom["vulnerabilities"][0]["id"] == "CVE-2021-44228"
    assert sbom["vulnerabilities"][0]["ratings"][0]["severity"] == "critical"


def test_cyclonedx_metadata(engine, org):
    asset = _make_asset(engine, org, name="test-service")
    _make_component(engine, org, asset["id"])
    sbom = engine.generate_cyclonedx(org, asset["id"])
    meta = sbom["metadata"]["component"]
    assert meta["name"] == "test-service"
    assert meta["version"] == "1.0.0"


def test_cyclonedx_asset_not_found_raises(engine, org):
    with pytest.raises(ValueError, match="Asset not found"):
        engine.generate_cyclonedx(org, "nonexistent-asset")


# ---------------------------------------------------------------------------
# generate_spdx
# ---------------------------------------------------------------------------

def test_generate_spdx_format(engine, org):
    asset = _make_asset(engine, org)
    _make_component(engine, org, asset["id"])
    sbom = engine.generate_spdx(org, asset["id"])
    assert sbom["spdxVersion"] == "SPDX-2.3"
    assert sbom["dataLicense"] == "CC0-1.0"
    assert sbom["SPDXID"] == "SPDXRef-DOCUMENT"
    assert sbom["documentNamespace"].startswith("https://aldeci.io/sbom/")


def test_spdx_has_packages(engine, org):
    asset = _make_asset(engine, org)
    _make_component(engine, org, asset["id"], name="lodash")
    _make_component(engine, org, asset["id"], name="axios")
    sbom = engine.generate_spdx(org, asset["id"])
    assert len(sbom["packages"]) == 2


def test_spdx_package_fields(engine, org):
    asset = _make_asset(engine, org)
    _make_component(engine, org, asset["id"], name="lodash", version="4.17.21", ecosystem="npm")
    sbom = engine.generate_spdx(org, asset["id"])
    pkg = sbom["packages"][0]
    assert pkg["name"] == "lodash"
    assert pkg["versionInfo"] == "4.17.21"
    assert "externalRefs" in pkg
    assert pkg["externalRefs"][0]["referenceType"] == "purl"
    assert pkg["externalRefs"][0]["referenceLocator"] == "pkg:npm/lodash@4.17.21"


def test_spdx_asset_not_found_raises(engine, org):
    with pytest.raises(ValueError, match="Asset not found"):
        engine.generate_spdx(org, "nonexistent-asset")


# ---------------------------------------------------------------------------
# save_export
# ---------------------------------------------------------------------------

def test_save_export(engine, org):
    asset = _make_asset(engine, org)
    sbom = engine.generate_cyclonedx(org, asset["id"])
    saved = engine.save_export(org, asset["id"], "cyclonedx", sbom)
    assert "id" in saved
    assert saved["format"] == "cyclonedx"
    assert saved["spec_version"] == "1.4"
    # sbom_content returned as dict, not JSON string
    assert isinstance(saved["sbom_content"], dict)
    assert saved["sbom_content"]["bomFormat"] == "CycloneDX"


def test_save_export_spdx(engine, org):
    asset = _make_asset(engine, org)
    sbom = engine.generate_spdx(org, asset["id"])
    saved = engine.save_export(org, asset["id"], "spdx", sbom)
    assert saved["spec_version"] == "2.3"


# ---------------------------------------------------------------------------
# get_license_summary
# ---------------------------------------------------------------------------

def test_license_summary(engine, org):
    asset = _make_asset(engine, org)
    _make_component(engine, org, asset["id"], name="pkg-mit")
    engine.add_component(org, asset["id"], {
        "component_name": "pkg-gpl",
        "component_version": "1.0",
        "component_type": "library",
        "license": "GPL-3.0",
    })
    summary = engine.get_license_summary(org)
    assert "high" in summary
    assert "low" in summary
    assert "medium" in summary
    assert summary["total_unique"] >= 2
    # GPL-3.0 → high
    high_licenses = [e["license"] for e in summary["high"]]
    assert "GPL-3.0" in high_licenses
    # MIT → low
    low_licenses = [e["license"] for e in summary["low"]]
    assert "MIT" in low_licenses


def test_license_summary_empty(engine, org):
    summary = engine.get_license_summary(org)
    assert summary["total_unique"] == 0
    assert summary["high"] == []


# ---------------------------------------------------------------------------
# get_vuln_exposure
# ---------------------------------------------------------------------------

def test_get_vuln_exposure(engine, org):
    asset = _make_asset(engine, org)
    _make_component(engine, org, asset["id"], name="safe-pkg")
    engine.add_component(org, asset["id"], {
        "component_name": "log4j-core",
        "component_version": "2.14.1",
        "component_type": "library",
        "known_vulns": ["CVE-2021-44228"],
        "risk_score": 10.0,
    })
    exposure = engine.get_vuln_exposure(org)
    assert exposure["total_components"] == 2
    assert exposure["vulnerable_components"] == 1
    assert "by_severity" in exposure
    assert "top_vulns" in exposure
    cve_ids = [v["cve_id"] for v in exposure["top_vulns"]]
    assert "CVE-2021-44228" in cve_ids


def test_get_vuln_exposure_empty(engine, org):
    exposure = engine.get_vuln_exposure(org)
    assert exposure["total_components"] == 0
    assert exposure["vulnerable_components"] == 0
    assert exposure["top_vulns"] == []


# ---------------------------------------------------------------------------
# get_sbom_stats
# ---------------------------------------------------------------------------

def test_get_sbom_stats(engine, org):
    asset = _make_asset(engine, org)
    _make_component(engine, org, asset["id"])
    sbom = engine.generate_cyclonedx(org, asset["id"])
    engine.save_export(org, asset["id"], "cyclonedx", sbom)
    stats = engine.get_sbom_stats(org)
    assert stats["total_assets"] == 1
    assert stats["total_components"] == 1
    assert "assets_with_vulns" in stats
    assert "license_risk_high" in stats
    assert "cyclonedx" in stats["formats_exported"]


def test_get_sbom_stats_zero_when_empty(engine, org):
    stats = engine.get_sbom_stats(org)
    assert stats["total_assets"] == 0
    assert stats["total_components"] == 0
    assert stats["assets_with_vulns"] == 0
    assert stats["formats_exported"] == []


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_assets(engine, org, org2):
    _make_asset(engine, org, "app-alpha")
    _make_asset(engine, org2, "app-beta")
    assert len(engine.list_assets(org)) == 1
    assert len(engine.list_assets(org2)) == 1
    assert engine.list_assets(org)[0]["asset_name"] == "app-alpha"
    assert engine.list_assets(org2)[0]["asset_name"] == "app-beta"


def test_org_isolation_components(engine, org, org2):
    asset_a = _make_asset(engine, org, "app-alpha")
    asset_b = _make_asset(engine, org2, "app-beta")
    _make_component(engine, org, asset_a["id"], name="pkg-for-a")
    _make_component(engine, org2, asset_b["id"], name="pkg-for-b")
    comps_a = engine.list_components(org)
    comps_b = engine.list_components(org2)
    assert len(comps_a) == 1
    assert comps_a[0]["component_name"] == "pkg-for-a"
    assert len(comps_b) == 1
    assert comps_b[0]["component_name"] == "pkg-for-b"


def test_org_isolation_get_asset(engine, org, org2):
    asset = _make_asset(engine, org)
    # org2 cannot see org's asset
    assert engine.get_asset(org2, asset["id"]) is None


def test_purl_format(engine, org):
    asset = _make_asset(engine, org)
    comp = _make_component(engine, org, asset["id"], name="lodash", version="4.17.21", ecosystem="npm")
    assert comp["purl"] == "pkg:npm/lodash@4.17.21"
    # Matches purl spec pattern
    assert re.match(r"pkg:[a-z]+/[^@]+@.+", comp["purl"])
