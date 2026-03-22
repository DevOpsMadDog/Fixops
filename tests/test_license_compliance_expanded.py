"""Verification test for expanded license compliance engine (55+ licenses)."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-evidence-risk"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from risk.license_compliance import LicenseComplianceAnalyzer, LicenseRisk, LicenseType


def _make_analyzer():
    return LicenseComplianceAnalyzer(config={"policy": {
        "project_license": "MIT",
        "blocked_licenses": ["AGPL-3.0", "SSPL-1.0"],
    }})


def test_license_database_size():
    a = _make_analyzer()
    assert len(a.license_database) >= 55, f"Expected 55+, got {len(a.license_database)}"


def test_alias_normalization():
    a = _make_analyzer()
    assert a.normalize_license("MIT License") == "MIT"
    assert a.normalize_license("Apache License 2.0") == "Apache-2.0"
    assert a.normalize_license("GPLv3") == "GPL-3.0"
    assert a.normalize_license("LGPLv2") == "LGPL-2.1"
    assert a.normalize_license("SSPL") == "SSPL-1.0"
    assert a.normalize_license("Business Source License") == "BSL-1.1"
    assert a.normalize_license("Public Domain") == "Unlicense"


def test_spdx_expression_or():
    a = _make_analyzer()
    result = a.parse_spdx_expression("MIT OR Apache-2.0")
    assert result == ["MIT", "Apache-2.0"], f"Got {result}"


def test_spdx_expression_with():
    a = _make_analyzer()
    result = a.parse_spdx_expression("GPL-2.0-only WITH Classpath-exception-2.0")
    assert result == ["GPL-2.0-only"], f"Got {result}"


def test_spdx_expression_complex():
    a = _make_analyzer()
    result = a.parse_spdx_expression("(MIT AND BSD-3-Clause) OR Apache-2.0")
    assert set(result) == {"MIT", "BSD-3-Clause", "Apache-2.0"}, f"Got {result}"


def test_analyze_blocked_agpl():
    a = _make_analyzer()
    pkgs = [{"name": "dangerous", "license": "AGPL-3.0"}]
    r = a.analyze(pkgs)
    f = r.findings[0]
    assert f.risk_level == LicenseRisk.CRITICAL


def test_analyze_dual_license_or():
    a = _make_analyzer()
    pkgs = [{"name": "dual", "license": "MIT OR Apache-2.0"}]
    r = a.analyze(pkgs)
    f = r.findings[0]
    assert f.risk_level == LicenseRisk.LOW, f"Expected LOW, got {f.risk_level}"


def test_analyze_blocked_sspl():
    a = _make_analyzer()
    pkgs = [{"name": "restrictive", "license": "SSPL-1.0"}]
    r = a.analyze(pkgs)
    f = r.findings[0]
    assert f.risk_level == LicenseRisk.CRITICAL


def test_transitive_analysis():
    a = _make_analyzer()
    tree = {
        "name": "app", "license": "MIT",
        "dependencies": [
            {"name": "lib-a", "license": "Apache-2.0", "dependencies": [
                {"name": "lib-a-dep", "license": "GPL-3.0", "dependencies": []},
            ]},
            {"name": "lib-b", "license": "BSD-3-Clause", "dependencies": []},
        ]
    }
    r = a.analyze_transitive(tree)
    gpl = [f for f in r.findings if f.package_name == "lib-a-dep"][0]
    assert gpl.risk_level == LicenseRisk.HIGH


def test_network_copyleft_type():
    a = _make_analyzer()
    info = a.license_database["AGPL-3.0"]
    assert info["type"] == LicenseType.NETWORK_COPYLEFT
    assert info["network_use"] is True


def test_public_domain_type():
    a = _make_analyzer()
    info = a.license_database["Unlicense"]
    assert info["type"] == LicenseType.PUBLIC_DOMAIN


def test_source_available_type():
    a = _make_analyzer()
    info = a.license_database["SSPL-1.0"]
    assert info["type"] == LicenseType.SOURCE_AVAILABLE
    assert info["commercial_use"] is False

