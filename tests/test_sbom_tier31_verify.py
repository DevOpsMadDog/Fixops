"""TIER 3.1 verification — Transitive deps, VEX, vuln cross-reference."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-evidence-risk"))

from risk.sbom.generator import (
    Dependency, SBOMGenerator, SBOMQualityScorer,
    VEXStatus, VEXJustification, VEXStatement, VEXDocument,
    KNOWN_VULN_DB,
)


def test_dependency_transitive_fields():
    d = Dependency(name="lodash", version="4.17.20", package_manager="npm",
                   is_transitive=True, depth=2, parent="express")
    assert d.is_transitive is True
    assert d.depth == 2
    assert d.parent == "express"


def test_vex_status_enum():
    assert VEXStatus.NOT_AFFECTED.value == "not_affected"
    assert VEXStatus.AFFECTED.value == "affected"
    assert VEXStatus.FIXED.value == "fixed"
    assert VEXStatus.UNDER_INVESTIGATION.value == "under_investigation"


def test_vex_justification_enum():
    assert VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH.value == "vulnerable_code_not_in_execute_path"


def test_known_vuln_db_populated():
    assert len(KNOWN_VULN_DB) >= 10
    assert "lodash" in KNOWN_VULN_DB
    assert "requests" in KNOWN_VULN_DB
    assert "spring-core" in KNOWN_VULN_DB


def test_cross_reference_vulnerabilities():
    gen = SBOMGenerator()
    deps = [
        Dependency(name="lodash", version="4.17.20", package_manager="npm"),
        Dependency(name="requests", version="2.28.0", package_manager="pip"),
        Dependency(name="safe-package", version="1.0.0", package_manager="npm"),
    ]
    report = gen.cross_reference_vulnerabilities(deps)
    assert report["total_vulnerabilities"] >= 2  # lodash + requests
    assert report["vulnerable_components"] >= 2
    assert report["scanned_components"] == 3
    # Check findings have correct structure
    for f in report["findings"]:
        assert "cve" in f
        assert "severity" in f
        assert "remediation" in f
        assert "purl" in f


def test_cross_reference_no_vuln():
    gen = SBOMGenerator()
    deps = [Dependency(name="nonexistent-pkg", version="1.0.0", package_manager="npm")]
    report = gen.cross_reference_vulnerabilities(deps)
    assert report["total_vulnerabilities"] == 0


def test_cross_reference_fixed_version():
    gen = SBOMGenerator()
    # lodash 4.17.21 should NOT be vulnerable (fixed_in = 4.17.21)
    deps = [Dependency(name="lodash", version="4.17.21", package_manager="npm")]
    report = gen.cross_reference_vulnerabilities(deps)
    assert report["total_vulnerabilities"] == 0


def test_generate_vex_document():
    gen = SBOMGenerator()
    deps = [
        Dependency(name="lodash", version="4.17.20", package_manager="npm"),
        Dependency(name="axios", version="1.5.0", package_manager="npm",
                   is_transitive=True, depth=2, parent="express"),
    ]
    vex = gen.generate_vex_document(deps)
    assert vex["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert vex["author"] == "ALdeci CTEM+"
    assert len(vex["statements"]) >= 2
    # Deep transitive should be UNDER_INVESTIGATION
    deep_trans = [s for s in vex["statements"]
                  if s.get("status") == "under_investigation"]
    assert len(deep_trans) >= 1


def test_parse_vex_document():
    vex_data = {
        "statements": [
            {
                "vulnerability": {"@id": "CVE-2021-44906"},
                "products": [{"@id": "pkg:npm/minimist@1.2.5"}],
                "status": "not_affected",
                "justification": "vulnerable_code_not_in_execute_path",
                "impact_statement": "Code path is unreachable",
            },
            {
                "vulnerability": {"@id": "CVE-2020-28500"},
                "products": [{"@id": "pkg:npm/lodash@4.17.20"}],
                "status": "affected",
            },
        ],
    }
    stmts = SBOMGenerator.parse_vex_document(vex_data)
    assert len(stmts) == 2
    assert stmts[0].vulnerability_id == "CVE-2021-44906"
    assert stmts[0].status == VEXStatus.NOT_AFFECTED
    assert stmts[0].justification == VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
    assert stmts[1].status == VEXStatus.AFFECTED


def test_apply_vex_to_sbom():
    gen = SBOMGenerator()
    sbom = {
        "components": [
            {"name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
        ],
    }
    stmts = [
        VEXStatement(
            vulnerability_id="CVE-2020-28500",
            status=VEXStatus.NOT_AFFECTED,
            justification=VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            products=["pkg:npm/lodash@4.17.20"],
        ),
    ]
    enriched = gen.apply_vex_to_sbom(sbom, stmts)
    assert enriched["_vex_applied"] is True
    assert enriched["_vex_statement_count"] == 1
    comp = enriched["components"][0]
    assert "vulnerabilities" in comp
    assert comp["vulnerabilities"][0]["id"] == "CVE-2020-28500"
    assert comp["vulnerabilities"][0]["status"] == "not_affected"


def test_cyclonedx_includes_transitive_metadata():
    gen = SBOMGenerator()
    from pathlib import Path
    deps = [
        Dependency(name="express", version="4.18.0", package_manager="npm", depth=0),
        Dependency(name="lodash", version="4.17.21", package_manager="npm",
                   is_transitive=True, depth=1, parent="express"),
    ]
    sbom = gen._generate_cyclonedx(deps, Path("/tmp/test"))
    assert sbom["specVersion"] == "1.5"
    assert "dependencies" in sbom
    # Check transitive property on lodash component
    lodash_comp = [c for c in sbom["components"] if c["name"] == "lodash"][0]
    props = {p["name"]: p["value"] for p in lodash_comp["properties"]}
    assert props["fixops:transitive"] == "true"
    assert props["fixops:depth"] == "1"
    assert props["fixops:parent"] == "express"


def test_spdx_includes_relationships():
    gen = SBOMGenerator()
    from pathlib import Path
    deps = [
        Dependency(name="express", version="4.18.0", package_manager="npm", depth=0),
        Dependency(name="lodash", version="4.17.21", package_manager="npm",
                   is_transitive=True, depth=1, parent="express"),
    ]
    sbom = gen._generate_spdx(deps, Path("/tmp/test"))
    assert "relationships" in sbom
    assert len(sbom["relationships"]) == 2
    # express -> doc, lodash -> express
    dep_ons = [r for r in sbom["relationships"] if r["relationshipType"] == "DEPENDS_ON"]
    assert len(dep_ons) == 2

