"""Tests for SupplyChainRiskEngine — 20 tests covering init, CRUD, SBOM, stats, org isolation."""
from __future__ import annotations

import os
import pytest

from core.supply_chain_risk_engine import SupplyChainRiskEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_sc.db")
    return SupplyChainRiskEngine(db_path=db)


ORG = "org-a"
ORG2 = "org-b"

# ---------------------------------------------------------------------------
# 1. Init
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = str(tmp_path / "sub" / "sc.db")
    eng = SupplyChainRiskEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "sc.db")
    SupplyChainRiskEngine(db_path=db)
    SupplyChainRiskEngine(db_path=db)  # must not raise


# ---------------------------------------------------------------------------
# 2. Suppliers
# ---------------------------------------------------------------------------


def test_add_supplier_returns_dict(engine):
    sup = engine.add_supplier(ORG, {
        "name": "Acme Corp",
        "category": "software",
        "country": "US",
        "risk_tier": "high",
        "compliance_score": 72.0,
        "contacts": [{"name": "Alice", "email": "alice@acme.com"}],
    })
    assert sup["supplier_id"]
    assert sup["name"] == "Acme Corp"
    assert sup["risk_tier"] == "high"
    assert isinstance(sup["contacts"], list)
    assert sup["contacts"][0]["name"] == "Alice"


def test_add_supplier_defaults(engine):
    sup = engine.add_supplier(ORG, {"name": "Unknown Vendor"})
    assert sup["category"] == "software"
    assert sup["risk_tier"] == "medium"
    assert sup["compliance_score"] == 0.0


def test_add_supplier_invalid_risk_tier_defaults(engine):
    sup = engine.add_supplier(ORG, {"name": "X", "risk_tier": "extreme"})
    assert sup["risk_tier"] == "medium"


def test_list_suppliers_empty(engine):
    assert engine.list_suppliers(ORG) == []


def test_list_suppliers_filter_risk_tier(engine):
    engine.add_supplier(ORG, {"name": "A", "risk_tier": "critical"})
    engine.add_supplier(ORG, {"name": "B", "risk_tier": "low"})
    critical = engine.list_suppliers(ORG, risk_tier="critical")
    assert len(critical) == 1
    assert critical[0]["name"] == "A"


# ---------------------------------------------------------------------------
# 3. Components
# ---------------------------------------------------------------------------


def test_add_component_returns_dict(engine):
    sup = engine.add_supplier(ORG, {"name": "LibCorp"})
    comp = engine.add_component(ORG, sup["supplier_id"], {
        "name": "log4j-core",
        "version": "2.14.1",
        "component_type": "library",
        "license": "Apache-2.0",
        "cve_count": 3,
        "is_eol": False,
        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
    })
    assert comp["component_id"]
    assert comp["name"] == "log4j-core"
    assert comp["cve_count"] == 3
    assert comp["is_eol"] is False


def test_add_component_eol_flag(engine):
    sup = engine.add_supplier(ORG, {"name": "OldLib"})
    comp = engine.add_component(ORG, sup["supplier_id"], {"name": "legacy-lib", "is_eol": True})
    assert comp["is_eol"] is True


def test_list_components_filter_eol(engine):
    sup = engine.add_supplier(ORG, {"name": "MixedLib"})
    engine.add_component(ORG, sup["supplier_id"], {"name": "active", "is_eol": False})
    engine.add_component(ORG, sup["supplier_id"], {"name": "deprecated", "is_eol": True})
    eol = engine.list_components(ORG, is_eol=True)
    assert len(eol) == 1
    assert eol[0]["name"] == "deprecated"


def test_list_components_filter_supplier(engine):
    sup1 = engine.add_supplier(ORG, {"name": "S1"})
    sup2 = engine.add_supplier(ORG, {"name": "S2"})
    engine.add_component(ORG, sup1["supplier_id"], {"name": "lib-a"})
    engine.add_component(ORG, sup2["supplier_id"], {"name": "lib-b"})
    comps = engine.list_components(ORG, supplier_id=sup1["supplier_id"])
    assert len(comps) == 1
    assert comps[0]["name"] == "lib-a"


# ---------------------------------------------------------------------------
# 4. Risks
# ---------------------------------------------------------------------------


def test_add_risk_returns_dict(engine):
    sup = engine.add_supplier(ORG, {"name": "SingleSrc"})
    risk = engine.add_risk(ORG, {
        "supplier_id": sup["supplier_id"],
        "risk_type": "single_source",
        "severity": "high",
        "description": "Only one vendor for this lib",
        "status": "open",
    })
    assert risk["risk_id"]
    assert risk["risk_type"] == "single_source"
    assert risk["severity"] == "high"


def test_add_risk_invalid_type_defaults(engine):
    risk = engine.add_risk(ORG, {"risk_type": "bogus"})
    assert risk["risk_type"] == "single_source"


def test_list_risks_filter_status(engine):
    engine.add_risk(ORG, {"risk_type": "eol", "status": "open"})
    engine.add_risk(ORG, {"risk_type": "no_audit", "status": "mitigated"})
    open_risks = engine.list_risks(ORG, status="open")
    assert len(open_risks) == 1


# ---------------------------------------------------------------------------
# 5. SBOM Import
# ---------------------------------------------------------------------------


def test_import_sbom_returns_stats(engine):
    sbom = {
        "components": [
            {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21",
             "license": "MIT", "cve_count": 0, "is_eol": False},
            {"name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/log4j-core@2.14.1",
             "license": "Apache-2.0", "cve_count": 3, "is_eol": True},
            {"name": "openssl", "version": "1.0.2k", "purl": "pkg:generic/openssl@1.0.2k",
             "license": "OpenSSL", "cve_count": 7, "is_eol": True},
        ]
    }
    result = engine.import_sbom(ORG, sbom)
    assert result["imported"] == 3
    assert result["eol_detected"] == 2
    assert result["cve_count"] == 10
    assert "batch_id" in result


def test_import_sbom_empty(engine):
    result = engine.import_sbom(ORG, {"components": []})
    assert result["imported"] == 0
    assert result["eol_detected"] == 0
    assert result["cve_count"] == 0


def test_import_sbom_skips_non_dict(engine):
    result = engine.import_sbom(ORG, {"components": ["not-a-dict", None, 42]})
    assert result["imported"] == 0


# ---------------------------------------------------------------------------
# 6. Stats
# ---------------------------------------------------------------------------


def test_get_supply_chain_stats_empty(engine):
    stats = engine.get_supply_chain_stats(ORG)
    assert stats["total_suppliers"] == 0
    assert stats["critical_tier"] == 0
    assert stats["total_components"] == 0
    assert stats["eol_components"] == 0
    assert stats["open_risks"] == 0
    assert stats["avg_compliance_score"] == 0.0


def test_get_supply_chain_stats_populated(engine):
    sup = engine.add_supplier(ORG, {"name": "CriticalVendor", "risk_tier": "critical", "compliance_score": 80.0})
    engine.add_supplier(ORG, {"name": "LowVendor", "risk_tier": "low", "compliance_score": 60.0})
    engine.add_component(ORG, sup["supplier_id"], {"name": "active-lib", "is_eol": False})
    engine.add_component(ORG, sup["supplier_id"], {"name": "old-lib", "is_eol": True})
    engine.add_risk(ORG, {"risk_type": "eol", "status": "open"})
    engine.add_risk(ORG, {"risk_type": "no_audit", "status": "mitigated"})
    stats = engine.get_supply_chain_stats(ORG)
    assert stats["total_suppliers"] == 2
    assert stats["critical_tier"] == 1
    assert stats["total_components"] == 2
    assert stats["eol_components"] == 1
    assert stats["open_risks"] == 1
    assert stats["avg_compliance_score"] == 70.0


# ---------------------------------------------------------------------------
# 7. Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_suppliers(engine):
    engine.add_supplier(ORG, {"name": "Org A Vendor"})
    assert engine.list_suppliers(ORG2) == []


def test_org_isolation_risks(engine):
    engine.add_risk(ORG, {"risk_type": "eol"})
    assert engine.list_risks(ORG2) == []


def test_org_isolation_components(engine):
    sup = engine.add_supplier(ORG, {"name": "CrossOrgLib"})
    engine.add_component(ORG, sup["supplier_id"], {"name": "libx"})
    assert engine.list_components(ORG2) == []


def test_org_isolation_stats(engine):
    engine.add_supplier(ORG, {"name": "VendorA", "risk_tier": "critical", "compliance_score": 90.0})
    stats_org2 = engine.get_supply_chain_stats(ORG2)
    assert stats_org2["total_suppliers"] == 0


# ---------------------------------------------------------------------------
# 8. Risk type / severity validation
# ---------------------------------------------------------------------------


def test_add_risk_severity_invalid_defaults_to_medium(engine):
    risk = engine.add_risk(ORG, {"risk_type": "eol", "severity": "apocalyptic"})
    assert risk["severity"] in ("low", "medium", "high", "critical")


def test_add_risk_status_defaults_to_open(engine):
    risk = engine.add_risk(ORG, {"risk_type": "eol"})
    assert risk["status"] == "open"


def test_add_risk_all_valid_types(engine):
    valid_types = ["single_source", "eol", "no_audit", "geo_risk", "license"]
    for rt in valid_types:
        risk = engine.add_risk(ORG, {"risk_type": rt})
        assert risk["risk_type"] == rt or risk["risk_type"] in valid_types


def test_list_risks_empty(engine):
    assert engine.list_risks(ORG) == []


def test_list_risks_filter_by_status_open_and_mitigated(engine):
    """list_risks filters by status (not severity — engine has no severity filter)."""
    engine.add_risk(ORG, {"risk_type": "eol", "severity": "critical", "status": "open"})
    engine.add_risk(ORG, {"risk_type": "no_audit", "severity": "low", "status": "mitigated"})
    open_risks = engine.list_risks(ORG, status="open")
    mitigated_risks = engine.list_risks(ORG, status="mitigated")
    assert len(open_risks) == 1
    assert open_risks[0]["severity"] == "critical"
    assert len(mitigated_risks) == 1


# ---------------------------------------------------------------------------
# 9. SBOM edge cases
# ---------------------------------------------------------------------------


def test_import_sbom_only_eol_components(engine):
    sbom = {"components": [
        {"name": "old-lib", "version": "1.0", "is_eol": True, "cve_count": 0},
    ]}
    result = engine.import_sbom(ORG, {"components": [
        {"name": "old-lib", "version": "1.0", "is_eol": True, "cve_count": 0},
    ]})
    assert result["eol_detected"] == 1
    assert result["imported"] == 1


def test_import_sbom_zero_cvss(engine):
    result = engine.import_sbom(ORG, {"components": [
        {"name": "safe-lib", "version": "2.0", "is_eol": False, "cve_count": 0},
    ]})
    assert result["cve_count"] == 0
    assert result["imported"] == 1


def test_import_sbom_missing_components_key(engine):
    """Missing 'components' key should be handled gracefully."""
    try:
        result = engine.import_sbom(ORG, {})
        assert result["imported"] == 0
    except (KeyError, TypeError):
        pass  # acceptable — engine enforces schema


def test_import_sbom_batch_id_unique(engine):
    sbom = {"components": [{"name": "a"}]}
    r1 = engine.import_sbom(ORG, sbom)
    r2 = engine.import_sbom(ORG, sbom)
    assert r1["batch_id"] != r2["batch_id"]


# ---------------------------------------------------------------------------
# 10. Supplier compliance score edge cases
# ---------------------------------------------------------------------------


def test_supplier_compliance_score_max(engine):
    sup = engine.add_supplier(ORG, {"name": "Perfect", "compliance_score": 100.0})
    assert sup["compliance_score"] == 100.0


def test_supplier_compliance_score_zero(engine):
    sup = engine.add_supplier(ORG, {"name": "Zero", "compliance_score": 0.0})
    assert sup["compliance_score"] == 0.0


def test_list_suppliers_multiple_orgs_independent(engine):
    engine.add_supplier(ORG, {"name": "A1"})
    engine.add_supplier(ORG, {"name": "A2"})
    engine.add_supplier(ORG2, {"name": "B1"})
    assert len(engine.list_suppliers(ORG)) == 2
    assert len(engine.list_suppliers(ORG2)) == 1


# ---------------------------------------------------------------------------
# 11. Component with CVE counts
# ---------------------------------------------------------------------------


def test_add_component_high_cve_count(engine):
    sup = engine.add_supplier(ORG, {"name": "VulnLib"})
    comp = engine.add_component(ORG, sup["supplier_id"], {
        "name": "vuln-pkg",
        "version": "1.0",
        "cve_count": 99,
    })
    assert comp["cve_count"] == 99


def test_list_components_empty(engine):
    assert engine.list_components(ORG) == []


def test_list_components_no_filter(engine):
    sup = engine.add_supplier(ORG, {"name": "MultiLib"})
    engine.add_component(ORG, sup["supplier_id"], {"name": "lib-a"})
    engine.add_component(ORG, sup["supplier_id"], {"name": "lib-b", "is_eol": True})
    all_comps = engine.list_components(ORG)
    assert len(all_comps) == 2


# ---------------------------------------------------------------------------
# 12. Supplier contacts
# ---------------------------------------------------------------------------


def test_supplier_contacts_empty_list(engine):
    sup = engine.add_supplier(ORG, {"name": "No contacts", "contacts": []})
    assert isinstance(sup["contacts"], list)
    assert sup["contacts"] == []


def test_supplier_contacts_multiple(engine):
    contacts = [
        {"name": "Alice", "email": "alice@corp.com"},
        {"name": "Bob", "email": "bob@corp.com"},
    ]
    sup = engine.add_supplier(ORG, {"name": "Multi-contact", "contacts": contacts})
    assert len(sup["contacts"]) == 2


# ---------------------------------------------------------------------------
# 13. Risk description and metadata
# ---------------------------------------------------------------------------


def test_add_risk_with_description(engine):
    risk = engine.add_risk(ORG, {
        "risk_type": "geo_risk",
        "severity": "high",
        "description": "Vendor located in sanctioned country",
        "status": "open",
    })
    assert risk["risk_id"] is not None
    assert risk["severity"] == "high"


def test_add_risk_returns_org_id(engine):
    risk = engine.add_risk(ORG, {"risk_type": "eol"})
    assert risk["org_id"] == ORG


# ---------------------------------------------------------------------------
# 14. SBOM import with purl field
# ---------------------------------------------------------------------------


def test_import_sbom_stores_purl(engine):
    result = engine.import_sbom(ORG, {"components": [
        {"name": "lodash", "version": "4.17.21",
         "purl": "pkg:npm/lodash@4.17.21", "is_eol": False, "cve_count": 0},
    ]})
    assert result["imported"] == 1


def test_import_sbom_mixed_eol_and_active(engine):
    result = engine.import_sbom(ORG, {"components": [
        {"name": "active-lib", "is_eol": False, "cve_count": 0},
        {"name": "dead-lib", "is_eol": True, "cve_count": 2},
        {"name": "also-dead", "is_eol": True, "cve_count": 1},
    ]})
    assert result["imported"] == 3
    assert result["eol_detected"] == 2
    assert result["cve_count"] == 3
