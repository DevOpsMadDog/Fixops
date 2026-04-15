"""Tests for SupplyChainRiskEngine — 28 tests covering all public methods + org isolation."""

from __future__ import annotations

import pytest
from core.supply_chain_risk_engine import SupplyChainRiskEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "sc_risk_test.db")
    return SupplyChainRiskEngine(db_path=db)


@pytest.fixture
def org():
    return "org-alpha"


@pytest.fixture
def org2():
    return "org-beta"


def _add_supplier(engine, org, name="Acme Corp", risk_tier="medium", category="software"):
    return engine.add_supplier(org, {
        "name": name,
        "category": category,
        "country": "US",
        "risk_tier": risk_tier,
        "compliance_score": 75.0,
        "contacts": [{"name": "Bob", "email": "bob@acme.com"}],
    })


# ---------------------------------------------------------------------------
# add_supplier
# ---------------------------------------------------------------------------

def test_add_supplier_returns_record(engine, org):
    supplier = _add_supplier(engine, org)
    assert supplier["supplier_id"] is not None
    assert supplier["name"] == "Acme Corp"
    assert supplier["org_id"] == org
    assert supplier["risk_tier"] == "medium"
    assert supplier["category"] == "software"
    assert isinstance(supplier["contacts"], list)


def test_add_supplier_invalid_category_defaults_to_software(engine, org):
    supplier = engine.add_supplier(org, {"name": "TestCo", "category": "bogus"})
    assert supplier["category"] == "software"


def test_add_supplier_invalid_risk_tier_defaults_to_medium(engine, org):
    supplier = engine.add_supplier(org, {"name": "TestCo", "risk_tier": "extreme"})
    assert supplier["risk_tier"] == "medium"


def test_add_supplier_all_categories(engine, org):
    for category in ("software", "hardware", "service", "cloud"):
        s = engine.add_supplier(org, {"name": f"Vendor-{category}", "category": category})
        assert s["category"] == category


def test_add_supplier_all_risk_tiers(engine, org):
    for tier in ("critical", "high", "medium", "low"):
        s = engine.add_supplier(org, {"name": f"Vendor-{tier}", "risk_tier": tier})
        assert s["risk_tier"] == tier


def test_add_supplier_contacts_as_string_parsed(engine, org):
    import json
    supplier = engine.add_supplier(org, {
        "name": "StringContactsCo",
        "contacts": json.dumps([{"name": "Alice"}]),
    })
    assert isinstance(supplier["contacts"], list)
    assert supplier["contacts"][0]["name"] == "Alice"


# ---------------------------------------------------------------------------
# list_suppliers
# ---------------------------------------------------------------------------

def test_list_suppliers_empty(engine, org):
    assert engine.list_suppliers(org) == []


def test_list_suppliers_returns_own_org_only(engine, org, org2):
    _add_supplier(engine, org, name="Org1 Supplier")
    _add_supplier(engine, org2, name="Org2 Supplier")
    result = engine.list_suppliers(org)
    assert len(result) == 1
    assert result[0]["name"] == "Org1 Supplier"


def test_list_suppliers_filter_by_risk_tier(engine, org):
    _add_supplier(engine, org, name="Critical Vendor", risk_tier="critical")
    _add_supplier(engine, org, name="Low Vendor", risk_tier="low")
    critical = engine.list_suppliers(org, risk_tier="critical")
    assert len(critical) == 1
    assert critical[0]["name"] == "Critical Vendor"


def test_list_suppliers_multiple(engine, org):
    _add_supplier(engine, org, name="A")
    _add_supplier(engine, org, name="B")
    _add_supplier(engine, org, name="C")
    result = engine.list_suppliers(org)
    assert len(result) == 3


# ---------------------------------------------------------------------------
# add_component
# ---------------------------------------------------------------------------

def test_add_component_returns_record(engine, org):
    supplier = _add_supplier(engine, org)
    component = engine.add_component(org, supplier["supplier_id"], {
        "name": "log4j-core",
        "version": "2.14.1",
        "component_type": "library",
        "license": "Apache-2.0",
        "cve_count": 3,
        "is_eol": False,
        "purl": "pkg:maven/log4j-core@2.14.1",
    })
    assert component["component_id"] is not None
    assert component["name"] == "log4j-core"
    assert component["org_id"] == org
    assert component["supplier_id"] == supplier["supplier_id"]
    assert component["cve_count"] == 3
    assert component["is_eol"] is False


def test_add_component_invalid_type_defaults_to_library(engine, org):
    supplier = _add_supplier(engine, org)
    component = engine.add_component(org, supplier["supplier_id"], {
        "name": "weird-component",
        "component_type": "alien",
    })
    assert component["component_type"] == "library"


def test_add_component_eol_flag(engine, org):
    supplier = _add_supplier(engine, org)
    comp = engine.add_component(org, supplier["supplier_id"], {
        "name": "eol-package", "version": "1.0", "is_eol": True
    })
    assert comp["is_eol"] is True


def test_add_component_all_types(engine, org):
    supplier = _add_supplier(engine, org)
    for comp_type in ("library", "container", "firmware", "service"):
        c = engine.add_component(org, supplier["supplier_id"], {
            "name": f"comp-{comp_type}",
            "component_type": comp_type,
        })
        assert c["component_type"] == comp_type


# ---------------------------------------------------------------------------
# list_components
# ---------------------------------------------------------------------------

def test_list_components_empty(engine, org):
    assert engine.list_components(org) == []


def test_list_components_org_isolation(engine, org, org2):
    s1 = _add_supplier(engine, org)
    s2 = _add_supplier(engine, org2, name="Org2 Supplier")
    engine.add_component(org, s1["supplier_id"], {"name": "comp-a"})
    engine.add_component(org2, s2["supplier_id"], {"name": "comp-b"})
    assert len(engine.list_components(org)) == 1
    assert len(engine.list_components(org2)) == 1


def test_list_components_filter_by_supplier(engine, org):
    s1 = _add_supplier(engine, org, name="Supplier A")
    s2 = _add_supplier(engine, org, name="Supplier B")
    engine.add_component(org, s1["supplier_id"], {"name": "comp-s1"})
    engine.add_component(org, s2["supplier_id"], {"name": "comp-s2"})
    result = engine.list_components(org, supplier_id=s1["supplier_id"])
    assert len(result) == 1
    assert result[0]["name"] == "comp-s1"


def test_list_components_filter_by_eol(engine, org):
    s = _add_supplier(engine, org)
    engine.add_component(org, s["supplier_id"], {"name": "old-lib", "is_eol": True})
    engine.add_component(org, s["supplier_id"], {"name": "new-lib", "is_eol": False})
    eol = engine.list_components(org, is_eol=True)
    active = engine.list_components(org, is_eol=False)
    assert len(eol) == 1
    assert eol[0]["name"] == "old-lib"
    assert len(active) == 1
    assert active[0]["name"] == "new-lib"


# ---------------------------------------------------------------------------
# add_risk / list_risks
# ---------------------------------------------------------------------------

def test_add_risk_returns_record(engine, org):
    supplier = _add_supplier(engine, org)
    risk = engine.add_risk(org, {
        "supplier_id": supplier["supplier_id"],
        "risk_type": "single_source",
        "severity": "high",
        "description": "Single vendor dependency",
        "status": "open",
    })
    assert risk["risk_id"] is not None
    assert risk["org_id"] == org
    assert risk["risk_type"] == "single_source"
    assert risk["severity"] == "high"
    assert risk["status"] == "open"


def test_add_risk_invalid_type_defaults(engine, org):
    risk = engine.add_risk(org, {"risk_type": "alien_invasion"})
    assert risk["risk_type"] == "single_source"


def test_add_risk_invalid_severity_defaults(engine, org):
    risk = engine.add_risk(org, {"severity": "extreme"})
    assert risk["severity"] == "medium"


def test_add_risk_all_risk_types(engine, org):
    for rt in ("single_source", "eol", "geo_political", "breach_history", "no_audit", "license_violation"):
        r = engine.add_risk(org, {"risk_type": rt})
        assert r["risk_type"] == rt


def test_list_risks_empty(engine, org):
    assert engine.list_risks(org) == []


def test_list_risks_org_isolation(engine, org, org2):
    engine.add_risk(org, {"risk_type": "eol", "description": "Org1 risk"})
    engine.add_risk(org2, {"risk_type": "eol", "description": "Org2 risk"})
    assert len(engine.list_risks(org)) == 1
    assert len(engine.list_risks(org2)) == 1


def test_list_risks_filter_by_status(engine, org):
    engine.add_risk(org, {"risk_type": "eol", "status": "open"})
    engine.add_risk(org, {"risk_type": "geo_political", "status": "mitigated"})
    open_risks = engine.list_risks(org, status="open")
    mitigated = engine.list_risks(org, status="mitigated")
    assert len(open_risks) == 1
    assert len(mitigated) == 1


# ---------------------------------------------------------------------------
# import_sbom
# ---------------------------------------------------------------------------

def test_import_sbom_basic(engine, org):
    sbom_data = {
        "components": [
            {"name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/log4j@2.14.1",
             "license": "Apache-2.0", "cve_count": 3, "is_eol": False},
            {"name": "struts2-core", "version": "2.3.32", "purl": "", "license": "Apache-2.0",
             "cve_count": 5, "is_eol": True},
        ]
    }
    result = engine.import_sbom(org, sbom_data)
    assert result["imported"] == 2
    assert result["eol_detected"] == 1
    assert result["cve_count"] == 8
    assert result["batch_id"] is not None


def test_import_sbom_empty(engine, org):
    result = engine.import_sbom(org, {"components": []})
    assert result["imported"] == 0
    assert result["eol_detected"] == 0
    assert result["cve_count"] == 0


def test_import_sbom_skips_non_dict_entries(engine, org):
    sbom_data = {"components": [
        {"name": "valid-comp", "cve_count": 1},
        "not-a-dict",
        None,
    ]}
    result = engine.import_sbom(org, sbom_data)
    assert result["imported"] == 1


def test_import_sbom_batch_id_unique(engine, org):
    sbom_data = {"components": [{"name": "comp-a"}]}
    r1 = engine.import_sbom(org, sbom_data)
    r2 = engine.import_sbom(org, sbom_data)
    assert r1["batch_id"] != r2["batch_id"]


# ---------------------------------------------------------------------------
# get_supply_chain_stats
# ---------------------------------------------------------------------------

def test_get_supply_chain_stats_empty(engine, org):
    stats = engine.get_supply_chain_stats(org)
    assert stats["total_suppliers"] == 0
    assert stats["critical_tier"] == 0
    assert stats["total_components"] == 0
    assert stats["eol_components"] == 0
    assert stats["open_risks"] == 0
    assert stats["avg_compliance_score"] == 0.0


def test_get_supply_chain_stats_populated(engine, org):
    s1 = _add_supplier(engine, org, name="Critical Vendor", risk_tier="critical")
    s2 = _add_supplier(engine, org, name="Normal Vendor", risk_tier="medium")
    engine.add_component(org, s1["supplier_id"], {"name": "eol-lib", "is_eol": True})
    engine.add_component(org, s2["supplier_id"], {"name": "active-lib", "is_eol": False})
    engine.add_risk(org, {"risk_type": "single_source", "status": "open"})
    engine.add_risk(org, {"risk_type": "eol", "status": "mitigated"})
    stats = engine.get_supply_chain_stats(org)
    assert stats["total_suppliers"] == 2
    assert stats["critical_tier"] == 1
    assert stats["total_components"] == 2
    assert stats["eol_components"] == 1
    assert stats["open_risks"] == 1
    assert stats["avg_compliance_score"] == 75.0


def test_get_supply_chain_stats_org_isolation(engine, org, org2):
    _add_supplier(engine, org, name="Org1 Vendor")
    _add_supplier(engine, org2, name="Org2 Vendor")
    s1 = engine.get_supply_chain_stats(org)
    s2 = engine.get_supply_chain_stats(org2)
    assert s1["total_suppliers"] == 1
    assert s2["total_suppliers"] == 1
