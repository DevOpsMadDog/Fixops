"""Tests for SupplyChainMonitoringEngine — 32 tests covering all methods + org isolation."""

from __future__ import annotations

import pytest
from core.supply_chain_monitoring_engine import SupplyChainMonitoringEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "scm_test.db")
    return SupplyChainMonitoringEngine(db_path=db)


@pytest.fixture
def org():
    return "org-alpha"


@pytest.fixture
def org2():
    return "org-beta"


def _supplier(engine, org, name="Acme Corp", supplier_type="software", risk_tier="medium"):
    return engine.register_supplier(org, {
        "name": name,
        "supplier_type": supplier_type,
        "risk_tier": risk_tier,
        "contact_email": "contact@acme.com",
        "website": "https://acme.com",
    })


def _event(engine, org, supplier_id, event_type="breach", severity="high"):
    return engine.record_supply_chain_event(org, {
        "supplier_id": supplier_id,
        "event_type": event_type,
        "severity": severity,
        "description": "Test event",
    })


# ---------------------------------------------------------------------------
# register_supplier
# ---------------------------------------------------------------------------

def test_register_supplier_returns_record(engine, org):
    s = _supplier(engine, org)
    assert s["name"] == "Acme Corp"
    assert s["supplier_type"] == "software"
    assert s["risk_tier"] == "medium"
    assert s["org_id"] == org
    assert "id" in s
    assert s["status"] == "active"
    assert s["risk_score"] == 50.0


def test_register_supplier_missing_name_raises(engine, org):
    with pytest.raises(ValueError, match="name"):
        engine.register_supplier(org, {"name": "", "supplier_type": "software", "risk_tier": "medium"})


def test_register_supplier_invalid_type_raises(engine, org):
    with pytest.raises(ValueError, match="supplier_type"):
        engine.register_supplier(org, {"name": "X", "supplier_type": "unknown", "risk_tier": "medium"})


def test_register_supplier_invalid_tier_raises(engine, org):
    with pytest.raises(ValueError, match="risk_tier"):
        engine.register_supplier(org, {"name": "X", "supplier_type": "software", "risk_tier": "extreme"})


def test_register_supplier_all_types(engine, org):
    for stype in ("software", "hardware", "services", "cloud", "logistics", "manufacturing"):
        s = engine.register_supplier(org, {"name": f"sup-{stype}", "supplier_type": stype, "risk_tier": "low"})
        assert s["supplier_type"] == stype


def test_register_supplier_all_risk_tiers(engine, org):
    for tier in ("critical", "high", "medium", "low"):
        s = engine.register_supplier(org, {"name": f"sup-{tier}", "supplier_type": "cloud", "risk_tier": tier})
        assert s["risk_tier"] == tier


# ---------------------------------------------------------------------------
# list_suppliers
# ---------------------------------------------------------------------------

def test_list_suppliers_empty(engine, org):
    assert engine.list_suppliers(org) == []


def test_list_suppliers_org_isolation(engine, org, org2):
    _supplier(engine, org, "Alpha Supplier")
    _supplier(engine, org2, "Beta Supplier")
    result = engine.list_suppliers(org)
    assert len(result) == 1
    assert result[0]["name"] == "Alpha Supplier"


def test_list_suppliers_filter_by_type(engine, org):
    _supplier(engine, org, "Soft Co", supplier_type="software")
    _supplier(engine, org, "Hard Co", supplier_type="hardware")
    result = engine.list_suppliers(org, supplier_type="software")
    assert len(result) == 1
    assert result[0]["name"] == "Soft Co"


def test_list_suppliers_filter_by_tier(engine, org):
    _supplier(engine, org, "Crit Co", risk_tier="critical")
    _supplier(engine, org, "Low Co", risk_tier="low")
    result = engine.list_suppliers(org, risk_tier="critical")
    assert len(result) == 1
    assert result[0]["name"] == "Crit Co"


# ---------------------------------------------------------------------------
# get_supplier
# ---------------------------------------------------------------------------

def test_get_supplier_returns_record(engine, org):
    s = _supplier(engine, org)
    fetched = engine.get_supplier(org, s["id"])
    assert fetched is not None
    assert fetched["id"] == s["id"]
    assert fetched["name"] == "Acme Corp"


def test_get_supplier_not_found_returns_none(engine, org):
    assert engine.get_supplier(org, "nonexistent-id") is None


def test_get_supplier_org_isolation(engine, org, org2):
    s = _supplier(engine, org)
    assert engine.get_supplier(org2, s["id"]) is None


# ---------------------------------------------------------------------------
# assess_supplier_risk
# ---------------------------------------------------------------------------

def test_assess_supplier_low_risk(engine, org):
    # score = 100 - 20 + 0 - 10 - 10 - 10 = 50 → medium (31-60)
    s = _supplier(engine, org)
    result = engine.assess_supplier_risk(org, s["id"], {
        "security_certifications": True,
        "incident_history": False,
        "financial_stability": True,
        "compliance_status": True,
        "business_continuity": True,
    })
    assert result["risk_level"] == "medium"
    assert result["risk_score"] == 50
    assert result["supplier_id"] == s["id"]


def test_assess_supplier_high_risk(engine, org):
    # score = 100 + 30 = 130 → clamped to 100 → critical
    s = _supplier(engine, org)
    result = engine.assess_supplier_risk(org, s["id"], {
        "security_certifications": False,
        "incident_history": True,
        "financial_stability": False,
        "compliance_status": False,
        "business_continuity": False,
    })
    assert result["risk_level"] == "critical"
    assert result["risk_score"] == 100


def test_assess_supplier_updates_db(engine, org):
    s = _supplier(engine, org)
    engine.assess_supplier_risk(org, s["id"], {"security_certifications": True})
    updated = engine.get_supplier(org, s["id"])
    assert updated["assessed_at"] is not None


def test_assess_supplier_factors_returned(engine, org):
    s = _supplier(engine, org)
    result = engine.assess_supplier_risk(org, s["id"], {"security_certifications": True})
    assert "factors" in result
    assert result["factors"]["security_certifications"] is True


# ---------------------------------------------------------------------------
# record_supply_chain_event
# ---------------------------------------------------------------------------

def test_record_event_returns_record(engine, org):
    s = _supplier(engine, org)
    ev = _event(engine, org, s["id"])
    assert ev["event_type"] == "breach"
    assert ev["severity"] == "high"
    assert ev["status"] == "open"
    assert ev["supplier_id"] == s["id"]
    assert "id" in ev


def test_record_event_missing_supplier_raises(engine, org):
    with pytest.raises(ValueError, match="supplier_id"):
        engine.record_supply_chain_event(org, {"supplier_id": "", "event_type": "breach", "severity": "high"})


def test_record_event_invalid_type_raises(engine, org):
    s = _supplier(engine, org)
    with pytest.raises(ValueError, match="event_type"):
        engine.record_supply_chain_event(org, {"supplier_id": s["id"], "event_type": "explosion", "severity": "high"})


def test_record_event_invalid_severity_raises(engine, org):
    s = _supplier(engine, org)
    with pytest.raises(ValueError, match="severity"):
        engine.record_supply_chain_event(org, {"supplier_id": s["id"], "event_type": "breach", "severity": "nuclear"})


def test_record_event_all_types(engine, org):
    s = _supplier(engine, org)
    for etype in ("breach", "disruption", "compliance_violation", "performance_issue", "contract_breach", "bankruptcy"):
        ev = engine.record_supply_chain_event(org, {"supplier_id": s["id"], "event_type": etype, "severity": "low"})
        assert ev["event_type"] == etype


# ---------------------------------------------------------------------------
# list_events
# ---------------------------------------------------------------------------

def test_list_events_empty(engine, org):
    assert engine.list_events(org) == []


def test_list_events_org_isolation(engine, org, org2):
    s1 = _supplier(engine, org)
    s2 = _supplier(engine, org2, "Beta Co")
    _event(engine, org, s1["id"])
    _event(engine, org2, s2["id"])
    assert len(engine.list_events(org)) == 1
    assert len(engine.list_events(org2)) == 1


def test_list_events_filter_by_supplier(engine, org):
    s1 = _supplier(engine, org, "Supplier A")
    s2 = _supplier(engine, org, "Supplier B")
    _event(engine, org, s1["id"])
    _event(engine, org, s2["id"])
    result = engine.list_events(org, supplier_id=s1["id"])
    assert len(result) == 1
    assert result[0]["supplier_id"] == s1["id"]


def test_list_events_filter_by_type(engine, org):
    s = _supplier(engine, org)
    _event(engine, org, s["id"], event_type="breach")
    _event(engine, org, s["id"], event_type="disruption")
    result = engine.list_events(org, event_type="breach")
    assert len(result) == 1
    assert result[0]["event_type"] == "breach"


def test_list_events_filter_by_status(engine, org):
    s = _supplier(engine, org)
    ev = _event(engine, org, s["id"])
    engine.resolve_event(org, ev["id"], "fixed")
    open_events = engine.list_events(org, status="open")
    resolved_events = engine.list_events(org, status="resolved")
    assert len(open_events) == 0
    assert len(resolved_events) == 1


# ---------------------------------------------------------------------------
# resolve_event
# ---------------------------------------------------------------------------

def test_resolve_event_returns_record(engine, org):
    s = _supplier(engine, org)
    ev = _event(engine, org, s["id"])
    result = engine.resolve_event(org, ev["id"], "Patched vendor library")
    assert result["status"] == "resolved"
    assert result["resolution"] == "Patched vendor library"
    assert result["event_id"] == ev["id"]
    assert result["resolved_at"] is not None


def test_resolve_event_updates_status(engine, org):
    s = _supplier(engine, org)
    ev = _event(engine, org, s["id"])
    engine.resolve_event(org, ev["id"], "resolved")
    events = engine.list_events(org, status="resolved")
    assert len(events) == 1


# ---------------------------------------------------------------------------
# get_supply_chain_stats
# ---------------------------------------------------------------------------

def test_get_stats_empty(engine, org):
    stats = engine.get_supply_chain_stats(org)
    assert stats["total_suppliers"] == 0
    assert stats["open_events"] == 0
    assert stats["avg_risk_score"] == 0.0


def test_get_stats_populated(engine, org):
    s1 = _supplier(engine, org, "Sup A", risk_tier="critical")
    s2 = _supplier(engine, org, "Sup B", risk_tier="low")
    _event(engine, org, s1["id"], severity="critical")
    _event(engine, org, s2["id"], severity="low")
    stats = engine.get_supply_chain_stats(org)
    assert stats["total_suppliers"] == 2
    assert stats["open_events"] == 2
    assert stats["critical_events"] == 1
    assert "critical" in stats["by_tier"]
    assert "breach" in stats["by_event_type"]


def test_get_stats_org_isolation(engine, org, org2):
    _supplier(engine, org)
    _supplier(engine, org2, "Beta Co")
    _supplier(engine, org2, "Gamma Co")
    assert engine.get_supply_chain_stats(org)["total_suppliers"] == 1
    assert engine.get_supply_chain_stats(org2)["total_suppliers"] == 2
