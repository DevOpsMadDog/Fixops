"""Tests for SecurityToolInventoryEngine.

Covers tool registration, listing, retrieval, status updates,
integrations, assessments, and statistics.
Total: 35 tests.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from core.security_tool_inventory_engine import SecurityToolInventoryEngine


def _future(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


@pytest.fixture()
def engine(tmp_path):
    return SecurityToolInventoryEngine(db_path=str(tmp_path / "sti_test.db"))


def _tool_data(**kwargs) -> dict:
    base = {
        "name": "Splunk SIEM",
        "vendor": "Splunk",
        "tool_category": "siem",
        "license_type": "subscription",
        "deployment_type": "cloud",
    }
    base.update(kwargs)
    return base


def _integration_data(tool_id: str, **kwargs) -> dict:
    base = {
        "tool_id": tool_id,
        "integrated_with": "ServiceNow",
        "integration_type": "api",
    }
    base.update(kwargs)
    return base


def _assessment_data(tool_id: str, **kwargs) -> dict:
    base = {
        "tool_id": tool_id,
        "assessed_by": "security-team",
        "coverage_score": 80,
        "effectiveness_score": 75,
        "utilization_pct": 60,
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "sti_init.db")
    SecurityToolInventoryEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "sti_idem.db")
    SecurityToolInventoryEngine(db_path=db)
    SecurityToolInventoryEngine(db_path=db)


# ---------------------------------------------------------------------------
# 2. register_tool
# ---------------------------------------------------------------------------

def test_register_tool_returns_record(engine):
    tool = engine.register_tool("org1", _tool_data())
    assert tool["id"]
    assert tool["name"] == "Splunk SIEM"
    assert tool["status"] == "active"


def test_register_tool_invalid_category_raises(engine):
    with pytest.raises(ValueError, match="tool_category"):
        engine.register_tool("org1", _tool_data(tool_category="antivirus"))


def test_register_tool_invalid_license_type_raises(engine):
    with pytest.raises(ValueError, match="license_type"):
        engine.register_tool("org1", _tool_data(license_type="freemium"))


def test_register_tool_invalid_deployment_type_raises(engine):
    with pytest.raises(ValueError, match="deployment_type"):
        engine.register_tool("org1", _tool_data(deployment_type="edge"))


def test_register_tool_all_deployment_types(engine):
    for dt in ("cloud", "on_prem", "hybrid", "saas"):
        tool = engine.register_tool("org1", _tool_data(deployment_type=dt, name=f"Tool-{dt}"))
        assert tool["deployment_type"] == dt


def test_register_tool_all_categories(engine):
    cats = [
        "siem", "edr", "dlp", "firewall", "waf", "sca", "dast", "sast",
        "iam", "pam", "soar", "threat_intel", "vulnerability_scanner",
        "network_monitor", "other",
    ]
    for cat in cats:
        tool = engine.register_tool("org1", _tool_data(tool_category=cat, name=f"Tool-{cat}"))
        assert tool["tool_category"] == cat


def test_register_tool_cost_annual(engine):
    tool = engine.register_tool("org1", _tool_data(cost_annual=12000.50))
    assert tool["cost_annual"] == 12000.50


# ---------------------------------------------------------------------------
# 3. list_tools
# ---------------------------------------------------------------------------

def test_list_tools_empty(engine):
    assert engine.list_tools("org1") == []


def test_list_tools_org_isolation(engine):
    engine.register_tool("org1", _tool_data())
    assert engine.list_tools("org2") == []


def test_list_tools_filter_category(engine):
    engine.register_tool("org1", _tool_data(tool_category="siem"))
    engine.register_tool("org1", _tool_data(tool_category="edr", name="CrowdStrike"))
    results = engine.list_tools("org1", tool_category="edr")
    assert len(results) == 1
    assert results[0]["tool_category"] == "edr"


def test_list_tools_filter_status(engine):
    engine.register_tool("org1", _tool_data(status="active"))
    engine.register_tool("org1", _tool_data(status="evaluating", name="Trial Tool"))
    results = engine.list_tools("org1", status="evaluating")
    assert len(results) == 1
    assert results[0]["status"] == "evaluating"


# ---------------------------------------------------------------------------
# 4. get_tool
# ---------------------------------------------------------------------------

def test_get_tool_returns_record(engine):
    created = engine.register_tool("org1", _tool_data())
    fetched = engine.get_tool("org1", created["id"])
    assert fetched is not None
    assert fetched["id"] == created["id"]


def test_get_tool_not_found_returns_none(engine):
    assert engine.get_tool("org1", "nonexistent") is None


def test_get_tool_org_isolation(engine):
    created = engine.register_tool("org1", _tool_data())
    assert engine.get_tool("org2", created["id"]) is None


# ---------------------------------------------------------------------------
# 5. update_tool_status
# ---------------------------------------------------------------------------

def test_update_tool_status_valid(engine):
    tool = engine.register_tool("org1", _tool_data())
    updated = engine.update_tool_status("org1", tool["id"], "deprecated")
    assert updated["status"] == "deprecated"


def test_update_tool_status_invalid_raises(engine):
    tool = engine.register_tool("org1", _tool_data())
    with pytest.raises(ValueError, match="status"):
        engine.update_tool_status("org1", tool["id"], "retired")


def test_update_tool_status_all_valid(engine):
    for s in ("active", "inactive", "deprecated", "evaluating"):
        tool = engine.register_tool("org1", _tool_data(name=f"T-{s}"))
        result = engine.update_tool_status("org1", tool["id"], s)
        assert result["status"] == s


# ---------------------------------------------------------------------------
# 6. add_integration + list_integrations
# ---------------------------------------------------------------------------

def test_add_integration_returns_record(engine):
    tool = engine.register_tool("org1", _tool_data())
    intg = engine.add_integration("org1", _integration_data(tool["id"]))
    assert intg["id"]
    assert intg["status"] == "pending"


def test_add_integration_invalid_type_raises(engine):
    tool = engine.register_tool("org1", _tool_data())
    with pytest.raises(ValueError, match="integration_type"):
        engine.add_integration("org1", _integration_data(tool["id"], integration_type="ftp"))


def test_list_integrations_tool_id_filter(engine):
    t1 = engine.register_tool("org1", _tool_data())
    t2 = engine.register_tool("org1", _tool_data(name="Tool2", tool_category="edr"))
    engine.add_integration("org1", _integration_data(t1["id"]))
    engine.add_integration("org1", _integration_data(t2["id"]))
    results = engine.list_integrations("org1", tool_id=t1["id"])
    assert len(results) == 1
    assert results[0]["tool_id"] == t1["id"]


def test_list_integrations_status_filter(engine):
    tool = engine.register_tool("org1", _tool_data())
    engine.add_integration("org1", _integration_data(tool["id"], status="active"))
    engine.add_integration("org1", _integration_data(tool["id"], status="broken"))
    results = engine.list_integrations("org1", status="broken")
    assert len(results) == 1
    assert results[0]["status"] == "broken"


def test_list_integrations_org_isolation(engine):
    tool = engine.register_tool("org1", _tool_data())
    engine.add_integration("org1", _integration_data(tool["id"]))
    assert engine.list_integrations("org2") == []


# ---------------------------------------------------------------------------
# 7. record_assessment + list_assessments
# ---------------------------------------------------------------------------

def test_record_assessment_returns_record(engine):
    tool = engine.register_tool("org1", _tool_data())
    assess = engine.record_assessment("org1", _assessment_data(tool["id"]))
    assert assess["id"]
    assert assess["coverage_score"] == 80.0


def test_record_assessment_clamps_over_100(engine):
    tool = engine.register_tool("org1", _tool_data())
    assess = engine.record_assessment(
        "org1",
        _assessment_data(tool["id"], coverage_score=150, effectiveness_score=200, utilization_pct=999),
    )
    assert assess["coverage_score"] == 100.0
    assert assess["effectiveness_score"] == 100.0
    assert assess["utilization_pct"] == 100.0


def test_record_assessment_clamps_below_0(engine):
    tool = engine.register_tool("org1", _tool_data())
    assess = engine.record_assessment(
        "org1",
        _assessment_data(tool["id"], coverage_score=-10, effectiveness_score=-5),
    )
    assert assess["coverage_score"] == 0.0
    assert assess["effectiveness_score"] == 0.0


def test_record_assessment_updates_last_assessed(engine):
    tool = engine.register_tool("org1", _tool_data())
    assert engine.get_tool("org1", tool["id"])["last_assessed"] is None
    engine.record_assessment("org1", _assessment_data(tool["id"]))
    assert engine.get_tool("org1", tool["id"])["last_assessed"] is not None


def test_list_assessments_tool_id_filter(engine):
    t1 = engine.register_tool("org1", _tool_data())
    t2 = engine.register_tool("org1", _tool_data(name="T2", tool_category="edr"))
    engine.record_assessment("org1", _assessment_data(t1["id"]))
    engine.record_assessment("org1", _assessment_data(t2["id"]))
    results = engine.list_assessments("org1", tool_id=t1["id"])
    assert len(results) == 1
    assert results[0]["tool_id"] == t1["id"]


def test_list_assessments_org_isolation(engine):
    tool = engine.register_tool("org1", _tool_data())
    engine.record_assessment("org1", _assessment_data(tool["id"]))
    assert engine.list_assessments("org2") == []


# ---------------------------------------------------------------------------
# 8. get_inventory_stats
# ---------------------------------------------------------------------------

def test_get_inventory_stats_empty_org(engine):
    stats = engine.get_inventory_stats("org1")
    assert stats["total_tools"] == 0
    assert stats["active_tools"] == 0
    assert stats["total_cost_annual"] == 0.0
    assert stats["coverage_avg"] == 0.0
    assert stats["effectiveness_avg"] == 0.0


def test_get_inventory_stats_populated_counts(engine):
    t1 = engine.register_tool("org1", _tool_data(cost_annual=5000))
    t2 = engine.register_tool("org1", _tool_data(
        name="CrowdStrike", tool_category="edr",
        status="inactive", cost_annual=3000,
    ))
    engine.record_assessment("org1", _assessment_data(t1["id"], coverage_score=80, effectiveness_score=60))

    stats = engine.get_inventory_stats("org1")
    assert stats["total_tools"] == 2
    assert stats["active_tools"] == 1
    assert stats["total_cost_annual"] == 8000.0
    assert "siem" in stats["by_category"]
    assert "edr" in stats["by_category"]
    assert stats["coverage_avg"] == 80.0
    assert stats["effectiveness_avg"] == 60.0


def test_get_inventory_stats_expiring_license(engine):
    engine.register_tool(
        "org1",
        _tool_data(license_expiry=_future(10)),
    )
    stats = engine.get_inventory_stats("org1")
    assert stats["tools_expiring_30d"] == 1


def test_get_inventory_stats_by_deployment(engine):
    engine.register_tool("org1", _tool_data(deployment_type="cloud"))
    engine.register_tool("org1", _tool_data(name="OnPrem", tool_category="edr", deployment_type="on_prem"))
    stats = engine.get_inventory_stats("org1")
    assert "cloud" in stats["by_deployment"]
    assert "on_prem" in stats["by_deployment"]
