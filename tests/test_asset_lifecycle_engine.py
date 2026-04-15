"""
Comprehensive tests for AssetLifecycleEngine — 30+ tests.

Covers:
- register_asset: valid/invalid asset_types, lifecycle_phases, criticalities, missing name
- list_assets: filters by type/phase/criticality, org isolation
- get_asset: found, not found, org isolation
- update_lifecycle_phase: valid transition, history appended, invalid phase
- record_maintenance: valid types, missing performed_by, invalid type, org isolation
- decommission_asset: sets phase/status/timestamps, missing asset
- get_lifecycle_stats: by_phase counts, by_type, by_criticality, decommissioned_count,
  maintenance_due logic, org isolation
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")

from core.asset_lifecycle_engine import AssetLifecycleEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return AssetLifecycleEngine(db_path=str(tmp_path / "asset_lifecycle.db"))


ORG = "org-asset-test"
ORG2 = "org-asset-other"


def _asset(overrides=None):
    base = {
        "name": "Web Server",
        "asset_type": "server",
        "lifecycle_phase": "operation",
        "criticality": "high",
        "vendor": "Dell",
        "model": "PowerEdge R750",
        "serial_number": "SN-001",
        "location": "DC-East",
    }
    if overrides:
        base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# register_asset
# ---------------------------------------------------------------------------

class TestRegisterAsset:
    def test_returns_dict_with_id(self, engine):
        result = engine.register_asset(ORG, _asset())
        assert "id" in result
        assert len(result["id"]) == 36

    def test_stores_name_and_type(self, engine):
        result = engine.register_asset(ORG, _asset({"name": "Router-A", "asset_type": "network"}))
        assert result["name"] == "Router-A"
        assert result["asset_type"] == "network"

    def test_default_lifecycle_phase_is_deployment(self, engine):
        data = {"name": "App", "asset_type": "software"}
        result = engine.register_asset(ORG, data)
        assert result["lifecycle_phase"] == "deployment"

    def test_default_criticality_is_medium(self, engine):
        data = {"name": "App", "asset_type": "software"}
        result = engine.register_asset(ORG, data)
        assert result["criticality"] == "medium"

    def test_default_status_is_active(self, engine):
        result = engine.register_asset(ORG, _asset())
        assert result["status"] == "active"

    def test_lifecycle_history_starts_empty(self, engine):
        result = engine.register_asset(ORG, _asset())
        assert result["lifecycle_history"] == []

    def test_missing_name_raises(self, engine):
        with pytest.raises(ValueError, match="name"):
            engine.register_asset(ORG, {"asset_type": "server"})

    def test_empty_name_raises(self, engine):
        with pytest.raises(ValueError, match="name"):
            engine.register_asset(ORG, {"name": "  ", "asset_type": "server"})

    def test_invalid_asset_type_raises(self, engine):
        with pytest.raises(ValueError, match="asset_type"):
            engine.register_asset(ORG, {"name": "X", "asset_type": "invalid_type"})

    def test_all_valid_asset_types(self, engine):
        for atype in ("hardware", "software", "cloud", "network", "endpoint", "server", "mobile"):
            r = engine.register_asset(ORG, {"name": f"Asset-{atype}", "asset_type": atype})
            assert r["asset_type"] == atype

    def test_invalid_lifecycle_phase_raises(self, engine):
        with pytest.raises(ValueError, match="lifecycle_phase"):
            engine.register_asset(ORG, {"name": "X", "asset_type": "server", "lifecycle_phase": "retired"})

    def test_all_valid_lifecycle_phases(self, engine):
        for phase in ("planning", "procurement", "deployment", "operation", "maintenance", "decommission"):
            r = engine.register_asset(ORG, {"name": f"Asset-{phase}", "asset_type": "hardware", "lifecycle_phase": phase})
            assert r["lifecycle_phase"] == phase

    def test_invalid_criticality_raises(self, engine):
        with pytest.raises(ValueError, match="criticality"):
            engine.register_asset(ORG, {"name": "X", "asset_type": "server", "criticality": "extreme"})

    def test_all_valid_criticalities(self, engine):
        for crit in ("low", "medium", "high", "critical"):
            r = engine.register_asset(ORG, {"name": f"Asset-{crit}", "asset_type": "server", "criticality": crit})
            assert r["criticality"] == crit

    def test_org_id_stored(self, engine):
        result = engine.register_asset(ORG, _asset())
        assert result["org_id"] == ORG


# ---------------------------------------------------------------------------
# list_assets
# ---------------------------------------------------------------------------

class TestListAssets:
    def test_empty_org_returns_empty(self, engine):
        assert engine.list_assets(ORG) == []

    def test_returns_registered_assets(self, engine):
        engine.register_asset(ORG, _asset())
        engine.register_asset(ORG, _asset({"name": "B"}))
        assert len(engine.list_assets(ORG)) == 2

    def test_filter_by_asset_type(self, engine):
        engine.register_asset(ORG, _asset({"asset_type": "server"}))
        engine.register_asset(ORG, _asset({"name": "Phone", "asset_type": "mobile"}))
        results = engine.list_assets(ORG, asset_type="mobile")
        assert len(results) == 1
        assert results[0]["asset_type"] == "mobile"

    def test_filter_by_lifecycle_phase(self, engine):
        engine.register_asset(ORG, _asset({"lifecycle_phase": "operation"}))
        engine.register_asset(ORG, _asset({"name": "B", "lifecycle_phase": "planning"}))
        results = engine.list_assets(ORG, lifecycle_phase="planning")
        assert len(results) == 1
        assert results[0]["lifecycle_phase"] == "planning"

    def test_filter_by_criticality(self, engine):
        engine.register_asset(ORG, _asset({"criticality": "critical"}))
        engine.register_asset(ORG, _asset({"name": "B", "criticality": "low"}))
        results = engine.list_assets(ORG, criticality="critical")
        assert len(results) == 1
        assert results[0]["criticality"] == "critical"

    def test_org_isolation(self, engine):
        engine.register_asset(ORG, _asset())
        engine.register_asset(ORG2, _asset({"name": "Other"}))
        assert len(engine.list_assets(ORG)) == 1
        assert len(engine.list_assets(ORG2)) == 1


# ---------------------------------------------------------------------------
# get_asset
# ---------------------------------------------------------------------------

class TestGetAsset:
    def test_found_returns_asset(self, engine):
        created = engine.register_asset(ORG, _asset())
        result = engine.get_asset(ORG, created["id"])
        assert result["id"] == created["id"]
        assert result["name"] == created["name"]

    def test_not_found_returns_empty(self, engine):
        result = engine.get_asset(ORG, "nonexistent-id")
        assert result == {}

    def test_org_isolation(self, engine):
        created = engine.register_asset(ORG, _asset())
        result = engine.get_asset(ORG2, created["id"])
        assert result == {}


# ---------------------------------------------------------------------------
# update_lifecycle_phase
# ---------------------------------------------------------------------------

class TestUpdateLifecyclePhase:
    def test_updates_phase(self, engine):
        asset = engine.register_asset(ORG, _asset({"lifecycle_phase": "deployment"}))
        result = engine.update_lifecycle_phase(ORG, asset["id"], "operation")
        assert result["lifecycle_phase"] == "operation"

    def test_appends_to_history(self, engine):
        asset = engine.register_asset(ORG, _asset())
        engine.update_lifecycle_phase(ORG, asset["id"], "maintenance", notes="Scheduled")
        result = engine.get_asset(ORG, asset["id"])
        assert len(result["lifecycle_history"]) == 1
        assert result["lifecycle_history"][0]["phase"] == "maintenance"
        assert result["lifecycle_history"][0]["notes"] == "Scheduled"

    def test_multiple_transitions_accumulate(self, engine):
        asset = engine.register_asset(ORG, _asset({"lifecycle_phase": "deployment"}))
        engine.update_lifecycle_phase(ORG, asset["id"], "operation")
        engine.update_lifecycle_phase(ORG, asset["id"], "maintenance")
        result = engine.get_asset(ORG, asset["id"])
        assert len(result["lifecycle_history"]) == 2

    def test_invalid_phase_raises(self, engine):
        asset = engine.register_asset(ORG, _asset())
        with pytest.raises(ValueError, match="lifecycle_phase"):
            engine.update_lifecycle_phase(ORG, asset["id"], "retired")

    def test_missing_asset_raises(self, engine):
        with pytest.raises(ValueError):
            engine.update_lifecycle_phase(ORG, "no-such-id", "operation")

    def test_history_has_timestamp(self, engine):
        asset = engine.register_asset(ORG, _asset())
        engine.update_lifecycle_phase(ORG, asset["id"], "maintenance")
        result = engine.get_asset(ORG, asset["id"])
        assert "timestamp" in result["lifecycle_history"][0]


# ---------------------------------------------------------------------------
# record_maintenance
# ---------------------------------------------------------------------------

class TestRecordMaintenance:
    def test_returns_record_with_id(self, engine):
        asset = engine.register_asset(ORG, _asset())
        result = engine.record_maintenance(ORG, asset["id"], {
            "maintenance_type": "patch",
            "performed_by": "admin",
        })
        assert "id" in result
        assert len(result["id"]) == 36

    def test_stores_maintenance_type(self, engine):
        asset = engine.register_asset(ORG, _asset())
        for mtype in ("patch", "inspection", "repair", "upgrade", "replacement"):
            r = engine.record_maintenance(ORG, asset["id"], {
                "maintenance_type": mtype,
                "performed_by": "team",
            })
            assert r["maintenance_type"] == mtype

    def test_cost_defaults_to_zero(self, engine):
        asset = engine.register_asset(ORG, _asset())
        result = engine.record_maintenance(ORG, asset["id"], {
            "maintenance_type": "inspection",
            "performed_by": "auditor",
        })
        assert result["cost"] == 0.0

    def test_cost_stored(self, engine):
        asset = engine.register_asset(ORG, _asset())
        result = engine.record_maintenance(ORG, asset["id"], {
            "maintenance_type": "upgrade",
            "performed_by": "vendor",
            "cost": 1500.0,
        })
        assert result["cost"] == 1500.0

    def test_next_maintenance_date_stored(self, engine):
        asset = engine.register_asset(ORG, _asset())
        future = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
        result = engine.record_maintenance(ORG, asset["id"], {
            "maintenance_type": "patch",
            "performed_by": "ops",
            "next_maintenance_date": future,
        })
        assert result["next_maintenance_date"] == future

    def test_invalid_maintenance_type_raises(self, engine):
        asset = engine.register_asset(ORG, _asset())
        with pytest.raises(ValueError, match="maintenance_type"):
            engine.record_maintenance(ORG, asset["id"], {
                "maintenance_type": "random_type",
                "performed_by": "ops",
            })

    def test_missing_performed_by_raises(self, engine):
        asset = engine.register_asset(ORG, _asset())
        with pytest.raises(ValueError, match="performed_by"):
            engine.record_maintenance(ORG, asset["id"], {
                "maintenance_type": "patch",
                "performed_by": "",
            })

    def test_missing_asset_raises(self, engine):
        with pytest.raises(ValueError):
            engine.record_maintenance(ORG, "no-such-id", {
                "maintenance_type": "patch",
                "performed_by": "ops",
            })


# ---------------------------------------------------------------------------
# decommission_asset
# ---------------------------------------------------------------------------

class TestDecommissionAsset:
    def test_sets_phase_to_decommission(self, engine):
        asset = engine.register_asset(ORG, _asset())
        result = engine.decommission_asset(ORG, asset["id"], "End of life")
        assert result["lifecycle_phase"] == "decommission"

    def test_sets_status_to_decommissioned(self, engine):
        asset = engine.register_asset(ORG, _asset())
        result = engine.decommission_asset(ORG, asset["id"], "Hardware failure")
        assert result["status"] == "decommissioned"

    def test_stores_decommission_reason(self, engine):
        asset = engine.register_asset(ORG, _asset())
        result = engine.decommission_asset(ORG, asset["id"], "Budget cut")
        assert result["decommission_reason"] == "Budget cut"

    def test_sets_decommissioned_at(self, engine):
        asset = engine.register_asset(ORG, _asset())
        result = engine.decommission_asset(ORG, asset["id"], "EOL")
        assert result["decommissioned_at"] is not None

    def test_appends_to_history(self, engine):
        asset = engine.register_asset(ORG, _asset())
        result = engine.decommission_asset(ORG, asset["id"], "EOL")
        assert any(h["phase"] == "decommission" for h in result["lifecycle_history"])

    def test_missing_asset_raises(self, engine):
        with pytest.raises(ValueError):
            engine.decommission_asset(ORG, "no-such-id", "reason")


# ---------------------------------------------------------------------------
# get_lifecycle_stats
# ---------------------------------------------------------------------------

class TestGetLifecycleStats:
    def test_empty_org_returns_zeros(self, engine):
        stats = engine.get_lifecycle_stats(ORG)
        assert stats["total_assets"] == 0
        assert stats["decommissioned_count"] == 0
        assert stats["maintenance_due"] == 0

    def test_total_assets_count(self, engine):
        engine.register_asset(ORG, _asset())
        engine.register_asset(ORG, _asset({"name": "B"}))
        stats = engine.get_lifecycle_stats(ORG)
        assert stats["total_assets"] == 2

    def test_by_type_counts(self, engine):
        engine.register_asset(ORG, _asset({"asset_type": "server"}))
        engine.register_asset(ORG, _asset({"name": "B", "asset_type": "server"}))
        engine.register_asset(ORG, _asset({"name": "C", "asset_type": "cloud"}))
        stats = engine.get_lifecycle_stats(ORG)
        assert stats["by_type"]["server"] == 2
        assert stats["by_type"]["cloud"] == 1

    def test_by_phase_counts(self, engine):
        engine.register_asset(ORG, _asset({"lifecycle_phase": "operation"}))
        engine.register_asset(ORG, _asset({"name": "B", "lifecycle_phase": "planning"}))
        stats = engine.get_lifecycle_stats(ORG)
        assert stats["by_phase"]["operation"] == 1
        assert stats["by_phase"]["planning"] == 1

    def test_by_criticality_counts(self, engine):
        engine.register_asset(ORG, _asset({"criticality": "critical"}))
        engine.register_asset(ORG, _asset({"name": "B", "criticality": "critical"}))
        engine.register_asset(ORG, _asset({"name": "C", "criticality": "low"}))
        stats = engine.get_lifecycle_stats(ORG)
        assert stats["by_criticality"]["critical"] == 2
        assert stats["by_criticality"]["low"] == 1

    def test_decommissioned_count(self, engine):
        a = engine.register_asset(ORG, _asset())
        b = engine.register_asset(ORG, _asset({"name": "B"}))
        engine.decommission_asset(ORG, a["id"], "EOL")
        stats = engine.get_lifecycle_stats(ORG)
        assert stats["decommissioned_count"] == 1

    def test_maintenance_due_counts_overdue(self, engine):
        asset = engine.register_asset(ORG, _asset({"lifecycle_phase": "operation"}))
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        engine.record_maintenance(ORG, asset["id"], {
            "maintenance_type": "patch",
            "performed_by": "ops",
            "next_maintenance_date": past,
        })
        stats = engine.get_lifecycle_stats(ORG)
        assert stats["maintenance_due"] >= 1

    def test_maintenance_due_excludes_future_beyond_window(self, engine):
        asset = engine.register_asset(ORG, _asset({"lifecycle_phase": "operation"}))
        far_future = (datetime.now(timezone.utc) + timedelta(days=60)).isoformat()
        engine.record_maintenance(ORG, asset["id"], {
            "maintenance_type": "patch",
            "performed_by": "ops",
            "next_maintenance_date": far_future,
        })
        stats = engine.get_lifecycle_stats(ORG)
        assert stats["maintenance_due"] == 0

    def test_org_isolation(self, engine):
        engine.register_asset(ORG, _asset())
        engine.register_asset(ORG, _asset({"name": "B"}))
        engine.register_asset(ORG2, _asset({"name": "C"}))
        stats = engine.get_lifecycle_stats(ORG)
        stats2 = engine.get_lifecycle_stats(ORG2)
        assert stats["total_assets"] == 2
        assert stats2["total_assets"] == 1
