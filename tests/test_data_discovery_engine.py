"""Tests for DataDiscoveryEngine — 35+ tests covering all methods."""
from __future__ import annotations

import pytest

from core.data_discovery_engine import DataDiscoveryEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_data_discovery_engine.db")


@pytest.fixture
def engine(db_path):
    return DataDiscoveryEngine(db_path=db_path)


ORG = "org-dd-test"
ORG2 = "org-dd-other"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_datastore(engine, org=ORG, **kwargs):
    defaults = {
        "name": "prod-database",
        "datastore_type": "database",
        "location": "db.internal:5432",
        "owner_team": "platform",
        "risk_level": "none",
    }
    defaults.update(kwargs)
    return engine.register_datastore(org, defaults)


def _make_discovery(engine, datastore_id, org=ORG, **kwargs):
    defaults = {
        "data_type": "pii",
        "record_count": 100,
        "confidence": 90,
        "risk_level": "high",
    }
    defaults.update(kwargs)
    return engine.record_discovery(org, datastore_id, defaults)


# ---------------------------------------------------------------------------
# register_datastore
# ---------------------------------------------------------------------------

class TestRegisterDatastore:
    def test_register_basic(self, engine):
        ds = _make_datastore(engine)
        assert ds["id"]
        assert ds["name"] == "prod-database"
        assert ds["datastore_type"] == "database"
        assert ds["record_count"] == 0
        assert ds["sensitive_record_count"] == 0
        assert ds["last_scanned"] == ""

    def test_register_all_types(self, engine):
        for dt in ("database", "s3", "filesystem", "api", "data_lake", "message_queue", "cache"):
            ds = _make_datastore(engine, name=f"ds-{dt}", datastore_type=dt)
            assert ds["datastore_type"] == dt

    def test_register_missing_name_raises(self, engine):
        with pytest.raises(ValueError, match="name is required"):
            engine.register_datastore(ORG, {"datastore_type": "database"})

    def test_register_invalid_type_raises(self, engine):
        with pytest.raises(ValueError, match="datastore_type"):
            _make_datastore(engine, datastore_type="ftp")

    def test_register_invalid_risk_level_raises(self, engine):
        with pytest.raises(ValueError, match="risk_level"):
            _make_datastore(engine, risk_level="extreme")

    def test_register_data_types_found_as_list(self, engine):
        ds = engine.register_datastore(ORG, {
            "name": "multi-type-store",
            "datastore_type": "s3",
            "data_types_found": ["pii", "financial"],
        })
        assert "pii" in ds["data_types_found"]
        assert "financial" in ds["data_types_found"]

    def test_register_sets_org_id(self, engine):
        ds = _make_datastore(engine, org=ORG)
        assert ds["org_id"] == ORG


# ---------------------------------------------------------------------------
# list_datastores
# ---------------------------------------------------------------------------

class TestListDatastores:
    def test_list_empty(self, engine):
        assert engine.list_datastores(ORG) == []

    def test_list_org_isolation(self, engine):
        _make_datastore(engine, org=ORG)
        _make_datastore(engine, org=ORG2)
        assert len(engine.list_datastores(ORG)) == 1
        assert len(engine.list_datastores(ORG2)) == 1

    def test_filter_by_type(self, engine):
        _make_datastore(engine, name="db", datastore_type="database")
        _make_datastore(engine, name="bucket", datastore_type="s3")
        results = engine.list_datastores(ORG, datastore_type="s3")
        assert len(results) == 1
        assert results[0]["datastore_type"] == "s3"

    def test_filter_by_risk_level(self, engine):
        _make_datastore(engine, name="safe", risk_level="none")
        _make_datastore(engine, name="risky", risk_level="high")
        results = engine.list_datastores(ORG, risk_level="high")
        assert len(results) == 1

    def test_list_data_types_found_as_list(self, engine):
        engine.register_datastore(ORG, {
            "name": "tagged-store",
            "datastore_type": "database",
            "data_types_found": ["pii"],
        })
        results = engine.list_datastores(ORG)
        assert isinstance(results[0]["data_types_found"], list)


# ---------------------------------------------------------------------------
# get_datastore
# ---------------------------------------------------------------------------

class TestGetDatastore:
    def test_get_existing(self, engine):
        ds = _make_datastore(engine)
        fetched = engine.get_datastore(ORG, ds["id"])
        assert fetched is not None
        assert fetched["id"] == ds["id"]
        assert isinstance(fetched["data_types_found"], list)

    def test_get_nonexistent_returns_none(self, engine):
        assert engine.get_datastore(ORG, "no-such-id") is None

    def test_get_wrong_org_returns_none(self, engine):
        ds = _make_datastore(engine, org=ORG)
        assert engine.get_datastore(ORG2, ds["id"]) is None


# ---------------------------------------------------------------------------
# record_discovery
# ---------------------------------------------------------------------------

class TestRecordDiscovery:
    def test_record_basic(self, engine):
        ds = _make_datastore(engine)
        disc = _make_discovery(engine, ds["id"])
        assert disc["id"]
        assert disc["datastore_id"] == ds["id"]
        assert disc["data_type"] == "pii"
        assert disc["confidence"] == 90
        assert disc["is_classified"] is False

    def test_record_updates_last_scanned(self, engine):
        ds = _make_datastore(engine)
        assert engine.get_datastore(ORG, ds["id"])["last_scanned"] == ""
        _make_discovery(engine, ds["id"])
        assert engine.get_datastore(ORG, ds["id"])["last_scanned"] != ""

    def test_record_pii_increments_sensitive_count(self, engine):
        ds = _make_datastore(engine)
        _make_discovery(engine, ds["id"], data_type="pii", record_count=50)
        fetched = engine.get_datastore(ORG, ds["id"])
        assert fetched["sensitive_record_count"] == 50

    def test_record_phi_increments_sensitive_count(self, engine):
        ds = _make_datastore(engine)
        _make_discovery(engine, ds["id"], data_type="phi", record_count=30)
        assert engine.get_datastore(ORG, ds["id"])["sensitive_record_count"] == 30

    def test_record_credentials_increments_sensitive_count(self, engine):
        ds = _make_datastore(engine)
        _make_discovery(engine, ds["id"], data_type="credentials", record_count=10)
        assert engine.get_datastore(ORG, ds["id"])["sensitive_record_count"] == 10

    def test_record_public_does_not_increment_sensitive(self, engine):
        ds = _make_datastore(engine)
        _make_discovery(engine, ds["id"], data_type="public", record_count=200)
        assert engine.get_datastore(ORG, ds["id"])["sensitive_record_count"] == 0

    def test_record_escalates_risk_level(self, engine):
        ds = _make_datastore(engine, risk_level="none")
        _make_discovery(engine, ds["id"], risk_level="critical")
        assert engine.get_datastore(ORG, ds["id"])["risk_level"] == "critical"

    def test_record_does_not_downgrade_risk_level(self, engine):
        ds = _make_datastore(engine, risk_level="high")
        _make_discovery(engine, ds["id"], risk_level="low")
        assert engine.get_datastore(ORG, ds["id"])["risk_level"] == "high"

    def test_record_invalid_data_type_raises(self, engine):
        ds = _make_datastore(engine)
        with pytest.raises(ValueError, match="data_type"):
            engine.record_discovery(ORG, ds["id"], {"data_type": "unknown"})

    def test_record_invalid_risk_level_raises(self, engine):
        ds = _make_datastore(engine)
        with pytest.raises(ValueError, match="risk_level"):
            engine.record_discovery(ORG, ds["id"], {"data_type": "pii", "risk_level": "extreme"})

    def test_record_confidence_clamped(self, engine):
        ds = _make_datastore(engine)
        disc = engine.record_discovery(ORG, ds["id"], {"data_type": "pii", "confidence": 150})
        assert disc["confidence"] == 100

    def test_record_all_data_types(self, engine):
        ds = _make_datastore(engine)
        for dt in ("pii", "phi", "financial", "credentials", "ip", "confidential", "public"):
            disc = engine.record_discovery(ORG, ds["id"], {"data_type": dt})
            assert disc["data_type"] == dt


# ---------------------------------------------------------------------------
# list_discoveries
# ---------------------------------------------------------------------------

class TestListDiscoveries:
    def test_list_empty(self, engine):
        assert engine.list_discoveries(ORG) == []

    def test_list_org_isolation(self, engine):
        ds1 = _make_datastore(engine, org=ORG)
        ds2 = _make_datastore(engine, org=ORG2)
        _make_discovery(engine, ds1["id"], org=ORG)
        _make_discovery(engine, ds2["id"], org=ORG2)
        assert len(engine.list_discoveries(ORG)) == 1

    def test_filter_by_datastore_id(self, engine):
        ds1 = _make_datastore(engine, name="ds1")
        ds2 = _make_datastore(engine, name="ds2")
        _make_discovery(engine, ds1["id"])
        _make_discovery(engine, ds2["id"])
        results = engine.list_discoveries(ORG, datastore_id=ds1["id"])
        assert len(results) == 1

    def test_filter_by_data_type(self, engine):
        ds = _make_datastore(engine)
        _make_discovery(engine, ds["id"], data_type="pii")
        _make_discovery(engine, ds["id"], data_type="financial")
        results = engine.list_discoveries(ORG, data_type="financial")
        assert len(results) == 1
        assert results[0]["data_type"] == "financial"

    def test_filter_by_risk_level(self, engine):
        ds = _make_datastore(engine)
        _make_discovery(engine, ds["id"], data_type="pii", risk_level="high")
        _make_discovery(engine, ds["id"], data_type="public", risk_level="low")
        results = engine.list_discoveries(ORG, risk_level="high")
        assert len(results) == 1

    def test_is_classified_bool(self, engine):
        ds = _make_datastore(engine)
        engine.record_discovery(ORG, ds["id"], {
            "data_type": "pii", "is_classified": True
        })
        results = engine.list_discoveries(ORG)
        assert results[0]["is_classified"] is True


# ---------------------------------------------------------------------------
# create_scan_job / list_scan_jobs
# ---------------------------------------------------------------------------

class TestScanJobs:
    def test_create_scan_job(self, engine):
        ds = _make_datastore(engine)
        scan = engine.create_scan_job(ORG, ds["id"], {"scanner_version": "2.0"})
        assert scan["id"]
        assert scan["datastore_id"] == ds["id"]
        assert scan["scan_status"] == "pending"
        assert scan["scanner_version"] == "2.0"
        assert scan["completed_at"] == ""

    def test_list_scan_jobs_empty(self, engine):
        assert engine.list_scan_jobs(ORG) == []

    def test_list_scan_jobs_org_isolation(self, engine):
        ds1 = _make_datastore(engine, org=ORG)
        ds2 = _make_datastore(engine, org=ORG2)
        engine.create_scan_job(ORG, ds1["id"], {})
        engine.create_scan_job(ORG2, ds2["id"], {})
        assert len(engine.list_scan_jobs(ORG)) == 1

    def test_list_scan_jobs_filter_by_datastore(self, engine):
        ds1 = _make_datastore(engine, name="ds1")
        ds2 = _make_datastore(engine, name="ds2")
        engine.create_scan_job(ORG, ds1["id"], {})
        engine.create_scan_job(ORG, ds2["id"], {})
        results = engine.list_scan_jobs(ORG, datastore_id=ds1["id"])
        assert len(results) == 1

    def test_list_scan_jobs_filter_by_status(self, engine):
        ds = _make_datastore(engine)
        engine.create_scan_job(ORG, ds["id"], {})  # pending
        results = engine.list_scan_jobs(ORG, scan_status="pending")
        assert len(results) == 1
        results_none = engine.list_scan_jobs(ORG, scan_status="completed")
        assert len(results_none) == 0


# ---------------------------------------------------------------------------
# get_discovery_stats
# ---------------------------------------------------------------------------

class TestDiscoveryStats:
    def test_stats_empty(self, engine):
        stats = engine.get_discovery_stats(ORG)
        assert stats["total_datastores"] == 0
        assert stats["high_risk_datastores"] == 0
        assert stats["total_discoveries"] == 0
        assert stats["pii_datastores"] == 0
        assert stats["total_sensitive_records"] == 0
        assert stats["by_datastore_type"] == {}
        assert stats["by_data_type"] == {}

    def test_stats_total_datastores(self, engine):
        _make_datastore(engine, name="d1")
        _make_datastore(engine, name="d2")
        stats = engine.get_discovery_stats(ORG)
        assert stats["total_datastores"] == 2

    def test_stats_high_risk_datastores(self, engine):
        _make_datastore(engine, name="safe", risk_level="none")
        ds = _make_datastore(engine, name="risky")
        _make_discovery(engine, ds["id"], risk_level="critical")
        stats = engine.get_discovery_stats(ORG)
        assert stats["high_risk_datastores"] == 1

    def test_stats_pii_datastores(self, engine):
        ds = _make_datastore(engine)
        _make_discovery(engine, ds["id"], data_type="pii")
        stats = engine.get_discovery_stats(ORG)
        assert stats["pii_datastores"] == 1

    def test_stats_total_sensitive_records(self, engine):
        ds = _make_datastore(engine)
        _make_discovery(engine, ds["id"], data_type="pii", record_count=100)
        _make_discovery(engine, ds["id"], data_type="phi", record_count=50)
        stats = engine.get_discovery_stats(ORG)
        assert stats["total_sensitive_records"] == 150

    def test_stats_by_datastore_type(self, engine):
        _make_datastore(engine, name="db", datastore_type="database")
        _make_datastore(engine, name="bucket", datastore_type="s3")
        stats = engine.get_discovery_stats(ORG)
        assert stats["by_datastore_type"]["database"] == 1
        assert stats["by_datastore_type"]["s3"] == 1

    def test_stats_by_data_type(self, engine):
        ds = _make_datastore(engine)
        _make_discovery(engine, ds["id"], data_type="pii")
        _make_discovery(engine, ds["id"], data_type="financial")
        stats = engine.get_discovery_stats(ORG)
        assert stats["by_data_type"]["pii"] == 1
        assert stats["by_data_type"]["financial"] == 1

    def test_stats_org_isolation(self, engine):
        _make_datastore(engine, org=ORG)
        _make_datastore(engine, org=ORG2)
        stats = engine.get_discovery_stats(ORG)
        assert stats["total_datastores"] == 1
