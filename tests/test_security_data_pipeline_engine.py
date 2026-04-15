"""Tests for SecurityDataPipelineEngine — 30+ test cases.

Covers: register pipeline, list/get/filter, run recording, counter increments,
error_count on failed runs, error_rate calculation, stats aggregation,
multi-tenant isolation, validation errors.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone

from core.security_data_pipeline_engine import SecurityDataPipelineEngine


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_sdp.db")
    return SecurityDataPipelineEngine(db_path=db)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_pipeline(engine, org_id="org1", **kwargs):
    data = {
        "name": "SIEM Ingestor",
        "source_type": "siem",
        "data_format": "json",
    }
    data.update(kwargs)
    return engine.register_pipeline(org_id, data)


def _make_run(engine, org_id, pipeline_id, run_status="completed", records_in=100, records_out=95, records_failed=5):
    return engine.record_pipeline_run(org_id, pipeline_id, {
        "run_status": run_status,
        "records_in": records_in,
        "records_out": records_out,
        "records_failed": records_failed,
        "duration_seconds": 10,
    })


# ---------------------------------------------------------------------------
# register_pipeline
# ---------------------------------------------------------------------------

class TestRegisterPipeline:
    def test_register_returns_dict_with_id(self, engine):
        p = _make_pipeline(engine)
        assert "id" in p
        assert p["status"] == "active"
        assert p["records_processed"] == 0
        assert p["error_count"] == 0

    def test_name_required(self, engine):
        with pytest.raises(ValueError, match="name"):
            engine.register_pipeline("org1", {"name": "", "source_type": "siem", "data_format": "json"})

    def test_invalid_source_type(self, engine):
        with pytest.raises(ValueError, match="source_type"):
            engine.register_pipeline("org1", {"name": "P", "source_type": "unknown"})

    def test_invalid_data_format(self, engine):
        with pytest.raises(ValueError, match="data_format"):
            engine.register_pipeline("org1", {"name": "P", "data_format": "xml"})

    def test_all_source_types_valid(self, engine):
        for st in ("siem", "edr", "ndr", "cloud", "api", "database", "file", "streaming"):
            p = engine.register_pipeline("org1", {"name": f"pipe-{st}", "source_type": st, "data_format": "json"})
            assert p["source_type"] == st

    def test_all_data_formats_valid(self, engine):
        for fmt in ("json", "cef", "leef", "syslog", "csv", "parquet", "avro"):
            p = engine.register_pipeline("org1", {"name": f"pipe-{fmt}", "source_type": "siem", "data_format": fmt})
            assert p["data_format"] == fmt

    def test_optional_fields_default(self, engine):
        p = engine.register_pipeline("org1", {"name": "Minimal"})
        assert p["source_type"] == "siem"
        assert p["data_format"] == "json"
        assert p["last_run"] is None

    def test_optional_fields_stored(self, engine):
        p = engine.register_pipeline("org1", {
            "name": "Full",
            "source_type": "edr",
            "source_endpoint": "https://edr.example.com/api",
            "data_format": "cef",
            "destination": "kafka://topic",
        })
        assert p["source_endpoint"] == "https://edr.example.com/api"
        assert p["destination"] == "kafka://topic"


# ---------------------------------------------------------------------------
# list_pipelines / get_pipeline
# ---------------------------------------------------------------------------

class TestListAndGet:
    def test_list_empty(self, engine):
        assert engine.list_pipelines("org1") == []

    def test_list_returns_all(self, engine):
        _make_pipeline(engine)
        _make_pipeline(engine, name="Second")
        assert len(engine.list_pipelines("org1")) == 2

    def test_get_returns_correct(self, engine):
        p = _make_pipeline(engine)
        fetched = engine.get_pipeline("org1", p["id"])
        assert fetched["id"] == p["id"]

    def test_get_missing_returns_none(self, engine):
        assert engine.get_pipeline("org1", "no-such-id") is None

    def test_filter_by_source_type(self, engine):
        _make_pipeline(engine, source_type="siem")
        _make_pipeline(engine, name="EDR Pipe", source_type="edr")
        assert len(engine.list_pipelines("org1", source_type="siem")) == 1
        assert len(engine.list_pipelines("org1", source_type="edr")) == 1

    def test_filter_by_status(self, engine):
        p = _make_pipeline(engine)
        engine.update_pipeline_status("org1", p["id"], "paused")
        assert len(engine.list_pipelines("org1", status="active")) == 0
        assert len(engine.list_pipelines("org1", status="paused")) == 1

    def test_multi_tenant_isolation(self, engine):
        _make_pipeline(engine, org_id="orgA")
        _make_pipeline(engine, org_id="orgB")
        assert len(engine.list_pipelines("orgA")) == 1
        assert len(engine.list_pipelines("orgB")) == 1
        orgA_id = engine.list_pipelines("orgA")[0]["id"]
        assert engine.get_pipeline("orgB", orgA_id) is None


# ---------------------------------------------------------------------------
# update_pipeline_status
# ---------------------------------------------------------------------------

class TestUpdateStatus:
    def test_valid_statuses(self, engine):
        p = _make_pipeline(engine)
        for status in ("paused", "error", "stopped", "testing", "active"):
            updated = engine.update_pipeline_status("org1", p["id"], status)
            assert updated["status"] == status

    def test_invalid_status_raises(self, engine):
        p = _make_pipeline(engine)
        with pytest.raises(ValueError, match="status"):
            engine.update_pipeline_status("org1", p["id"], "running_wild")

    def test_missing_pipeline_raises(self, engine):
        with pytest.raises(ValueError):
            engine.update_pipeline_status("org1", "no-such", "paused")


# ---------------------------------------------------------------------------
# record_pipeline_run
# ---------------------------------------------------------------------------

class TestRecordRun:
    def test_run_returns_dict_with_id(self, engine):
        p = _make_pipeline(engine)
        run = _make_run(engine, "org1", p["id"])
        assert "id" in run
        assert run["run_status"] == "completed"

    def test_invalid_run_status(self, engine):
        p = _make_pipeline(engine)
        with pytest.raises(ValueError, match="run_status"):
            engine.record_pipeline_run("org1", p["id"], {"run_status": "exploded"})

    def test_records_processed_increments_on_completed(self, engine):
        p = _make_pipeline(engine)
        _make_run(engine, "org1", p["id"], run_status="completed", records_out=50)
        _make_run(engine, "org1", p["id"], run_status="completed", records_out=30)
        updated = engine.get_pipeline("org1", p["id"])
        assert updated["records_processed"] == 80

    def test_records_processed_increments_on_failed(self, engine):
        """records_processed still counts records_out even for failed runs."""
        p = _make_pipeline(engine)
        _make_run(engine, "org1", p["id"], run_status="failed", records_out=10)
        updated = engine.get_pipeline("org1", p["id"])
        assert updated["records_processed"] == 10

    def test_error_count_increments_on_failed(self, engine):
        p = _make_pipeline(engine)
        _make_run(engine, "org1", p["id"], run_status="failed")
        _make_run(engine, "org1", p["id"], run_status="failed")
        updated = engine.get_pipeline("org1", p["id"])
        assert updated["error_count"] == 2

    def test_error_count_not_incremented_on_completed(self, engine):
        p = _make_pipeline(engine)
        _make_run(engine, "org1", p["id"], run_status="completed")
        _make_run(engine, "org1", p["id"], run_status="completed")
        updated = engine.get_pipeline("org1", p["id"])
        assert updated["error_count"] == 0

    def test_last_run_updated_after_run(self, engine):
        p = _make_pipeline(engine)
        assert p["last_run"] is None
        _make_run(engine, "org1", p["id"])
        updated = engine.get_pipeline("org1", p["id"])
        assert updated["last_run"] is not None

    def test_partial_run_status(self, engine):
        p = _make_pipeline(engine)
        run = engine.record_pipeline_run("org1", p["id"], {"run_status": "partial", "records_out": 20})
        assert run["run_status"] == "partial"

    def test_all_valid_run_statuses(self, engine):
        p = _make_pipeline(engine)
        for rs in ("queued", "running", "completed", "failed", "partial"):
            run = engine.record_pipeline_run("org1", p["id"], {"run_status": rs})
            assert run["run_status"] == rs


# ---------------------------------------------------------------------------
# list_runs
# ---------------------------------------------------------------------------

class TestListRuns:
    def test_list_runs_empty(self, engine):
        assert engine.list_runs("org1") == []

    def test_list_runs_all(self, engine):
        p = _make_pipeline(engine)
        _make_run(engine, "org1", p["id"])
        _make_run(engine, "org1", p["id"])
        assert len(engine.list_runs("org1")) == 2

    def test_filter_by_pipeline_id(self, engine):
        p1 = _make_pipeline(engine)
        p2 = _make_pipeline(engine, name="P2")
        _make_run(engine, "org1", p1["id"])
        _make_run(engine, "org1", p2["id"])
        assert len(engine.list_runs("org1", pipeline_id=p1["id"])) == 1

    def test_filter_by_run_status(self, engine):
        p = _make_pipeline(engine)
        _make_run(engine, "org1", p["id"], run_status="completed")
        _make_run(engine, "org1", p["id"], run_status="failed")
        assert len(engine.list_runs("org1", run_status="completed")) == 1
        assert len(engine.list_runs("org1", run_status="failed")) == 1

    def test_runs_org_isolated(self, engine):
        p1 = _make_pipeline(engine, org_id="orgA")
        p2 = _make_pipeline(engine, org_id="orgB")
        _make_run(engine, "orgA", p1["id"])
        assert engine.list_runs("orgB") == []


# ---------------------------------------------------------------------------
# get_pipeline_stats
# ---------------------------------------------------------------------------

class TestPipelineStats:
    def test_empty_stats(self, engine):
        stats = engine.get_pipeline_stats("org1")
        assert stats["total_pipelines"] == 0
        assert stats["active_pipelines"] == 0
        assert stats["total_records_processed"] == 0
        assert stats["error_rate"] == 0.0
        assert stats["avg_throughput"] == 0.0

    def test_total_and_active_counts(self, engine):
        p1 = _make_pipeline(engine)
        p2 = _make_pipeline(engine, name="P2")
        engine.update_pipeline_status("org1", p2["id"], "paused")
        stats = engine.get_pipeline_stats("org1")
        assert stats["total_pipelines"] == 2
        assert stats["active_pipelines"] == 1

    def test_total_records_processed(self, engine):
        p = _make_pipeline(engine)
        _make_run(engine, "org1", p["id"], records_out=100)
        _make_run(engine, "org1", p["id"], records_out=200)
        stats = engine.get_pipeline_stats("org1")
        assert stats["total_records_processed"] == 300

    def test_error_rate_calculation(self, engine):
        """3 completed + 1 failed → error_rate = 25.0"""
        p = _make_pipeline(engine)
        for _ in range(3):
            _make_run(engine, "org1", p["id"], run_status="completed")
        _make_run(engine, "org1", p["id"], run_status="failed")
        stats = engine.get_pipeline_stats("org1")
        assert stats["error_rate"] == 25.0

    def test_error_rate_zero_when_no_failures(self, engine):
        p = _make_pipeline(engine)
        _make_run(engine, "org1", p["id"], run_status="completed")
        stats = engine.get_pipeline_stats("org1")
        assert stats["error_rate"] == 0.0

    def test_avg_throughput(self, engine):
        """avg of records_out: (100 + 200) / 2 = 150"""
        p = _make_pipeline(engine)
        _make_run(engine, "org1", p["id"], records_out=100)
        _make_run(engine, "org1", p["id"], records_out=200)
        stats = engine.get_pipeline_stats("org1")
        assert stats["avg_throughput"] == 150.0

    def test_by_source_type_breakdown(self, engine):
        _make_pipeline(engine, source_type="siem")
        _make_pipeline(engine, name="P2", source_type="siem")
        _make_pipeline(engine, name="P3", source_type="edr")
        stats = engine.get_pipeline_stats("org1")
        assert stats["by_source_type"]["siem"] == 2
        assert stats["by_source_type"]["edr"] == 1

    def test_stats_org_isolated(self, engine):
        _make_pipeline(engine, org_id="orgA")
        _make_pipeline(engine, org_id="orgB")
        _make_pipeline(engine, org_id="orgB")
        statsA = engine.get_pipeline_stats("orgA")
        assert statsA["total_pipelines"] == 1

    def test_failed_runs_today_counted(self, engine):
        p = _make_pipeline(engine)
        _make_run(engine, "org1", p["id"], run_status="failed")
        stats = engine.get_pipeline_stats("org1")
        assert stats["failed_runs_today"] >= 1
