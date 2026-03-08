"""Tests for core.analytics — AnalyticsStore persistence and ROI computations."""

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.analytics import AnalyticsStore, _validate_run_id  # noqa: E402


# ---------------------------------------------------------------------------
# _validate_run_id
# ---------------------------------------------------------------------------


class TestValidateRunId:
    def test_valid_run_id(self):
        assert _validate_run_id("run-123_abc") == "run-123_abc"
        assert _validate_run_id("simple") == "simple"
        assert _validate_run_id("UPPER") == "UPPER"
        assert _validate_run_id("a-b_c") == "a-b_c"

    def test_strips_whitespace(self):
        assert _validate_run_id("  run-1  ") == "run-1"

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            _validate_run_id("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            _validate_run_id("   ")

    def test_non_string_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            _validate_run_id(42)

    def test_special_chars_raises(self):
        with pytest.raises(ValueError, match="unsupported characters"):
            _validate_run_id("run/bad")
        with pytest.raises(ValueError, match="unsupported characters"):
            _validate_run_id("run..bad")
        with pytest.raises(ValueError, match="unsupported characters"):
            _validate_run_id("run@bad")
        with pytest.raises(ValueError, match="unsupported characters"):
            _validate_run_id("run bad")


# ---------------------------------------------------------------------------
# AnalyticsStore
# ---------------------------------------------------------------------------


class TestAnalyticsStore:
    @pytest.fixture
    def store(self, tmp_path):
        return AnalyticsStore(tmp_path)

    def test_init_creates_directory(self, tmp_path):
        base = tmp_path / "analytics"
        store = AnalyticsStore(base)
        assert store.base_directory.exists()

    def test_write_forecast(self, store):
        path = store._write_entry(
            AnalyticsStore._FORECASTS,
            "run-001",
            {"metric": "exploit_probability", "value": 0.85},
        )
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["metric"] == "exploit_probability"
        assert data["value"] == 0.85

    def test_write_exploit_snapshot(self, store):
        path = store._write_entry(
            AnalyticsStore._EXPLOIT,
            "run-002",
            {"cve": "CVE-2024-1234", "exploited": True},
        )
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["cve"] == "CVE-2024-1234"

    def test_write_ticket_metrics(self, store):
        path = store._write_entry(
            AnalyticsStore._TICKETS,
            "run-003",
            {"ticket_id": "JIRA-123", "sla_hours": 24},
        )
        assert path.exists()

    def test_write_feedback(self, store):
        path = store._write_entry(
            AnalyticsStore._FEEDBACK_EVENTS,
            "run-004",
            {"event": "false_positive_reported", "finding_id": "F-1"},
        )
        assert path.exists()

    def test_load_entries_empty(self, store):
        entries = store._load_entries(AnalyticsStore._FORECASTS)
        assert entries == []

    def test_load_entries_after_write(self, store):
        store._write_entry(
            AnalyticsStore._FORECASTS,
            "run-load",
            {"metric": "test", "value": 42},
        )
        entries = store._load_entries(AnalyticsStore._FORECASTS)
        assert len(entries) >= 1
        assert any(e.get("metric") == "test" for e in entries)

    def test_category_directory_creates_subdirs(self, store):
        directory = store._category_directory(AnalyticsStore._EXPLOIT, "run-sub")
        assert directory.exists()
        assert "exploit_snapshots" in str(directory)
        assert "run-sub" in str(directory)

    def test_invalid_run_id_in_write(self, store):
        with pytest.raises(ValueError):
            store._write_entry(AnalyticsStore._FORECASTS, "bad/id", {"data": 1})

    def test_allowlist_enforcement(self, tmp_path):
        base = tmp_path / "analytics"
        store = AnalyticsStore(base, allowlist=[tmp_path])
        # Should work — base is under tmp_path
        path = store._write_entry(
            AnalyticsStore._FORECASTS,
            "run-allowed",
            {"ok": True},
        )
        assert path.exists()

    def test_timestamp_returns_int(self, store):
        ts = store._timestamp()
        assert isinstance(ts, int)
        assert ts > 0


# ---------------------------------------------------------------------------
# Multiple entries and persistence
# ---------------------------------------------------------------------------


class TestAnalyticsStorePersistence:
    def test_multiple_writes_same_run(self, tmp_path):
        store = AnalyticsStore(tmp_path)
        for i in range(5):
            store._write_entry(
                AnalyticsStore._FORECASTS,
                "run-multi",
                {"index": i, "value": i * 10},
            )
        entries = store._load_entries(AnalyticsStore._FORECASTS)
        assert len(entries) == 5

    def test_multiple_runs(self, tmp_path):
        store = AnalyticsStore(tmp_path)
        for run_id in ["run-a", "run-b", "run-c"]:
            store._write_entry(
                AnalyticsStore._TICKETS,
                run_id,
                {"run": run_id},
            )
        entries = store._load_entries(AnalyticsStore._TICKETS)
        assert len(entries) == 3
        run_ids = {e["run"] for e in entries}
        assert run_ids == {"run-a", "run-b", "run-c"}
