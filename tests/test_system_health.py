"""Tests for system health monitoring module and API router.

Tests for:
1. suite-core/core/system_health.py
   - SubsystemStatus enum
   - SubsystemHealth model
   - ResourceUsage model
   - SystemHealthReport model
   - SystemHealthMonitor: check_all, check_subsystem, get_resource_usage,
     get_uptime, record_health, get_health_history, get_degraded_subsystems,
     get_health_trend, get_warnings, subsystem checkers, _determine_overall

2. suite-api/apps/api/system_health_router.py
   - GET /api/v1/system/health
   - GET /api/v1/system/health/{subsystem}
   - GET /api/v1/system/resources
   - GET /api/v1/system/health/history
   - GET /api/v1/system/health/degraded
   - GET /api/v1/system/warnings

Usage:
    pytest tests/test_system_health.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core is importable
suite_core_path = str(Path(__file__).parent.parent / "suite-core")
if suite_core_path not in sys.path:
    sys.path.insert(0, suite_core_path)

from core.system_health import (
    ResourceUsage,
    SubsystemHealth,
    SubsystemStatus,
    SystemHealthMonitor,
    SystemHealthReport,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def monitor(tmp_path):
    """Fresh SystemHealthMonitor with a temporary DB."""
    db_path = str(tmp_path / "test_system_health.db")
    return SystemHealthMonitor(db_path=db_path)


@pytest.fixture
def sample_subsystem():
    return SubsystemHealth(
        name="pipeline",
        status=SubsystemStatus.HEALTHY,
        response_ms=12.5,
        details={"module": "core.brain_pipeline"},
    )


@pytest.fixture
def sample_resources():
    return ResourceUsage(
        disk_total_gb=100.0,
        disk_used_gb=40.0,
        disk_pct=40.0,
        memory_total_mb=8192.0,
        memory_used_mb=4096.0,
        memory_pct=50.0,
        cpu_pct=15.0,
        db_size_mb=2.5,
    )


@pytest.fixture
def sample_report(sample_resources):
    subsystems = [
        SubsystemHealth(name="pipeline", status=SubsystemStatus.HEALTHY, response_ms=10.0),
        SubsystemHealth(name="database", status=SubsystemStatus.HEALTHY, response_ms=5.0),
    ]
    return SystemHealthReport(
        overall_status=SubsystemStatus.HEALTHY,
        subsystems=subsystems,
        resources=sample_resources,
        uptime_seconds=120.0,
        warnings=[],
    )


# ============================================================================
# Model tests
# ============================================================================


class TestSubsystemStatus:
    def test_enum_values(self):
        assert SubsystemStatus.HEALTHY == "healthy"
        assert SubsystemStatus.DEGRADED == "degraded"
        assert SubsystemStatus.CRITICAL == "critical"
        assert SubsystemStatus.UNKNOWN == "unknown"

    def test_all_four_members(self):
        members = {s.value for s in SubsystemStatus}
        assert members == {"healthy", "degraded", "critical", "unknown"}


class TestSubsystemHealth:
    def test_defaults(self):
        sh = SubsystemHealth(
            name="cache",
            status=SubsystemStatus.HEALTHY,
            response_ms=3.0,
        )
        assert sh.details == {}
        assert sh.error is None
        assert sh.last_check is not None

    def test_with_error(self):
        sh = SubsystemHealth(
            name="queue",
            status=SubsystemStatus.CRITICAL,
            response_ms=0.0,
            error="Connection refused",
        )
        assert sh.error == "Connection refused"

    def test_model_dump(self, sample_subsystem):
        d = sample_subsystem.model_dump()
        assert d["name"] == "pipeline"
        assert d["status"] == "healthy"
        assert "response_ms" in d
        assert "details" in d


class TestResourceUsage:
    def test_fields(self, sample_resources):
        assert sample_resources.disk_total_gb == 100.0
        assert sample_resources.disk_pct == 40.0
        assert sample_resources.memory_pct == 50.0
        assert sample_resources.cpu_pct == 15.0
        assert sample_resources.db_size_mb == 2.5

    def test_model_dump(self, sample_resources):
        d = sample_resources.model_dump()
        assert "disk_total_gb" in d
        assert "memory_used_mb" in d
        assert "cpu_pct" in d
        assert "db_size_mb" in d


class TestSystemHealthReport:
    def test_defaults(self, sample_report):
        assert sample_report.warnings == []
        assert sample_report.uptime_seconds == 120.0
        assert len(sample_report.subsystems) == 2

    def test_model_dump(self, sample_report):
        d = sample_report.model_dump()
        assert "overall_status" in d
        assert "subsystems" in d
        assert "resources" in d
        assert "uptime_seconds" in d
        assert "checked_at" in d
        assert "warnings" in d


# ============================================================================
# SystemHealthMonitor unit tests
# ============================================================================


class TestSystemHealthMonitor:

    def test_init_creates_db(self, tmp_path):
        db_path = str(tmp_path / "init_test.db")
        monitor = SystemHealthMonitor(db_path=db_path)
        assert Path(db_path).exists()

    def test_get_uptime_increases(self, monitor):
        u1 = monitor.get_uptime()
        time.sleep(0.05)
        u2 = monitor.get_uptime()
        assert u2 > u1

    def test_get_resource_usage_returns_model(self, monitor):
        resources = monitor.get_resource_usage()
        assert isinstance(resources, ResourceUsage)
        assert resources.disk_total_gb >= 0
        assert resources.memory_total_mb >= 0
        assert 0.0 <= resources.disk_pct <= 100.0
        assert 0.0 <= resources.memory_pct <= 100.0
        assert resources.cpu_pct >= 0.0

    def test_determine_overall_all_healthy(self, monitor):
        subsystems = [
            SubsystemHealth(name="a", status=SubsystemStatus.HEALTHY, response_ms=1.0),
            SubsystemHealth(name="b", status=SubsystemStatus.HEALTHY, response_ms=2.0),
        ]
        result = monitor._determine_overall(subsystems)
        assert result == SubsystemStatus.HEALTHY

    def test_determine_overall_worst_of(self, monitor):
        subsystems = [
            SubsystemHealth(name="a", status=SubsystemStatus.HEALTHY, response_ms=1.0),
            SubsystemHealth(name="b", status=SubsystemStatus.DEGRADED, response_ms=2.0),
            SubsystemHealth(name="c", status=SubsystemStatus.CRITICAL, response_ms=3.0),
        ]
        result = monitor._determine_overall(subsystems)
        assert result == SubsystemStatus.CRITICAL

    def test_determine_overall_degraded_wins_over_unknown(self, monitor):
        subsystems = [
            SubsystemHealth(name="a", status=SubsystemStatus.UNKNOWN, response_ms=1.0),
            SubsystemHealth(name="b", status=SubsystemStatus.DEGRADED, response_ms=2.0),
        ]
        result = monitor._determine_overall(subsystems)
        assert result == SubsystemStatus.DEGRADED

    def test_determine_overall_empty(self, monitor):
        result = monitor._determine_overall([])
        assert result == SubsystemStatus.UNKNOWN

    def test_record_health_and_get_history(self, monitor, sample_report):
        monitor.record_health(sample_report)
        history = monitor.get_health_history(hours=1)
        assert len(history) >= 1
        assert history[0].overall_status == SubsystemStatus.HEALTHY

    def test_get_health_history_empty(self, monitor):
        history = monitor.get_health_history(hours=1)
        assert isinstance(history, list)

    def test_get_health_trend(self, monitor, sample_report):
        monitor.record_health(sample_report)
        trend = monitor.get_health_trend("pipeline", hours=1)
        assert isinstance(trend, list)
        if trend:
            entry = trend[0]
            assert "status" in entry
            assert "response_ms" in entry
            assert "checked_at" in entry

    def test_get_health_trend_empty_subsystem(self, monitor):
        trend = monitor.get_health_trend("nonexistent", hours=1)
        assert trend == []

    def test_get_warnings_no_issues(self, monitor):
        resources = ResourceUsage(
            disk_total_gb=100.0, disk_used_gb=30.0, disk_pct=30.0,
            memory_total_mb=8192.0, memory_used_mb=2048.0, memory_pct=25.0,
            cpu_pct=10.0, db_size_mb=1.0,
        )
        subsystems = [
            SubsystemHealth(name="a", status=SubsystemStatus.HEALTHY, response_ms=1.0),
        ]
        warnings = monitor.get_warnings(subsystems=subsystems, resources=resources)
        assert warnings == []

    def test_get_warnings_disk_high(self, monitor):
        resources = ResourceUsage(
            disk_total_gb=100.0, disk_used_gb=85.0, disk_pct=85.0,
            memory_total_mb=8192.0, memory_used_mb=2048.0, memory_pct=25.0,
            cpu_pct=10.0, db_size_mb=1.0,
        )
        warnings = monitor.get_warnings(subsystems=[], resources=resources)
        assert any("Disk" in w for w in warnings)

    def test_get_warnings_memory_high(self, monitor):
        resources = ResourceUsage(
            disk_total_gb=100.0, disk_used_gb=20.0, disk_pct=20.0,
            memory_total_mb=8192.0, memory_used_mb=7500.0, memory_pct=92.0,
            cpu_pct=10.0, db_size_mb=1.0,
        )
        warnings = monitor.get_warnings(subsystems=[], resources=resources)
        assert any("Memory" in w for w in warnings)

    def test_get_warnings_critical_subsystem(self, monitor):
        resources = ResourceUsage(
            disk_total_gb=100.0, disk_used_gb=20.0, disk_pct=20.0,
            memory_total_mb=8192.0, memory_used_mb=2048.0, memory_pct=25.0,
            cpu_pct=10.0, db_size_mb=1.0,
        )
        subsystems = [
            SubsystemHealth(
                name="queue",
                status=SubsystemStatus.CRITICAL,
                response_ms=0.0,
                error="Connection refused",
            )
        ]
        warnings = monitor.get_warnings(subsystems=subsystems, resources=resources)
        assert any("DOWN" in w or "queue" in w for w in warnings)

    def test_get_warnings_degraded_subsystem(self, monitor):
        resources = ResourceUsage(
            disk_total_gb=100.0, disk_used_gb=20.0, disk_pct=20.0,
            memory_total_mb=8192.0, memory_used_mb=2048.0, memory_pct=25.0,
            cpu_pct=10.0, db_size_mb=1.0,
        )
        subsystems = [
            SubsystemHealth(
                name="feeds",
                status=SubsystemStatus.DEGRADED,
                response_ms=50.0,
                error="Low feed count",
            )
        ]
        warnings = monitor.get_warnings(subsystems=subsystems, resources=resources)
        assert any("degraded" in w.lower() for w in warnings)


# ============================================================================
# Subsystem checker tests
# ============================================================================


class TestSubsystemCheckers:

    def test_check_pipeline_returns_health(self, monitor):
        result = monitor._check_pipeline()
        assert isinstance(result, SubsystemHealth)
        assert result.name == "pipeline"
        assert result.status in {SubsystemStatus.HEALTHY, SubsystemStatus.DEGRADED, SubsystemStatus.CRITICAL}
        assert result.response_ms >= 0

    def test_check_database_returns_health(self, monitor):
        result = monitor._check_database()
        assert isinstance(result, SubsystemHealth)
        assert result.name == "database"
        assert result.status in {SubsystemStatus.HEALTHY, SubsystemStatus.CRITICAL}
        assert result.response_ms >= 0

    def test_check_connectors_returns_health(self, monitor):
        result = monitor._check_connectors()
        assert isinstance(result, SubsystemHealth)
        assert result.name == "connectors"
        assert result.response_ms >= 0

    def test_check_feeds_returns_health(self, monitor):
        result = monitor._check_feeds()
        assert isinstance(result, SubsystemHealth)
        assert result.name == "feeds"
        assert result.response_ms >= 0

    def test_check_queue_returns_health(self, monitor):
        result = monitor._check_queue()
        assert isinstance(result, SubsystemHealth)
        assert result.name == "queue"
        assert result.response_ms >= 0
        # Queue may be degraded if Redis not running — that's fine
        assert result.status in {SubsystemStatus.HEALTHY, SubsystemStatus.DEGRADED, SubsystemStatus.CRITICAL}

    def test_check_cache_returns_health(self, monitor):
        result = monitor._check_cache()
        assert isinstance(result, SubsystemHealth)
        assert result.name == "cache"
        assert result.status in {SubsystemStatus.HEALTHY, SubsystemStatus.CRITICAL}

    def test_check_subsystem_pipeline(self, monitor):
        result = monitor.check_subsystem("pipeline")
        assert result.name == "pipeline"

    def test_check_subsystem_database(self, monitor):
        result = monitor.check_subsystem("database")
        assert result.name == "database"

    def test_check_subsystem_unknown(self, monitor):
        result = monitor.check_subsystem("nonexistent_xyz")
        assert result.status == SubsystemStatus.UNKNOWN
        assert result.error is not None

    def test_check_subsystem_case_insensitive(self, monitor):
        result = monitor.check_subsystem("PIPELINE")
        assert result.name == "pipeline"


# ============================================================================
# check_all integration test
# ============================================================================


class TestCheckAll:

    def test_check_all_returns_report(self, monitor):
        report = monitor.check_all()
        assert isinstance(report, SystemHealthReport)
        assert len(report.subsystems) == 6
        assert report.overall_status in SubsystemStatus.__members__.values()
        assert report.uptime_seconds >= 0
        assert isinstance(report.warnings, list)
        assert isinstance(report.resources, ResourceUsage)

    def test_check_all_subsystem_names(self, monitor):
        report = monitor.check_all()
        names = {s.name for s in report.subsystems}
        assert "pipeline" in names
        assert "database" in names
        assert "connectors" in names
        assert "feeds" in names
        assert "queue" in names
        assert "cache" in names

    def test_check_all_stores_history(self, monitor):
        monitor.check_all()
        history = monitor.get_health_history(hours=1)
        assert len(history) >= 1

    def test_get_degraded_subsystems_returns_list(self, monitor):
        degraded = monitor.get_degraded_subsystems()
        assert isinstance(degraded, list)
        # All non-healthy subsystems should appear
        for sub in degraded:
            assert sub.status != SubsystemStatus.HEALTHY


# ============================================================================
# Router tests (via FastAPI TestClient)
# ============================================================================


class TestSystemHealthRouter:
    """Test the FastAPI router endpoints."""

    @pytest.fixture(autouse=True)
    def setup_client(self, tmp_path, monkeypatch):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        # Import router
        sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))
        from apps.api.system_health_router import router, _get_monitor

        # Patch the singleton to use a fresh temp-DB monitor
        test_monitor = SystemHealthMonitor(db_path=str(tmp_path / "router_test.db"))

        import apps.api.system_health_router as health_router_mod
        monkeypatch.setattr(health_router_mod, "_monitor", test_monitor)

        app = FastAPI()
        app.include_router(router)
        self.client = TestClient(app)

    def test_get_health_200(self):
        resp = self.client.get("/api/v1/system/health")
        assert resp.status_code == 200
        data = resp.json()
        assert "overall_status" in data
        assert "subsystems" in data
        assert "resources" in data
        assert "uptime_seconds" in data
        assert "warnings" in data

    def test_get_health_subsystems_count(self):
        resp = self.client.get("/api/v1/system/health")
        data = resp.json()
        assert len(data["subsystems"]) == 6

    def test_get_subsystem_health_pipeline(self):
        resp = self.client.get("/api/v1/system/health/pipeline")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "pipeline"
        assert "status" in data
        assert "response_ms" in data

    def test_get_subsystem_health_database(self):
        resp = self.client.get("/api/v1/system/health/database")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "database"

    def test_get_subsystem_health_unknown_404(self):
        resp = self.client.get("/api/v1/system/health/nonexistent_xyz")
        assert resp.status_code == 404

    def test_get_resources_200(self):
        resp = self.client.get("/api/v1/system/resources")
        assert resp.status_code == 200
        data = resp.json()
        assert "disk_total_gb" in data
        assert "memory_total_mb" in data
        assert "cpu_pct" in data
        assert "db_size_mb" in data

    def test_get_history_empty(self):
        resp = self.client.get("/api/v1/system/health/history")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_get_history_after_check(self):
        # Trigger a check to populate history
        self.client.get("/api/v1/system/health")
        resp = self.client.get("/api/v1/system/health/history?hours=1")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_get_degraded_200(self):
        resp = self.client.get("/api/v1/system/health/degraded")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_get_warnings_200(self):
        resp = self.client.get("/api/v1/system/warnings")
        assert resp.status_code == 200
        data = resp.json()
        assert "warnings" in data
        assert "count" in data
        assert "overall_status" in data
        assert "checked_at" in data

    def test_get_warnings_count_matches(self):
        resp = self.client.get("/api/v1/system/warnings")
        data = resp.json()
        assert data["count"] == len(data["warnings"])

    def test_history_hours_param(self):
        resp = self.client.get("/api/v1/system/health/history?hours=48")
        assert resp.status_code == 200

    def test_all_subsystems_reachable(self):
        for subsystem in ("pipeline", "database", "connectors", "feeds", "queue", "cache"):
            resp = self.client.get(f"/api/v1/system/health/{subsystem}")
            assert resp.status_code == 200, f"Failed for subsystem: {subsystem}"
