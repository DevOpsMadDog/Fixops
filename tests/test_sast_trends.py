"""Tests for GET /api/v1/sast/trends endpoint.

Covers:
- Empty store returns zero data_points with flat summary
- Single scan returns correct data point shape
- Multiple scans sorted oldest-first with correct summary stats
- limit parameter clamps to most-recent N scans
- trend_direction calculation (increasing / decreasing / stable / flat)
- by_cwe capped at 10 entries per data point
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from threading import Lock
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Minimal stubs so the router can import without the full engine on disk
# ---------------------------------------------------------------------------

@dataclass
class _FakeSastFinding:
    rule_id: str = "SAST-001"
    title: str = "Test Finding"
    severity: Any = None
    cwe_id: str = "CWE-89"
    language: Any = None
    file_path: str = "test.py"
    line_number: int = 1
    finding_id: str = "SAST-abc123"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": "high",
            "cwe_id": self.cwe_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
        }


@dataclass
class _FakeScanResult:
    scan_id: str
    files_scanned: int
    total_findings: int
    findings: List[_FakeSastFinding]
    taint_flows: List[Dict[str, Any]]
    by_severity: Dict[str, int]
    by_cwe: Dict[str, int]
    duration_ms: float = 100.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "files_scanned": self.files_scanned,
            "total_findings": self.total_findings,
            "findings": [f.to_dict() for f in self.findings],
            "taint_flows": self.taint_flows,
            "by_severity": self.by_severity,
            "by_cwe": self.by_cwe,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp.isoformat(),
        }


class _FakeEngine:
    """Minimal SASTEngine stub with controllable _scan_store."""

    def __init__(self, scan_store: Optional[Dict[str, _FakeScanResult]] = None):
        self._lock = Lock()
        self._scan_store: Dict[str, _FakeScanResult] = scan_store or {}
        self._latest_scan_id: Optional[str] = None
        self._custom_rules: List[Any] = []

    def get_custom_rules(self) -> List[Any]:
        return []

    def get_summary(self) -> Dict[str, Any]:
        return {"status": "no_scan"}

    def get_all_findings(self, **_kw) -> List[Any]:
        return []


def _make_scan(scan_id: str, total: int, ts: datetime, by_severity: Optional[Dict] = None,
               by_cwe: Optional[Dict] = None) -> _FakeScanResult:
    return _FakeScanResult(
        scan_id=scan_id,
        files_scanned=5,
        total_findings=total,
        findings=[],
        taint_flows=[],
        by_severity=by_severity or {"high": total, "medium": 0, "low": 0, "critical": 0, "info": 0},
        by_cwe=by_cwe or {"CWE-89": total},
        duration_ms=50.0,
        timestamp=ts,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

NOW = datetime(2026, 5, 3, 12, 0, 0, tzinfo=timezone.utc)


def _build_client(scan_store: Dict[str, _FakeScanResult]) -> TestClient:
    fake_engine = _FakeEngine(scan_store)

    # Patch all engine / dependency imports before importing the router
    fake_sast_rules = [
        ("SAST-001", "SQL Injection", "high", "CWE-89", r"execute\(.*%s", "msg", "fix", ["python"])
    ]
    extra_rules: list = []

    with patch.dict("sys.modules", {
        "core.sast_engine": MagicMock(
            get_sast_engine=lambda: fake_engine,
            SAST_RULES=fake_sast_rules,
            _EXTRA_RULES=extra_rules,
            SASTEngine=MagicMock(get_supported_languages=lambda: {}),
        ),
        "core.analytics_db": MagicMock(),
        "core.analytics_models": MagicMock(),
        "core.security_findings_engine": MagicMock(),
        "core.trustgraph_event_bus": MagicMock(
            get_event_bus=lambda: None,
            EVENT_FINDING_CREATED="finding.created",
        ),
        "apps.api.dependencies": MagicMock(get_org_id=lambda: "org-test"),
    }):
        # Force reimport so patches apply
        if "apps.api.sast_router" in sys.modules:
            del sys.modules["apps.api.sast_router"]

        from apps.api.sast_router import router  # noqa: PLC0415

    app = FastAPI()
    app.include_router(router)

    # Override org_id dependency to return a fixed value
    from apps.api.dependencies import get_org_id  # type: ignore[import]  # noqa: F401

    async def _fixed_org() -> str:
        return "org-test"

    app.dependency_overrides[get_org_id] = _fixed_org
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSastTrendsEmptyStore:
    def test_empty_store_returns_zero_datapoints(self) -> None:
        client = _build_client({})
        resp = client.get("/api/v1/sast/trends", headers={"X-API-Key": "test-token"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["data_points"] == []
        assert body["total_scans"] == 0
        assert body["summary"]["trend_direction"] == "flat"
        assert body["summary"]["peak_findings"] == 0
        assert body["summary"]["peak_scan_id"] is None

    def test_empty_store_avg_findings_zero(self) -> None:
        client = _build_client({})
        body = client.get("/api/v1/sast/trends", headers={"X-API-Key": "test-token"}).json()
        assert body["summary"]["avg_findings_per_scan"] == 0


class TestSastTrendsSingleScan:
    def setup_method(self) -> None:
        scan = _make_scan("scan-001", total=7, ts=NOW)
        self.client = _build_client({"scan-001": scan})

    def test_single_scan_shape(self) -> None:
        body = self.client.get("/api/v1/sast/trends", headers={"X-API-Key": "test-token"}).json()
        assert len(body["data_points"]) == 1
        dp = body["data_points"][0]
        assert dp["scan_id"] == "scan-001"
        assert dp["total_findings"] == 7
        assert "by_severity" in dp
        assert "by_cwe" in dp
        assert "timestamp" in dp
        assert "files_scanned" in dp
        assert "duration_ms" in dp

    def test_single_scan_summary(self) -> None:
        body = self.client.get("/api/v1/sast/trends", headers={"X-API-Key": "test-token"}).json()
        assert body["summary"]["peak_findings"] == 7
        assert body["summary"]["peak_scan_id"] == "scan-001"
        assert body["summary"]["avg_findings_per_scan"] == 7.0


class TestSastTrendsMultipleScans:
    def setup_method(self) -> None:
        t0 = NOW - timedelta(hours=4)
        t1 = NOW - timedelta(hours=2)
        t2 = NOW
        store = {
            "scan-A": _make_scan("scan-A", total=3, ts=t0),
            "scan-B": _make_scan("scan-B", total=10, ts=t1),
            "scan-C": _make_scan("scan-C", total=6, ts=t2),
        }
        self.client = _build_client(store)

    def test_sorted_oldest_first(self) -> None:
        body = self.client.get("/api/v1/sast/trends", headers={"X-API-Key": "test-token"}).json()
        ids = [dp["scan_id"] for dp in body["data_points"]]
        assert ids == ["scan-A", "scan-B", "scan-C"]

    def test_total_scans_reflects_full_store(self) -> None:
        body = self.client.get("/api/v1/sast/trends", headers={"X-API-Key": "test-token"}).json()
        assert body["total_scans"] == 3

    def test_limit_returns_most_recent(self) -> None:
        body = self.client.get(
            "/api/v1/sast/trends?limit=2", headers={"X-API-Key": "test-token"}
        ).json()
        assert len(body["data_points"]) == 2
        ids = [dp["scan_id"] for dp in body["data_points"]]
        assert ids == ["scan-B", "scan-C"]

    def test_avg_findings_correct(self) -> None:
        body = self.client.get("/api/v1/sast/trends", headers={"X-API-Key": "test-token"}).json()
        # (3 + 10 + 6) / 3 = 6.33...
        assert abs(body["summary"]["avg_findings_per_scan"] - 6.33) < 0.01

    def test_peak_scan_identified(self) -> None:
        body = self.client.get("/api/v1/sast/trends", headers={"X-API-Key": "test-token"}).json()
        assert body["summary"]["peak_findings"] == 10
        assert body["summary"]["peak_scan_id"] == "scan-B"


class TestSastTrendsTrendDirection:
    def _run(self, totals: List[int]) -> str:
        store = {}
        base = NOW - timedelta(hours=len(totals))
        for i, total in enumerate(totals):
            sid = f"scan-{i}"
            ts = base + timedelta(hours=i)
            store[sid] = _make_scan(sid, total=total, ts=ts)
        client = _build_client(store)
        body = client.get("/api/v1/sast/trends", headers={"X-API-Key": "test-token"}).json()
        return body["summary"]["trend_direction"]

    def test_increasing_trend(self) -> None:
        assert self._run([1, 2, 3, 4, 10, 20]) == "increasing"

    def test_decreasing_trend(self) -> None:
        assert self._run([20, 15, 10, 3, 2, 1]) == "decreasing"

    def test_stable_trend(self) -> None:
        assert self._run([5, 5, 5, 5, 5, 5]) == "stable"


class TestSastTrendsCweCapAt10:
    def test_by_cwe_capped_at_10(self) -> None:
        big_cwe = {f"CWE-{i}": i for i in range(1, 20)}  # 19 entries
        scan = _make_scan("scan-X", total=5, ts=NOW, by_cwe=big_cwe)
        client = _build_client({"scan-X": scan})
        body = client.get("/api/v1/sast/trends", headers={"X-API-Key": "test-token"}).json()
        assert len(body["data_points"][0]["by_cwe"]) <= 10
