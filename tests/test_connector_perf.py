"""Performance assertions for connector PULL/sync hot paths.

Three perf contracts verified here:
  1. bulk_push parallelism — N concurrent pushes must complete in < 2× single push time.
  2. _ensure_endpoint cache — repeated lookups for the same hostname must not call
     list_endpoints more than once per hostname (O(1) amortized, not O(N)).
  3. scan_fleet parallelism — scanning K tenants in parallel must be faster than
     K × single-tenant time (using a controlled wall-clock bound).
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import asyncio
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from connectors.pull_connector import (
    BidirectionalConnector,
    ConnectorMetadata,
    ConnectorOutcome,
    PullSchedule,
    SDLCStage,
)
from datetime import timedelta


# ---------------------------------------------------------------------------
# Helpers / stubs
# ---------------------------------------------------------------------------

def _make_metadata(name: str = "perf-test") -> ConnectorMetadata:
    return ConnectorMetadata(
        name=name,
        description="Perf test connector",
        vendor="PerfVendor",
        sdlc_stages=[SDLCStage.CODE],
        target_cores=[1],
        version="1.0.0",
    )


def _make_schedule() -> PullSchedule:
    return PullSchedule(
        interval=timedelta(hours=1),
        initial_backfill=timedelta(days=7),
    )


class _SlowPushConnector(BidirectionalConnector):
    """Stub connector whose push_enrichment sleeps for a fixed delay."""

    def __init__(self, push_delay: float = 0.05):
        super().__init__(
            settings={"org_id": "perf-org"},
            schedule=_make_schedule(),
            metadata=_make_metadata("slow-push"),
        )
        self._push_delay = push_delay

    @property
    def configured(self) -> bool:
        return True

    async def pull(self, since=None):
        return []

    async def push_enrichment(self, entity_id: str, enrichment: Dict[str, Any]) -> ConnectorOutcome:
        await asyncio.sleep(self._push_delay)
        return ConnectorOutcome("success", {"entity_id": entity_id})

    async def sync_status(self, entity_id: str) -> ConnectorOutcome:
        return ConnectorOutcome("success", {"entity_id": entity_id})


# ---------------------------------------------------------------------------
# Test 1: bulk_push parallelism
# ---------------------------------------------------------------------------

class TestBulkPushParallelism:
    """bulk_push must run pushes concurrently, not sequentially."""

    @pytest.mark.asyncio
    async def test_bulk_push_is_parallel(self):
        """10 pushes each sleeping 50 ms should finish in < 5× single push time.

        Sequential execution would take ~500 ms. Parallel should take ~50-100 ms.
        The assertion allows up to 5× single-push time (250 ms) to stay robust
        on slow CI, while still catching the O(N) sequential regression.
        """
        PUSH_DELAY = 0.05   # 50 ms per push
        N = 10
        connector = _SlowPushConnector(push_delay=PUSH_DELAY)
        items = [{"entity_id": f"ent-{i}", "enrichment": {"k": i}} for i in range(N)]

        t0 = time.monotonic()
        outcomes = await connector.bulk_push(items)
        elapsed = time.monotonic() - t0

        assert len(outcomes) == N
        assert all(o.status == "success" for o in outcomes)

        sequential_time = PUSH_DELAY * N           # ~500 ms
        max_allowed = PUSH_DELAY * 5              # 250 ms — generous for CI
        assert elapsed < max_allowed, (
            f"bulk_push took {elapsed:.3f}s for {N} items "
            f"(sequential would be {sequential_time:.3f}s, max allowed {max_allowed:.3f}s). "
            "Likely regression to sequential execution."
        )

    @pytest.mark.asyncio
    async def test_bulk_push_missing_entity_id_handled(self):
        """Items without entity_id must return failed outcome without crashing."""
        connector = _SlowPushConnector(push_delay=0.001)
        items = [
            {"entity_id": "good-1", "enrichment": {}},
            {"enrichment": {}},  # missing entity_id
            {"entity_id": "good-2", "enrichment": {}},
        ]
        outcomes = await connector.bulk_push(items)
        assert len(outcomes) == 3
        assert outcomes[0].status == "success"
        assert outcomes[1].status == "failed"
        assert outcomes[2].status == "success"

    @pytest.mark.asyncio
    async def test_bulk_push_empty_list(self):
        """Empty item list must return empty results immediately."""
        connector = _SlowPushConnector(push_delay=0.1)
        t0 = time.monotonic()
        outcomes = await connector.bulk_push([])
        elapsed = time.monotonic() - t0
        assert outcomes == []
        assert elapsed < 0.05, "Empty bulk_push should return instantly"


# ---------------------------------------------------------------------------
# Test 2: _ensure_endpoint cache (O(1) amortized)
# ---------------------------------------------------------------------------

class TestEnsureEndpointCache:
    """_ensure_endpoint must not call list_endpoints more than once per hostname."""

    def _make_connector(self, existing_hostnames: List[str]):
        """Return a CrowdStrikeFalconConnector with a mocked EDR engine."""
        from connectors.crowdstrike_falcon_connector import CrowdStrikeFalconConnector

        edr = MagicMock()
        # list_endpoints returns a fixed list — we count how many times it's called.
        edr.list_endpoints.return_value = [
            {"hostname": h, "endpoint_id": f"ep-{h}"} for h in existing_hostnames
        ]
        edr.register_endpoint.return_value = {"endpoint_id": "ep-new"}
        return CrowdStrikeFalconConnector(edr_engine=edr), edr

    def test_same_hostname_calls_list_endpoints_once(self):
        """When the same hostname appears in 5 detections, list_endpoints called once."""
        from connectors.crowdstrike_falcon_connector import (
            FALCON_SAMPLE_DETECTIONS,
            CrowdStrikeFalconConnector,
        )

        # Build a dump where every event has the same hostname
        hostname = "WIN-REPEATED-001"
        events = []
        for i in range(5):
            ev = {
                "metadata": {"eventCreationTime": 1798875600000 + i},
                "event": {
                    "DetectId": f"ldt:test:ev-repeated-{i:03d}",
                    "DetectDescription": "Test repeated hostname",
                    "Severity": 80,
                    "ComputerName": hostname,
                    "Technique": "PowerShell",
                    "Tactic": "Execution",
                },
            }
            events.append(ev)

        connector, edr_mock = self._make_connector([hostname])
        connector.ingest_falcon_dump(events, org_id="test-org")

        # list_endpoints must have been called exactly once despite 5 events
        # sharing the same hostname (cache hit for events 2-5).
        assert edr_mock.list_endpoints.call_count == 1, (
            f"list_endpoints called {edr_mock.list_endpoints.call_count}× "
            "for 5 events with the same hostname — cache not working."
        )

    def test_different_hostnames_each_call_list_endpoints_once(self):
        """K distinct hostnames → list_endpoints called K times (one miss per hostname)."""
        hostnames = [f"WIN-HOST-{i:03d}" for i in range(4)]
        events = []
        for i, h in enumerate(hostnames):
            events.append({
                "metadata": {"eventCreationTime": 1798875600000 + i},
                "event": {
                    "DetectId": f"ldt:test:ev-{i:03d}",
                    "DetectDescription": "Test distinct hostnames",
                    "Severity": 70,
                    "ComputerName": h,
                    "Technique": "PowerShell",
                    "Tactic": "Execution",
                },
            })

        connector, edr_mock = self._make_connector(hostnames)
        connector.ingest_falcon_dump(events, org_id="test-org")

        assert edr_mock.list_endpoints.call_count == len(hostnames), (
            f"Expected {len(hostnames)} list_endpoints calls for {len(hostnames)} "
            f"distinct hostnames, got {edr_mock.list_endpoints.call_count}."
        )


# ---------------------------------------------------------------------------
# Test 3: scan_fleet parallelism
# ---------------------------------------------------------------------------

class TestScanFleetParallelism:
    """scan_fleet must scan tenants in parallel, not sequentially."""

    def test_scan_fleet_parallel_faster_than_sequential(self, tmp_path: Path):
        """Scanning 4 tenants in parallel must finish in < 3× single-tenant time.

        Each tenant scan is stubbed to sleep 50 ms. Sequential = 200 ms.
        Parallel with 4 workers should be ~50-80 ms.
        """
        from connectors.snyk_oss_connector import SnykOSSConnector, TenantScanResult

        TENANT_DELAY = 0.05   # 50 ms per tenant
        N_TENANTS = 4

        # Create N_TENANTS directories under tmp_path
        fleet_root = tmp_path / "fleet"
        fleet_root.mkdir()
        for i in range(N_TENANTS):
            (fleet_root / f"tenant-{i}").mkdir()

        connector = SnykOSSConnector(fleet_root=fleet_root)

        call_count = {"n": 0}

        def _slow_scan_tenant(tenant_path, org_id="default"):
            call_count["n"] += 1
            time.sleep(TENANT_DELAY)
            return TenantScanResult(tenant=tenant_path.name, repo_path=str(tenant_path))

        with patch.object(connector, "scan_tenant", side_effect=_slow_scan_tenant):
            t0 = time.monotonic()
            result = connector.scan_fleet(org_id="perf-org", max_workers=N_TENANTS)
            elapsed = time.monotonic() - t0

        assert result["tenants_scanned"] == N_TENANTS
        assert call_count["n"] == N_TENANTS

        sequential_time = TENANT_DELAY * N_TENANTS   # 200 ms
        max_allowed = TENANT_DELAY * 3               # 150 ms — generous CI bound
        assert elapsed < max_allowed, (
            f"scan_fleet took {elapsed:.3f}s for {N_TENANTS} tenants "
            f"(sequential would be {sequential_time:.3f}s, max allowed {max_allowed:.3f}s). "
            "Likely regression to sequential execution."
        )

    def test_scan_fleet_empty_fleet(self, tmp_path: Path):
        """scan_fleet with no tenants returns empty results immediately."""
        from connectors.snyk_oss_connector import SnykOSSConnector

        fleet_root = tmp_path / "empty_fleet"
        fleet_root.mkdir()
        connector = SnykOSSConnector(fleet_root=fleet_root)

        result = connector.scan_fleet()
        assert result["tenants_scanned"] == 0
        assert result["total_findings_recorded"] == 0
        assert result["tenants"] == []

    def test_scan_fleet_tenant_failure_doesnt_abort_others(self, tmp_path: Path):
        """If one tenant raises, other tenants still complete."""
        from connectors.snyk_oss_connector import SnykOSSConnector, TenantScanResult

        fleet_root = tmp_path / "fleet_with_failure"
        fleet_root.mkdir()
        (fleet_root / "good-tenant").mkdir()
        (fleet_root / "bad-tenant").mkdir()

        connector = SnykOSSConnector(fleet_root=fleet_root)

        def _maybe_fail(tenant_path, org_id="default"):
            if tenant_path.name == "bad-tenant":
                raise RuntimeError("simulated scan failure")
            return TenantScanResult(tenant=tenant_path.name, repo_path=str(tenant_path))

        with patch.object(connector, "scan_tenant", side_effect=_maybe_fail):
            result = connector.scan_fleet()

        # Both tenants accounted for (one as error result)
        assert result["tenants_scanned"] == 2
