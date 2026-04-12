"""Comprehensive test suite for ALDECI's connector framework.

Tests cover:
- PullSchedule: scheduling logic with priority ordering
- ConnectorMetadata: metadata validation and SDLC stage routing
- SDLCStage: enumeration completeness
- PullConnector: abstract base with pull cycle orchestration
- BidirectionalConnector: push + sync operations
- ConnectorRegistry: singleton connector management
- ConnectorGateway: ingestion, deduplication, and routing
"""

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from connectors.connector_registry import ConnectorGateway, ConnectorRegistry
from connectors.pull_connector import (
    BidirectionalConnector,
    ConnectorMetadata,
    PullConnector,
    PullSchedule,
    SDLCStage,
)
from core.connectors import ConnectorHealth, ConnectorOutcome

logger = logging.getLogger(__name__)


# ============================================================================
# Test PullSchedule
# ============================================================================


class TestPullSchedule:
    """Tests for PullSchedule scheduling logic."""

    def test_pull_schedule_is_due_when_never_pulled(self):
        """PullSchedule should be due when last_pulled_at is None."""
        schedule = PullSchedule(
            interval=timedelta(hours=1),
            initial_backfill=timedelta(days=30),
        )
        assert schedule.last_pulled_at is None
        assert schedule.is_due() is True

    def test_pull_schedule_is_due_after_interval(self):
        """PullSchedule should be due when interval has elapsed."""
        now = datetime.now(timezone.utc)
        last_pulled = now - timedelta(hours=2)

        schedule = PullSchedule(
            interval=timedelta(hours=1),
            initial_backfill=timedelta(days=30),
            last_pulled_at=last_pulled,
        )
        assert schedule.is_due(now=now) is True

    def test_pull_schedule_not_due_before_interval(self):
        """PullSchedule should not be due before interval has elapsed."""
        now = datetime.now(timezone.utc)
        last_pulled = now - timedelta(minutes=30)

        schedule = PullSchedule(
            interval=timedelta(hours=1),
            initial_backfill=timedelta(days=30),
            last_pulled_at=last_pulled,
        )
        assert schedule.is_due(now=now) is False

    def test_pull_schedule_priority_ordering(self):
        """Priority 1 should be higher priority (lower value) than priority 10."""
        schedule1 = PullSchedule(
            interval=timedelta(hours=1),
            initial_backfill=timedelta(days=30),
            priority=1,
        )
        schedule2 = PullSchedule(
            interval=timedelta(hours=1),
            initial_backfill=timedelta(days=30),
            priority=10,
        )
        assert schedule1.priority < schedule2.priority

    def test_pull_schedule_exact_interval_boundary(self):
        """PullSchedule should be due at exact interval boundary."""
        now = datetime.now(timezone.utc)
        last_pulled = now - timedelta(hours=1)

        schedule = PullSchedule(
            interval=timedelta(hours=1),
            initial_backfill=timedelta(days=30),
            last_pulled_at=last_pulled,
        )
        assert schedule.is_due(now=now) is True

    def test_pull_schedule_configurable_max_page_size(self):
        """PullSchedule should allow custom max_page_size."""
        schedule = PullSchedule(
            interval=timedelta(hours=1),
            initial_backfill=timedelta(days=30),
            max_page_size=500,
        )
        assert schedule.max_page_size == 500


# ============================================================================
# Test ConnectorMetadata
# ============================================================================


class TestConnectorMetadata:
    """Tests for ConnectorMetadata validation and properties."""

    def test_connector_metadata_creation(self):
        """Valid metadata should be created with all required fields."""
        metadata = ConnectorMetadata(
            name="snyk-pull",
            description="Pull vulnerabilities from Snyk",
            vendor="Snyk",
            sdlc_stages=[SDLCStage.BUILD, SDLCStage.TEST],
            target_cores=[1, 2],
            version="1.0.0",
        )
        assert metadata.name == "snyk-pull"
        assert metadata.vendor == "Snyk"
        assert SDLCStage.BUILD in metadata.sdlc_stages

    def test_connector_metadata_validation_success(self):
        """Metadata.validate() should return True for valid metadata."""
        metadata = ConnectorMetadata(
            name="jira-pull",
            description="Pull issues from Jira",
            vendor="Atlassian",
            sdlc_stages=[SDLCStage.CODE],
            target_cores=[3],
            version="2.1.0",
        )
        assert metadata.validate() is True

    def test_connector_metadata_validation_missing_name(self):
        """Metadata.validate() should return False when name is missing."""
        metadata = ConnectorMetadata(
            name="",
            description="Pull issues",
            vendor="Vendor",
            sdlc_stages=[SDLCStage.CODE],
            target_cores=[1],
            version="1.0.0",
        )
        assert metadata.validate() is False

    def test_connector_metadata_validation_invalid_core_range(self):
        """Metadata.validate() should return False for core IDs outside 1-5."""
        metadata = ConnectorMetadata(
            name="test",
            description="Test",
            vendor="Vendor",
            sdlc_stages=[SDLCStage.CODE],
            target_cores=[6],  # Invalid: must be 1-5
            version="1.0.0",
        )
        assert metadata.validate() is False

    def test_connector_metadata_sdlc_stages(self):
        """Metadata should correctly map multiple SDLC stages."""
        stages = [SDLCStage.DESIGN, SDLCStage.CODE, SDLCStage.BUILD]
        metadata = ConnectorMetadata(
            name="multi-stage",
            description="Multi-stage connector",
            vendor="Test",
            sdlc_stages=stages,
            target_cores=[1, 2, 3],
            version="1.0.0",
        )
        assert len(metadata.sdlc_stages) == 3
        assert SDLCStage.DESIGN in metadata.sdlc_stages
        assert SDLCStage.BUILD in metadata.sdlc_stages

    def test_connector_metadata_target_cores_validation(self):
        """Metadata should validate all target cores are in range 1-5."""
        metadata = ConnectorMetadata(
            name="test",
            description="Test",
            vendor="Vendor",
            sdlc_stages=[SDLCStage.TEST],
            target_cores=[1, 2, 3, 4, 5],
            version="1.0.0",
        )
        assert metadata.validate() is True

    def test_connector_metadata_with_tags(self):
        """Metadata should support optional tags for discovery."""
        metadata = ConnectorMetadata(
            name="snyk",
            description="Snyk connector",
            vendor="Snyk",
            sdlc_stages=[SDLCStage.BUILD],
            target_cores=[1],
            version="1.0.0",
            tags=["vulnerability", "sca", "oss"],
        )
        assert "vulnerability" in metadata.tags
        assert len(metadata.tags) == 3


# ============================================================================
# Test SDLCStage
# ============================================================================


class TestSDLCStage:
    """Tests for SDLCStage enumeration."""

    def test_sdlc_stages_complete(self):
        """All 7 SDLC stages should exist."""
        expected_stages = [
            SDLCStage.DESIGN,
            SDLCStage.CODE,
            SDLCStage.BUILD,
            SDLCStage.TEST,
            SDLCStage.DEPLOY,
            SDLCStage.OPERATE,
            SDLCStage.GOVERN,
        ]
        assert len(expected_stages) == 7

    def test_sdlc_stage_values(self):
        """SDLC stage values should match their names."""
        assert SDLCStage.DESIGN.value == "design"
        assert SDLCStage.CODE.value == "code"
        assert SDLCStage.BUILD.value == "build"
        assert SDLCStage.TEST.value == "test"
        assert SDLCStage.DEPLOY.value == "deploy"
        assert SDLCStage.OPERATE.value == "operate"
        assert SDLCStage.GOVERN.value == "govern"

    def test_sdlc_stage_iteration(self):
        """Should be able to iterate all SDLC stages."""
        stages = list(SDLCStage)
        assert len(stages) == 7


# ============================================================================
# Mock PullConnector Implementation
# ============================================================================


class MockPullConnector(PullConnector):
    """Mock implementation of PullConnector for testing."""

    def __init__(
        self,
        settings: Mapping[str, Any],
        schedule: PullSchedule,
        metadata: ConnectorMetadata,
        **kwargs: Any,
    ):
        super().__init__(settings, schedule, metadata, **kwargs)
        self._mock_raw_data: List[Dict[str, Any]] = []
        self._push_results: Dict[str, ConnectorOutcome] = {}

    @property
    def configured(self) -> bool:
        """Mock is configured if settings has 'api_key'."""
        return "api_key" in self._settings

    async def pull(
        self, since: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Mock pull returns predefined data."""
        return self._mock_raw_data

    async def push_enrichment(
        self, entity_id: str, enrichment: Dict[str, Any]
    ) -> ConnectorOutcome:
        """Mock push records the enrichment."""
        outcome = ConnectorOutcome("success", {"entity_id": entity_id})
        self._push_results[entity_id] = outcome
        return outcome

    def _normalize_finding(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Mock normalize adds a 'normalized' flag."""
        normalized = dict(raw)
        normalized["normalized"] = True
        return normalized


# ============================================================================
# Test PullConnector
# ============================================================================


class TestPullConnector:
    """Tests for PullConnector base class."""

    @pytest.fixture
    def mock_connector(self) -> MockPullConnector:
        """Create a configured mock connector."""
        metadata = ConnectorMetadata(
            name="test-pull",
            description="Test pull connector",
            vendor="Test",
            sdlc_stages=[SDLCStage.BUILD],
            target_cores=[1],
            version="1.0.0",
        )
        schedule = PullSchedule(
            interval=timedelta(hours=1),
            initial_backfill=timedelta(days=30),
        )
        return MockPullConnector(
            settings={"api_key": "test-key"},
            schedule=schedule,
            metadata=metadata,
        )

    def test_pull_connector_configured_true(self, mock_connector: MockPullConnector):
        """Configured property should return True when api_key is set."""
        assert mock_connector.configured is True

    def test_pull_connector_configured_false(self):
        """Configured property should return False without api_key."""
        metadata = ConnectorMetadata(
            name="test",
            description="Test",
            vendor="Test",
            sdlc_stages=[SDLCStage.CODE],
            target_cores=[1],
            version="1.0.0",
        )
        schedule = PullSchedule(
            interval=timedelta(hours=1),
            initial_backfill=timedelta(days=30),
        )
        connector = MockPullConnector(
            settings={},  # No api_key
            schedule=schedule,
            metadata=metadata,
        )
        assert connector.configured is False

    @pytest.mark.asyncio
    async def test_pull_connector_execute_cycle(
        self, mock_connector: MockPullConnector
    ):
        """Execute pull cycle should fetch, normalize, and track."""
        mock_connector._mock_raw_data = [
            {"id": "1", "title": "Finding 1"},
            {"id": "2", "title": "Finding 2"},
        ]

        outcome = await mock_connector.execute_pull_cycle()

        assert outcome.status == "success"
        assert outcome.details["count"] == 2
        assert outcome.details["connector"] == "test-pull"
        assert mock_connector._schedule.last_pulled_at is not None

    @pytest.mark.asyncio
    async def test_pull_connector_execute_cycle_normalization(
        self, mock_connector: MockPullConnector
    ):
        """Execute pull cycle should normalize findings."""
        mock_connector._mock_raw_data = [
            {"id": "1", "title": "Finding 1"},
        ]

        outcome = await mock_connector.execute_pull_cycle()

        assert outcome.details["data"][0]["normalized"] is True

    @pytest.mark.asyncio
    async def test_pull_connector_execute_cycle_not_configured(self):
        """Execute pull cycle should skip if not configured."""
        metadata = ConnectorMetadata(
            name="unconfigured",
            description="Test",
            vendor="Test",
            sdlc_stages=[SDLCStage.CODE],
            target_cores=[1],
            version="1.0.0",
        )
        schedule = PullSchedule(
            interval=timedelta(hours=1),
            initial_backfill=timedelta(days=30),
        )
        connector = MockPullConnector(
            settings={},  # Not configured
            schedule=schedule,
            metadata=metadata,
        )

        outcome = await connector.execute_pull_cycle()

        assert outcome.status == "skipped"
        assert "not configured" in outcome.details["reason"]

    @pytest.mark.asyncio
    async def test_pull_connector_execute_cycle_not_due(
        self, mock_connector: MockPullConnector
    ):
        """Execute pull cycle should skip if not due."""
        now = datetime.now(timezone.utc)
        mock_connector._schedule.last_pulled_at = now

        outcome = await mock_connector.execute_pull_cycle()

        assert outcome.status == "skipped"
        assert "not due" in outcome.details["reason"]

    @pytest.mark.asyncio
    async def test_pull_connector_metrics(
        self, mock_connector: MockPullConnector
    ):
        """Get pull metrics should return correct counts."""
        mock_connector._mock_raw_data = [
            {"id": "1", "title": "Finding 1"},
        ]

        await mock_connector.execute_pull_cycle()
        metrics = mock_connector.get_pull_metrics()

        assert metrics["total_pulled"] == 1
        assert metrics["pull_errors"] == 0
        assert metrics["last_pulled_at"] is not None

    @pytest.mark.asyncio
    async def test_pull_connector_metrics_errors(
        self, mock_connector: MockPullConnector
    ):
        """Pull metrics should track errors."""
        mock_connector._mock_raw_data = [{"id": "1"}]

        # Simulate an error
        original_pull = mock_connector.pull

        async def failing_pull(*args: Any, **kwargs: Any) -> List[Dict[str, Any]]:
            raise RuntimeError("API error")

        mock_connector.pull = failing_pull

        # First execution should fail and increment error count
        await mock_connector.execute_pull_cycle()
        metrics = mock_connector.get_pull_metrics()

        assert metrics["pull_errors"] == 1


# ============================================================================
# Mock BidirectionalConnector Implementation
# ============================================================================


class MockBidirectionalConnector(BidirectionalConnector):
    """Mock implementation of BidirectionalConnector for testing."""

    def __init__(
        self,
        settings: Mapping[str, Any],
        schedule: PullSchedule,
        metadata: ConnectorMetadata,
        **kwargs: Any,
    ):
        super().__init__(settings, schedule, metadata, **kwargs)
        self._entity_statuses: Dict[str, Dict[str, Any]] = {}

    @property
    def configured(self) -> bool:
        return "api_key" in self._settings

    async def pull(
        self, since: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        return []

    async def push_enrichment(
        self, entity_id: str, enrichment: Dict[str, Any]
    ) -> ConnectorOutcome:
        self._entity_statuses[entity_id] = enrichment
        return ConnectorOutcome("success", {"entity_id": entity_id})

    async def sync_status(self, entity_id: str) -> ConnectorOutcome:
        """Mock sync returns stored status."""
        if entity_id in self._entity_statuses:
            return ConnectorOutcome(
                "success",
                {
                    "entity_id": entity_id,
                    "status": self._entity_statuses[entity_id],
                },
            )
        return ConnectorOutcome("failed", {"error": "not found"})


# ============================================================================
# Test BidirectionalConnector
# ============================================================================


class TestBidirectionalConnector:
    """Tests for BidirectionalConnector."""

    @pytest.fixture
    def bidirectional_connector(self) -> MockBidirectionalConnector:
        """Create a mock bidirectional connector."""
        metadata = ConnectorMetadata(
            name="jira-bidirectional",
            description="Jira bidirectional connector",
            vendor="Atlassian",
            sdlc_stages=[SDLCStage.CODE],
            target_cores=[2],
            version="1.0.0",
        )
        schedule = PullSchedule(
            interval=timedelta(hours=1),
            initial_backfill=timedelta(days=30),
        )
        return MockBidirectionalConnector(
            settings={"api_key": "jira-key"},
            schedule=schedule,
            metadata=metadata,
        )

    @pytest.mark.asyncio
    async def test_bidirectional_sync_status(
        self, bidirectional_connector: MockBidirectionalConnector
    ):
        """Sync status should retrieve previously pushed status."""
        entity_id = "JIRA-123"
        enrichment = {"status": "resolved", "resolution": "DONE"}

        await bidirectional_connector.push_enrichment(entity_id, enrichment)
        outcome = await bidirectional_connector.sync_status(entity_id)

        assert outcome.status == "success"
        assert outcome.details["entity_id"] == entity_id

    @pytest.mark.asyncio
    async def test_bidirectional_sync_status_not_found(
        self, bidirectional_connector: MockBidirectionalConnector
    ):
        """Sync status should fail for non-existent entity."""
        outcome = await bidirectional_connector.sync_status("UNKNOWN-999")

        assert outcome.status == "failed"
        assert "not found" in outcome.details["error"]

    @pytest.mark.asyncio
    async def test_bidirectional_bulk_push(
        self, bidirectional_connector: MockBidirectionalConnector
    ):
        """Bulk push should process multiple enrichments."""
        items = [
            {
                "entity_id": "JIRA-1",
                "enrichment": {"status": "resolved"},
            },
            {
                "entity_id": "JIRA-2",
                "enrichment": {"status": "open"},
            },
        ]

        results = await bidirectional_connector.bulk_push(items)

        assert len(results) == 2
        assert results[0].status == "success"
        assert results[1].status == "success"

    @pytest.mark.asyncio
    async def test_bidirectional_bulk_push_missing_entity_id(
        self, bidirectional_connector: MockBidirectionalConnector
    ):
        """Bulk push should handle missing entity_id gracefully."""
        items = [
            {"enrichment": {"status": "resolved"}},  # Missing entity_id
        ]

        results = await bidirectional_connector.bulk_push(items)

        assert len(results) == 1
        assert results[0].status == "failed"
        assert "missing entity_id" in results[0].details["error"]


# ============================================================================
# Test ConnectorRegistry
# ============================================================================


class TestConnectorRegistry:
    """Tests for ConnectorRegistry singleton."""

    @pytest.fixture(autouse=True)
    def reset_registry(self) -> None:
        """Reset registry before each test."""
        ConnectorRegistry._instance = None
        yield
        ConnectorRegistry._instance = None

    @pytest.fixture
    def test_connector(self) -> MockPullConnector:
        """Create a test connector."""
        metadata = ConnectorMetadata(
            name="test-registry",
            description="Test connector",
            vendor="Test",
            sdlc_stages=[SDLCStage.BUILD],
            target_cores=[1],
            version="1.0.0",
        )
        schedule = PullSchedule(
            interval=timedelta(hours=1),
            initial_backfill=timedelta(days=30),
        )
        return MockPullConnector(
            settings={"api_key": "key"},
            schedule=schedule,
            metadata=metadata,
        )

    def test_registry_singleton(self):
        """Registry should be a singleton."""
        registry1 = ConnectorRegistry()
        registry2 = ConnectorRegistry()
        assert registry1 is registry2

    def test_registry_register_and_get(self, test_connector: MockPullConnector):
        """Should register and retrieve connector by name."""
        registry = ConnectorRegistry()
        registry.register(test_connector)

        retrieved = registry.get("test-registry")
        assert retrieved is test_connector

    def test_registry_register_duplicate(self, test_connector: MockPullConnector):
        """Registering duplicate name should raise ValueError."""
        registry = ConnectorRegistry()
        registry.register(test_connector)

        with pytest.raises(ValueError, match="already registered"):
            registry.register(test_connector)

    def test_registry_register_invalid_type(self):
        """Registering non-PullConnector should raise TypeError."""
        registry = ConnectorRegistry()

        with pytest.raises(TypeError, match="must be PullConnector"):
            registry.register("not-a-connector")  # type: ignore

    def test_registry_get_missing(self):
        """Getting non-existent connector should return None."""
        registry = ConnectorRegistry()
        assert registry.get("missing") is None

    def test_registry_unregister(self, test_connector: MockPullConnector):
        """Should unregister a connector."""
        registry = ConnectorRegistry()
        registry.register(test_connector)
        assert registry.get("test-registry") is not None

        result = registry.unregister("test-registry")
        assert result is True
        assert registry.get("test-registry") is None

    def test_registry_unregister_missing(self):
        """Unregistering non-existent connector should return False."""
        registry = ConnectorRegistry()
        result = registry.unregister("missing")
        assert result is False

    def test_registry_get_by_stage(self, test_connector: MockPullConnector):
        """Should retrieve connectors by SDLC stage."""
        registry = ConnectorRegistry()
        registry.register(test_connector)

        build_connectors = registry.get_by_stage(SDLCStage.BUILD)
        assert len(build_connectors) == 1
        assert build_connectors[0].metadata.name == "test-registry"

        test_connectors = registry.get_by_stage(SDLCStage.TEST)
        assert len(test_connectors) == 0

    def test_registry_get_by_stage_multiple_connectors(
        self, test_connector: MockPullConnector
    ):
        """Should retrieve multiple connectors with same stage."""
        registry = ConnectorRegistry()
        registry.register(test_connector)

        # Register another connector with BUILD stage
        metadata2 = ConnectorMetadata(
            name="another-build",
            description="Another",
            vendor="Test",
            sdlc_stages=[SDLCStage.BUILD],
            target_cores=[2],
            version="1.0.0",
        )
        schedule2 = PullSchedule(
            interval=timedelta(hours=2),
            initial_backfill=timedelta(days=30),
        )
        connector2 = MockPullConnector(
            settings={"api_key": "key2"},
            schedule=schedule2,
            metadata=metadata2,
        )
        registry.register(connector2)

        build_connectors = registry.get_by_stage(SDLCStage.BUILD)
        assert len(build_connectors) == 2

    def test_registry_get_by_core(self, test_connector: MockPullConnector):
        """Should retrieve connectors by TrustGraph core."""
        registry = ConnectorRegistry()
        registry.register(test_connector)

        core1_connectors = registry.get_by_core(1)
        assert len(core1_connectors) == 1

        core5_connectors = registry.get_by_core(5)
        assert len(core5_connectors) == 0

    def test_registry_get_by_core_invalid_id(self):
        """Get by core with invalid ID should raise ValueError."""
        registry = ConnectorRegistry()

        with pytest.raises(ValueError, match="must be 1-5"):
            registry.get_by_core(6)

    def test_registry_list_all(self, test_connector: MockPullConnector):
        """Should list all registered connector metadata."""
        registry = ConnectorRegistry()
        registry.register(test_connector)

        all_metadata = registry.list_all()
        assert len(all_metadata) == 1
        assert all_metadata[0].name == "test-registry"

    def test_registry_get_due_connectors(self, test_connector: MockPullConnector):
        """Should return connectors due for execution."""
        registry = ConnectorRegistry()
        registry.register(test_connector)

        due = registry.get_due_connectors()
        assert len(due) == 1
        assert due[0].metadata.name == "test-registry"

    def test_registry_get_due_connectors_not_due(
        self, test_connector: MockPullConnector
    ):
        """Should not return connectors not due."""
        registry = ConnectorRegistry()
        now = datetime.now(timezone.utc)
        test_connector._schedule.last_pulled_at = now
        registry.register(test_connector)

        due = registry.get_due_connectors(now=now)
        assert len(due) == 0

    def test_registry_health_report(self, test_connector: MockPullConnector):
        """Should return health report for all connectors."""
        registry = ConnectorRegistry()
        registry.register(test_connector)

        report = registry.get_health_report()
        assert "test-registry" in report
        assert "metrics" in report["test-registry"]


# ============================================================================
# Test ConnectorGateway
# ============================================================================


class TestConnectorGateway:
    """Tests for ConnectorGateway ingestion and routing."""

    @pytest.fixture(autouse=True)
    def reset_registry_for_gateway(self) -> None:
        """Reset registry before each gateway test."""
        ConnectorRegistry._instance = None
        yield
        ConnectorRegistry._instance = None

    @pytest.fixture
    def gateway(self) -> ConnectorGateway:
        """Create a test gateway."""
        registry = ConnectorRegistry()
        return ConnectorGateway(registry=registry)

    @pytest.mark.asyncio
    async def test_gateway_ingest_valid_findings(
        self, gateway: ConnectorGateway
    ):
        """Gateway should accept and validate findings."""
        findings = [
            {"id": "1", "title": "Finding 1", "severity": "high"},
            {"id": "2", "title": "Finding 2", "severity": "medium"},
        ]

        outcome = await gateway.ingest(
            source="snyk",
            findings=findings,
            metadata={"timestamp": "2026-04-12T10:00:00Z"},
        )

        assert outcome.status == "success"
        assert outcome.details["accepted"] == 2
        assert outcome.details["deduplicated"] == 0

    @pytest.mark.asyncio
    async def test_gateway_ingest_invalid_source(
        self, gateway: ConnectorGateway
    ):
        """Gateway should reject empty source."""
        findings = [{"id": "1"}]

        outcome = await gateway.ingest(
            source="",  # Empty source
            findings=findings,
            metadata={},
        )

        assert outcome.status == "failed"

    @pytest.mark.asyncio
    async def test_gateway_ingest_invalid_findings(
        self, gateway: ConnectorGateway
    ):
        """Gateway should reject non-list findings."""
        outcome = await gateway.ingest(
            source="snyk",
            findings="not-a-list",  # type: ignore
            metadata={},
        )

        assert outcome.status == "failed"

    @pytest.mark.asyncio
    async def test_gateway_ingest_dedup_identical_findings(
        self, gateway: ConnectorGateway
    ):
        """Gateway should deduplicate identical findings."""
        findings = [
            {"id": "1", "title": "Finding 1"},
            {"id": "1", "title": "Finding 1"},  # Duplicate
        ]

        outcome = await gateway.ingest(
            source="snyk",
            findings=findings,
            metadata={},
        )

        assert outcome.details["accepted"] == 1
        assert outcome.details["deduplicated"] == 1

    @pytest.mark.asyncio
    async def test_gateway_ingest_dedup_across_calls(
        self, gateway: ConnectorGateway
    ):
        """Gateway should deduplicate across multiple ingest calls."""
        finding = {"id": "1", "title": "Finding 1"}

        # First ingest
        outcome1 = await gateway.ingest(
            source="snyk",
            findings=[finding],
            metadata={},
        )
        assert outcome1.details["accepted"] == 1

        # Second ingest with same finding
        outcome2 = await gateway.ingest(
            source="snyk",
            findings=[finding],
            metadata={},
        )
        assert outcome2.details["accepted"] == 0
        assert outcome2.details["deduplicated"] == 1

    @pytest.mark.asyncio
    async def test_gateway_route_to_pipeline_valid_stage(
        self, gateway: ConnectorGateway
    ):
        """Gateway should route findings to valid pipeline stage."""
        findings = [{"id": "1", "title": "Finding 1"}]

        outcome = await gateway.route_to_pipeline(findings, entry_stage=1)

        assert outcome.status == "success"
        assert outcome.details["entry_stage"] == 1

    @pytest.mark.asyncio
    async def test_gateway_route_to_pipeline_invalid_stage(
        self, gateway: ConnectorGateway
    ):
        """Gateway should reject invalid pipeline stage."""
        findings = [{"id": "1"}]

        outcome = await gateway.route_to_pipeline(findings, entry_stage=16)

        assert outcome.status == "failed"
        assert "invalid entry_stage" in outcome.details["error"]

    @pytest.mark.asyncio
    async def test_gateway_route_unknown_format_json(
        self, gateway: ConnectorGateway
    ):
        """Gateway should detect and parse JSON format."""
        raw_data = json.dumps({"data": "test"}).encode("utf-8")

        outcome = await gateway.route_unknown_format(
            raw_data=raw_data,
            format_hint="application/json",
        )

        assert outcome.status == "success"
        assert outcome.details["format"] == "json"

    @pytest.mark.asyncio
    async def test_gateway_route_unknown_format_sarif(
        self, gateway: ConnectorGateway
    ):
        """Gateway should detect SARIF format."""
        sarif_data = {"version": "2.1.0", "runs": []}
        raw_data = json.dumps(sarif_data).encode("utf-8")

        outcome = await gateway.route_unknown_format(
            raw_data=raw_data,
            format_hint="application/json",
        )

        assert outcome.status == "success"
        assert outcome.details["format"] == "sarif"

    @pytest.mark.asyncio
    async def test_gateway_route_unknown_format_cyclonedx(
        self, gateway: ConnectorGateway
    ):
        """Gateway should detect CycloneDX format."""
        cyclonedx_data = {"cyclonedx": "true", "components": []}
        raw_data = json.dumps(cyclonedx_data).encode("utf-8")

        outcome = await gateway.route_unknown_format(
            raw_data=raw_data,
            format_hint="application/json",
        )

        assert outcome.status == "success"
        assert outcome.details["format"] == "cyclonedx"

    @pytest.mark.asyncio
    async def test_gateway_route_unknown_format_unsupported(
        self, gateway: ConnectorGateway
    ):
        """Gateway should fail on unsupported format."""
        raw_data = b"<xml>invalid</xml>"

        outcome = await gateway.route_unknown_format(
            raw_data=raw_data,
            format_hint="application/xml",
        )

        assert outcome.status == "failed"
        assert "unsupported format" in outcome.details["error"]

    @pytest.mark.asyncio
    async def test_gateway_route_unknown_format_invalid_json(
        self, gateway: ConnectorGateway
    ):
        """Gateway should handle invalid JSON gracefully."""
        raw_data = b"{invalid json"

        outcome = await gateway.route_unknown_format(
            raw_data=raw_data,
            format_hint="application/json",
        )

        assert outcome.status == "failed"

    def test_gateway_content_hash(self, gateway: ConnectorGateway):
        """Gateway should compute consistent content hash."""
        content = "test content"
        hash1 = gateway._content_hash(content)
        hash2 = gateway._content_hash(content)

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex digest

    def test_gateway_content_hash_different(self, gateway: ConnectorGateway):
        """Different content should produce different hashes."""
        hash1 = gateway._content_hash("content1")
        hash2 = gateway._content_hash("content2")

        assert hash1 != hash2


# ============================================================================
# Integration Tests
# ============================================================================


class TestConnectorFrameworkIntegration:
    """Integration tests for full connector framework workflow."""

    @pytest.fixture(autouse=True)
    def reset_registry_for_integration(self) -> None:
        """Reset registry before each integration test."""
        ConnectorRegistry._instance = None
        yield
        ConnectorRegistry._instance = None

    @pytest.mark.asyncio
    async def test_full_pull_workflow(self):
        """Test complete pull -> normalize -> ingest workflow."""
        # Create connector
        metadata = ConnectorMetadata(
            name="integration-test",
            description="Integration test connector",
            vendor="Test",
            sdlc_stages=[SDLCStage.BUILD, SDLCStage.TEST],
            target_cores=[1, 2],
            version="1.0.0",
        )
        schedule = PullSchedule(
            interval=timedelta(hours=1),
            initial_backfill=timedelta(days=30),
        )
        connector = MockPullConnector(
            settings={"api_key": "test"},
            schedule=schedule,
            metadata=metadata,
        )
        connector._mock_raw_data = [
            {"id": "1", "title": "Finding 1"},
        ]

        # Register connector
        registry = ConnectorRegistry()
        registry.register(connector)

        # Execute pull
        outcome = await connector.execute_pull_cycle()
        assert outcome.status == "success"

        # Verify in registry
        registered = registry.get("integration-test")
        assert registered is not None

        # Verify metrics
        metrics = registered.get_pull_metrics()
        assert metrics["total_pulled"] == 1

    @pytest.mark.asyncio
    async def test_full_push_workflow(self):
        """Test complete enrichment push workflow."""
        metadata = ConnectorMetadata(
            name="bidirectional-test",
            description="Bidirectional test",
            vendor="Test",
            sdlc_stages=[SDLCStage.CODE],
            target_cores=[3],
            version="1.0.0",
        )
        schedule = PullSchedule(
            interval=timedelta(hours=1),
            initial_backfill=timedelta(days=30),
        )
        connector = MockBidirectionalConnector(
            settings={"api_key": "test"},
            schedule=schedule,
            metadata=metadata,
        )

        # Push enrichment
        entity_id = "TEST-123"
        enrichment = {"status": "resolved", "assignee": "dev-team"}
        outcome = await connector.push_enrichment(entity_id, enrichment)
        assert outcome.status == "success"

        # Sync status
        sync_outcome = await connector.sync_status(entity_id)
        assert sync_outcome.status == "success"

    @pytest.mark.asyncio
    async def test_full_ingest_workflow(self):
        """Test complete ingest -> deduplicate -> route workflow."""
        registry = ConnectorRegistry()
        gateway = ConnectorGateway(registry=registry)

        # Ingest findings
        findings = [
            {"id": "1", "title": "Finding 1", "severity": "high"},
        ]
        ingest_outcome = await gateway.ingest(
            source="snyk",
            findings=findings,
            metadata={"ref": "main"},
        )
        assert ingest_outcome.status == "success"
        assert ingest_outcome.details["accepted"] == 1

        # Route to pipeline
        route_outcome = await gateway.route_to_pipeline(
            ingest_outcome.details["data"],
            entry_stage=1,
        )
        assert route_outcome.status == "success"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--timeout=10"])
