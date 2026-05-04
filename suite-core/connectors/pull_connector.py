"""ALDECI Pull Connector Framework — bidirectional data integration.

Enterprise-grade pull connectors with:
- Scheduled data collection (incremental or full backfill)
- Bidirectional operations (pull data AND push enrichments back)
- SDLC stage mapping for pipeline routing
- TrustGraph Knowledge Core targeting (1-5)
- Normalized finding format conversion
- Pull cycle orchestration with cursor tracking
- Bulk operations for batch enrichment
- Status sync for pushed items

Connectors support the ALdeci CTEM+ pipeline: Steps 1-3 (data ingestion)
and Step 13 (enrichment feedback) for closed-loop threat management.
"""

from __future__ import annotations

import asyncio
import logging
from abc import abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from threading import Lock
from typing import Any, Dict, List, Mapping, Optional

from core.connectors import ConnectorOutcome, _BaseConnector

from connectors._emit import emit_connector_event

logger = logging.getLogger(__name__)


def _connector_kind_from_metadata(metadata: "ConnectorMetadata") -> str:
    """Best-effort map ConnectorMetadata.tags/sdlc_stages -> emit source_kind."""
    tag_set = {t.lower() for t in (metadata.tags or [])}
    if "secret-scanning" in tag_set or "secrets" in tag_set:
        return "secrets"
    if "container-scanning" in tag_set or "supply-chain" in tag_set:
        return "container"
    if "dast" in tag_set or "web-security" in tag_set:
        return "dast"
    if "sast" in tag_set or "code-review" in tag_set:
        return "sast"
    if "compliance" in tag_set or "governance" in tag_set:
        return "policy"
    if "siem" in tag_set or "security-events" in tag_set:
        return "siem"
    if "iam" in tag_set or "sso" in tag_set:
        return "iam"
    if "easm" in tag_set or "external-surface" in tag_set:
        return "asset"
    if "kubernetes" in tag_set or "container-orchestration" in tag_set:
        return "container"
    if "threat" in tag_set or "vulnerability" in tag_set:
        return "vuln_intel"
    return "sdlc"


# ---------------------------------------------------------------------------
# Enums and Data Classes
# ---------------------------------------------------------------------------


class SDLCStage(Enum):
    """Software Development Lifecycle stages for findings routing."""

    DESIGN = "design"
    CODE = "code"
    BUILD = "build"
    TEST = "test"
    DEPLOY = "deploy"
    OPERATE = "operate"
    GOVERN = "govern"


@dataclass
class PullSchedule:
    """Schedule configuration for periodic data pulls."""

    interval: timedelta
    """Time between pulls (e.g., timedelta(hours=1) for hourly)."""

    initial_backfill: timedelta
    """How far back to pull on first run (e.g., timedelta(days=30))."""

    incremental: bool = True
    """Whether to use incremental pulls (true) or full pulls (false)."""

    last_pulled_at: Optional[datetime] = None
    """Timestamp of last successful pull (None if never pulled)."""

    priority: int = 5
    """Priority for scheduler (1-10, higher = earlier execution)."""

    max_page_size: int = 100
    """Maximum items per page for paginated APIs."""

    def is_due(self, now: Optional[datetime] = None) -> bool:
        """Check if schedule is due for execution.

        Args:
            now: Current time (defaults to UTC now).

        Returns:
            True if due, False otherwise.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        if self.last_pulled_at is None:
            return True  # Never pulled before

        next_pull_time = self.last_pulled_at + self.interval
        return now >= next_pull_time


@dataclass
class ConnectorMetadata:
    """Metadata describing a connector's capabilities and targets."""

    name: str
    """Connector name (must be unique, e.g., 'snyk-pull', 'jira-pull')."""

    description: str
    """Human-readable description of what this connector does."""

    vendor: str
    """Vendor/platform name (e.g., 'Snyk', 'Jira', 'GitHub')."""

    sdlc_stages: List[SDLCStage]
    """SDLC stages this connector targets (e.g., [BUILD, TEST, DEPLOY])."""

    target_cores: List[int]
    """TrustGraph Knowledge Core IDs to feed (1-5)."""

    version: str
    """Connector version (e.g., '1.0.0', 'v2024.04')."""

    tags: List[str] = field(default_factory=list)
    """Tags for discovery and filtering (e.g., ['vulnerability', 'compliance'])."""

    def validate(self) -> bool:
        """Validate metadata consistency.

        Returns:
            True if valid, False otherwise.
        """
        if not self.name or not self.description or not self.vendor:
            return False
        if not self.sdlc_stages or not self.target_cores:
            return False
        if not all(1 <= core <= 5 for core in self.target_cores):
            return False
        if not self.version:
            return False
        return True


# ---------------------------------------------------------------------------
# PullConnector: Base abstract class
# ---------------------------------------------------------------------------


class PullConnector(_BaseConnector):
    """Base class for all pull-based connectors.

    A pull connector actively fetches data from a source on a schedule,
    normalizes it, and can bidirectionally push enrichments back.

    Subclasses must implement:
    - configured property
    - pull() async method
    - push_enrichment() async method
    """

    def __init__(
        self,
        settings: Mapping[str, Any],
        schedule: PullSchedule,
        metadata: ConnectorMetadata,
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        rate_limit: float = 10.0,
        circuit_breaker_threshold: int = 5,
    ) -> None:
        """Initialize a PullConnector.

        Args:
            settings: Configuration mapping (vendor-specific).
            schedule: Pull schedule configuration.
            metadata: Connector metadata (name, description, stages, cores).
            timeout: HTTP timeout in seconds.
            max_retries: Max retry attempts on 5xx errors.
            backoff_factor: Exponential backoff multiplier.
            rate_limit: Max requests per second.
            circuit_breaker_threshold: Failures before circuit opens.

        Raises:
            ValueError: If metadata is invalid.
        """
        super().__init__(
            timeout=timeout,
            max_retries=max_retries,
            backoff_factor=backoff_factor,
            rate_limit=rate_limit,
            circuit_breaker_threshold=circuit_breaker_threshold,
        )
        if not metadata.validate():
            raise ValueError(f"Invalid connector metadata: {metadata}")

        self._settings = dict(settings)
        self._schedule = schedule
        self._metadata = metadata

        # Tracking counters
        self._pull_lock = Lock()
        self._total_pulled = 0
        self._pull_errors = 0

    @property
    def metadata(self) -> ConnectorMetadata:
        """Get connector metadata."""
        return self._metadata

    @property
    def schedule(self) -> PullSchedule:
        """Get pull schedule."""
        return self._schedule

    @property
    @abstractmethod
    def configured(self) -> bool:
        """Check if connector is fully configured.

        Must be overridden by subclasses to validate required settings.

        Returns:
            True if all required settings are present and valid.
        """
        pass

    @abstractmethod
    async def pull(
        self, since: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Pull data from the source.

        This is the main data retrieval method. Subclasses must implement
        vendor-specific logic to fetch and return raw findings/events.

        Args:
            since: Pull data modified/created after this time. If None,
                   use initial_backfill or last_pulled_at as appropriate.

        Returns:
            List of raw data items (will be normalized via _normalize_finding).

        Raises:
            Exception: On connection, authentication, or API errors.
        """
        pass

    @abstractmethod
    async def push_enrichment(
        self, entity_id: str, enrichment: Dict[str, Any]
    ) -> ConnectorOutcome:
        """Push enrichment data back to the source.

        Bidirectional feedback: after findings are processed and enriched
        by the pipeline, push results back (e.g., set Jira label, update
        GitHub issue, post to Slack).

        Args:
            entity_id: Identifier of the item to enrich (e.g., issue key).
            enrichment: Dict of enrichment data (key-value pairs to update).

        Returns:
            ConnectorOutcome with status and details.
        """
        pass

    def _normalize_finding(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a raw finding to standard ALDECI format.

        Default implementation is pass-through. Subclasses override to
        normalize vendor-specific formats to common schema (title, severity,
        description, entity_id, source, timestamp, metadata).

        Args:
            raw: Raw finding/event from vendor API.

        Returns:
            Normalized finding dict.
        """
        return raw

    async def execute_pull_cycle(self) -> ConnectorOutcome:
        """Execute a complete pull cycle: fetch, normalize, track.

        This orchestrates the pull process:
        1. Check if scheduled pull is due
        2. Determine the 'since' timestamp
        3. Call pull() to fetch raw data
        4. Normalize findings via _normalize_finding()
        5. Track pull metrics
        6. Update last_pulled_at
        7. Return outcome with counts

        Returns:
            ConnectorOutcome with status and counts of pulled items.
        """
        if not self.configured:
            return ConnectorOutcome(
                "skipped",
                {
                    "reason": f"connector {self._metadata.name} not configured",
                    "count": 0,
                },
            )

        if not self._schedule.is_due():
            return ConnectorOutcome(
                "skipped",
                {
                    "reason": f"connector {self._metadata.name} not due (next pull at {self._schedule.last_pulled_at + self._schedule.interval})",
                    "count": 0,
                },
            )

        try:
            # Determine the 'since' timestamp for incremental pulls
            since = None
            if self._schedule.incremental and self._schedule.last_pulled_at:
                since = self._schedule.last_pulled_at
            elif not self._schedule.incremental:
                # Full pull: fetch all
                since = None
            else:
                # First pull (no last_pulled_at): use initial_backfill
                since = datetime.now(timezone.utc) - self._schedule.initial_backfill

            logger.info(
                "Starting pull cycle for %s (since=%s)",
                self._metadata.name,
                since.isoformat() if since else "all",
            )

            # Fetch raw data
            raw_findings = await self.pull(since=since)

            # Normalize findings
            normalized = [self._normalize_finding(f) for f in raw_findings]

            # Track metrics
            with self._pull_lock:
                self._total_pulled += len(normalized)

            # Update schedule
            self._schedule.last_pulled_at = datetime.now(timezone.utc)

            logger.info(
                "Pull cycle completed for %s: fetched %d items",
                self._metadata.name,
                len(normalized),
            )

            # TrustGraph emit — fire-and-forget, never breaks the pull cycle.
            try:
                org_id = str(self._settings.get("org_id") or self._settings.get("tenant") or "default")
                emit_connector_event(
                    connector=self._metadata.name,
                    org_id=org_id,
                    source_kind=_connector_kind_from_metadata(self._metadata),
                    finding_count=len(normalized),
                    extra={
                        "vendor": self._metadata.vendor,
                        "sdlc_stages": [s.value for s in self._metadata.sdlc_stages],
                        "version": self._metadata.version,
                        "since": since.isoformat() if since else None,
                    },
                )
            except Exception:  # pragma: no cover — defensive
                pass

            return ConnectorOutcome(
                "success",
                {
                    "connector": self._metadata.name,
                    "count": len(normalized),
                    "data": normalized,
                    "since": since.isoformat() if since else None,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            )

        except Exception as exc:
            with self._pull_lock:
                self._pull_errors += 1

            logger.error(
                "Pull cycle failed for %s: %s",
                self._metadata.name,
                type(exc).__name__,
                exc_info=True,
            )
            return ConnectorOutcome(
                "failed",
                {
                    "connector": self._metadata.name,
                    "error": str(exc),
                    "type": type(exc).__name__,
                },
            )

    def get_pull_metrics(self) -> Dict[str, Any]:
        """Get pull-specific metrics extending base metrics.

        Returns a dict with:
        - All base metrics (request_count, error_count, circuit_state, error_rate)
        - Pull-specific: last_pulled_at, total_pulled, pull_errors

        Returns:
            Dict of metric name -> value.
        """
        base_metrics = self.get_metrics()
        with self._pull_lock:
            pull_metrics = {
                "last_pulled_at": (
                    self._schedule.last_pulled_at.isoformat()
                    if self._schedule.last_pulled_at
                    else None
                ),
                "total_pulled": self._total_pulled,
                "pull_errors": self._pull_errors,
            }
        return {**base_metrics, **pull_metrics}


# ---------------------------------------------------------------------------
# BidirectionalConnector: Enhanced pull+push
# ---------------------------------------------------------------------------


class BidirectionalConnector(PullConnector):
    """Extended PullConnector with bidirectional sync operations.

    Adds:
    - Status sync: check if previously pushed item still exists
    - Bulk push: batch enrichment operations
    """

    @abstractmethod
    async def sync_status(self, entity_id: str) -> ConnectorOutcome:
        """Sync status of a previously pushed item.

        After pushing an enrichment (e.g., "status: resolved"), check
        if that item was actually updated in the source. Useful for
        validating feedback loop success.

        Args:
            entity_id: Identifier of the item to check (e.g., issue key).

        Returns:
            ConnectorOutcome with status and current item details.
        """
        pass

    async def bulk_push(
        self, items: List[Dict[str, Any]]
    ) -> List[ConnectorOutcome]:
        """Batch push enrichments.

        Push multiple enrichments in one operation. Each item should have:
        - entity_id: The identifier to update
        - enrichment: Dict of fields to update

        Args:
            items: List of dicts with entity_id and enrichment keys.

        Returns:
            List of ConnectorOutcome (one per item).
        """
        async def _push_one(item: Dict[str, Any]) -> ConnectorOutcome:
            entity_id = item.get("entity_id")
            enrichment = item.get("enrichment", {})
            if not entity_id:
                return ConnectorOutcome("failed", {"error": "missing entity_id"})
            return await self.push_enrichment(entity_id, enrichment)

        return list(await asyncio.gather(*[_push_one(item) for item in items]))
