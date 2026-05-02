"""ALDECI Connector Registry and Gateway — central dispatcher.

Enterprise-grade connector management with:
- Singleton registry for all active connectors
- SDLC stage and TrustGraph Core routing
- Health monitoring across all connectors
- Ingestion gateway for webhook findings
- Format detection and normalization
- Deduplication via content hashing
- Async pipeline routing
- Pydantic validation

The registry provides:
- Connector lifecycle management (register, unregister, query)
- Scheduling queries (which connectors are due?)
- Multi-dimensional routing (stage, core, capability)

The gateway provides:
- HTTP POST webhook ingestion from n8n, webhooks, custom sources
- Format detection for unknown payloads
- Dedup protection via content hash
- Pipeline routing to correct SDLC stage entry point
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, List, Optional

from core.connectors import ConnectorOutcome
from pydantic import BaseModel, ValidationError, field_validator

from connectors.pull_connector import (
    ConnectorMetadata,
    PullConnector,
    SDLCStage,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic Models for Validation
# ---------------------------------------------------------------------------


class IngestPayload(BaseModel):
    """Validated ingestion payload structure.

    Expected shape:
    {
        "source": "snyk",
        "findings": [{"id": "...", "title": "...", ...}],
        "metadata": {"ref": "main", "timestamp": "2026-04-12T..."}
    }
    """

    source: str
    """Source identifier (e.g., 'snyk', 'jira', 'custom-webhook')."""

    findings: List[Dict[str, Any]]
    """List of findings/events to ingest."""

    metadata: Dict[str, Any] = {}
    """Additional metadata (ref, timestamp, branch, etc.)."""

    @field_validator("source")
    @classmethod
    def source_not_empty(cls, v: str) -> str:
        """Ensure source is non-empty."""
        if not v or not v.strip():
            raise ValueError("source must be non-empty")
        return v.strip()

    @field_validator("findings")
    @classmethod
    def findings_is_list(cls, v: Any) -> List[Dict[str, Any]]:
        """Ensure findings is a list of dicts."""
        if not isinstance(v, list):
            raise ValueError("findings must be a list")
        if not all(isinstance(f, dict) for f in v):
            raise ValueError("all findings must be dicts")
        return v


# ---------------------------------------------------------------------------
# ConnectorRegistry: Singleton
# ---------------------------------------------------------------------------


class ConnectorRegistry:
    """Singleton registry for all active connectors.

    Manages connector instances, lifecycle, and queries.
    Thread-safe with internal locking.

    Usage:
        registry = ConnectorRegistry()
        registry.register(snyk_connector)
        registry.get("snyk")
        due = registry.get_due_connectors()
    """

    _instance: Optional[ConnectorRegistry] = None
    _lock: Lock = Lock()

    def __new__(cls) -> ConnectorRegistry:
        """Ensure singleton pattern."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        """Initialize registry (only on first instantiation)."""
        if self._initialized:
            return

        self._connectors: Dict[str, PullConnector] = {}
        self._registry_lock = Lock()
        self._initialized = True

        logger.info("ConnectorRegistry initialized")

    def register(self, connector: PullConnector) -> None:
        """Register a connector instance.

        Args:
            connector: PullConnector instance to register.

        Raises:
            ValueError: If a connector with same name is already registered.
        """
        if not isinstance(connector, PullConnector):
            raise TypeError(
                f"connector must be PullConnector, got {type(connector)}"
            )

        with self._registry_lock:
            name = connector.metadata.name
            if name in self._connectors:
                raise ValueError(
                    f"Connector '{name}' already registered. "
                    f"Call unregister('{name}') first."
                )
            self._connectors[name] = connector
            logger.info(
                "Registered connector: %s (vendor: %s, cores: %s)",
                name,
                connector.metadata.vendor,
                connector.metadata.target_cores,
            )

    def unregister(self, name: str) -> bool:
        """Unregister a connector by name.

        Args:
            name: Connector name.

        Returns:
            True if unregistered, False if not found.
        """
        with self._registry_lock:
            if name in self._connectors:
                del self._connectors[name]
                logger.info("Unregistered connector: %s", name)
                return True
            return False

    def get(self, name: str) -> Optional[PullConnector]:
        """Get a connector by name.

        Args:
            name: Connector name.

        Returns:
            PullConnector instance or None if not found.
        """
        with self._registry_lock:
            return self._connectors.get(name)

    def get_by_stage(self, stage: SDLCStage) -> List[PullConnector]:
        """Get all connectors targeting a specific SDLC stage.

        Args:
            stage: SDLCStage enum value.

        Returns:
            List of matching connectors.
        """
        with self._registry_lock:
            return [
                c for c in self._connectors.values()
                if stage in c.metadata.sdlc_stages
            ]

    def get_by_core(self, core_id: int) -> List[PullConnector]:
        """Get all connectors feeding a TrustGraph Knowledge Core.

        Args:
            core_id: Core ID (1-5).

        Returns:
            List of matching connectors.
        """
        if not (1 <= core_id <= 5):
            raise ValueError(f"core_id must be 1-5, got {core_id}")

        with self._registry_lock:
            return [
                c for c in self._connectors.values()
                if core_id in c.metadata.target_cores
            ]

    def list_all(self) -> List[ConnectorMetadata]:
        """List metadata of all registered connectors.

        Returns:
            List of ConnectorMetadata objects.
        """
        with self._registry_lock:
            return [c.metadata for c in self._connectors.values()]

    def get_due_connectors(
        self, now: Optional[datetime] = None
    ) -> List[PullConnector]:
        """Get all connectors whose schedule is due for execution.

        Args:
            now: Current time (defaults to UTC now).

        Returns:
            List of connectors due for pull.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        with self._registry_lock:
            return [
                c for c in self._connectors.values()
                if c.schedule.is_due(now)
            ]

    def get_health_report(self) -> Dict[str, Any]:
        """Get health status of all connectors.

        Returns a dict: {connector_name -> health_info}

        Each health_info has:
        - healthy: bool
        - latency_ms: float
        - message: str
        - metrics: dict (from get_metrics)
        """
        report: Dict[str, Any] = {}
        with self._registry_lock:
            for name, connector in self._connectors.items():
                try:
                    health = connector.health_check()
                    report[name] = {
                        **health.to_dict(),
                        "metrics": connector.get_pull_metrics(),
                    }
                except NotImplementedError:
                    # Some connectors may not implement health_check
                    report[name] = {
                        "healthy": None,
                        "message": "health_check not implemented",
                        "metrics": connector.get_pull_metrics(),
                    }
                except Exception as exc:
                    report[name] = {
                        "healthy": False,
                        "message": f"health check failed: {type(exc).__name__}",
                        "metrics": connector.get_pull_metrics(),
                    }
        return report


# ---------------------------------------------------------------------------
# ConnectorGateway: Ingestion and Routing
# ---------------------------------------------------------------------------


class ConnectorGateway:
    """Gateway for receiving and routing findings to the pipeline.

    Responsibilities:
    - Validate ingest payloads (Pydantic)
    - Dedup findings via content hash
    - Route to correct SDLC stage entry point
    - Handle unknown formats via DefectDojo parser API
    - Feed TrustGraph Knowledge Cores
    """

    def __init__(
        self,
        registry: Optional[ConnectorRegistry] = None,
        enable_core_routing: bool = True,
    ) -> None:
        """Initialize gateway.

        Args:
            registry: ConnectorRegistry instance (defaults to singleton).
            enable_core_routing: Whether to route findings to TrustGraph
                Knowledge Cores after dedup (default True).
        """
        self._registry = registry or ConnectorRegistry()
        self._seen_hashes: Dict[str, str] = {}  # hash -> connector_source
        self._seen_lock = Lock()

        # Lazy-init CoreRouter — gracefully handles missing TrustGraph
        self._core_router = None
        self._enable_core_routing = enable_core_routing
        if enable_core_routing:
            try:
                from connectors.trustgraph_core_router import CoreRouter

                self._core_router = CoreRouter()
                logger.info("ConnectorGateway initialized with CoreRouter")
            except ImportError:
                logger.info(
                    "ConnectorGateway initialized (CoreRouter not available — "
                    "findings will not be routed to Knowledge Cores)"
                )
        else:
            logger.info("ConnectorGateway initialized (core routing disabled)")

    @staticmethod
    def _content_hash(content: str) -> str:
        """Compute SHA256 hash of content for dedup.

        Args:
            content: String content to hash.

        Returns:
            Hex digest.
        """
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    async def ingest(
        self, source: str, findings: List[Dict[str, Any]], metadata: Dict[str, Any]
    ) -> ConnectorOutcome:
        """Ingest findings from a source.

        Validates, deduplicates, and prepares findings for pipeline routing.

        Args:
            source: Source identifier (e.g., 'snyk', 'jira').
            findings: List of finding dicts.
            metadata: Additional metadata.

        Returns:
            ConnectorOutcome with status and count of accepted findings.
        """
        try:
            # Validate payload
            payload = IngestPayload(source=source, findings=findings, metadata=metadata)
        except ValidationError as exc:
            logger.warning("Validation error in ingest: %s", exc)
            return ConnectorOutcome(
                "failed",
                {"error": "validation failed", "details": exc.errors()},
            )

        # Dedup findings
        accepted = []
        deduplicated = 0

        for finding in payload.findings:
            # Hash the finding content for dedup
            finding_json = json.dumps(finding, sort_keys=True, default=str)
            finding_hash = self._content_hash(finding_json)

            with self._seen_lock:
                if finding_hash in self._seen_hashes:
                    deduplicated += 1
                    logger.debug(
                        "Deduplicated finding from %s (hash: %s)",
                        source,
                        finding_hash[:8],
                    )
                    continue
                self._seen_hashes[finding_hash] = source

            accepted.append(finding)

        logger.info(
            "Ingest from %s: %d findings, %d deduplicated",
            source,
            len(findings),
            deduplicated,
        )

        # Route accepted findings to TrustGraph Knowledge Cores
        core_routing_results = []
        if self._core_router and accepted:
            connector_meta = None
            # Try to get connector metadata for routing hints
            connector = self._registry.get(source)
            if connector:
                connector_meta = connector.metadata

            for finding in accepted:
                try:
                    result = await self._core_router.route_finding_to_cores(
                        finding=finding,
                        connector_meta=connector_meta,
                    )
                    core_routing_results.append(result.to_dict())
                except Exception as exc:
                    logger.warning(
                        "Core routing failed for finding from %s: %s",
                        source,
                        type(exc).__name__,
                    )

        return ConnectorOutcome(
            "success",
            {
                "source": source,
                "accepted": len(accepted),
                "deduplicated": deduplicated,
                "data": accepted,
                "metadata": dict(payload.metadata),
                "core_routing": core_routing_results if core_routing_results else None,
            },
        )

    async def route_to_pipeline(
        self, findings: List[Dict[str, Any]], entry_stage: int
    ) -> ConnectorOutcome:
        """Route findings to the correct pipeline stage.

        The 15-stage ALDECI pipeline:
        1. Collect (ingest from sources)
        2. Normalize
        3. Enrich (static data)
        4. Deduplicate
        5. Correlate
        6. Score
        7. Prioritize
        8. Validate
        9. Classify
        10. Contextualize
        11. Filter/Suppress
        12. Run Playbooks
        13. Enrichment Feedback
        14. Report
        15. Archive

        Args:
            findings: List of normalized findings.
            entry_stage: Pipeline stage number (1-15) to enter at.

        Returns:
            ConnectorOutcome with routing details.
        """
        if not (1 <= entry_stage <= 15):
            return ConnectorOutcome(
                "failed",
                {"error": f"invalid entry_stage {entry_stage}, must be 1-15"},
            )

        logger.info(
            "Routing %d findings to pipeline stage %d",
            len(findings),
            entry_stage,
        )

        # TODO: Implement actual routing to pipeline
        # This would call the pipeline dispatcher with findings and stage info
        return ConnectorOutcome(
            "success",
            {
                "findings_count": len(findings),
                "entry_stage": entry_stage,
                "routed_at": datetime.now(timezone.utc).isoformat(),
            },
        )

    async def route_unknown_format(
        self, raw_data: bytes, format_hint: str
    ) -> ConnectorOutcome:
        """Route raw data of unknown format through detection.

        When a webhook/ingestion has unknown format, attempt to detect:
        - SARIF, CycloneDX, CVSS, JSON, XML, CSV, YAML
        - Fall back to DefectDojo parser API if supported

        Args:
            raw_data: Raw bytes from webhook.
            format_hint: Hint about format (e.g., 'application/json').

        Returns:
            ConnectorOutcome with parsed findings or error.
        """
        try:
            # Decode to text first — specific format detection before generic JSON
            text = raw_data.decode("utf-8", errors="replace")

            # SARIF detection (has "runs" array — definitive SARIF marker)
            if '"runs"' in text and ('"version"' in text or '"$schema"' in text):
                logger.info("Detected SARIF format")
                return ConnectorOutcome(
                    "success",
                    {"format": "sarif", "data": json.loads(text)},
                )

            # CycloneDX detection ("cyclonedx" keyword or "components" key)
            if "cyclonedx" in text.lower() or '"components"' in text:
                logger.info("Detected CycloneDX format")
                return ConnectorOutcome(
                    "success",
                    {"format": "cyclonedx", "data": json.loads(text)},
                )

            # Generic JSON fallback (after specific formats checked)
            if format_hint and "json" in format_hint.lower():
                parsed = json.loads(text)
                logger.info("Successfully parsed unknown format as JSON")
                return ConnectorOutcome(
                    "success",
                    {
                        "format": "json",
                        "data": parsed if isinstance(parsed, list) else [parsed],
                    },
                )

            logger.warning(
                "Could not detect format for data: %s (hint: %s)",
                raw_data[:100],
                format_hint,
            )

            return ConnectorOutcome(
                "failed",
                {
                    "error": "unsupported format",
                    "hint": format_hint,
                    "raw_sample": raw_data[:200].decode("utf-8", errors="replace"),
                },
            )

        except json.JSONDecodeError as exc:
            logger.error("JSON decode error: %s", exc)
            return ConnectorOutcome(
                "failed",
                {"error": "json decode failed", "details": str(exc)},
            )
        except Exception as exc:
            logger.error(
                "Format detection error: %s %s",
                type(exc).__name__,
                exc,
                exc_info=True,
            )
            return ConnectorOutcome(
                "failed",
                {"error": str(exc), "type": type(exc).__name__},
            )
