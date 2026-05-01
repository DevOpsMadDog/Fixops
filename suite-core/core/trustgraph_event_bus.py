"""
TrustGraph Event Bus — Automatic pipeline from ALL API responses into TrustGraph.

This module closes the #1 architectural gap in ALDECI: 97% of endpoints produce
findings/assets/incidents that never reach TrustGraph.  This event bus wires them
all automatically via three mechanisms:

1. ResponseInterceptorMiddleware — inspects every POST/PUT/PATCH response body for
   entity ID keys (finding_id, asset_id, incident_id, control_id, vendor_id,
   actor_id) and emits an event without blocking the API response.

2. In-process EventBus — lightweight pub/sub (emit/on) with async dispatch.
   Any engine can call `get_event_bus().emit("finding.created", data)` directly.

3. Offline SQLite queue — if TrustGraph is unavailable events are durably queued
   (max 10,000) and flushed automatically when TrustGraph recovers.

Event types:
    finding.created     → UniversalFindingIndexer.index()
    finding.updated     → UniversalFindingIndexer.index()
    asset.discovered    → TrustGraphBackbone.index_asset()
    incident.created    → TrustGraphBackbone.index_incident()
    control.assessed    → TrustGraphBackbone.index_compliance_control()
    vendor.updated      → TrustGraphBackbone.index_vendor()
    actor.identified    → TrustGraphBackbone.index_threat_actor()

Configuration:
    TRUSTGRAPH_EVENT_BUS_ENABLED   = 1/0  (default: 1)
    TRUSTGRAPH_EVENT_BUS_BATCH     = N    (flush batch size, default: 50)
    TRUSTGRAPH_EVENT_BUS_DB        = path (default: ./.aldeci/event_bus_queue.db)
    FIXOPS_TEST_MODE               = 1    (disables bus entirely in test runs)

Usage:
    # Direct emit from any engine:
    from core.trustgraph_event_bus import get_event_bus
    await get_event_bus().emit("finding.created", {"id": "f_001", "engine": "sast", ...})

    # Wire middleware into FastAPI app:
    from core.trustgraph_event_bus import ResponseInterceptorMiddleware, init_event_bus
    init_event_bus(app)  # registers middleware + startup handler
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = structlog.get_logger("core.trustgraph_event_bus")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# All supported event type strings
EVENT_FINDING_CREATED = "finding.created"
EVENT_FINDING_UPDATED = "finding.updated"
EVENT_ASSET_DISCOVERED = "asset.discovered"
EVENT_INCIDENT_CREATED = "incident.created"
EVENT_CONTROL_ASSESSED = "control.assessed"
EVENT_VENDOR_UPDATED = "vendor.updated"
EVENT_ACTOR_IDENTIFIED = "actor.identified"

# Extended event type constants for wave engine coverage
EVENT_SCAN_COMPLETED = "scan.completed"
EVENT_CVE_DISCOVERED = "cve.discovered"
EVENT_THREAT_DETECTED = "threat.detected"
EVENT_RISK_ASSESSED = "risk.assessed"
EVENT_EVIDENCE_COLLECTED = "evidence.collected"
EVENT_JOB_COMPLETED = "job.completed"
EVENT_IDENTITY_UPDATED = "identity.updated"
EVENT_SESSION_CREATED = "session.created"
EVENT_RULE_UPDATED = "rule.updated"
EVENT_PLAYBOOK_EXECUTED = "playbook.executed"
EVENT_EVENT_CREATED = "event.created"
EVENT_ALERT_CREATED = "alert.created"
EVENT_ASSET_UPDATED = "asset.updated"
EVENT_SCENARIO_CREATED = "scenario.created"
EVENT_TRAINING_COMPLETED = "training.completed"
EVENT_REVIEW_COMPLETED = "review.completed"
EVENT_SCHEDULE_UPDATED = "schedule.updated"
EVENT_OPERATION_COMPLETED = "operation.completed"
EVENT_ENGAGEMENT_CREATED = "engagement.created"
EVENT_STEP_COMPLETED = "step.completed"
EVENT_TEAM_UPDATED = "team.updated"
EVENT_POLICY_UPDATED = "policy.updated"

ALL_EVENT_TYPES: Set[str] = {
    EVENT_FINDING_CREATED,
    EVENT_FINDING_UPDATED,
    EVENT_ASSET_DISCOVERED,
    EVENT_INCIDENT_CREATED,
    EVENT_CONTROL_ASSESSED,
    EVENT_VENDOR_UPDATED,
    EVENT_ACTOR_IDENTIFIED,
    # Extended event types
    EVENT_SCAN_COMPLETED,
    EVENT_CVE_DISCOVERED,
    EVENT_THREAT_DETECTED,
    EVENT_RISK_ASSESSED,
    EVENT_EVIDENCE_COLLECTED,
    EVENT_JOB_COMPLETED,
    EVENT_IDENTITY_UPDATED,
    EVENT_SESSION_CREATED,
    EVENT_RULE_UPDATED,
    EVENT_PLAYBOOK_EXECUTED,
    EVENT_EVENT_CREATED,
    EVENT_ALERT_CREATED,
    EVENT_ASSET_UPDATED,
    EVENT_SCENARIO_CREATED,
    EVENT_TRAINING_COMPLETED,
    EVENT_REVIEW_COMPLETED,
    EVENT_SCHEDULE_UPDATED,
    EVENT_OPERATION_COMPLETED,
    EVENT_ENGAGEMENT_CREATED,
    EVENT_STEP_COMPLETED,
    EVENT_TEAM_UPDATED,
    EVENT_POLICY_UPDATED,
}

# Response body keys → (event_type, entity_type_label)
_RESPONSE_KEY_MAP: Dict[str, tuple[str, str]] = {
    # Original 6 entity keys
    "finding_id": (EVENT_FINDING_CREATED, "finding"),
    "asset_id": (EVENT_ASSET_DISCOVERED, "asset"),
    "incident_id": (EVENT_INCIDENT_CREATED, "incident"),
    "control_id": (EVENT_CONTROL_ASSESSED, "control"),
    "vendor_id": (EVENT_VENDOR_UPDATED, "vendor"),
    "actor_id": (EVENT_ACTOR_IDENTIFIED, "actor"),

    # Vulnerability Management
    "ticket_id": (EVENT_FINDING_CREATED, "vuln_ticket"),
    "scan_id": (EVENT_SCAN_COMPLETED, "scan"),
    "cve_id": (EVENT_CVE_DISCOVERED, "cve"),
    "detection_id": (EVENT_THREAT_DETECTED, "detection"),

    # Risk & Compliance
    "risk_id": (EVENT_RISK_ASSESSED, "risk"),
    "assessment_id": (EVENT_CONTROL_ASSESSED, "assessment"),
    "gap_id": (EVENT_CONTROL_ASSESSED, "gap"),
    "policy_id": (EVENT_POLICY_UPDATED, "policy"),
    "framework_id": (EVENT_CONTROL_ASSESSED, "framework"),
    "evidence_id": (EVENT_EVIDENCE_COLLECTED, "evidence"),
    "job_id": (EVENT_JOB_COMPLETED, "job"),

    # Identity & Access
    "identity_id": (EVENT_IDENTITY_UPDATED, "identity"),
    "session_id": (EVENT_SESSION_CREATED, "session"),
    "device_id": (EVENT_ASSET_DISCOVERED, "device"),
    "cert_id": (EVENT_ASSET_DISCOVERED, "certificate"),

    # Threat Intel
    "campaign_id": (EVENT_THREAT_DETECTED, "campaign"),
    "technique_id": (EVENT_THREAT_DETECTED, "technique"),
    "tactic_id": (EVENT_THREAT_DETECTED, "tactic"),
    "chain_id": (EVENT_THREAT_DETECTED, "attack_chain"),
    "simulation_id": (EVENT_THREAT_DETECTED, "simulation"),

    # SOC Operations
    "rule_id": (EVENT_RULE_UPDATED, "rule"),
    "execution_id": (EVENT_PLAYBOOK_EXECUTED, "execution"),
    "event_id": (EVENT_EVENT_CREATED, "event"),
    "alert_id": (EVENT_ALERT_CREATED, "alert"),

    # Assets & Infrastructure
    "resource_id": (EVENT_ASSET_DISCOVERED, "resource"),
    "app_id": (EVENT_ASSET_DISCOVERED, "application"),
    "domain_id": (EVENT_ASSET_DISCOVERED, "domain"),
    "account_id": (EVENT_ASSET_DISCOVERED, "account"),
    "tag_id": (EVENT_ASSET_UPDATED, "tag"),

    # Other domains
    "scenario_id": (EVENT_SCENARIO_CREATED, "scenario"),
    "twin_id": (EVENT_ASSET_DISCOVERED, "digital_twin"),
    "challenge_id": (EVENT_TRAINING_COMPLETED, "challenge"),
    "review_id": (EVENT_REVIEW_COMPLETED, "review"),
    "run_id": (EVENT_JOB_COMPLETED, "run"),
    "schedule_id": (EVENT_SCHEDULE_UPDATED, "schedule"),
    "operation_id": (EVENT_OPERATION_COMPLETED, "operation"),
    "engagement_id": (EVENT_ENGAGEMENT_CREATED, "engagement"),
    "step_id": (EVENT_STEP_COMPLETED, "step"),
    "team_id": (EVENT_TEAM_UPDATED, "team"),
    "client_id": (EVENT_ASSET_DISCOVERED, "client"),

    # Generic / cross-cutting IDs (broader coverage for wave A/B/C/D routers)
    "correlation_id": (EVENT_EVENT_CREATED, "correlation"),
    "tenant_id": (EVENT_ASSET_DISCOVERED, "tenant"),
    "tenant": (EVENT_ASSET_DISCOVERED, "tenant"),
    "org_id": (EVENT_ASSET_DISCOVERED, "org"),
    "repo": (EVENT_ASSET_DISCOVERED, "repository"),
    "repo_id": (EVENT_ASSET_DISCOVERED, "repository"),
    "digest": (EVENT_EVIDENCE_COLLECTED, "digest"),
    "q_id": (EVENT_RISK_ASSESSED, "quantification"),
    "fair_id": (EVENT_RISK_ASSESSED, "fair_analysis"),
    "artifact": (EVENT_EVIDENCE_COLLECTED, "artifact"),
    "artifact_id": (EVENT_EVIDENCE_COLLECTED, "artifact"),
    "mapping_id": (EVENT_RULE_UPDATED, "mapping"),
    "seed_id": (EVENT_ASSET_DISCOVERED, "seed"),
    "domain": (EVENT_ASSET_DISCOVERED, "domain"),
    "id": (EVENT_EVENT_CREATED, "generic"),  # bare "id" — last resort, generic event
}

# Wrapper keys to recursively unwrap when looking for IDs.
# Many routers wrap their response as {"data": {...}}, {"result": {...}},
# {"item": {...}}, {"items": [...]}, {"results": [...]}, {"payload": {...}}.
_WRAPPER_KEYS: Set[str] = {
    "data",
    "result",
    "results",
    "item",
    "items",
    "payload",
    "response",
    "body",
    "record",
    "records",
    "entity",
    "entities",
    "object",
}

# Maximum recursion depth when walking nested response shapes.
_MAX_UNWRAP_DEPTH = 3

# HTTP methods whose responses may create/modify entities
_MUTATING_METHODS: Set[str] = {"POST", "PUT", "PATCH"}

# Max response body bytes to inspect (don't buffer large payloads)
_MAX_BODY_INSPECT = 64 * 1024  # 64 KB

# Default SQLite queue path
_DEFAULT_QUEUE_DB = "./.aldeci/event_bus_queue.db"

# Default max queue size
_DEFAULT_QUEUE_MAX = 10_000

# Default batch flush size
_DEFAULT_BATCH_SIZE = 50


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


@dataclass
class EventBusMetrics:
    """Counters and latency tracking for the event bus."""

    events_emitted: int = 0
    events_indexed: int = 0
    events_queued: int = 0
    events_failed: int = 0
    events_dropped: int = 0
    flush_runs: int = 0
    flush_indexed: int = 0

    # Per event-type counters
    by_type_emitted: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    by_type_indexed: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    by_type_failed: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Latency tracking (total ms, count per event type)
    latency_total_ms: Dict[str, float] = field(default_factory=lambda: defaultdict(float))
    latency_count: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)

    def record_emit(self, event_type: str) -> None:
        with self._lock:
            self.events_emitted += 1
            self.by_type_emitted[event_type] += 1

    def record_indexed(self, event_type: str, latency_ms: float) -> None:
        with self._lock:
            self.events_indexed += 1
            self.by_type_indexed[event_type] += 1
            self.latency_total_ms[event_type] += latency_ms
            self.latency_count[event_type] += 1

    def record_queued(self, event_type: str) -> None:
        with self._lock:
            self.events_queued += 1

    def record_failed(self, event_type: str) -> None:
        with self._lock:
            self.events_failed += 1
            self.by_type_failed[event_type] += 1

    def record_dropped(self) -> None:
        with self._lock:
            self.events_dropped += 1

    def avg_latency_ms(self, event_type: str) -> float:
        with self._lock:
            count = self.latency_count.get(event_type, 0)
            if count == 0:
                return 0.0
            return self.latency_total_ms[event_type] / count

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "events_emitted": self.events_emitted,
                "events_indexed": self.events_indexed,
                "events_queued": self.events_queued,
                "events_failed": self.events_failed,
                "events_dropped": self.events_dropped,
                "flush_runs": self.flush_runs,
                "flush_indexed": self.flush_indexed,
                "by_type": {
                    et: {
                        "emitted": self.by_type_emitted.get(et, 0),
                        "indexed": self.by_type_indexed.get(et, 0),
                        "failed": self.by_type_failed.get(et, 0),
                        "avg_latency_ms": round(self.avg_latency_ms(et), 2),
                    }
                    for et in ALL_EVENT_TYPES
                },
            }


# ---------------------------------------------------------------------------
# Offline SQLite Queue
# ---------------------------------------------------------------------------


class _OfflineQueue:
    """Durable SQLite queue for events when TrustGraph is unavailable."""

    def __init__(self, db_path: str = _DEFAULT_QUEUE_DB, max_size: int = _DEFAULT_QUEUE_MAX) -> None:
        self.db_path = db_path
        self.max_size = max_size
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS event_bus_queue (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT    NOT NULL,
                    payload    TEXT    NOT NULL,
                    created_at TEXT    NOT NULL,
                    status     TEXT    NOT NULL DEFAULT 'queued'
                              CHECK(status IN ('queued', 'indexed', 'failed'))
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ebq_status ON event_bus_queue(status)"
            )
            conn.commit()

    def enqueue(self, event_type: str, data: Dict[str, Any]) -> bool:
        try:
            payload = json.dumps(data, default=str)
            created_at = datetime.now(timezone.utc).isoformat()
            with sqlite3.connect(self.db_path) as conn:
                # Evict oldest if at capacity
                (count,) = conn.execute(
                    "SELECT COUNT(*) FROM event_bus_queue WHERE status = 'queued'"
                ).fetchone()
                if count >= self.max_size:
                    conn.execute(
                        """
                        DELETE FROM event_bus_queue WHERE id IN (
                            SELECT id FROM event_bus_queue
                            WHERE status = 'queued'
                            ORDER BY created_at ASC LIMIT ?
                        )
                        """,
                        (max(1, count - self.max_size + 1),),
                    )
                    logger.warning(
                        "event_bus_queue: max_size reached, evicted oldest events",
                        max_size=self.max_size,
                    )
                conn.execute(
                    "INSERT INTO event_bus_queue (event_type, payload, created_at) VALUES (?, ?, ?)",
                    (event_type, payload, created_at),
                )
                conn.commit()
            return True
        except Exception as exc:
            logger.error("event_bus_queue.enqueue failed", error=str(exc))
            return False

    def get_pending(self, limit: int = _DEFAULT_BATCH_SIZE) -> List[Dict[str, Any]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM event_bus_queue WHERE status = 'queued' ORDER BY created_at ASC LIMIT ?",
                    (limit,),
                ).fetchall()
                return [
                    {
                        "id": r["id"],
                        "event_type": r["event_type"],
                        "payload": json.loads(r["payload"]),
                        "created_at": r["created_at"],
                    }
                    for r in rows
                ]
        except Exception as exc:
            logger.error("event_bus_queue.get_pending failed", error=str(exc))
            return []

    def mark_indexed(self, queue_id: int) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "UPDATE event_bus_queue SET status = 'indexed' WHERE id = ?", (queue_id,)
                )
                conn.commit()
        except Exception as exc:
            logger.warning("event_bus_queue.mark_indexed failed", error=str(exc))

    def mark_failed(self, queue_id: int) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "UPDATE event_bus_queue SET status = 'failed' WHERE id = ?", (queue_id,)
                )
                conn.commit()
        except Exception as exc:
            logger.warning("event_bus_queue.mark_failed failed", error=str(exc))

    def queue_stats(self) -> Dict[str, Any]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT status, COUNT(*) as cnt FROM event_bus_queue GROUP BY status"
                ).fetchall()
                stats = {r[0]: r[1] for r in rows}
                return {
                    "queued": stats.get("queued", 0),
                    "indexed": stats.get("indexed", 0),
                    "failed": stats.get("failed", 0),
                    "total": sum(stats.values()),
                    "max_size": self.max_size,
                }
        except Exception as exc:
            return {"error": str(exc)}


# ---------------------------------------------------------------------------
# TrustGraph Handlers
# ---------------------------------------------------------------------------


def _get_finding_indexer(org_id: str = "default") -> Any:
    """Lazy-load UniversalFindingIndexer scoped to an org."""
    from core.trustgraph_integrations import UniversalFindingIndexer
    return UniversalFindingIndexer(org_id=org_id)


def _get_backbone(org_id: str = "default") -> Any:
    """Lazy-load TrustGraphBackbone scoped to an org."""
    from core.trustgraph_backbone import TrustGraphBackbone
    return TrustGraphBackbone(org_id=org_id)


def _payload_org_id(data: Dict[str, Any]) -> str:
    """Extract org_id (or tenant_id) from an event payload, defaulting to 'default'."""
    try:
        return str(data.get("org_id") or data.get("tenant_id") or "default")
    except Exception:
        return "default"


async def _handle_finding_created(data: Dict[str, Any]) -> bool:
    """Route finding.created / finding.updated to UniversalFindingIndexer.

    Always returns True (indicating "no retry needed"); failures are logged
    but never raised so the bus is never destabilised.
    """
    try:
        # Ensure engine key exists (required by FindingInput)
        if "engine" not in data:
            data = {**data, "engine": data.get("scanner", "api")}
        indexer = _get_finding_indexer(org_id=_payload_org_id(data))
        entity_id = indexer.index(data)
        logger.debug("event_bus: indexed finding", entity_id=entity_id)
    except Exception as exc:  # noqa: BLE001 — handlers must never raise
        logger.warning("event_bus: finding index failed", error=str(exc))
    return True


async def _handle_asset_discovered(data: Dict[str, Any]) -> bool:
    """Route asset.discovered to TrustGraphBackbone.index_asset()."""
    try:
        backbone = _get_backbone(org_id=_payload_org_id(data))
        entity_id = backbone.index_asset(data)
        logger.debug("event_bus: indexed asset", entity_id=entity_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("event_bus: asset index failed", error=str(exc))
    return True


async def _handle_incident_created(data: Dict[str, Any]) -> bool:
    """Route incident.created to TrustGraphBackbone.index_incident()."""
    try:
        backbone = _get_backbone(org_id=_payload_org_id(data))
        entity_id = backbone.index_incident(data)
        logger.debug("event_bus: indexed incident", entity_id=entity_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("event_bus: incident index failed", error=str(exc))
    return True


async def _handle_control_assessed(data: Dict[str, Any]) -> bool:
    """Route control.assessed to TrustGraphBackbone.index_compliance_control()."""
    try:
        backbone = _get_backbone(org_id=_payload_org_id(data))
        entity_id = backbone.index_compliance_control(data)
        logger.debug("event_bus: indexed control", entity_id=entity_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("event_bus: control index failed", error=str(exc))
    return True


async def _handle_vendor_updated(data: Dict[str, Any]) -> bool:
    """Route vendor.updated to TrustGraphBackbone.index_vendor() if available."""
    try:
        backbone = _get_backbone(org_id=_payload_org_id(data))
        if hasattr(backbone, "index_vendor"):
            entity_id = backbone.index_vendor(data)
        else:
            # Fallback: index as asset with vendor type
            data_copy = {**data, "type": "vendor"}
            entity_id = backbone.index_asset(data_copy)
        logger.debug("event_bus: indexed vendor", entity_id=entity_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("event_bus: vendor index failed", error=str(exc))
    return True


async def _handle_actor_identified(data: Dict[str, Any]) -> bool:
    """Route actor.identified to TrustGraphBackbone.index_threat_actor() if available."""
    try:
        backbone = _get_backbone(org_id=_payload_org_id(data))
        if hasattr(backbone, "index_threat_actor"):
            entity_id = backbone.index_threat_actor(data)
        else:
            # Fallback: index as finding with engine=threat_intel
            data_copy = {**data, "engine": "threat_intel"}
            indexer = _get_finding_indexer(org_id=_payload_org_id(data))
            entity_id = indexer.index(data_copy)
        logger.debug("event_bus: indexed threat actor", entity_id=entity_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("event_bus: actor index failed", error=str(exc))
    return True


async def _handle_cve_discovered(data: Dict[str, Any]) -> bool:
    """Route cve.discovered to UniversalFindingIndexer as a feed-derived finding.

    CVE events come from threat-intel feeds; we surface them as findings with
    engine=feed and entity_type=cve so they show up in dashboards alongside
    scanner-derived findings.
    """
    try:
        merged = {**data, "engine": data.get("engine") or "feed", "entity_type": "cve"}
        indexer = _get_finding_indexer(org_id=_payload_org_id(data))
        entity_id = indexer.index(merged)
        logger.debug("event_bus: indexed cve", entity_id=entity_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("event_bus: cve index failed", error=str(exc))
    return True


async def _handle_risk_assessed(data: Dict[str, Any]) -> bool:
    """Route risk.assessed to KnowledgeBrain as a FINDING-typed risk node.

    Risk assessments are first-class entities in the brain; we add them as
    Finding nodes so they participate in cross-domain queries. Falls back
    to the universal indexer if the brain import fails.
    """
    try:
        from core.knowledge_brain import EntityType, KnowledgeBrain

        org = _payload_org_id(data)
        brain = KnowledgeBrain(org_id=org) if "org_id" in KnowledgeBrain.__init__.__code__.co_varnames else KnowledgeBrain()
        node_id = data.get("id") or data.get("risk_id") or f"risk_{uuid_hex()}"
        name = data.get("title") or data.get("name") or str(node_id)
        try:
            brain.add_node(
                node_id=str(node_id),
                entity_type=EntityType.FINDING,
                name=name,
                properties={k: v for k, v in data.items() if k not in {"id", "name"}},
            )
        except TypeError:
            # KnowledgeBrain.add_node signature varies across versions; degrade
            # gracefully to the universal indexer below.
            raise
        logger.debug("event_bus: indexed risk", node_id=node_id)
    except Exception as exc:  # noqa: BLE001 — fall back to indexer, never raise
        logger.debug("event_bus: KnowledgeBrain risk index failed, using indexer", error=str(exc))
        try:
            merged = {**data, "engine": data.get("engine") or "risk_engine"}
            indexer = _get_finding_indexer(org_id=_payload_org_id(data))
            indexer.index(merged)
        except Exception as exc2:  # noqa: BLE001
            logger.warning("event_bus: risk fallback index failed", error=str(exc2))
    return True


def uuid_hex() -> str:
    """Short uuid hex helper (kept module-local to avoid extra imports at load)."""
    import uuid as _uuid
    return _uuid.uuid4().hex[:8]


# Default handler registry
_DEFAULT_HANDLERS: Dict[str, Callable[[Dict[str, Any]], Coroutine]] = {
    EVENT_FINDING_CREATED: _handle_finding_created,
    EVENT_FINDING_UPDATED: _handle_finding_created,  # same logic
    EVENT_ASSET_DISCOVERED: _handle_asset_discovered,
    EVENT_INCIDENT_CREATED: _handle_incident_created,
    EVENT_CONTROL_ASSESSED: _handle_control_assessed,
    EVENT_VENDOR_UPDATED: _handle_vendor_updated,
    EVENT_ACTOR_IDENTIFIED: _handle_actor_identified,
    EVENT_CVE_DISCOVERED: _handle_cve_discovered,
    EVENT_RISK_ASSESSED: _handle_risk_assessed,
}


# ---------------------------------------------------------------------------
# EventBus
# ---------------------------------------------------------------------------


class EventBus:
    """Lightweight in-process async event bus with offline queueing.

    Thread-safe. Multiple handlers per event type are supported.
    All handlers are dispatched as background tasks (fire-and-forget) so
    the API response path is never blocked.

    Args:
        enabled: Master on/off switch (also respects env var).
        batch_size: Flush batch size for the offline queue.
        queue_db_path: SQLite path for the offline queue.
        queue_max_size: Max queued events before oldest are evicted.
    """

    def __init__(
        self,
        enabled: bool = True,
        batch_size: int = _DEFAULT_BATCH_SIZE,
        queue_db_path: str = _DEFAULT_QUEUE_DB,
        queue_max_size: int = _DEFAULT_QUEUE_MAX,
    ) -> None:
        # Honour env overrides
        if os.getenv("FIXOPS_TEST_MODE", "0") == "1":
            enabled = False
        if os.getenv("TRUSTGRAPH_EVENT_BUS_ENABLED", "1") == "0":
            enabled = False
        self.enabled = enabled

        batch_env = os.getenv("TRUSTGRAPH_EVENT_BUS_BATCH")
        self.batch_size = int(batch_env) if batch_env else batch_size

        db_env = os.getenv("TRUSTGRAPH_EVENT_BUS_DB")
        db_path = db_env if db_env else queue_db_path

        self.metrics = EventBusMetrics()
        self._handlers: Dict[str, List[Callable]] = defaultdict(list)
        self._enabled_types: Set[str] = set(ALL_EVENT_TYPES)
        self._queue = _OfflineQueue(db_path=db_path, max_size=queue_max_size)
        self._flush_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

        logger.info(
            "TrustGraph EventBus initialized",
            enabled=self.enabled,
            batch_size=self.batch_size,
            queue_db=db_path,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def on(self, event_type: str, handler: Callable[[Dict[str, Any]], Any]) -> None:
        """Register a handler for an event type.

        Args:
            event_type: One of the EVENT_* constants.
            handler: Async or sync callable taking one dict argument.
        """
        self._handlers[event_type].append(handler)
        logger.debug("EventBus.on: registered handler", event_type=event_type, handler=handler.__name__)

    async def emit(self, event_type: str, data: Dict[str, Any]) -> None:
        """Emit an event. Dispatches handlers as background tasks (non-blocking).

        Args:
            event_type: One of the EVENT_* constants.
            data: Entity dict payload.
        """
        if not self.enabled:
            return
        if event_type not in self._enabled_types:
            self.metrics.record_dropped()
            return

        self.metrics.record_emit(event_type)
        handlers = list(self._handlers.get(event_type, []))

        # AgentDB dual-write — fire-and-forget, additive, never blocks.
        # Lazy-imported and try/except so a missing/broken bridge can't
        # take down the bus.
        try:  # pragma: no cover — bridge is optional
            from trustgraph.agentdb_bridge import get_agentdb_bridge

            asyncio.ensure_future(
                asyncio.to_thread(
                    get_agentdb_bridge().dual_write,
                    event_type=event_type,
                    payload=data,
                )
            )
        except Exception:  # noqa: BLE001
            pass

        if not handlers:
            # No handlers registered — queue for later (handlers registered on startup)
            self._queue.enqueue(event_type, data)
            self.metrics.record_queued(event_type)
            return

        # Dispatch as background task to avoid blocking API response
        for handler in handlers:
            asyncio.ensure_future(self._dispatch(event_type, handler, data))

        # Fire-and-forget: push to WebSocket alert broadcaster (best-effort)
        asyncio.ensure_future(self._broadcast_alert(event_type, data))

    async def _dispatch(
        self,
        event_type: str,
        handler: Callable,
        data: Dict[str, Any],
    ) -> None:
        """Dispatch a single handler, queuing on failure."""
        start = time.monotonic()
        try:
            if asyncio.iscoroutinefunction(handler):
                success = await handler(data)
            else:
                loop = asyncio.get_event_loop()
                success = await loop.run_in_executor(None, handler, data)

            elapsed_ms = (time.monotonic() - start) * 1000.0

            if success:
                self.metrics.record_indexed(event_type, elapsed_ms)
            else:
                # Handler returned False → queue for retry
                self._queue.enqueue(event_type, data)
                self.metrics.record_queued(event_type)
        except Exception as exc:
            logger.warning(
                "EventBus handler failed, queuing event",
                event_type=event_type,
                error=str(exc),
            )
            self._queue.enqueue(event_type, data)
            self.metrics.record_queued(event_type)

    async def _broadcast_alert(self, event_type: str, data: Dict[str, Any]) -> None:
        """Fire-and-forget push to AlertBroadcaster (best-effort, never raises)."""
        try:
            from core.alert_broadcaster import build_alert, get_alert_broadcaster

            # Map TrustGraph event types to alert broadcaster types
            _event_to_alert_type: Dict[str, str] = {
                EVENT_FINDING_CREATED: "finding_created",
                EVENT_FINDING_UPDATED: "finding_created",
                EVENT_INCIDENT_CREATED: "incident_opened",
                EVENT_ASSET_DISCOVERED: "threat_detected",
                EVENT_CONTROL_ASSESSED: "policy_violation",
                EVENT_VENDOR_UPDATED: "threat_detected",
                EVENT_ACTOR_IDENTIFIED: "threat_detected",
            }
            alert_type = _event_to_alert_type.get(event_type)
            if not alert_type:
                return

            severity = data.get("severity", "medium")
            if severity not in ("critical", "high", "medium", "low", "info"):
                severity = "medium"

            alert = build_alert(
                alert_type=alert_type,
                severity=severity,
                title=data.get("title", event_type.replace(".", " ").title()),
                message=data.get("message", f"Event: {event_type}"),
                tenant_id=data.get("tenant_id") or data.get("org_id"),
                metadata={"event_type": event_type, "source": data.get("engine", "trustgraph")},
            )
            broadcaster = get_alert_broadcaster()
            tenant_id = alert.get("tenant_id")
            if tenant_id:
                await broadcaster.broadcast_to_tenant(tenant_id, alert)
            else:
                await broadcaster.broadcast(alert)
        except Exception as exc:  # noqa: BLE001 — best-effort, must never raise
            logger.debug("EventBus._broadcast_alert: skipped", error=str(exc))

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def enable_event_type(self, event_type: str) -> None:
        """Enable processing for a specific event type."""
        self._enabled_types.add(event_type)

    def disable_event_type(self, event_type: str) -> None:
        """Disable processing for a specific event type."""
        self._enabled_types.discard(event_type)

    def get_enabled_types(self) -> List[str]:
        return sorted(self._enabled_types)

    def set_enabled(self, enabled: bool) -> None:
        """Master enable/disable toggle."""
        self.enabled = enabled

    # ------------------------------------------------------------------
    # Queue management
    # ------------------------------------------------------------------

    async def flush_queue(self, batch_size: Optional[int] = None) -> Dict[str, int]:
        """Flush queued events back through registered handlers.

        Returns:
            Dict with keys: attempted, indexed, failed.
        """
        limit = batch_size or self.batch_size
        pending = self._queue.get_pending(limit=limit)
        indexed = 0
        failed = 0
        self.metrics.flush_runs += 1

        for item in pending:
            event_type = item["event_type"]
            payload = item["payload"]
            queue_id = item["id"]

            handlers = list(self._handlers.get(event_type, []))
            if not handlers:
                # Still no handler — leave queued
                continue

            success = False
            for handler in handlers:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        result = await handler(payload)
                    else:
                        loop = asyncio.get_event_loop()
                        result = await loop.run_in_executor(None, handler, payload)
                    if result:
                        success = True
                        break
                except Exception as exc:
                    logger.warning(
                        "EventBus flush: handler failed",
                        queue_id=queue_id,
                        event_type=event_type,
                        error=str(exc),
                    )

            if success:
                self._queue.mark_indexed(queue_id)
                self.metrics.record_indexed(event_type, 0.0)
                self.metrics.flush_indexed += 1
                indexed += 1
            else:
                self._queue.mark_failed(queue_id)
                self.metrics.record_failed(event_type)
                failed += 1

        return {"attempted": len(pending), "indexed": indexed, "failed": failed}

    def queue_stats(self) -> Dict[str, Any]:
        return self._queue.queue_stats()

    def get_status(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "enabled_event_types": self.get_enabled_types(),
            "registered_handlers": {
                et: len(self._handlers.get(et, [])) for et in ALL_EVENT_TYPES
            },
            "metrics": self.metrics.to_dict(),
            "queue": self.queue_stats(),
        }


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_bus_instance: Optional[EventBus] = None
_bus_lock = threading.Lock()


def get_event_bus() -> EventBus:
    """Return the singleton EventBus instance."""
    global _bus_instance
    if _bus_instance is None:
        with _bus_lock:
            if _bus_instance is None:
                _bus_instance = EventBus()
    return _bus_instance


def register_default_handlers(bus: EventBus) -> None:
    """Register all default TrustGraph indexing handlers on the given bus.

    Idempotent: only attaches a default handler if no handler is already
    registered for that event type. Safe to call multiple times.

    Wired here:
      - finding.created  → UniversalFindingIndexer.index
      - finding.updated  → UniversalFindingIndexer.index
      - asset.discovered → TrustGraphBackbone.index_asset
      - incident.created → TrustGraphBackbone.index_incident
      - control.assessed → TrustGraphBackbone.index_compliance_control
      - vendor.updated   → TrustGraphBackbone.index_vendor (fallback: index_asset)
      - actor.identified → TrustGraphBackbone.index_threat_actor (fallback: indexer)
      - cve.discovered   → UniversalFindingIndexer.index (engine=feed, entity_type=cve)
      - risk.assessed    → KnowledgeBrain.add_node (EntityType.FINDING; fallback: indexer)
    """
    for event_type, handler in _DEFAULT_HANDLERS.items():
        # Only register if no handlers already registered for this event type
        if not bus._handlers.get(event_type):
            bus.on(event_type, handler)
    logger.info("TrustGraph event bus: default handlers registered")


# Backwards-compat alias for the previous private name
_register_default_handlers = register_default_handlers


# ---------------------------------------------------------------------------
# Response Interceptor Middleware
# ---------------------------------------------------------------------------


class ResponseInterceptorMiddleware(BaseHTTPMiddleware):
    """Inspect POST/PUT/PATCH responses for entity IDs, emit events.

    Matches response body JSON for known entity ID keys and emits the
    appropriate event type without blocking the response.

    The response body is only read if:
    - Method is POST, PUT, or PATCH
    - Status code is 200, 201, or 202
    - Content-Type is application/json
    - Body is <= _MAX_BODY_INSPECT bytes
    """

    def __init__(self, app: Any, bus: Optional[EventBus] = None) -> None:
        super().__init__(app)
        self._bus = bus or get_event_bus()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Only intercept mutating methods
        if request.method not in _MUTATING_METHODS:
            return response

        # Only successful responses
        if response.status_code not in (200, 201, 202):
            return response

        # Only JSON responses
        content_type = response.headers.get("content-type", "")
        if "application/json" not in content_type:
            return response

        # Stream response body, consuming it safely
        try:
            body_chunks: List[bytes] = []
            total_size = 0
            async for chunk in response.body_iterator:
                total_size += len(chunk)
                if total_size > _MAX_BODY_INSPECT:
                    # Too large — reassemble and skip inspection
                    body_chunks.append(chunk)
                    async for remaining in response.body_iterator:
                        body_chunks.append(remaining)
                    body = b"".join(body_chunks)
                    return _rebuild_response(response, body)
                body_chunks.append(chunk)

            body = b"".join(body_chunks)
        except Exception as exc:
            logger.debug("ResponseInterceptor: body read error", error=str(exc))
            return response

        # Parse and inspect
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return _rebuild_response(response, body)

        if isinstance(data, (dict, list)):
            asyncio.ensure_future(self._inspect_and_emit(request, data))

        return _rebuild_response(response, body)

    async def _inspect_and_emit(self, request: Request, data: Any) -> None:
        """Check body for entity ID keys and emit appropriate events.

        Walks nested wrapper shapes recursively (max depth 3) so envelopes
        like {"data": {"finding_id": ...}}, {"result": [...]} and
        {"items": [{...}, {...}]} are correctly unwrapped before ID matching.
        """
        if not self._bus.enabled:
            return

        # Determine if this is a create or update from request method
        is_update = request.method in ("PUT", "PATCH")

        emitted: Set[str] = set()

        # Collect all candidate dicts from the response (root + nested wrappers).
        candidates = _collect_id_candidates(data, max_depth=_MAX_UNWRAP_DEPTH)

        for candidate in candidates:
            for key, (base_event_type, _label) in _RESPONSE_KEY_MAP.items():
                if key not in candidate:
                    continue
                # The bare "id" key only fires if no specific *_id matched
                # this candidate yet — avoids generic event spam when a
                # specific entity ID is also present.
                if key == "id" and any(
                    other_key in candidate
                    for other_key in _RESPONSE_KEY_MAP
                    if other_key != "id"
                ):
                    continue

                # Adjust event type for updates vs creates
                if is_update and base_event_type == EVENT_FINDING_CREATED:
                    event_type = EVENT_FINDING_UPDATED
                else:
                    event_type = base_event_type

                if event_type not in emitted:
                    emitted.add(event_type)
                    await self._bus.emit(event_type, candidate)
                    logger.debug(
                        "ResponseInterceptor: emitted event",
                        event_type=event_type,
                        path=request.url.path,
                        key=key,
                    )


def _collect_id_candidates(
    data: Any,
    max_depth: int = _MAX_UNWRAP_DEPTH,
    _depth: int = 0,
    _seen_ids: Optional[Set[int]] = None,
) -> List[Dict[str, Any]]:
    """Recursively walk a response body to collect all dict candidates that
    might contain an entity ID.

    Handles wrapper shapes:
      - {"data": {...}}            -> [{...}]
      - {"result": {...}}          -> [{...}]
      - {"items": [{...}, {...}]}  -> [{...}, {...}]
      - {"data": {"items": [...]}} -> recurses both layers

    Returns at most ~32 dicts (limit guards against pathological payloads
    such as large lists). Aborts gracefully on non-dict/list / cycles.
    """
    if _seen_ids is None:
        _seen_ids = set()

    out: List[Dict[str, Any]] = []
    if data is None or _depth > max_depth:
        return out

    # Cycle / repeated-object guard
    obj_id = id(data)
    if obj_id in _seen_ids:
        return out
    _seen_ids.add(obj_id)

    if isinstance(data, dict):
        out.append(data)
        # Walk wrapper keys
        for wrapper in _WRAPPER_KEYS:
            if wrapper in data:
                child = data[wrapper]
                out.extend(
                    _collect_id_candidates(child, max_depth, _depth + 1, _seen_ids)
                )
                if len(out) >= 32:
                    break
    elif isinstance(data, list):
        # Limit list expansion — don't blow up on huge collections.
        for item in data[:8]:
            out.extend(_collect_id_candidates(item, max_depth, _depth + 1, _seen_ids))
            if len(out) >= 32:
                break

    return out


def _rebuild_response(original: Response, body: bytes) -> Response:
    """Reconstruct a Response with the consumed body bytes."""
    from starlette.responses import Response as StarletteResponse

    return StarletteResponse(
        content=body,
        status_code=original.status_code,
        headers=dict(original.headers),
        media_type=original.media_type,
    )


# ---------------------------------------------------------------------------
# App integration
# ---------------------------------------------------------------------------


def init_event_bus(app: Any) -> EventBus:
    """Wire EventBus into a FastAPI app.

    - Adds ResponseInterceptorMiddleware
    - Registers default TrustGraph handlers on startup
    - Returns the singleton bus for further customization

    Args:
        app: FastAPI application instance.

    Returns:
        The configured EventBus singleton.
    """
    bus = get_event_bus()

    if not bus.enabled:
        logger.info("TrustGraph EventBus is disabled — skipping wiring")
        return bus

    # Register response interceptor middleware
    app.add_middleware(ResponseInterceptorMiddleware, bus=bus)
    logger.info("TrustGraph EventBus: ResponseInterceptorMiddleware wired")

    # Register default handlers immediately so any synchronous emit() during
    # startup (or in CLI / non-FastAPI contexts) is wired even before the
    # FastAPI startup event fires.
    register_default_handlers(bus)

    # Re-register at startup (idempotent) and flush any events that were
    # queued before TrustGraph came online.
    @app.on_event("startup")
    async def _startup_register_handlers() -> None:
        register_default_handlers(bus)
        # Flush any events queued from a previous run
        result = await bus.flush_queue()
        if result["attempted"] > 0:
            logger.info(
                "TrustGraph EventBus: startup flush completed",
                attempted=result["attempted"],
                indexed=result["indexed"],
                failed=result["failed"],
            )

    return bus


# ---------------------------------------------------------------------------
# Module-load registration (CLI / non-FastAPI contexts)
# ---------------------------------------------------------------------------
# When the module is imported in CLI mode (no FastAPI app), the singleton
# bus is still created on first get_event_bus() call. Wire default handlers
# at that point so emit() fires real handlers even outside a FastAPI app.
# Skipped under FIXOPS_TEST_MODE so unit tests can exercise empty-bus paths.

def _eager_register_at_module_load() -> None:
    if os.getenv("FIXOPS_TEST_MODE", "0") == "1":
        return
    if os.getenv("TRUSTGRAPH_EVENT_BUS_ENABLED", "1") == "0":
        return
    if os.getenv("TRUSTGRAPH_EVENT_BUS_AUTO_REGISTER", "1") == "0":
        return
    try:
        bus = get_event_bus()
        if bus.enabled:
            register_default_handlers(bus)
    except Exception as exc:  # noqa: BLE001 — never crash on import
        logger.debug("TrustGraph EventBus: module-load registration skipped", error=str(exc))


_eager_register_at_module_load()
