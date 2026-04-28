"""TrustGraph Core Router for ALDECI Phase 2.

Route findings from ConnectorGateway to the correct TrustGraph Knowledge Core(s).

The router:
- Takes normalized findings from ConnectorGateway
- Determines routing based on connector metadata, finding type, SDLC stage, content analysis
- Validates findings against Core Pydantic schemas
- Routes to Core ingestion (when TrustGraph available) or local SQLite queue (when unavailable)
- Tracks routing metrics per Core

The 5 Knowledge Cores:
  1. Customer Environment: Assets, configs, deployments, services, repos, containers
  2. Threat Intelligence: CVEs, exploits, attack techniques, threat actors, IOCs
  3. Compliance & Regulatory: Frameworks, controls, evidence, audit results, policy violations
  4. Decision Memory: Past triage decisions, false positives, analyst feedback
  5. Competitive Intelligence: Competitor capabilities, market positioning, feature gaps

Multi-core routing: Some findings span multiple cores (e.g., CVE in a deployed asset → Core 1 + Core 2).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import structlog
from pydantic import BaseModel, ValidationError

from connectors.pull_connector import ConnectorMetadata, SDLCStage
from connectors.trustgraph_schemas import (
    CORE1_ENTITY_TYPES,
    CORE2_ENTITY_TYPES,
    CORE3_ENTITY_TYPES,
    CORE4_ENTITY_TYPES,
    CORE5_ENTITY_TYPES,
    KnowledgeCoreManager,
)

logger = structlog.get_logger("connectors.core_router")


# ---------------------------------------------------------------------------
# Core Routing Result and Models
# ---------------------------------------------------------------------------


@dataclass
class CoreRoutingResult:
    """Result of routing a finding to Core(s)."""

    finding_id: str
    connector_name: str
    routed_cores: List[int] = field(default_factory=list)
    """Core IDs (1-5) the finding was routed to."""

    queued_cores: List[int] = field(default_factory=list)
    """Core IDs where finding was queued (TrustGraph unavailable)."""

    validation_errors: Dict[int, str] = field(default_factory=dict)
    """Validation errors per Core (core_id -> error message)."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    """Timestamp of routing decision."""

    metadata: Dict[str, Any] = field(default_factory=dict)
    """Additional routing metadata."""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "connector_name": self.connector_name,
            "routed_cores": self.routed_cores,
            "queued_cores": self.queued_cores,
            "validation_errors": self.validation_errors,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Core Routing Rules
# ---------------------------------------------------------------------------


class CoreRoutingRules:
    """Deterministic rules for routing findings to Knowledge Cores.

    Rules consider:
    - Connector metadata (target_cores, sdlc_stages)
    - Finding type and attributes (severity, source, entity type)
    - SDLC stage context
    - Content keywords and patterns
    """

    # Keywords indicating Core 1 (Customer Environment) findings
    CORE1_KEYWORDS = {
        "asset", "deployment", "service", "repository", "container", "artifact",
        "cluster", "pod", "namespace", "endpoint", "api", "cloud", "account",
        "iam", "role", "policy", "network", "datastore", "configuration",
        "pipeline", "pullrequest", "commit", "branch", "sbom", "inventory",
    }

    # Keywords indicating Core 2 (Threat Intelligence) findings
    CORE2_KEYWORDS = {
        "cve", "exploit", "vulnerability", "threat", "actor", "campaign",
        "ioc", "indicator", "malware", "attack", "technique", "tactic",
        "weakness", "cwe", "capec", "advisory", "cvss", "epss", "kev",
        "ransomware", "trojan", "worm", "botnet",
    }

    # Keywords indicating Core 3 (Compliance & Regulatory) findings
    CORE3_KEYWORDS = {
        "compliance", "framework", "control", "requirement", "evidence",
        "audit", "assessment", "gap", "policy", "regulation", "gdpr",
        "hipaa", "pci-dss", "nist", "iso27001", "sox", "classification",
        "consent", "retention", "data_protection",
    }

    # Keywords indicating Core 4 (Decision Memory) findings
    CORE4_KEYWORDS = {
        "triage", "verdict", "decision", "escalation", "remediation",
        "false_positive", "accepted_risk", "playbook", "incident",
        "council", "vote", "roi", "metric", "measured",
    }

    # Keywords indicating Core 5 (Competitive Intelligence) findings
    CORE5_KEYWORDS = {
        "competitor", "product", "feature", "integration", "pricing",
        "market", "segment", "competing", "competitive",
    }

    @staticmethod
    def extract_keywords(text: str) -> Set[str]:
        """Extract lowercase keywords from text."""
        if not text:
            return set()
        text = text.lower()
        # Simple word extraction: split on non-alphanumeric, remove empty
        words = {w for w in text.split() if w and w.replace("_", "").replace("-", "").isalnum()}
        return words

    @classmethod
    def match_keywords(cls, text: str, keyword_set: Set[str]) -> int:
        """Count how many keywords from keyword_set match the text.

        Args:
            text: Text to search.
            keyword_set: Set of keywords to match.

        Returns:
            Count of matched keywords.
        """
        if not text:
            return 0
        words = cls.extract_keywords(text)
        return len(words & keyword_set)

    @classmethod
    def determine_cores(
        cls,
        finding: Dict[str, Any],
        connector_meta: ConnectorMetadata,
        sdlc_stage: Optional[SDLCStage] = None,
    ) -> Set[int]:
        """Determine which Core(s) a finding belongs to.

        Multi-core routing: Returns a set of Core IDs (1-5).

        Args:
            finding: Normalized finding dict.
            connector_meta: Connector metadata.
            sdlc_stage: Optional SDLC stage context.

        Returns:
            Set of Core IDs (1-5) the finding should route to.
        """
        cores = set()

        # Start with connector's declared target cores
        cores.update(connector_meta.target_cores)

        # If SDLC stage is CODE/BUILD, likely has environment assets → Core 1
        if sdlc_stage in (SDLCStage.CODE, SDLCStage.BUILD):
            cores.add(1)

        # If SDLC stage is DEPLOY/OPERATE, likely has environment assets → Core 1
        if sdlc_stage in (SDLCStage.DEPLOY, SDLCStage.OPERATE):
            cores.add(1)

        # Extract text fields for keyword matching
        title = finding.get("title", "")
        description = finding.get("description", "")
        source = finding.get("source", "")
        combined_text = f"{title} {description} {source}".lower()

        # Content-based routing: score each core by keyword matches
        core1_score = cls.match_keywords(combined_text, cls.CORE1_KEYWORDS)
        core2_score = cls.match_keywords(combined_text, cls.CORE2_KEYWORDS)
        core3_score = cls.match_keywords(combined_text, cls.CORE3_KEYWORDS)
        core4_score = cls.match_keywords(combined_text, cls.CORE4_KEYWORDS)
        core5_score = cls.match_keywords(combined_text, cls.CORE5_KEYWORDS)

        # Add cores with strong keyword matches (score >= 2)
        if core1_score >= 2:
            cores.add(1)
        if core2_score >= 2:
            cores.add(2)
        if core3_score >= 2:
            cores.add(3)
        if core4_score >= 2:
            cores.add(4)
        if core5_score >= 2:
            cores.add(5)

        # Heuristic: if "vulnerability" or "cve" in title, add Core 2 (Threat Intelligence)
        if any(kw in title.lower() for kw in ["vulnerability", "cve", "exploit"]):
            cores.add(2)

        # Heuristic: if "compliance", "framework", or "control" in title, add Core 3
        if any(kw in title.lower() for kw in ["compliance", "framework", "control", "audit"]):
            cores.add(3)

        # Heuristic: if finding source is "manual_triage" or "analyst", add Core 4
        if source.lower() in ("manual_triage", "analyst", "council", "verdict"):
            cores.add(4)

        # Ensure we always have at least one core (fallback to Core 1)
        if not cores:
            cores.add(1)

        return cores


# ---------------------------------------------------------------------------
# Core Validator
# ---------------------------------------------------------------------------


class CoreValidator:
    """Validates and transforms findings for TrustGraph Knowledge Cores.

    Uses Pydantic models from trustgraph_schemas to validate finding shape.
    """

    # Map Core ID -> entity type models dict
    CORE_ENTITY_MAPS = {
        1: CORE1_ENTITY_TYPES,
        2: CORE2_ENTITY_TYPES,
        3: CORE3_ENTITY_TYPES,
        4: CORE4_ENTITY_TYPES,
        5: CORE5_ENTITY_TYPES,
    }

    @classmethod
    def validate_for_core(
        cls, finding: Dict[str, Any], core_id: int
    ) -> Tuple[bool, Optional[str], Optional[BaseModel]]:
        """Validate finding against a Core's schema.

        Args:
            finding: Normalized finding dict.
            core_id: Target Core ID (1-5).

        Returns:
            Tuple: (is_valid, error_message, validated_model)
        """
        if core_id not in cls.CORE_ENTITY_MAPS:
            return False, f"Invalid core_id {core_id}", None

        entity_types = cls.CORE_ENTITY_MAPS[core_id]

        # Infer entity type from finding attributes
        entity_type = cls._infer_entity_type(finding, core_id)

        if not entity_type:
            return False, f"Could not infer entity type for Core {core_id}", None

        model_class = entity_types.get(entity_type)
        if not model_class:
            return False, f"Unknown entity type {entity_type} for Core {core_id}", None

        try:
            # Attempt to instantiate Pydantic model
            instance = model_class(**finding)
            return True, None, instance
        except ValidationError as e:
            return False, str(e), None

    @classmethod
    def _infer_entity_type(cls, finding: Dict[str, Any], core_id: int) -> Optional[str]:
        """Infer the entity type of a finding for a given Core.

        Args:
            finding: Normalized finding dict.
            core_id: Target Core ID.

        Returns:
            Entity type name (string) or None.
        """
        finding_type = finding.get("type", "").lower()
        source = finding.get("source", "").lower()
        title = finding.get("title", "").lower()
        combined = f"{finding_type} {source} {title}".lower()

        if core_id == 1:
            # Customer Environment core
            if any(k in combined for k in ["asset", "inventory"]):
                return "Service"
            if any(k in combined for k in ["repository", "repo", "github"]):
                return "Repository"
            if any(k in combined for k in ["container", "docker", "image"]):
                return "Container"
            if any(k in combined for k in ["kubernetes", "k8s", "pod"]):
                return "Pod"
            if any(k in combined for k in ["cloud", "aws", "gcp", "azure", "account"]):
                return "CloudAccount"
            if any(k in combined for k in ["endpoint", "host", "server"]):
                return "Endpoint"
            if any(k in combined for k in ["api", "endpoint"]):
                return "APIEndpoint"
            if any(k in combined for k in ["finding", "issue", "vulnerability"]):
                return "Finding"
            if any(k in combined for k in ["sbom", "bill_of_materials"]):
                return "SBOM"
            if any(k in combined for k in ["pipeline", "ci/cd"]):
                return "Pipeline"
            return "Finding"

        elif core_id == 2:
            # Threat Intelligence core
            if any(k in combined for k in ["cve", "vulnerability"]):
                return "CVE"
            if any(k in combined for k in ["exploit", "poc"]):
                return "Exploit"
            if any(k in combined for k in ["threat", "actor", "group"]):
                return "ThreatActor"
            if any(k in combined for k in ["campaign", "attack"]):
                return "Campaign"
            if any(k in combined for k in ["ioc", "indicator"]):
                return "Indicator"
            if any(k in combined for k in ["technique", "tactic"]):
                return "ATTACKTechnique"
            if any(k in combined for k in ["advisory"]):
                return "Advisory"
            if any(k in combined for k in ["cwe", "weakness"]):
                return "CWE"
            return "CVE"

        elif core_id == 3:
            # Compliance & Regulatory core
            if any(k in combined for k in ["framework", "standard"]):
                return "Framework"
            if any(k in combined for k in ["control"]):
                return "Control"
            if any(k in combined for k in ["requirement"]):
                return "Requirement"
            if any(k in combined for k in ["evidence", "audit"]):
                return "Evidence"
            if any(k in combined for k in ["assessment", "audit"]):
                return "Assessment"
            if any(k in combined for k in ["gap", "violation"]):
                return "Gap"
            if any(k in combined for k in ["policy"]):
                return "Policy"
            if any(k in combined for k in ["classification", "sensitivity"]):
                return "DataClassification"
            return "Gap"

        elif core_id == 4:
            # Decision Memory core
            if any(k in combined for k in ["triage", "triaged"]):
                return "Triage"
            if any(k in combined for k in ["verdict", "decision"]):
                return "Verdict"
            if any(k in combined for k in ["remediation", "remediate", "fix"]):
                return "Remediation"
            if any(k in combined for k in ["escalation", "escalate"]):
                return "Escalation"
            if any(k in combined for k in ["incident", "breach"]):
                return "Incident"
            if any(k in combined for k in ["playbook", "runbook"]):
                return "Playbook"
            if any(k in combined for k in ["council", "session"]):
                return "CouncilSession"
            if any(k in combined for k in ["vote", "voted"]):
                return "Vote"
            return "Verdict"

        elif core_id == 5:
            # Competitive Intelligence core
            if any(k in combined for k in ["competitor", "competing"]):
                return "Competitor"
            if any(k in combined for k in ["product", "offering"]):
                return "Product"
            if any(k in combined for k in ["feature"]):
                return "Feature"
            if any(k in combined for k in ["integration"]):
                return "Integration"
            if any(k in combined for k in ["pricing", "tier"]):
                return "PricingTier"
            if any(k in combined for k in ["market", "segment"]):
                return "MarketSegment"
            return "Competitor"

        return None


# ---------------------------------------------------------------------------
# Core Queue (SQLite-backed for when TrustGraph is unavailable)
# ---------------------------------------------------------------------------


class CoreQueue:
    """SQLite-backed queue for routing findings when TrustGraph is unavailable.

    Persists findings to a local SQLite database. When TrustGraph comes online,
    drain the queue into the correct cores.

    Table: core_routing_queue
    - id: Auto-increment primary key
    - core_id: Target Core (1-5)
    - entity_type: Inferred entity type (string)
    - finding_id: Finding identifier
    - payload: JSON payload
    - created_at: When the finding was queued
    - status: 'queued', 'synced', 'failed'
    """

    def __init__(self, db_path: str = "./.aldeci/core_routing_queue.db", max_size: int = 10000):
        """Initialize Core Queue.

        Args:
            db_path: Path to SQLite database file.
            max_size: Maximum queue size before evicting oldest entries.
        """
        self.db_path = db_path
        self.max_size = max_size
        self._initialize_db()

    def _initialize_db(self) -> None:
        """Create the queue table if it doesn't exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS core_routing_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    core_id INTEGER NOT NULL,
                    entity_type TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    status TEXT DEFAULT 'queued' CHECK(status IN ('queued', 'synced', 'failed'))
                )
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_core_status
                ON core_routing_queue(core_id, status)
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_finding_id
                ON core_routing_queue(finding_id)
                """
            )
            conn.commit()

    def enqueue(self, core_id: int, entity_type: str, finding: Dict[str, Any]) -> bool:
        """Enqueue a finding for later sync to a Core.

        Args:
            core_id: Target Core ID (1-5).
            entity_type: Inferred entity type.
            finding: Finding dict to queue.

        Returns:
            True if enqueued successfully, False on error.
        """
        try:
            finding_id = finding.get("id", "unknown")
            payload = json.dumps(finding)
            created_at = datetime.now(timezone.utc).isoformat()

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Check queue size and evict oldest if needed
                cursor.execute("SELECT COUNT(*) FROM core_routing_queue")
                (count,) = cursor.fetchone()
                if count >= self.max_size:
                    # Evict oldest queued entries (oldest-first)
                    cursor.execute(
                        """
                        DELETE FROM core_routing_queue WHERE id IN (
                            SELECT id FROM core_routing_queue
                            WHERE status = 'queued'
                            ORDER BY created_at ASC
                            LIMIT ?
                        )
                        """,
                        (count - self.max_size + 1,),
                    )
                    logger.warning(
                        "Core queue exceeded max size; evicted oldest entries",
                        max_size=self.max_size,
                    )

                cursor.execute(
                    """
                    INSERT INTO core_routing_queue
                    (core_id, entity_type, finding_id, payload, created_at, status)
                    VALUES (?, ?, ?, ?, ?, 'queued')
                    """,
                    (core_id, entity_type, finding_id, payload, created_at),
                )
                conn.commit()

            logger.debug(
                "Enqueued finding for Core",
                core_id=core_id,
                finding_id=finding_id,
                entity_type=entity_type,
            )
            return True

        except Exception as e:
            logger.error("Failed to enqueue finding", error=str(e), exc_info=True)
            return False

    def get_pending(self, core_id: Optional[int] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get pending queued findings.

        Args:
            core_id: Optional Core ID to filter by. If None, get all cores.
            limit: Maximum number of records to return.

        Returns:
            List of queued findings.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                if core_id is not None:
                    cursor.execute(
                        """
                        SELECT * FROM core_routing_queue
                        WHERE core_id = ? AND status = 'queued'
                        ORDER BY created_at ASC
                        LIMIT ?
                        """,
                        (core_id, limit),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT * FROM core_routing_queue
                        WHERE status = 'queued'
                        ORDER BY created_at ASC
                        LIMIT ?
                        """,
                        (limit,),
                    )

                rows = cursor.fetchall()
                return [
                    {
                        "id": row["id"],
                        "core_id": row["core_id"],
                        "entity_type": row["entity_type"],
                        "finding_id": row["finding_id"],
                        "payload": json.loads(row["payload"]),
                        "created_at": row["created_at"],
                        "status": row["status"],
                    }
                    for row in rows
                ]

        except Exception as e:
            logger.error("Failed to get pending items", error=str(e), exc_info=True)
            return []

    def mark_synced(self, queue_id: int) -> bool:
        """Mark a queued item as synced.

        Args:
            queue_id: Queue record ID.

        Returns:
            True if successful.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE core_routing_queue SET status = 'synced' WHERE id = ?",
                    (queue_id,),
                )
                conn.commit()
            return True
        except Exception as e:
            logger.error("Failed to mark synced", error=str(e), exc_info=True)
            return False

    def mark_failed(self, queue_id: int) -> bool:
        """Mark a queued item as failed.

        Args:
            queue_id: Queue record ID.

        Returns:
            True if successful.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE core_routing_queue SET status = 'failed' WHERE id = ?",
                    (queue_id,),
                )
                conn.commit()
            return True
        except Exception as e:
            logger.error("Failed to mark failed", error=str(e), exc_info=True)
            return False

    def queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics.

        Returns:
            Dict with queue size, pending count, synced count, failed count per core.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM core_routing_queue")
                (total,) = cursor.fetchone()

                cursor.execute(
                    """
                    SELECT core_id, status, COUNT(*) as count
                    FROM core_routing_queue
                    GROUP BY core_id, status
                    """
                )
                stats = {}
                for row in cursor.fetchall():
                    core_id, status, count = row
                    if core_id not in stats:
                        stats[core_id] = {"queued": 0, "synced": 0, "failed": 0}
                    stats[core_id][status] = count

                return {
                    "total": total,
                    "by_core": stats,
                    "max_size": self.max_size,
                }

        except Exception as e:
            logger.error("Failed to get queue stats", error=str(e), exc_info=True)
            return {"error": str(e)}


# ---------------------------------------------------------------------------
# Core Router
# ---------------------------------------------------------------------------


class CoreRouter:
    """Routes findings from ConnectorGateway to TrustGraph Knowledge Cores.

    High-level responsibilities:
    - Determine target Core(s) for each finding
    - Validate findings against Core schemas
    - Route to Core ingestion (when TrustGraph available)
    - Queue to SQLite (when TrustGraph unavailable)
    - Track routing metrics per Core
    """

    def __init__(
        self,
        trustgraph_client: Optional[Any] = None,
        queue_db_path: str = "./.aldeci/core_routing_queue.db",
        queue_max_size: int = 10000,
    ):
        """Initialize Core Router.

        Args:
            trustgraph_client: TrustGraph client instance (optional).
                               If None, all findings are queued locally.
            queue_db_path: Path to SQLite queue database.
            queue_max_size: Maximum queue size before eviction.
        """
        self._trustgraph = trustgraph_client
        self._queue = CoreQueue(db_path=queue_db_path, max_size=queue_max_size)
        self._core_manager = KnowledgeCoreManager()

        # Metrics
        self._metrics = {
            core_id: {
                "routed": 0,
                "queued": 0,
                "validation_errors": 0,
            }
            for core_id in range(1, 6)
        }
        self._metrics_lock = __import__("threading").Lock()

        logger.info(
            "CoreRouter initialized",
            trustgraph_available=self._trustgraph is not None,
            queue_db=queue_db_path,
        )

    def route_finding_to_cores(
        self, finding: Dict[str, Any], connector_meta: ConnectorMetadata, sdlc_stage: Optional[SDLCStage] = None
    ) -> CoreRoutingResult:
        """Route a normalized finding to the correct Core(s).

        Main entry point: takes a finding from ConnectorGateway and routes it.

        Args:
            finding: Normalized finding dict with id, title, description, source, etc.
            connector_meta: Connector metadata (target_cores, sdlc_stages, etc.).
            sdlc_stage: Optional SDLC stage context.

        Returns:
            CoreRoutingResult with routing decisions and metrics.
        """
        finding_id = finding.get("id", "unknown")
        result = CoreRoutingResult(
            finding_id=finding_id,
            connector_name=connector_meta.name,
        )

        # Determine target Core(s)
        target_cores = CoreRoutingRules.determine_cores(finding, connector_meta, sdlc_stage)

        # Route to each Core
        for core_id in sorted(target_cores):
            # Validate for this Core
            is_valid, error_msg, validated_model = CoreValidator.validate_for_core(finding, core_id)

            if not is_valid:
                result.validation_errors[core_id] = error_msg or "Unknown validation error"
                self._update_metrics(core_id, "validation_errors")
                logger.warning(
                    "Finding validation failed for Core",
                    core_id=core_id,
                    finding_id=finding_id,
                    error=error_msg,
                )
                continue

            # Infer entity type for queue
            entity_type = CoreValidator._infer_entity_type(finding, core_id)

            # Try to route to TrustGraph if available
            if self._trustgraph:
                try:
                    # TODO: Implement actual TrustGraph ingestion call
                    # For now, just log and track
                    logger.info(
                        "Routed finding to Core",
                        core_id=core_id,
                        finding_id=finding_id,
                        entity_type=entity_type,
                        connector=connector_meta.name,
                    )
                    result.routed_cores.append(core_id)
                    self._update_metrics(core_id, "routed")

                except Exception as e:
                    logger.warning(
                        "Failed to route to TrustGraph; queuing instead",
                        core_id=core_id,
                        finding_id=finding_id,
                        error=str(e),
                    )
                    # Fallback to queue
                    if self._queue.enqueue(core_id, entity_type or "Unknown", finding):
                        result.queued_cores.append(core_id)
                        self._update_metrics(core_id, "queued")
            else:
                # TrustGraph not available; queue locally
                if self._queue.enqueue(core_id, entity_type or "Unknown", finding):
                    result.queued_cores.append(core_id)
                    self._update_metrics(core_id, "queued")

        logger.info(
            "Routing complete",
            finding_id=finding_id,
            routed=len(result.routed_cores),
            queued=len(result.queued_cores),
            errors=len(result.validation_errors),
        )

        return result

    def _update_metrics(self, core_id: int, metric_type: str) -> None:
        """Update routing metrics for a Core.

        Args:
            core_id: Core ID (1-5).
            metric_type: 'routed', 'queued', or 'validation_errors'.
        """
        if core_id not in self._metrics:
            return

        with self._metrics_lock:
            self._metrics[core_id][metric_type] += 1

    def get_metrics(self) -> Dict[int, Dict[str, int]]:
        """Get routing metrics per Core.

        Returns:
            Dict: {core_id -> {routed, queued, validation_errors}}
        """
        with self._metrics_lock:
            return {k: dict(v) for k, v in self._metrics.items()}

    def get_queue_stats(self) -> Dict[str, Any]:
        """Get Core Queue statistics.

        Returns:
            Queue stats including pending count per core.
        """
        return self._queue.queue_stats()

    def get_pending_findings(self, core_id: Optional[int] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get pending queued findings.

        Args:
            core_id: Optional Core ID to filter by.
            limit: Maximum findings to return.

        Returns:
            List of pending findings.
        """
        return self._queue.get_pending(core_id=core_id, limit=limit)

    def mark_finding_synced(self, queue_id: int) -> bool:
        """Mark a queued finding as synced to TrustGraph.

        Args:
            queue_id: Queue record ID.

        Returns:
            True if successful.
        """
        return self._queue.mark_synced(queue_id)

    def mark_finding_failed(self, queue_id: int) -> bool:
        """Mark a queued finding as failed.

        Args:
            queue_id: Queue record ID.

        Returns:
            True if successful.
        """
        return self._queue.mark_failed(queue_id)

    def flush_queue_to_core(self, core_id: int, batch_size: int = 100) -> Tuple[int, int]:
        """Drain queued findings for a Core into TrustGraph.

        When TrustGraph becomes available, call this to flush pending findings.

        Args:
            core_id: Target Core ID (1-5).
            batch_size: Process in batches of this size.

        Returns:
            Tuple: (synced_count, failed_count)
        """
        if not self._trustgraph:
            logger.warning("TrustGraph not available; cannot flush queue")
            return 0, 0

        synced = 0
        failed = 0

        while True:
            pending = self._queue.get_pending(core_id=core_id, limit=batch_size)
            if not pending:
                break

            for item in pending:
                try:
                    # TODO: Implement actual TrustGraph ingestion
                    logger.info(
                        "Flushed queued finding to Core",
                        core_id=core_id,
                        finding_id=item["finding_id"],
                        queue_id=item["id"],
                    )
                    self._queue.mark_synced(item["id"])
                    synced += 1

                except Exception as e:
                    logger.error(
                        "Failed to flush queued finding",
                        core_id=core_id,
                        finding_id=item["finding_id"],
                        error=str(e),
                    )
                    self._queue.mark_failed(item["id"])
                    failed += 1

        logger.info(
            "Queue flush complete",
            core_id=core_id,
            synced=synced,
            failed=failed,
        )

        return synced, failed
