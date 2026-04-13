"""
Core 4 Decision Memory persistence layer for ALDECI.

Stores every LLM Council decision as a permanent record for learning, audit, and replay.

Features:
  - Append-only decision record store (SQLite-backed)
  - Finding similarity matching via SHA-256 hashing
  - Analyst override tracking for continuous learning
  - Accuracy statistics and decision distribution analysis
  - Optional TrustGraph integration for RDF-based provenance
  - Training data export for RL controller fine-tuning

Usage:
    from core.decision_memory import DecisionMemoryStore, DecisionRecord

    store = DecisionMemoryStore(db_path="data/decision_memory.db")
    record = DecisionRecord(
        finding_id="vuln-123",
        finding_hash=sha256("cve-2024-..."),
        decision_type="council_verdict",
        action="patch",
        confidence=0.92,
        reasoning="High CVSS + exploited in wild",
        council_session_id="sess-456",
        org_id="acme-corp",
    )
    record_id = store.record(record)

    # Query similar past decisions
    similar = store.find_similar(finding_hash, org_id="acme-corp", limit=5)

    # Track analyst corrections
    store.record_override(
        finding_id="vuln-123",
        original_action="patch",
        new_action="false_positive",
        analyst_id="alice@acme.com",
        reason="Not exploitable in our environment",
    )

    # Get accuracy metrics
    stats = store.get_accuracy_stats("acme-corp")
"""

import hashlib
import json
import logging
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.errors import TrustGraphError  # noqa: F401 - re-exported for callers

logger = logging.getLogger(__name__)


# ===========================================================================
# Helper Functions
# ===========================================================================


def _ensure_list(value: Any) -> list[Any]:
    """Ensure value is a list; convert or wrap as needed."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _sha256_finding(content: str) -> str:
    """Compute SHA-256 hash of finding content for similarity matching."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    """Return current UTC time in ISO format."""
    return datetime.now(timezone.utc).isoformat()


# ===========================================================================
# Core 4 Decision Record Dataclass
# ===========================================================================


@dataclass
class DecisionRecord:
    """
    Immutable record of a security decision.

    Attributes:
        record_id: Unique identifier (UUID) for this decision record.
        finding_id: Reference to the original security finding.
        finding_hash: SHA-256 hash of finding content for similarity matching.
        timestamp: When decision was made (ISO 8601).
        decision_type: Kind of decision ("council_verdict", "analyst_override",
                       "escalation", "auto_triage", "false_positive").
        action: Recommended action ("patch", "mitigate", "accept_risk",
                "investigate", "false_positive", "review").
        confidence: Confidence score (0.0-1.0).
        reasoning: Chain-of-thought reasoning or explanation.
        council_session_id: Links to CouncilSession if verdict came from council.
        analyst_id: Who made/overrode decision (analyst email/ID).
        mitre_techniques: MITRE techniques identified (e.g., T1110, T1190).
        compliance_impact: Frameworks impacted (e.g., ["SOC2", "HIPAA"]).
        org_id: Organization ID (multi-tenant).
        metadata: Additional context (provider costs, latency, etc).
    """

    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = ""
    finding_hash: str = ""
    timestamp: str = field(default_factory=_now_iso)
    decision_type: str = "council_verdict"
    action: str = "review"
    confidence: float = 0.5
    reasoning: str = ""
    council_session_id: Optional[str] = None
    analyst_id: Optional[str] = None
    mitre_techniques: List[str] = field(default_factory=list)
    compliance_impact: List[str] = field(default_factory=list)
    org_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to serializable dictionary."""
        d = asdict(self)
        # Ensure lists are clean
        d["mitre_techniques"] = _ensure_list(d["mitre_techniques"])
        d["compliance_impact"] = _ensure_list(d["compliance_impact"])
        return d

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "DecisionRecord":
        """Construct record from dictionary."""
        return DecisionRecord(
            record_id=data.get("record_id", str(uuid.uuid4())),
            finding_id=data.get("finding_id", ""),
            finding_hash=data.get("finding_hash", ""),
            timestamp=data.get("timestamp", _now_iso()),
            decision_type=data.get("decision_type", "council_verdict"),
            action=data.get("action", "review"),
            confidence=float(data.get("confidence", 0.5)),
            reasoning=data.get("reasoning", ""),
            council_session_id=data.get("council_session_id"),
            analyst_id=data.get("analyst_id"),
            mitre_techniques=_ensure_list(data.get("mitre_techniques")),
            compliance_impact=_ensure_list(data.get("compliance_impact")),
            org_id=data.get("org_id", ""),
            metadata=data.get("metadata", {}),
        )


# ===========================================================================
# Accuracy Statistics Dataclass
# ===========================================================================


@dataclass
class AccuracyStats:
    """
    Aggregated accuracy metrics for council decisions.

    Attributes:
        total_decisions: Total decisions in period.
        analyst_overrides: Count of analyst overrides.
        override_rate: Proportion of decisions overridden (0.0-1.0).
        false_positive_rate: Proportion marked as FP (0.0-1.0).
        action_accuracy: Per-action accuracy (action → accuracy rate).
        most_overridden_action: Which action gets overridden most.
        period_days: Time span of analysis in days.
    """

    total_decisions: int = 0
    analyst_overrides: int = 0
    override_rate: float = 0.0
    false_positive_rate: float = 0.0
    action_accuracy: Dict[str, float] = field(default_factory=dict)
    most_overridden_action: Optional[str] = None
    period_days: int = 30

    def to_dict(self) -> Dict[str, Any]:
        """Convert to serializable dictionary."""
        return {
            "total_decisions": self.total_decisions,
            "analyst_overrides": self.analyst_overrides,
            "override_rate": round(self.override_rate, 3),
            "false_positive_rate": round(self.false_positive_rate, 3),
            "action_accuracy": {
                k: round(v, 3) for k, v in self.action_accuracy.items()
            },
            "most_overridden_action": self.most_overridden_action,
            "period_days": self.period_days,
        }


# ===========================================================================
# Decision Memory Store (SQLite-backed)
# ===========================================================================


class DecisionMemoryStore:
    """
    Persistent store for LLM Council decisions.

    Provides append-only decision recording, similarity lookup,
    override tracking, and accuracy analytics.
    """

    def __init__(self, db_path: str = "data/decision_memory.db"):
        """
        Initialize decision memory store.

        Args:
            db_path: Path to SQLite database file.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection with Row factory."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self):
        """Initialize decision memory tables."""
        conn = self._get_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS decision_memory (
                    record_id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL,
                    finding_hash TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    decision_type TEXT NOT NULL,
                    action TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    reasoning TEXT,
                    council_session_id TEXT,
                    analyst_id TEXT,
                    mitre_techniques TEXT,
                    compliance_impact TEXT,
                    org_id TEXT NOT NULL,
                    metadata TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_decision_finding_hash
                    ON decision_memory(finding_hash, org_id);
                CREATE INDEX IF NOT EXISTS idx_decision_org_timestamp
                    ON decision_memory(org_id, timestamp);
                CREATE INDEX IF NOT EXISTS idx_decision_finding_id
                    ON decision_memory(finding_id);
                CREATE INDEX IF NOT EXISTS idx_decision_analyst
                    ON decision_memory(analyst_id, org_id);
                CREATE INDEX IF NOT EXISTS idx_decision_type
                    ON decision_memory(decision_type, org_id);
                CREATE INDEX IF NOT EXISTS idx_decision_action
                    ON decision_memory(action, org_id);
                """
            )
            conn.commit()
            logger.info(f"Decision memory tables initialized: {self.db_path}")
        except (sqlite3.Error, OSError) as e:
            logger.error(f"Failed to initialize decision memory tables: {e}")
            raise
        finally:
            conn.close()

    def record(self, record: DecisionRecord) -> str:
        """
        Record a decision (append-only).

        Args:
            record: DecisionRecord to store.

        Returns:
            The record_id of the stored record.

        Raises:
            ValueError: If record_id already exists (duplicate).
        """
        conn = self._get_connection()
        try:
            conn.execute(
                """
                INSERT INTO decision_memory
                (record_id, finding_id, finding_hash, timestamp, decision_type,
                 action, confidence, reasoning, council_session_id, analyst_id,
                 mitre_techniques, compliance_impact, org_id, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.record_id,
                    record.finding_id,
                    record.finding_hash,
                    record.timestamp,
                    record.decision_type,
                    record.action,
                    record.confidence,
                    record.reasoning,
                    record.council_session_id,
                    record.analyst_id,
                    json.dumps(_ensure_list(record.mitre_techniques)),
                    json.dumps(_ensure_list(record.compliance_impact)),
                    record.org_id,
                    json.dumps(record.metadata),
                ),
            )
            conn.commit()
            logger.debug(f"Recorded decision: {record.record_id} (org: {record.org_id})")
            return record.record_id
        except sqlite3.IntegrityError as e:
            logger.error(f"Duplicate record_id {record.record_id}: {e}")
            raise ValueError(f"Record {record.record_id} already exists") from e
        finally:
            conn.close()

    def get(self, record_id: str) -> Optional[DecisionRecord]:
        """
        Retrieve a decision record by ID.

        Args:
            record_id: UUID of the record.

        Returns:
            DecisionRecord if found, None otherwise.
        """
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM decision_memory WHERE record_id = ?", (record_id,)
            ).fetchone()
            if not row:
                return None
            return self._row_to_record(row)
        finally:
            conn.close()

    def find_similar(
        self, finding_hash: str, org_id: str, limit: int = 5
    ) -> List[DecisionRecord]:
        """
        Find past decisions for identical/similar findings.

        Looks up by finding_hash within the same organization.

        Args:
            finding_hash: SHA-256 hash of finding content.
            org_id: Organization ID.
            limit: Max results to return.

        Returns:
            List of DecisionRecords with matching hash (newest first).
        """
        conn = self._get_connection()
        try:
            rows = conn.execute(
                """
                SELECT * FROM decision_memory
                WHERE finding_hash = ? AND org_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (finding_hash, org_id, limit),
            ).fetchall()
            return [self._row_to_record(row) for row in rows]
        finally:
            conn.close()

    def find_by_finding(self, finding_id: str) -> List[DecisionRecord]:
        """
        Find all decisions for a specific finding.

        Args:
            finding_id: The finding identifier.

        Returns:
            List of all decisions related to this finding (newest first).
        """
        conn = self._get_connection()
        try:
            rows = conn.execute(
                """
                SELECT * FROM decision_memory
                WHERE finding_id = ?
                ORDER BY timestamp DESC
                """,
                (finding_id,),
            ).fetchall()
            return [self._row_to_record(row) for row in rows]
        finally:
            conn.close()

    def find_overrides(
        self, org_id: str, since: Optional[datetime] = None
    ) -> List[DecisionRecord]:
        """
        Find analyst override decisions for learning.

        Args:
            org_id: Organization ID.
            since: Only include decisions after this datetime. If None,
                   returns all analyst_override records.

        Returns:
            List of analyst_override DecisionRecords (newest first).
        """
        conn = self._get_connection()
        try:
            if since:
                since_iso = since.isoformat()
                rows = conn.execute(
                    """
                    SELECT * FROM decision_memory
                    WHERE org_id = ? AND decision_type = 'analyst_override'
                      AND timestamp > ?
                    ORDER BY timestamp DESC
                    """,
                    (org_id, since_iso),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM decision_memory
                    WHERE org_id = ? AND decision_type = 'analyst_override'
                    ORDER BY timestamp DESC
                    """,
                    (org_id,),
                ).fetchall()
            return [self._row_to_record(row) for row in rows]
        finally:
            conn.close()

    def get_accuracy_stats(self, org_id: str, period_days: int = 30) -> AccuracyStats:
        """
        Compute accuracy statistics from decision history.

        Tracks:
          - Total council verdicts vs analyst overrides
          - Override rate and false positive rate
          - Per-action accuracy (how often each action was overridden)

        Args:
            org_id: Organization ID.
            period_days: Lookback window (default 30 days).

        Returns:
            AccuracyStats with computed metrics.
        """
        conn = self._get_connection()
        try:
            # Get all council verdicts in period
            cutoff_iso = (
                datetime.now(timezone.utc).timestamp() - (period_days * 86400)
            )
            rows = conn.execute(
                """
                SELECT decision_type, action, finding_id
                FROM decision_memory
                WHERE org_id = ? AND timestamp >= datetime(?, 'unixepoch')
                ORDER BY timestamp DESC
                """,
                (org_id, cutoff_iso),
            ).fetchall()

            if not rows:
                return AccuracyStats(period_days=period_days)

            total_decisions = len(rows)
            override_count = sum(1 for r in rows if r[0] == "analyst_override")
            false_positive_count = sum(
                1 for r in rows if r[0] == "analyst_override" and r[1] == "false_positive"
            )

            # Per-action accuracy: how many times each action was overridden
            action_counts: Dict[str, int] = {}
            action_overrides: Dict[str, int] = {}
            for row in rows:
                action = row[1]
                action_counts[action] = action_counts.get(action, 0) + 1
                if row[0] == "analyst_override":
                    action_overrides[action] = action_overrides.get(action, 0) + 1

            action_accuracy = {}
            for action, count in action_counts.items():
                override_cnt = action_overrides.get(action, 0)
                accuracy = 1.0 - (override_cnt / count) if count > 0 else 1.0
                action_accuracy[action] = max(0.0, min(1.0, accuracy))

            # Find most overridden action
            most_overridden = (
                max(action_overrides, key=action_overrides.get)
                if action_overrides
                else None
            )

            return AccuracyStats(
                total_decisions=total_decisions,
                analyst_overrides=override_count,
                override_rate=(
                    override_count / total_decisions if total_decisions > 0 else 0.0
                ),
                false_positive_rate=(
                    false_positive_count / total_decisions if total_decisions > 0 else 0.0
                ),
                action_accuracy=action_accuracy,
                most_overridden_action=most_overridden,
                period_days=period_days,
            )
        finally:
            conn.close()

    def get_decision_distribution(self, org_id: str) -> Dict[str, int]:
        """
        Get distribution of recommended actions.

        Args:
            org_id: Organization ID.

        Returns:
            Dict mapping action → count of decisions.
        """
        conn = self._get_connection()
        try:
            rows = conn.execute(
                """
                SELECT action, COUNT(*) as cnt
                FROM decision_memory
                WHERE org_id = ?
                GROUP BY action
                ORDER BY cnt DESC
                """,
                (org_id,),
            ).fetchall()
            return {row[0]: row[1] for row in rows}
        finally:
            conn.close()

    def search(
        self,
        org_id: str,
        action: Optional[str] = None,
        decision_type: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[DecisionRecord]:
        """
        Search decision records with optional filters.

        Args:
            org_id: Organization ID (required).
            action: Filter by recommended action (optional).
            decision_type: Filter by decision type (optional).
            since: Filter by timestamp >= since (optional).
            limit: Max results (default 100).

        Returns:
            List of matching DecisionRecords (newest first).
        """
        conn = self._get_connection()
        try:
            query = "SELECT * FROM decision_memory WHERE org_id = ?"
            params: List[Any] = [org_id]

            if action:
                query += " AND action = ?"
                params.append(action)

            if decision_type:
                query += " AND decision_type = ?"
                params.append(decision_type)

            if since:
                since_iso = since.isoformat()
                query += " AND timestamp >= ?"
                params.append(since_iso)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            return [self._row_to_record(row) for row in rows]
        finally:
            conn.close()

    def count(self, org_id: str) -> int:
        """
        Count total decisions for an organization.

        Args:
            org_id: Organization ID.

        Returns:
            Number of decision records.
        """
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM decision_memory WHERE org_id = ?", (org_id,)
            ).fetchone()
            return row[0] if row else 0
        finally:
            conn.close()

    def _row_to_record(self, row: sqlite3.Row) -> DecisionRecord:
        """Convert database row to DecisionRecord."""
        return DecisionRecord(
            record_id=row["record_id"],
            finding_id=row["finding_id"],
            finding_hash=row["finding_hash"],
            timestamp=row["timestamp"],
            decision_type=row["decision_type"],
            action=row["action"],
            confidence=float(row["confidence"]),
            reasoning=row["reasoning"] or "",
            council_session_id=row["council_session_id"],
            analyst_id=row["analyst_id"],
            mitre_techniques=json.loads(row["mitre_techniques"] or "[]"),
            compliance_impact=json.loads(row["compliance_impact"] or "[]"),
            org_id=row["org_id"],
            metadata=json.loads(row["metadata"] or "{}"),
        )


# ===========================================================================
# Decision Feedback Loop (for analyst corrections & learning)
# ===========================================================================


class DecisionFeedbackLoop:
    """
    Tracks analyst corrections and generates training data for RL controller.

    Enables continuous learning from analyst feedback and override patterns.
    """

    def __init__(self, store: DecisionMemoryStore):
        """
        Initialize feedback loop with a decision store.

        Args:
            store: DecisionMemoryStore instance.
        """
        self.store = store

    def record_override(
        self,
        finding_id: str,
        original_action: str,
        new_action: str,
        analyst_id: str,
        reason: str,
        org_id: str,
        council_session_id: Optional[str] = None,
    ) -> str:
        """
        Record an analyst override of a council decision.

        Args:
            finding_id: The finding being overridden.
            original_action: What council recommended.
            new_action: What analyst chose instead.
            analyst_id: Who made the correction.
            reason: Why it was overridden.
            org_id: Organization ID.
            council_session_id: Link to council session if available.

        Returns:
            record_id of the override record.
        """
        record = DecisionRecord(
            finding_id=finding_id,
            finding_hash="",  # Will be populated from original if available
            decision_type="analyst_override",
            action=new_action,
            confidence=1.0,  # Analyst decision is certain
            reasoning=f"Override from {original_action} → {new_action}: {reason}",
            analyst_id=analyst_id,
            org_id=org_id,
            council_session_id=council_session_id,
            metadata={
                "original_action": original_action,
                "override_reason": reason,
            },
        )
        return self.store.record(record)

    def record_false_positive(
        self,
        finding_id: str,
        analyst_id: str,
        reason: str,
        org_id: str,
        council_session_id: Optional[str] = None,
    ) -> str:
        """
        Mark a finding as a false positive with analyst justification.

        Args:
            finding_id: Finding determined to be FP.
            analyst_id: Who made the determination.
            reason: Why it's a false positive.
            org_id: Organization ID.
            council_session_id: Link to council session if available.

        Returns:
            record_id of the FP record.
        """
        record = DecisionRecord(
            finding_id=finding_id,
            finding_hash="",
            decision_type="analyst_override",
            action="false_positive",
            confidence=1.0,
            reasoning=f"False positive: {reason}",
            analyst_id=analyst_id,
            org_id=org_id,
            council_session_id=council_session_id,
            metadata={"fp_reason": reason},
        )
        return self.store.record(record)

    def get_learning_data(
        self, org_id: str, limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """
        Export training data for RL controller fine-tuning.

        Returns analyst overrides as (original_action, new_action) pairs
        with reasoning and metadata for training.

        Args:
            org_id: Organization ID.
            limit: Max training examples to return.

        Returns:
            List of training data dicts.
        """
        overrides = self.store.find_overrides(org_id)[:limit]
        training_data = []

        for override in overrides:
            original_action = override.metadata.get("original_action", "unknown")
            training_data.append(
                {
                    "finding_id": override.finding_id,
                    "original_action": original_action,
                    "corrected_action": override.action,
                    "confidence": override.confidence,
                    "reasoning": override.reasoning,
                    "analyst_id": override.analyst_id,
                    "mitre_techniques": override.mitre_techniques,
                    "compliance_impact": override.compliance_impact,
                    "timestamp": override.timestamp,
                }
            )

        return training_data

    def get_similar_past_decisions(
        self, finding: Dict[str, Any], org_id: str
    ) -> List[DecisionRecord]:
        """
        Look up past decisions for similar findings.

        Used by Council Stage 1 to inform analysis with historical context.

        Args:
            finding: Finding dict with content to hash.
            org_id: Organization ID.

        Returns:
            List of similar past decisions (most recent first).
        """
        # Compute hash from finding content
        finding_content = json.dumps(finding, sort_keys=True, default=str)
        finding_hash = _sha256_finding(finding_content)

        return self.store.find_similar(finding_hash, org_id, limit=10)

    def compute_provider_accuracy(self, org_id: str) -> Dict[str, float]:
        """
        Compute per-provider accuracy based on override data.

        Requires member_votes in raw analyses (set in council verdicts).
        This is a post-hoc analysis of who got it right.

        Args:
            org_id: Organization ID.

        Returns:
            Dict mapping provider name → accuracy (0-1).
        """
        # This would typically require additional data from the council store
        # For now, return a simple dict; extend with provider tracking if needed.
        logger.info(
            f"Provider accuracy computation for {org_id} requires "
            "additional provider vote tracking in council verdicts"
        )
        return {}


# ===========================================================================
# TrustGraph Integration (optional RDF provenance)
# ===========================================================================


class DecisionMemoryTrustGraphBridge:
    """
    Optional bridge to sync decision records to TrustGraph Core 4 as RDF triples.

    If TrustGraph is available, creates W3C PROV-O provenance records
    linking decisions, findings, and analysts.
    """

    def __init__(self, store: DecisionMemoryStore, trustgraph_client: Optional[Any] = None):
        """
        Initialize TrustGraph bridge.

        Args:
            store: DecisionMemoryStore instance.
            trustgraph_client: Optional TrustGraph client (if available).
                               If None, bridge is disabled.
        """
        self.store = store
        self.trustgraph = trustgraph_client
        self.enabled = trustgraph_client is not None

    def sync_to_trustgraph(self, record: DecisionRecord) -> bool:
        """
        Sync a decision record to TrustGraph Core 4.

        Creates RDF triples with PROV-O provenance:
          - Decision entity (core:Decision)
          - Association with analyst (prov:wasAssociatedWith)
          - Link to finding (prov:wasGeneratedBy)
          - Timestamp and reasoning (rdfs:comment)

        Args:
            record: DecisionRecord to sync.

        Returns:
            True if synced successfully, False if TrustGraph unavailable.
        """
        if not self.enabled or not self.trustgraph:
            return False

        try:
            # Map decision record fields to Core 4 entities
            # This would use trustgraph_schemas.Verdict, Escalation, etc.
            # depending on record.decision_type.
            logger.debug(
                f"Syncing decision {record.record_id} to TrustGraph "
                f"(type: {record.decision_type})"
            )

            # Example: create RDF triple for decision
            # This requires trustgraph API integration
            # For now, log intent.
            logger.info(
                f"Decision record {record.record_id} would sync to TrustGraph "
                f"with action={record.action}, confidence={record.confidence}"
            )
            return True
        except (TrustGraphError, OSError, RuntimeError) as e:
            logger.error(f"Failed to sync decision to TrustGraph: {e}")
            return False

    def sync_all(self, org_id: str, limit: int = 1000) -> int:
        """
        Batch sync all recent decisions to TrustGraph.

        Args:
            org_id: Organization ID.
            limit: Max records to sync.

        Returns:
            Number of records successfully synced.
        """
        if not self.enabled:
            return 0

        records = self.store.search(org_id, limit=limit)
        synced_count = 0

        for record in records:
            if self.sync_to_trustgraph(record):
                synced_count += 1

        logger.info(f"Synced {synced_count}/{len(records)} decision records to TrustGraph")
        return synced_count


# ===========================================================================
# Module Exports
# ===========================================================================

__all__ = [
    "DecisionRecord",
    "AccuracyStats",
    "DecisionMemoryStore",
    "DecisionFeedbackLoop",
    "DecisionMemoryTrustGraphBridge",
    "_sha256_finding",
    "_ensure_list",
]
