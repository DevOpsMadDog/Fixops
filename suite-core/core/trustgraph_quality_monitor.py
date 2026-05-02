"""
TrustGraph Data Quality Monitor for ALDECI.

Tracks what's in the graph, identifies missing connections, orphaned findings,
disconnected assets, and runs quality checks across all 5 Knowledge Cores.

Usage:
    monitor = TrustGraphQualityMonitor()
    report = monitor.get_coverage_report()
    issues = monitor.run_quality_checks()
    orphans = monitor.find_orphaned_findings()
    result = monitor.backfill_missing_data(dry_run=True)
"""

from __future__ import annotations

import logging
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

__all__ = [
    "TrustGraphQualityMonitor",
    "CoverageReport",
    "CoreCoverage",
    "BackfillReport",
    "GraphStats",
    "QualityIssue",
]


# ============================================================================
# Knowledge Core Definitions
# ============================================================================

CORE_DEFINITIONS = {
    1: {
        "name": "Customer Environment",
        "description": "Assets, services, infrastructure inventory",
        "primary_entity_types": ["Service", "Asset", "Host", "Container"],
    },
    2: {
        "name": "Threat Intelligence",
        "description": "Scanner findings, CVEs, threat actors",
        "primary_entity_types": ["CVE", "Finding", "ThreatActor", "Indicator"],
    },
    3: {
        "name": "Compliance",
        "description": "Compliance controls, frameworks, evidence",
        "primary_entity_types": ["Control", "Framework", "Evidence", "Policy"],
    },
    4: {
        "name": "Decision Memory",
        "description": "Incidents, decisions, playbook executions",
        "primary_entity_types": ["Incident", "Decision", "Playbook", "Alert"],
    },
    5: {
        "name": "Risk Registry",
        "description": "Risk entries, exceptions, mitigations",
        "primary_entity_types": ["Risk", "Exception", "Mitigation", "SLA"],
    },
}


# ============================================================================
# Data Classes
# ============================================================================


@dataclass
class CoreCoverage:
    """Coverage statistics for a single Knowledge Core."""

    core_id: int
    core_name: str
    total_entities: int
    connected_entities: int
    orphaned_entities: int
    coverage_pct: float
    entity_type_breakdown: Dict[str, int] = field(default_factory=dict)
    last_updated: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CoverageReport:
    """Overall TrustGraph coverage report across all Knowledge Cores."""

    cores: Dict[int, CoreCoverage]
    total_coverage_pct: float
    total_entities: int
    connected_entities: int
    orphaned_count: int
    last_checked: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["cores"] = {k: v for k, v in d["cores"].items()}
        return d


@dataclass
class BackfillReport:
    """Report from a backfill operation."""

    dry_run: bool
    would_index: int
    actually_indexed: int
    skipped: int
    errors: int
    items: List[Dict[str, Any]] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GraphStats:
    """High-level graph statistics."""

    total_entities: int
    total_relationships: int
    entities_per_core: Dict[int, int]
    relationships_per_core: Dict[int, int]
    coverage_pct: float
    orphaned_count: int
    last_updated: Optional[str]
    db_path: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class QualityIssue:
    """A detected quality issue in TrustGraph data."""

    issue_id: str
    type: str
    severity: str  # critical | high | medium | low
    description: str
    entity_count: int
    auto_fixable: bool
    example_ids: List[str] = field(default_factory=list)
    detected_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================================
# Monitor
# ============================================================================


class TrustGraphQualityMonitor:
    """Monitors TrustGraph data quality and identifies missing connections.

    Works directly against the TrustGraph SQLite database to assess:
    - Coverage per Knowledge Core
    - Orphaned findings not indexed in TrustGraph
    - Disconnected assets with no relationships
    - Data quality issues (missing severity, duplicates, stale entries)
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        """Initialize the quality monitor.

        Args:
            db_path: Path to TrustGraph SQLite DB. Defaults to /tmp/trustgraph.db.
        """
        self.db_path = db_path or "/tmp/trustgraph.db"  # nosec B108
        logger.info("TrustGraphQualityMonitor initialized with db=%s", self.db_path)

    def _get_conn(self) -> sqlite3.Connection:
        """Open a read-write SQLite connection."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _db_exists(self) -> bool:
        """Check if the TrustGraph database file exists."""
        return Path(self.db_path).exists()

    # -------------------------------------------------------------------------
    # get_coverage_report
    # -------------------------------------------------------------------------

    def get_coverage_report(self) -> CoverageReport:
        """Compute coverage % of ALDECI data indexed in TrustGraph per core.

        Returns:
            CoverageReport with per-core stats and overall coverage percentage.
        """
        if not self._db_exists():
            return self._empty_coverage_report()

        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cores: Dict[int, CoreCoverage] = {}
            total_entities = 0
            total_connected = 0
            total_orphaned = 0

            for core_id, core_def in CORE_DEFINITIONS.items():
                # Total entities in this core
                cursor.execute(
                    "SELECT COUNT(*) FROM entities WHERE core_id = ? AND deleted_at IS NULL",
                    (core_id,),
                )
                entity_count = cursor.fetchone()[0]

                # Entities that have at least one relationship (connected)
                cursor.execute(
                    """
                    SELECT COUNT(DISTINCT e.entity_id) FROM entities e
                    WHERE e.core_id = ? AND e.deleted_at IS NULL
                    AND (
                        EXISTS (SELECT 1 FROM relationships r WHERE r.source_id = e.entity_id)
                        OR EXISTS (SELECT 1 FROM relationships r WHERE r.target_id = e.entity_id)
                    )
                    """,
                    (core_id,),
                )
                connected_count = cursor.fetchone()[0]

                orphaned = entity_count - connected_count
                coverage_pct = (connected_count / entity_count * 100.0) if entity_count > 0 else 0.0

                # Type breakdown
                cursor.execute(
                    """
                    SELECT entity_type, COUNT(*) FROM entities
                    WHERE core_id = ? AND deleted_at IS NULL
                    GROUP BY entity_type ORDER BY COUNT(*) DESC
                    """,
                    (core_id,),
                )
                type_breakdown = {row[0]: row[1] for row in cursor.fetchall()}

                # Last updated
                cursor.execute(
                    "SELECT MAX(updated_at) FROM entities WHERE core_id = ? AND deleted_at IS NULL",
                    (core_id,),
                )
                row = cursor.fetchone()
                last_updated = row[0] if row and row[0] else None

                cores[core_id] = CoreCoverage(
                    core_id=core_id,
                    core_name=core_def["name"],
                    total_entities=entity_count,
                    connected_entities=connected_count,
                    orphaned_entities=orphaned,
                    coverage_pct=round(coverage_pct, 2),
                    entity_type_breakdown=type_breakdown,
                    last_updated=last_updated,
                )
                total_entities += entity_count
                total_connected += connected_count
                total_orphaned += orphaned

            total_coverage_pct = (
                round(total_connected / total_entities * 100.0, 2) if total_entities > 0 else 0.0
            )

            return CoverageReport(
                cores=cores,
                total_coverage_pct=total_coverage_pct,
                total_entities=total_entities,
                connected_entities=total_connected,
                orphaned_count=total_orphaned,
                last_checked=datetime.utcnow().isoformat(),
            )
        finally:
            conn.close()

    def _empty_coverage_report(self) -> CoverageReport:
        """Return an empty coverage report when DB doesn't exist."""
        cores = {
            core_id: CoreCoverage(
                core_id=core_id,
                core_name=defn["name"],
                total_entities=0,
                connected_entities=0,
                orphaned_entities=0,
                coverage_pct=0.0,
            )
            for core_id, defn in CORE_DEFINITIONS.items()
        }
        return CoverageReport(
            cores=cores,
            total_coverage_pct=0.0,
            total_entities=0,
            connected_entities=0,
            orphaned_count=0,
            last_checked=datetime.utcnow().isoformat(),
        )

    # -------------------------------------------------------------------------
    # find_orphaned_findings
    # -------------------------------------------------------------------------

    def find_orphaned_findings(self) -> List[Dict[str, Any]]:
        """Find security findings (Core 2) not connected to any other entity.

        Returns:
            List of orphaned finding dicts with entity_id, name, properties.
        """
        if not self._db_exists():
            return []

        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            # Findings in Core 2 with no relationships whatsoever
            cursor.execute(
                """
                SELECT e.entity_id, e.entity_type, e.name, e.properties, e.updated_at
                FROM entities e
                WHERE e.core_id = 2 AND e.deleted_at IS NULL
                AND NOT EXISTS (
                    SELECT 1 FROM relationships r
                    WHERE r.source_id = e.entity_id OR r.target_id = e.entity_id
                )
                ORDER BY e.updated_at DESC
                LIMIT 500
                """
            )
            rows = cursor.fetchall()
            orphans = []
            for row in rows:
                import json
                orphans.append({
                    "entity_id": row["entity_id"],
                    "entity_type": row["entity_type"],
                    "name": row["name"],
                    "properties": json.loads(row["properties"]) if row["properties"] else {},
                    "last_updated": row["updated_at"],
                    "core_id": 2,
                    "issue": "no_relationships",
                })
            return orphans
        finally:
            conn.close()

    # -------------------------------------------------------------------------
    # find_disconnected_assets
    # -------------------------------------------------------------------------

    def find_disconnected_assets(self) -> List[Dict[str, Any]]:
        """Find assets (Core 1) with no TrustGraph relationships.

        Returns:
            List of disconnected asset dicts.
        """
        if not self._db_exists():
            return []

        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT e.entity_id, e.entity_type, e.name, e.properties, e.updated_at
                FROM entities e
                WHERE e.core_id = 1 AND e.deleted_at IS NULL
                AND NOT EXISTS (
                    SELECT 1 FROM relationships r
                    WHERE r.source_id = e.entity_id OR r.target_id = e.entity_id
                )
                ORDER BY e.updated_at DESC
                LIMIT 500
                """
            )
            rows = cursor.fetchall()
            disconnected = []
            for row in rows:
                import json
                disconnected.append({
                    "entity_id": row["entity_id"],
                    "entity_type": row["entity_type"],
                    "name": row["name"],
                    "properties": json.loads(row["properties"]) if row["properties"] else {},
                    "last_updated": row["updated_at"],
                    "core_id": 1,
                    "issue": "no_relationships",
                })
            return disconnected
        finally:
            conn.close()

    # -------------------------------------------------------------------------
    # backfill_missing_data
    # -------------------------------------------------------------------------

    def backfill_missing_data(self, dry_run: bool = True) -> BackfillReport:
        """Index all orphaned findings/assets into TrustGraph by creating relationships.

        For each orphaned entity, creates a "belongs_to_core" self-reference
        relationship to a synthetic core anchor entity, making it reachable.

        Args:
            dry_run: If True, only report what would be done. If False, actually create relationships.

        Returns:
            BackfillReport with counts and details.
        """
        started_at = datetime.utcnow().isoformat()

        if not self._db_exists():
            return BackfillReport(
                dry_run=dry_run,
                would_index=0,
                actually_indexed=0,
                skipped=0,
                errors=0,
                items=[],
                started_at=started_at,
                completed_at=datetime.utcnow().isoformat(),
            )

        orphaned_findings = self.find_orphaned_findings()
        disconnected_assets = self.find_disconnected_assets()
        all_orphans = orphaned_findings + disconnected_assets

        would_index = len(all_orphans)
        actually_indexed = 0
        skipped = 0
        errors = 0
        items: List[Dict[str, Any]] = []

        if not dry_run and all_orphans:
            conn = self._get_conn()
            try:
                cursor = conn.cursor()
                now = datetime.utcnow().isoformat()

                for orphan in all_orphans:
                    try:
                        core_id = orphan["core_id"]
                        anchor_id = f"core_{core_id}_anchor"
                        core_name = CORE_DEFINITIONS.get(core_id, {}).get("name", f"Core {core_id}")

                        # Ensure anchor entity exists
                        cursor.execute(
                            """
                            INSERT OR IGNORE INTO entities
                            (entity_id, core_id, entity_type, name, properties, created_at, updated_at, org_id)
                            VALUES (?, ?, 'CoreAnchor', ?, '{}', ?, ?, 'system')
                            """,
                            (anchor_id, core_id, core_name, now, now),
                        )

                        # Create relationship: orphan -> core anchor
                        rel_id = f"backfill_{orphan['entity_id']}_{anchor_id}"
                        cursor.execute(
                            """
                            INSERT OR IGNORE INTO relationships
                            (rel_id, source_id, target_id, rel_type, properties, confidence, created_at)
                            VALUES (?, ?, ?, 'belongs_to_core', '{}', 0.5, ?)
                            """,
                            (rel_id, orphan["entity_id"], anchor_id, now),
                        )
                        actually_indexed += 1
                        items.append({
                            "entity_id": orphan["entity_id"],
                            "action": "linked_to_core_anchor",
                            "rel_id": rel_id,
                        })
                    except Exception as exc:
                        logger.warning("Backfill error for %s: %s", orphan.get("entity_id"), exc)
                        errors += 1
                        items.append({
                            "entity_id": orphan.get("entity_id", "unknown"),
                            "action": "error",
                            "error": str(exc),
                        })

                conn.commit()
            finally:
                conn.close()
        else:
            # dry_run — just populate items with what would happen
            for orphan in all_orphans:
                items.append({
                    "entity_id": orphan["entity_id"],
                    "action": "would_link_to_core_anchor",
                    "core_id": orphan["core_id"],
                })

        return BackfillReport(
            dry_run=dry_run,
            would_index=would_index,
            actually_indexed=actually_indexed,
            skipped=skipped,
            errors=errors,
            items=items,
            started_at=started_at,
            completed_at=datetime.utcnow().isoformat(),
        )

    # -------------------------------------------------------------------------
    # get_graph_stats
    # -------------------------------------------------------------------------

    def get_graph_stats(self) -> GraphStats:
        """Get high-level graph statistics: total entities, relationships, coverage %.

        Returns:
            GraphStats summary.
        """
        if not self._db_exists():
            return GraphStats(
                total_entities=0,
                total_relationships=0,
                entities_per_core={c: 0 for c in CORE_DEFINITIONS},
                relationships_per_core={c: 0 for c in CORE_DEFINITIONS},
                coverage_pct=0.0,
                orphaned_count=0,
                last_updated=None,
                db_path=self.db_path,
            )

        conn = self._get_conn()
        try:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM entities WHERE deleted_at IS NULL")
            total_entities = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM relationships")
            total_rels = cursor.fetchone()[0]

            # Per-core entity counts
            cursor.execute(
                "SELECT core_id, COUNT(*) FROM entities WHERE deleted_at IS NULL GROUP BY core_id"
            )
            entities_per_core = {c: 0 for c in CORE_DEFINITIONS}
            for row in cursor.fetchall():
                if row[0] in entities_per_core:
                    entities_per_core[row[0]] = row[1]

            # Per-core relationship counts (source entity determines core)
            cursor.execute(
                """
                SELECT e.core_id, COUNT(*) FROM relationships r
                JOIN entities e ON e.entity_id = r.source_id AND e.deleted_at IS NULL
                GROUP BY e.core_id
                """
            )
            rels_per_core = {c: 0 for c in CORE_DEFINITIONS}
            for row in cursor.fetchall():
                if row[0] in rels_per_core:
                    rels_per_core[row[0]] = row[1]

            # Connected entities (have at least one relationship)
            cursor.execute(
                """
                SELECT COUNT(DISTINCT e.entity_id) FROM entities e
                WHERE e.deleted_at IS NULL
                AND (
                    EXISTS (SELECT 1 FROM relationships r WHERE r.source_id = e.entity_id)
                    OR EXISTS (SELECT 1 FROM relationships r WHERE r.target_id = e.entity_id)
                )
                """
            )
            connected = cursor.fetchone()[0]
            orphaned = total_entities - connected
            coverage_pct = round(connected / total_entities * 100.0, 2) if total_entities > 0 else 0.0

            # Last updated
            cursor.execute("SELECT MAX(updated_at) FROM entities WHERE deleted_at IS NULL")
            row = cursor.fetchone()
            last_updated = row[0] if row and row[0] else None

            return GraphStats(
                total_entities=total_entities,
                total_relationships=total_rels,
                entities_per_core=entities_per_core,
                relationships_per_core=rels_per_core,
                coverage_pct=coverage_pct,
                orphaned_count=orphaned,
                last_updated=last_updated,
                db_path=self.db_path,
            )
        finally:
            conn.close()

    # -------------------------------------------------------------------------
    # run_quality_checks
    # -------------------------------------------------------------------------

    def run_quality_checks(self) -> List[QualityIssue]:
        """Run 5 quality checks on TrustGraph data.

        Checks:
            1. Findings without severity in properties
            2. Assets without classification in properties
            3. Duplicate findings (same source+rule+file in Core 2)
            4. Stale entities (not updated in 30 days)
            5. Disconnected subgraphs (entities with no relationships)

        Returns:
            List of QualityIssue objects describing each problem found.
        """
        if not self._db_exists():
            return []

        issues: List[QualityIssue] = []
        conn = self._get_conn()
        try:
            cursor = conn.cursor()

            # ------------------------------------------------------------------
            # Check 1: Findings without severity
            # ------------------------------------------------------------------
            cursor.execute(
                """
                SELECT entity_id, name, properties FROM entities
                WHERE core_id = 2 AND deleted_at IS NULL
                AND (
                    json_extract(properties, '$.severity') IS NULL
                    OR json_extract(properties, '$.severity') = ''
                )
                LIMIT 100
                """
            )
            rows = cursor.fetchall()
            if rows:
                issues.append(
                    QualityIssue(
                        issue_id=str(uuid.uuid4()),
                        type="missing_severity",
                        severity="high",
                        description="Security findings in Core 2 have no severity field in properties.",
                        entity_count=len(rows),
                        auto_fixable=False,
                        example_ids=[r["entity_id"] for r in rows[:5]],
                    )
                )

            # ------------------------------------------------------------------
            # Check 2: Assets without classification
            # ------------------------------------------------------------------
            cursor.execute(
                """
                SELECT entity_id, name, properties FROM entities
                WHERE core_id = 1 AND deleted_at IS NULL
                AND (
                    json_extract(properties, '$.classification') IS NULL
                    AND json_extract(properties, '$.criticality') IS NULL
                )
                LIMIT 100
                """
            )
            rows = cursor.fetchall()
            if rows:
                issues.append(
                    QualityIssue(
                        issue_id=str(uuid.uuid4()),
                        type="missing_classification",
                        severity="medium",
                        description="Assets in Core 1 have no classification or criticality in properties.",
                        entity_count=len(rows),
                        auto_fixable=False,
                        example_ids=[r["entity_id"] for r in rows[:5]],
                    )
                )

            # ------------------------------------------------------------------
            # Check 3: Duplicate findings (same source+rule+file)
            # ------------------------------------------------------------------
            cursor.execute(
                """
                SELECT
                    json_extract(properties, '$.source') as src,
                    json_extract(properties, '$.rule') as rule,
                    json_extract(properties, '$.file') as file,
                    COUNT(*) as cnt,
                    GROUP_CONCAT(entity_id, ',') as ids
                FROM entities
                WHERE core_id = 2 AND deleted_at IS NULL
                    AND json_extract(properties, '$.source') IS NOT NULL
                GROUP BY src, rule, file
                HAVING cnt > 1
                LIMIT 50
                """
            )
            rows = cursor.fetchall()
            if rows:
                total_dupes = sum(r["cnt"] - 1 for r in rows)
                example_ids: List[str] = []
                for r in rows[:3]:
                    example_ids.extend((r["ids"] or "").split(",")[:2])
                issues.append(
                    QualityIssue(
                        issue_id=str(uuid.uuid4()),
                        type="duplicate_findings",
                        severity="medium",
                        description=(
                            f"Found {len(rows)} groups of duplicate findings "
                            f"(same source+rule+file), {total_dupes} extra copies."
                        ),
                        entity_count=total_dupes,
                        auto_fixable=True,
                        example_ids=example_ids[:5],
                    )
                )

            # ------------------------------------------------------------------
            # Check 4: Stale entities (not updated in 30 days)
            # ------------------------------------------------------------------
            stale_cutoff = (datetime.utcnow() - timedelta(days=30)).isoformat()
            cursor.execute(
                """
                SELECT entity_id FROM entities
                WHERE deleted_at IS NULL AND updated_at < ?
                LIMIT 200
                """,
                (stale_cutoff,),
            )
            rows = cursor.fetchall()
            if rows:
                issues.append(
                    QualityIssue(
                        issue_id=str(uuid.uuid4()),
                        type="stale_entities",
                        severity="low",
                        description="Entities not updated in the last 30 days may have outdated data.",
                        entity_count=len(rows),
                        auto_fixable=False,
                        example_ids=[r["entity_id"] for r in rows[:5]],
                    )
                )

            # ------------------------------------------------------------------
            # Check 5: Disconnected entities (no relationships at all)
            # ------------------------------------------------------------------
            cursor.execute(
                """
                SELECT entity_id FROM entities e
                WHERE e.deleted_at IS NULL
                AND NOT EXISTS (
                    SELECT 1 FROM relationships r
                    WHERE r.source_id = e.entity_id OR r.target_id = e.entity_id
                )
                LIMIT 200
                """
            )
            rows = cursor.fetchall()
            if rows:
                issues.append(
                    QualityIssue(
                        issue_id=str(uuid.uuid4()),
                        type="disconnected_entities",
                        severity="medium",
                        description=(
                            "Entities with no relationships form isolated subgraphs "
                            "and are invisible to graph traversal queries."
                        ),
                        entity_count=len(rows),
                        auto_fixable=True,
                        example_ids=[r["entity_id"] for r in rows[:5]],
                    )
                )

        finally:
            conn.close()

        logger.info("Quality checks completed: %d issues found", len(issues))
        return issues
