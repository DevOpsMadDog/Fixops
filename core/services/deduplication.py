"""Deduplication & Correlation Service - Wire findings to clusters."""

import json
import sqlite3
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from .identity import IdentityResolver


class ClusterStatus(str, Enum):
    """Status of a finding cluster."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class DeduplicationService:
    """Service for deduplicating and correlating findings across runs."""

    def __init__(
        self, db_path: Path, identity_resolver: Optional[IdentityResolver] = None
    ):
        """Initialize deduplication service."""
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.identity_resolver = identity_resolver or IdentityResolver()
        self._init_db()

    def _init_db(self):
        """Initialize database schema for clusters and events."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Finding clusters - deduplicated identity
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS clusters (
                cluster_id TEXT PRIMARY KEY,
                correlation_key TEXT NOT NULL UNIQUE,
                fingerprint TEXT NOT NULL,
                org_id TEXT NOT NULL,
                app_id TEXT NOT NULL,
                component_id TEXT NOT NULL,
                category TEXT NOT NULL,
                cve_id TEXT,
                rule_id TEXT,
                title TEXT,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                occurrence_count INTEGER DEFAULT 1,
                assignee TEXT,
                ticket_id TEXT,
                ticket_url TEXT,
                metadata TEXT
            )
        """
        )

        # Finding events - individual observations
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                cluster_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                source TEXT NOT NULL,
                raw_finding TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (cluster_id) REFERENCES clusters(cluster_id)
            )
        """
        )

        # Correlation links - relationships between clusters
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS correlation_links (
                link_id TEXT PRIMARY KEY,
                source_cluster_id TEXT NOT NULL,
                target_cluster_id TEXT NOT NULL,
                link_type TEXT NOT NULL,
                confidence REAL NOT NULL,
                reason TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (source_cluster_id) REFERENCES clusters(cluster_id),
                FOREIGN KEY (target_cluster_id) REFERENCES clusters(cluster_id)
            )
        """
        )

        # Status history for audit trail
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS status_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cluster_id TEXT NOT NULL,
                old_status TEXT,
                new_status TEXT NOT NULL,
                changed_by TEXT,
                reason TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (cluster_id) REFERENCES clusters(cluster_id)
            )
        """
        )

        # Indexes for performance
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_clusters_correlation_key ON clusters(correlation_key)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_clusters_org_app ON clusters(org_id, app_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_clusters_status ON clusters(status)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_cluster ON events(cluster_id)"
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id)")

        conn.commit()
        conn.close()

    def process_finding(
        self,
        finding: Dict[str, Any],
        run_id: str,
        org_id: str,
        source: str = "sarif",
    ) -> Dict[str, Any]:
        """Process a single finding - deduplicate and return cluster info.

        Returns:
            Dict with cluster_id, correlation_key, is_new, occurrence_count
        """
        # Enrich finding with identity resolution
        if "app_id" not in finding:
            finding["app_id"] = self.identity_resolver.resolve_app_id(finding)
        if "component_id" not in finding:
            finding["component_id"] = self.identity_resolver.resolve_component_id(
                finding
            )
        if "asset_id" not in finding:
            finding["asset_id"] = self.identity_resolver.resolve_asset_id(finding)

        # Compute correlation key and fingerprint
        correlation_key = self.identity_resolver.compute_correlation_key(finding)
        fingerprint = self.identity_resolver.compute_fingerprint(finding)

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Check if cluster exists
        cursor.execute(
            "SELECT * FROM clusters WHERE correlation_key = ?",
            (correlation_key,),
        )
        existing = cursor.fetchone()

        now = datetime.utcnow().isoformat()
        event_id = str(uuid.uuid4())

        if existing:
            # Update existing cluster
            cluster_id = existing["cluster_id"]
            new_count = existing["occurrence_count"] + 1

            cursor.execute(
                """
                UPDATE clusters
                SET last_seen = ?, occurrence_count = ?, fingerprint = ?
                WHERE cluster_id = ?
            """,
                (now, new_count, fingerprint, cluster_id),
            )

            # Record event
            cursor.execute(
                """
                INSERT INTO events (event_id, cluster_id, run_id, source, raw_finding, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (event_id, cluster_id, run_id, source, json.dumps(finding), now),
            )

            conn.commit()
            conn.close()

            return {
                "cluster_id": cluster_id,
                "correlation_key": correlation_key,
                "fingerprint": fingerprint,
                "is_new": False,
                "occurrence_count": new_count,
                "first_seen": existing["first_seen"],
                "last_seen": now,
                "status": existing["status"],
            }
        else:
            # Create new cluster
            cluster_id = str(uuid.uuid4())

            cursor.execute(
                """
                INSERT INTO clusters (
                    cluster_id, correlation_key, fingerprint, org_id, app_id,
                    component_id, category, cve_id, rule_id, title, severity,
                    status, first_seen, last_seen, occurrence_count, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    cluster_id,
                    correlation_key,
                    fingerprint,
                    org_id,
                    finding.get("app_id", "unknown"),
                    finding.get("component_id", "unknown"),
                    finding.get("category", source),
                    finding.get("cve_id"),
                    finding.get("rule_id"),
                    finding.get("title", finding.get("message", "")),
                    finding.get("severity", "medium"),
                    ClusterStatus.OPEN.value,
                    now,
                    now,
                    1,
                    json.dumps(finding.get("metadata", {})),
                ),
            )

            # Record initial status
            cursor.execute(
                """
                INSERT INTO status_history (cluster_id, new_status, reason, timestamp)
                VALUES (?, ?, ?, ?)
            """,
                (cluster_id, ClusterStatus.OPEN.value, "Initial discovery", now),
            )

            # Record event
            cursor.execute(
                """
                INSERT INTO events (event_id, cluster_id, run_id, source, raw_finding, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (event_id, cluster_id, run_id, source, json.dumps(finding), now),
            )

            conn.commit()
            conn.close()

            return {
                "cluster_id": cluster_id,
                "correlation_key": correlation_key,
                "fingerprint": fingerprint,
                "is_new": True,
                "occurrence_count": 1,
                "first_seen": now,
                "last_seen": now,
                "status": ClusterStatus.OPEN.value,
            }

    def process_findings_batch(
        self,
        findings: List[Dict[str, Any]],
        run_id: str,
        org_id: str,
        source: str = "sarif",
    ) -> Dict[str, Any]:
        """Process a batch of findings and return deduplication summary.

        Returns:
            Dict with total, new_count, existing_count, clusters list
        """
        results = []
        new_count = 0
        existing_count = 0

        for finding in findings:
            result = self.process_finding(finding, run_id, org_id, source)
            results.append(result)
            if result["is_new"]:
                new_count += 1
            else:
                existing_count += 1

        # Calculate noise reduction
        total = len(findings)
        unique_clusters = len(set(r["cluster_id"] for r in results))
        noise_reduction = (
            round((1 - unique_clusters / total) * 100, 1) if total > 0 else 0
        )

        return {
            "total_findings": total,
            "unique_clusters": unique_clusters,
            "new_clusters": new_count,
            "existing_clusters": existing_count,
            "noise_reduction_percent": noise_reduction,
            "clusters": results,
        }

    def get_cluster(self, cluster_id: str) -> Optional[Dict[str, Any]]:
        """Get cluster by ID."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM clusters WHERE cluster_id = ?", (cluster_id,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
        finally:
            conn.close()

    def get_clusters(
        self,
        org_id: str,
        app_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Get clusters with optional filters."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            query = "SELECT * FROM clusters WHERE org_id = ?"
            params: List[Any] = [org_id]

            if app_id:
                query += " AND app_id = ?"
                params.append(app_id)
            if status:
                query += " AND status = ?"
                params.append(status)
            if severity:
                query += " AND severity = ?"
                params.append(severity)

            query += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def update_cluster_status(
        self,
        cluster_id: str,
        new_status: str,
        changed_by: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> bool:
        """Update cluster status with audit trail."""
        try:
            ClusterStatus(new_status)
        except ValueError:
            valid_statuses = [s.value for s in ClusterStatus]
            raise ValueError(f"Invalid status. Must be one of: {valid_statuses}")

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT status FROM clusters WHERE cluster_id = ?", (cluster_id,)
            )
            row = cursor.fetchone()
            if not row:
                return False

            old_status = row["status"]
            now = datetime.utcnow().isoformat()

            cursor.execute(
                "UPDATE clusters SET status = ? WHERE cluster_id = ?",
                (new_status, cluster_id),
            )

            cursor.execute(
                """
                INSERT INTO status_history (cluster_id, old_status, new_status, changed_by, reason, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (cluster_id, old_status, new_status, changed_by, reason, now),
            )

            conn.commit()
            return True
        finally:
            conn.close()

    def link_to_ticket(
        self, cluster_id: str, ticket_id: str, ticket_url: Optional[str] = None
    ) -> bool:
        """Link cluster to external ticket."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE clusters SET ticket_id = ?, ticket_url = ? WHERE cluster_id = ?",
                (ticket_id, ticket_url, cluster_id),
            )
            updated = cursor.rowcount > 0
            conn.commit()
            return updated
        finally:
            conn.close()

    def assign_cluster(self, cluster_id: str, assignee: str) -> bool:
        """Assign cluster to a user."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE clusters SET assignee = ? WHERE cluster_id = ?",
                (assignee, cluster_id),
            )
            updated = cursor.rowcount > 0
            conn.commit()
            return updated
        finally:
            conn.close()

    def create_correlation_link(
        self,
        source_cluster_id: str,
        target_cluster_id: str,
        link_type: str,
        confidence: float,
        reason: Optional[str] = None,
    ) -> str:
        """Create a correlation link between two clusters."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            link_id = str(uuid.uuid4())
            now = datetime.utcnow().isoformat()

            cursor.execute(
                """
                INSERT INTO correlation_links (
                    link_id, source_cluster_id, target_cluster_id,
                    link_type, confidence, reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    link_id,
                    source_cluster_id,
                    target_cluster_id,
                    link_type,
                    confidence,
                    reason,
                    now,
                ),
            )

            conn.commit()
            return link_id
        finally:
            conn.close()

    def get_related_clusters(
        self, cluster_id: str, min_confidence: float = 0.5
    ) -> List[Dict[str, Any]]:
        """Get clusters related to the given cluster."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT c.*, cl.link_type, cl.confidence, cl.reason
                FROM clusters c
                JOIN correlation_links cl ON (
                    (cl.target_cluster_id = c.cluster_id AND cl.source_cluster_id = ?)
                    OR (cl.source_cluster_id = c.cluster_id AND cl.target_cluster_id = ?)
                )
                WHERE cl.confidence >= ?
                ORDER BY cl.confidence DESC
            """,
                (cluster_id, cluster_id, min_confidence),
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def get_dedup_stats(self, org_id: str) -> Dict[str, Any]:
        """Get deduplication statistics for an organization."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT COUNT(*) as count FROM clusters WHERE org_id = ?", (org_id,)
            )
            total_clusters = cursor.fetchone()["count"]

            cursor.execute(
                """
                SELECT COUNT(*) as count FROM events e
                JOIN clusters c ON e.cluster_id = c.cluster_id
                WHERE c.org_id = ?
            """,
                (org_id,),
            )
            total_events = cursor.fetchone()["count"]

            cursor.execute(
                """
                SELECT status, COUNT(*) as count
                FROM clusters WHERE org_id = ?
                GROUP BY status
            """,
                (org_id,),
            )
            status_breakdown = {
                row["status"]: row["count"] for row in cursor.fetchall()
            }

            cursor.execute(
                """
                SELECT severity, COUNT(*) as count
                FROM clusters WHERE org_id = ?
                GROUP BY severity
            """,
                (org_id,),
            )
            severity_breakdown = {
                row["severity"]: row["count"] for row in cursor.fetchall()
            }

            noise_reduction = (
                round((1 - total_clusters / total_events) * 100, 1)
                if total_events > 0
                else 0
            )

            return {
                "total_clusters": total_clusters,
                "total_events": total_events,
                "noise_reduction_percent": noise_reduction,
                "status_breakdown": status_breakdown,
                "severity_breakdown": severity_breakdown,
            }
        finally:
            conn.close()
