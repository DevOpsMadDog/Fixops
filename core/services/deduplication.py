"""Deduplication & Correlation Service - Wire findings to clusters."""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
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
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        try:
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
                "CREATE INDEX IF NOT EXISTS idx_clusters_correlation_key "
                "ON clusters(correlation_key)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_clusters_org_app "
                "ON clusters(org_id, app_id)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_clusters_status ON clusters(status)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_cluster ON events(cluster_id)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id)"
            )

            conn.commit()
        finally:
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

        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Check if cluster exists
        cursor.execute(
            "SELECT * FROM clusters WHERE correlation_key = ?",
            (correlation_key,),
        )
        existing = cursor.fetchone()

        now = datetime.now(timezone.utc).isoformat()
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
        conn = sqlite3.connect(self.db_path, timeout=30.0)
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

    def get_cluster_events(
        self, cluster_id: str, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get events belonging to a cluster.

        Returns the raw findings associated with a cluster, parsed from JSON.
        """
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT event_id, cluster_id, run_id, source, raw_finding, timestamp
                FROM events
                WHERE cluster_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (cluster_id, limit),
            )
            rows = cursor.fetchall()
            events = []
            for row in rows:
                event = dict(row)
                # Parse raw_finding JSON if present
                raw = event.get("raw_finding")
                if raw:
                    try:
                        parsed = json.loads(raw)
                        event.update(parsed)
                    except (json.JSONDecodeError, TypeError):
                        pass
                events.append(event)
            return events
        finally:
            conn.close()

    def get_events_for_clusters(
        self, cluster_ids: List[str], limit_per_cluster: int = 100
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Get events for multiple clusters in a single query.

        This is more efficient than calling get_cluster_events() in a loop
        as it uses a single database connection and query.

        Args:
            cluster_ids: List of cluster IDs to fetch events for
            limit_per_cluster: Maximum events per cluster (applied in Python after
                fetching all rows, not via SQL window function)

        Returns:
            Dict mapping cluster_id to list of events

        Note:
            The per-cluster limit is applied in Python after fetching all rows
            from the database. For clusters with many events, this may be less
            efficient than using a SQL window function with ROW_NUMBER() OVER
            (PARTITION BY cluster_id ORDER BY timestamp DESC). However, this
            approach is simpler and works with SQLite's limited window function
            support in older versions.
        """
        if not cluster_ids:
            return {}

        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            # Use placeholders for the IN clause
            placeholders = ",".join("?" * len(cluster_ids))
            cursor.execute(
                f"""
                SELECT event_id, cluster_id, run_id, source, raw_finding, timestamp
                FROM events
                WHERE cluster_id IN ({placeholders})
                ORDER BY cluster_id, timestamp DESC
                """,
                cluster_ids,
            )
            rows = cursor.fetchall()

            # Group events by cluster_id
            events_by_cluster: Dict[str, List[Dict[str, Any]]] = {
                cid: [] for cid in cluster_ids
            }
            for row in rows:
                event = dict(row)
                cluster_id = event["cluster_id"]

                # Apply per-cluster limit
                if len(events_by_cluster[cluster_id]) >= limit_per_cluster:
                    continue

                # Parse raw_finding JSON if present
                raw = event.get("raw_finding")
                if raw:
                    try:
                        parsed = json.loads(raw)
                        event.update(parsed)
                    except (json.JSONDecodeError, TypeError):
                        pass
                events_by_cluster[cluster_id].append(event)

            return events_by_cluster
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
        conn = sqlite3.connect(self.db_path, timeout=30.0)
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

        conn = sqlite3.connect(self.db_path, timeout=30.0)
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
            now = datetime.now(timezone.utc).isoformat()

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
        conn = sqlite3.connect(self.db_path, timeout=30.0)
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
        conn = sqlite3.connect(self.db_path, timeout=30.0)
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
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        try:
            cursor = conn.cursor()

            link_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc).isoformat()

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
        conn = sqlite3.connect(self.db_path, timeout=30.0)
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
        conn = sqlite3.connect(self.db_path, timeout=30.0)
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

    def correlate_cross_stage(
        self, org_id: str, min_confidence: float = 0.7
    ) -> Dict[str, Any]:
        """Find and create cross-stage correlation links.

        Cross-stage anchors:
        - CVE+purl: Same vulnerability in same package across stages
        - rule_id+file_path: Same rule violation in same file across stages
        - resource_id+policy_id: Same policy violation on same resource

        Returns:
            Dict with correlation statistics and new links created
        """
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            # Get all clusters for the org with stage info from metadata
            cursor.execute(
                "SELECT * FROM clusters WHERE org_id = ?",
                (org_id,),
            )
            clusters = [dict(row) for row in cursor.fetchall()]

            # Parse metadata to extract stage info
            for cluster in clusters:
                metadata = json.loads(cluster.get("metadata") or "{}")
                cluster["stage"] = metadata.get("stage", "unknown")
                cluster["purl"] = metadata.get("purl")
                cluster["resource_id"] = metadata.get("resource_id")
                cluster["policy_id"] = metadata.get("policy_id")
                cluster["file_path"] = metadata.get("file_path") or metadata.get("file")

            # Group by stage
            stages = ["design", "build", "deploy", "runtime"]
            by_stage: Dict[str, List[Dict[str, Any]]] = {s: [] for s in stages}
            for cluster in clusters:
                stage = cluster.get("stage", "unknown")
                if stage in by_stage:
                    by_stage[stage].append(cluster)

            links_created = []
            correlation_stats = {
                "cve_purl_matches": 0,
                "rule_file_matches": 0,
                "resource_policy_matches": 0,
            }

            # Find cross-stage correlations
            for i, stage1 in enumerate(stages):
                for stage2 in stages[i + 1 :]:
                    for c1 in by_stage[stage1]:
                        for c2 in by_stage[stage2]:
                            if c1["cluster_id"] == c2["cluster_id"]:
                                continue

                            link_type = None
                            confidence = 0.0
                            reason = None

                            # CVE + purl anchor
                            if (
                                c1.get("cve_id")
                                and c1.get("cve_id") == c2.get("cve_id")
                                and c1.get("purl")
                                and c1.get("purl") == c2.get("purl")
                            ):
                                link_type = "cve_purl_anchor"
                                confidence = 0.95
                                reason = f"Same CVE ({c1['cve_id']}) in same package across {stage1}->{stage2}"
                                correlation_stats["cve_purl_matches"] += 1

                            # rule_id + file_path anchor
                            elif (
                                c1.get("rule_id")
                                and c1.get("rule_id") == c2.get("rule_id")
                                and c1.get("file_path")
                                and c1.get("file_path") == c2.get("file_path")
                            ):
                                link_type = "rule_file_anchor"
                                confidence = 0.85
                                reason = f"Same rule ({c1['rule_id']}) in same file across {stage1}->{stage2}"
                                correlation_stats["rule_file_matches"] += 1

                            # resource_id + policy_id anchor
                            elif (
                                c1.get("resource_id")
                                and c1.get("resource_id") == c2.get("resource_id")
                                and c1.get("policy_id")
                                and c1.get("policy_id") == c2.get("policy_id")
                            ):
                                link_type = "resource_policy_anchor"
                                confidence = 0.90
                                reason = f"Same policy violation on same resource across {stage1}->{stage2}"
                                correlation_stats["resource_policy_matches"] += 1

                            if link_type and confidence >= min_confidence:
                                # Check if link already exists
                                cursor.execute(
                                    """
                                    SELECT link_id FROM correlation_links
                                    WHERE (source_cluster_id = ? AND target_cluster_id = ?)
                                    OR (source_cluster_id = ? AND target_cluster_id = ?)
                                """,
                                    (
                                        c1["cluster_id"],
                                        c2["cluster_id"],
                                        c2["cluster_id"],
                                        c1["cluster_id"],
                                    ),
                                )
                                if not cursor.fetchone():
                                    link_id = self.create_correlation_link(
                                        c1["cluster_id"],
                                        c2["cluster_id"],
                                        link_type,
                                        confidence,
                                        reason,
                                    )
                                    links_created.append(
                                        {
                                            "link_id": link_id,
                                            "source": c1["cluster_id"],
                                            "target": c2["cluster_id"],
                                            "type": link_type,
                                            "confidence": confidence,
                                            "stages": [stage1, stage2],
                                        }
                                    )

            return {
                "links_created": len(links_created),
                "links": links_created,
                "correlation_stats": correlation_stats,
                "clusters_analyzed": len(clusters),
                "by_stage": {s: len(by_stage[s]) for s in stages},
            }
        finally:
            conn.close()

    def get_correlation_graph(
        self, org_id: str, cluster_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get the correlation graph for visualization.

        Returns nodes (clusters) and edges (correlation links) in a format
        suitable for graph visualization.
        """
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            # Get clusters
            if cluster_id:
                # Get specific cluster and its related clusters
                cursor.execute(
                    "SELECT * FROM clusters WHERE cluster_id = ?",
                    (cluster_id,),
                )
                root = cursor.fetchone()
                if not root:
                    return {"nodes": [], "edges": [], "error": "Cluster not found"}

                # Get related clusters
                cursor.execute(
                    """
                    SELECT DISTINCT c.* FROM clusters c
                    JOIN correlation_links cl ON (
                        c.cluster_id = cl.source_cluster_id
                        OR c.cluster_id = cl.target_cluster_id
                    )
                    WHERE cl.source_cluster_id = ? OR cl.target_cluster_id = ?
                """,
                    (cluster_id, cluster_id),
                )
                related = cursor.fetchall()
                clusters = [dict(root)] + [dict(r) for r in related]

                # Get edges for these clusters
                cluster_ids = [c["cluster_id"] for c in clusters]
                placeholders = ",".join("?" * len(cluster_ids))
                cursor.execute(
                    f"""
                    SELECT * FROM correlation_links
                    WHERE source_cluster_id IN ({placeholders})
                    AND target_cluster_id IN ({placeholders})
                """,
                    cluster_ids + cluster_ids,
                )
            else:
                # Get all clusters for org
                cursor.execute(
                    "SELECT * FROM clusters WHERE org_id = ?",
                    (org_id,),
                )
                clusters = [dict(row) for row in cursor.fetchall()]

                # Get all edges
                cluster_ids = [c["cluster_id"] for c in clusters]
                if cluster_ids:
                    placeholders = ",".join("?" * len(cluster_ids))
                    cursor.execute(
                        f"""
                        SELECT * FROM correlation_links
                        WHERE source_cluster_id IN ({placeholders})
                        OR target_cluster_id IN ({placeholders})
                    """,
                        cluster_ids + cluster_ids,
                    )
                else:
                    cursor.execute("SELECT * FROM correlation_links WHERE 1=0")

            edges = [dict(row) for row in cursor.fetchall()]

            # Format nodes with stage info
            nodes = []
            for cluster in clusters:
                metadata = json.loads(cluster.get("metadata") or "{}")
                nodes.append(
                    {
                        "id": cluster["cluster_id"],
                        "label": cluster.get("title")
                        or cluster.get("cve_id")
                        or cluster.get("rule_id")
                        or cluster["cluster_id"][:8],
                        "severity": cluster["severity"],
                        "status": cluster["status"],
                        "stage": metadata.get("stage", "unknown"),
                        "category": cluster["category"],
                        "occurrence_count": cluster["occurrence_count"],
                    }
                )

            # Format edges with explainability
            formatted_edges = []
            for edge in edges:
                formatted_edges.append(
                    {
                        "id": edge["link_id"],
                        "source": edge["source_cluster_id"],
                        "target": edge["target_cluster_id"],
                        "type": edge["link_type"],
                        "confidence": edge["confidence"],
                        "reason": edge["reason"],
                    }
                )

            return {
                "nodes": nodes,
                "edges": formatted_edges,
                "node_count": len(nodes),
                "edge_count": len(formatted_edges),
            }
        finally:
            conn.close()

    def record_operator_feedback(
        self,
        cluster_id: str,
        feedback_type: str,
        target_cluster_id: Optional[str] = None,
        reason: Optional[str] = None,
        operator_id: Optional[str] = None,
        event_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Record operator feedback for correlation corrections.

        Feedback types:
        - merge_allowed: Confirm two clusters should be merged
        - merge_blocked: Block automatic merge of two clusters
        - split_cluster: Split a cluster into separate findings

        Returns:
            Dict with feedback_id and action taken
        """
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        try:
            cursor = conn.cursor()

            # Create feedback table if not exists
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS operator_feedback (
                    feedback_id TEXT PRIMARY KEY,
                    cluster_id TEXT NOT NULL,
                    target_cluster_id TEXT,
                    feedback_type TEXT NOT NULL,
                    reason TEXT,
                    operator_id TEXT,
                    created_at TEXT NOT NULL,
                    applied BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (cluster_id) REFERENCES clusters(cluster_id)
                )
            """
            )

            feedback_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc).isoformat()

            cursor.execute(
                """
                INSERT INTO operator_feedback (
                    feedback_id, cluster_id, target_cluster_id,
                    feedback_type, reason, operator_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    feedback_id,
                    cluster_id,
                    target_cluster_id,
                    feedback_type,
                    reason,
                    operator_id,
                    now,
                ),
            )

            action_result: Optional[Dict[str, Any]] = None

            # Apply feedback based on type
            if feedback_type == "merge_allowed" and target_cluster_id:
                # Create high-confidence correlation link inline (avoid nested connection)
                link_id = str(uuid.uuid4())
                link_reason = f"Operator confirmed merge: {reason}"
                now_link = datetime.now(timezone.utc).isoformat()
                cursor.execute(
                    """
                    INSERT INTO correlation_links (
                        link_id, source_cluster_id, target_cluster_id,
                        link_type, confidence, reason, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        link_id,
                        cluster_id,
                        target_cluster_id,
                        "operator_merge",
                        1.0,
                        link_reason,
                        now_link,
                    ),
                )
                action_result = {"action": "link_created", "link_id": link_id}

            elif feedback_type == "merge_blocked" and target_cluster_id:
                # Remove any existing correlation links between these clusters
                cursor.execute(
                    """
                    DELETE FROM correlation_links
                    WHERE (source_cluster_id = ? AND target_cluster_id = ?)
                    OR (source_cluster_id = ? AND target_cluster_id = ?)
                """,
                    (cluster_id, target_cluster_id, target_cluster_id, cluster_id),
                )
                action_result = {
                    "action": "links_removed",
                    "count": cursor.rowcount,
                }

            elif feedback_type == "split_cluster":
                # Mark cluster for manual review (use IN_PROGRESS as review status)
                cursor.execute(
                    """
                    UPDATE clusters SET status = ?
                    WHERE cluster_id = ?
                """,
                    (ClusterStatus.IN_PROGRESS.value, cluster_id),
                )
                action_result = {
                    "action": "marked_for_review",
                    "event_ids": event_ids or [],
                }

            # Mark feedback as applied
            cursor.execute(
                "UPDATE operator_feedback SET applied = TRUE WHERE feedback_id = ?",
                (feedback_id,),
            )

            conn.commit()

            return {
                "feedback_id": feedback_id,
                "feedback_type": feedback_type,
                "cluster_id": cluster_id,
                "target_cluster_id": target_cluster_id,
                "action_result": action_result,
            }
        finally:
            conn.close()

    def get_baseline_comparison(
        self,
        org_id: str,
        current_run_id: str,
        baseline_run_id: str,
    ) -> Dict[str, Any]:
        """Compare current run against a baseline to identify NEW/EXISTING/FIXED.

        Returns:
            Dict with new, existing, and fixed findings
        """
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            # Get clusters from current run
            cursor.execute(
                """
                SELECT DISTINCT c.* FROM clusters c
                JOIN events e ON c.cluster_id = e.cluster_id
                WHERE c.org_id = ? AND e.run_id = ?
            """,
                (org_id, current_run_id),
            )
            current_clusters = {
                row["correlation_key"]: dict(row) for row in cursor.fetchall()
            }

            # Get clusters from baseline run
            cursor.execute(
                """
                SELECT DISTINCT c.* FROM clusters c
                JOIN events e ON c.cluster_id = e.cluster_id
                WHERE c.org_id = ? AND e.run_id = ?
            """,
                (org_id, baseline_run_id),
            )
            baseline_clusters = {
                row["correlation_key"]: dict(row) for row in cursor.fetchall()
            }

            # Categorize findings
            new_findings = []
            existing_findings = []
            fixed_findings = []

            for corr_key, cluster in current_clusters.items():
                if corr_key in baseline_clusters:
                    cluster["baseline_status"] = "EXISTING"
                    cluster["baseline_first_seen"] = baseline_clusters[corr_key][
                        "first_seen"
                    ]
                    existing_findings.append(cluster)
                else:
                    cluster["baseline_status"] = "NEW"
                    new_findings.append(cluster)

            for corr_key, cluster in baseline_clusters.items():
                if corr_key not in current_clusters:
                    cluster["baseline_status"] = "FIXED"
                    fixed_findings.append(cluster)

            return {
                "current_run_id": current_run_id,
                "baseline_run_id": baseline_run_id,
                "summary": {
                    "total_current": len(current_clusters),
                    "total_baseline": len(baseline_clusters),
                    "new_count": len(new_findings),
                    "existing_count": len(existing_findings),
                    "fixed_count": len(fixed_findings),
                },
                "new": new_findings,
                "existing": existing_findings,
                "fixed": fixed_findings,
            }
        finally:
            conn.close()
