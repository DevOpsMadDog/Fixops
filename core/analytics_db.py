"""
Analytics database manager using SQLite.
"""
import json
import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.analytics_models import (
    Decision,
    DecisionOutcome,
    Finding,
    FindingSeverity,
    FindingStatus,
    Metric,
)


class AnalyticsDB:
    """Database manager for analytics records."""

    def __init__(self, db_path: str = "data/analytics.db"):
        """Initialize database connection."""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self):
        """Initialize database tables."""
        conn = self._get_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    application_id TEXT,
                    service_id TEXT,
                    rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    source TEXT NOT NULL,
                    cve_id TEXT,
                    cvss_score REAL,
                    epss_score REAL,
                    exploitable INTEGER NOT NULL,
                    metadata TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    resolved_at TEXT
                );

                CREATE TABLE IF NOT EXISTS decisions (
                    id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    reasoning TEXT NOT NULL,
                    llm_votes TEXT,
                    policy_matched TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (finding_id) REFERENCES findings(id)
                );

                CREATE TABLE IF NOT EXISTS metrics (
                    id TEXT PRIMARY KEY,
                    metric_type TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    value REAL NOT NULL,
                    unit TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    metadata TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
                CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at);
                CREATE INDEX IF NOT EXISTS idx_decisions_finding ON decisions(finding_id);
                CREATE INDEX IF NOT EXISTS idx_decisions_outcome ON decisions(outcome);
                CREATE INDEX IF NOT EXISTS idx_metrics_type ON metrics(metric_type);
                CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp);
            """
            )
            conn.commit()
        finally:
            conn.close()

    def create_finding(self, finding: Finding) -> Finding:
        """Create new finding."""
        if not finding.id:
            finding.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding.id,
                    finding.application_id,
                    finding.service_id,
                    finding.rule_id,
                    finding.severity.value,
                    finding.status.value,
                    finding.title,
                    finding.description,
                    finding.source,
                    finding.cve_id,
                    finding.cvss_score,
                    finding.epss_score,
                    1 if finding.exploitable else 0,
                    json.dumps(finding.metadata),
                    finding.created_at.isoformat(),
                    finding.updated_at.isoformat(),
                    finding.resolved_at.isoformat() if finding.resolved_at else None,
                ),
            )
            conn.commit()
            return finding
        finally:
            conn.close()

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """Get finding by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
            if row:
                return self._row_to_finding(row)
            return None
        finally:
            conn.close()

    def list_findings(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Finding]:
        """List findings with optional filtering."""
        conn = self._get_connection()
        try:
            query = "SELECT * FROM findings WHERE 1=1"
            params: List[Any] = []

            if severity:
                query += " AND severity = ?"
                params.append(severity)
            if status:
                query += " AND status = ?"
                params.append(status)

            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            rows = conn.execute(query, params).fetchall()
            return [self._row_to_finding(row) for row in rows]
        finally:
            conn.close()

    def update_finding(self, finding: Finding) -> Finding:
        """Update finding."""
        finding.updated_at = datetime.utcnow()
        conn = self._get_connection()
        try:
            conn.execute(
                """UPDATE findings SET status=?, metadata=?, updated_at=?, resolved_at=? WHERE id=?""",
                (
                    finding.status.value,
                    json.dumps(finding.metadata),
                    finding.updated_at.isoformat(),
                    finding.resolved_at.isoformat() if finding.resolved_at else None,
                    finding.id,
                ),
            )
            conn.commit()
            return finding
        finally:
            conn.close()

    def create_decision(self, decision: Decision) -> Decision:
        """Create new decision."""
        if not decision.id:
            decision.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    decision.id,
                    decision.finding_id,
                    decision.outcome.value,
                    decision.confidence,
                    decision.reasoning,
                    json.dumps(decision.llm_votes),
                    decision.policy_matched,
                    decision.created_at.isoformat(),
                ),
            )
            conn.commit()
            return decision
        finally:
            conn.close()

    def list_decisions(
        self, finding_id: Optional[str] = None, limit: int = 100, offset: int = 0
    ) -> List[Decision]:
        """List decisions with optional filtering."""
        conn = self._get_connection()
        try:
            if finding_id:
                rows = conn.execute(
                    "SELECT * FROM decisions WHERE finding_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (finding_id, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM decisions ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
            return [self._row_to_decision(row) for row in rows]
        finally:
            conn.close()

    def create_metric(self, metric: Metric) -> Metric:
        """Create new metric."""
        if not metric.id:
            metric.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO metrics VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    metric.id,
                    metric.metric_type,
                    metric.metric_name,
                    metric.value,
                    metric.unit,
                    metric.timestamp.isoformat(),
                    json.dumps(metric.metadata),
                ),
            )
            conn.commit()
            return metric
        finally:
            conn.close()

    def list_metrics(
        self,
        metric_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Metric]:
        """List metrics with optional filtering."""
        conn = self._get_connection()
        try:
            query = "SELECT * FROM metrics WHERE 1=1"
            params: List[Any] = []

            if metric_type:
                query += " AND metric_type = ?"
                params.append(metric_type)
            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time.isoformat())
            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time.isoformat())

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            return [self._row_to_metric(row) for row in rows]
        finally:
            conn.close()

    def get_dashboard_overview(self) -> Dict[str, Any]:
        """Get dashboard overview statistics."""
        conn = self._get_connection()
        try:
            total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            open_findings = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE status = 'open'"
            ).fetchone()[0]
            critical_findings = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE severity = 'critical' AND status = 'open'"
            ).fetchone()[0]

            thirty_days_ago = (datetime.utcnow() - timedelta(days=30)).isoformat()
            recent_findings = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE created_at >= ?",
                (thirty_days_ago,),
            ).fetchone()[0]

            return {
                "total_findings": total_findings,
                "open_findings": open_findings,
                "critical_findings": critical_findings,
                "recent_findings_30d": recent_findings,
                "timestamp": datetime.utcnow().isoformat(),
            }
        finally:
            conn.close()

    def get_top_risks(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top risks by severity and exploitability."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                """SELECT * FROM findings
                   WHERE status = 'open'
                   ORDER BY
                     CASE severity
                       WHEN 'critical' THEN 1
                       WHEN 'high' THEN 2
                       WHEN 'medium' THEN 3
                       WHEN 'low' THEN 4
                       ELSE 5
                     END,
                     exploitable DESC,
                     cvss_score DESC
                   LIMIT ?""",
                (limit,),
            ).fetchall()
            return [self._row_to_finding(row).to_dict() for row in rows]
        finally:
            conn.close()

    def calculate_mttr(self) -> Optional[float]:
        """Calculate mean time to remediation in hours."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                """SELECT created_at, resolved_at FROM findings
                   WHERE resolved_at IS NOT NULL"""
            ).fetchall()

            if not rows:
                return None

            total_hours = 0.0
            for row in rows:
                created = datetime.fromisoformat(row["created_at"])
                resolved = datetime.fromisoformat(row["resolved_at"])
                hours = (resolved - created).total_seconds() / 3600
                total_hours += hours

            return total_hours / len(rows)
        finally:
            conn.close()

    def _row_to_finding(self, row) -> Finding:
        """Convert database row to Finding object."""
        return Finding(
            id=row["id"],
            application_id=row["application_id"],
            service_id=row["service_id"],
            rule_id=row["rule_id"],
            severity=FindingSeverity(row["severity"]),
            status=FindingStatus(row["status"]),
            title=row["title"],
            description=row["description"],
            source=row["source"],
            cve_id=row["cve_id"],
            cvss_score=row["cvss_score"],
            epss_score=row["epss_score"],
            exploitable=bool(row["exploitable"]),
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            resolved_at=(
                datetime.fromisoformat(row["resolved_at"])
                if row["resolved_at"]
                else None
            ),
        )

    def _row_to_decision(self, row) -> Decision:
        """Convert database row to Decision object."""
        return Decision(
            id=row["id"],
            finding_id=row["finding_id"],
            outcome=DecisionOutcome(row["outcome"]),
            confidence=row["confidence"],
            reasoning=row["reasoning"],
            llm_votes=json.loads(row["llm_votes"]) if row["llm_votes"] else {},
            policy_matched=row["policy_matched"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    def _row_to_metric(self, row) -> Metric:
        """Convert database row to Metric object."""
        return Metric(
            id=row["id"],
            metric_type=row["metric_type"],
            metric_name=row["metric_name"],
            value=row["value"],
            unit=row["unit"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        )
