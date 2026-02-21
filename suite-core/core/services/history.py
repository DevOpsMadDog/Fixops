"""Run History Store - Track findings and outcomes for learning."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class RunHistoryStore:
    """Store run history for learning and weight recalibration."""

    def __init__(self, db_path: Path):
        """Initialize history store with database path."""
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                app_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                total_findings INTEGER,
                critical_count INTEGER,
                high_count INTEGER,
                medium_count INTEGER,
                low_count INTEGER,
                metadata TEXT
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                correlation_key TEXT NOT NULL,
                org_id TEXT NOT NULL,
                app_id TEXT NOT NULL,
                component_id TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                category TEXT NOT NULL,
                cve_id TEXT,
                rule_id TEXT,
                posterior_risk REAL NOT NULL,
                risk_tier TEXT NOT NULL,
                decision TEXT,
                outcome TEXT,
                timestamp TEXT NOT NULL,
                metadata TEXT,
                FOREIGN KEY (run_id) REFERENCES runs(run_id)
            )
        """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_correlation_key
            ON findings(correlation_key)
        """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_org_app
            ON findings(org_id, app_id)
        """
        )

        conn.commit()
        conn.close()

    def record_run(
        self,
        run_id: str,
        org_id: str,
        app_id: str,
        findings: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Record a complete run."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in findings:
            tier = finding.get("risk_tier", "LOW")
            risk_counts[tier] = risk_counts.get(tier, 0) + 1

        cursor.execute(
            """
            INSERT INTO runs (
                run_id, org_id, app_id, timestamp,
                total_findings, critical_count, high_count, medium_count, low_count,
                metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                run_id,
                org_id,
                app_id,
                datetime.utcnow().isoformat(),
                len(findings),
                risk_counts["CRITICAL"],
                risk_counts["HIGH"],
                risk_counts["MEDIUM"],
                risk_counts["LOW"],
                json.dumps(metadata or {}),
            ),
        )

        for finding in findings:
            cursor.execute(
                """
                INSERT INTO findings (
                    run_id, correlation_key, org_id, app_id, component_id, asset_id,
                    category, cve_id, rule_id, posterior_risk, risk_tier,
                    decision, outcome, timestamp, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    run_id,
                    finding.get("correlation_key", ""),
                    org_id,
                    app_id,
                    finding.get("component_id", "unknown"),
                    finding.get("asset_id", ""),
                    finding.get("category", ""),
                    finding.get("cve_id"),
                    finding.get("rule_id"),
                    finding.get("posterior_risk", 0.0),
                    finding.get("risk_tier", "LOW"),
                    finding.get("decision", "warn"),
                    finding.get("outcome"),
                    datetime.utcnow().isoformat(),
                    json.dumps(finding.get("metadata", {})),
                ),
            )

        conn.commit()
        conn.close()

    def get_historical_findings(
        self,
        org_id: str,
        app_id: str,
        limit: int = 1000,
        correlation_key: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get historical findings for an org/app."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if correlation_key:
            cursor.execute(
                """
                SELECT * FROM findings
                WHERE org_id = ? AND app_id = ? AND correlation_key = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """,
                (org_id, app_id, correlation_key, limit),
            )
        else:
            cursor.execute(
                """
                SELECT * FROM findings
                WHERE org_id = ? AND app_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """,
                (org_id, app_id, limit),
            )

        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    def get_runs(
        self, org_id: str, app_id: str, limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get recent runs for an org/app."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT * FROM runs
            WHERE org_id = ? AND app_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """,
            (org_id, app_id, limit),
        )

        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    def update_outcome(
        self, correlation_key: str, org_id: str, app_id: str, outcome: str
    ):
        """Update outcome for a finding (for learning)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE findings
            SET outcome = ?
            WHERE correlation_key = ? AND org_id = ? AND app_id = ?
        """,
            (outcome, correlation_key, org_id, app_id),
        )

        conn.commit()
        conn.close()
