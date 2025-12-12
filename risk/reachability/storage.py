"""Enterprise storage for reachability analysis results."""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from risk.reachability.analyzer import VulnerabilityReachability

logger = logging.getLogger(__name__)


class ReachabilityStorage:
    """Enterprise storage with SQLite persistence and caching."""

    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        """Initialize storage.

        Parameters
        ----------
        config
            Configuration for storage.
        """
        self.config = config or {}

        # Database path
        db_path = self.config.get("database_path", "data/reachability/results.db")
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Cache settings
        self.cache_ttl_hours = self.config.get("cache_ttl_hours", 24)
        self.max_cache_size_mb = self.config.get("max_cache_size_mb", 1000)

        # Initialize database
        self._init_database()

    def _init_database(self) -> None:
        """Initialize SQLite database schema."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # Results table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS reachability_results (
                id TEXT PRIMARY KEY,
                cve_id TEXT NOT NULL,
                component_name TEXT NOT NULL,
                component_version TEXT NOT NULL,
                repo_url TEXT NOT NULL,
                repo_commit TEXT,
                result_json TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP
            )
            """
        )

        # Create indexes for results table
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_cve ON reachability_results (cve_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_component ON reachability_results (component_name, component_version)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_repo ON reachability_results (repo_url, repo_commit)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_expires ON reachability_results (expires_at)"
        )

        # Metrics table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS reachability_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                metadata TEXT
            )
            """
        )

        # Create index for metrics table
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_metric ON reachability_metrics (metric_name, timestamp)"
        )

        conn.commit()
        conn.close()

        logger.info(f"Initialized storage database: {self.db_path}")

    def get_cached_result(
        self,
        cve_id: str,
        component_name: str,
        component_version: str,
        repo_url: str,
        repo_commit: Optional[str] = None,
    ) -> Optional[VulnerabilityReachability]:
        """Get cached analysis result.

        Parameters
        ----------
        cve_id
            CVE identifier.
        component_name
            Component name.
        component_version
            Component version.
        repo_url
            Repository URL.
        repo_commit
            Repository commit.

        Returns
        -------
        Optional[VulnerabilityReachability]
            Cached result if found and not expired, None otherwise.
        """
        result_id = self._generate_result_id(
            cve_id, component_name, component_version, repo_url, repo_commit
        )

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT result_json, expires_at
            FROM reachability_results
            WHERE id = ? AND (expires_at IS NULL OR expires_at > ?)
            """,
            (result_id, datetime.now(timezone.utc)),
        )

        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        result_json, expires_at = row

        try:
            data = json.loads(result_json)
            return VulnerabilityReachability(**data)
        except Exception as e:
            logger.warning(f"Failed to deserialize cached result: {e}")
            return None

    def save_result(
        self,
        result: VulnerabilityReachability,
        repo_url: str,
        repo_commit: Optional[str] = None,
    ) -> None:
        """Save analysis result.

        Parameters
        ----------
        result
            Analysis result to save.
        repo_url
            Repository URL.
        repo_commit
            Repository commit.
        """
        result_id = self._generate_result_id(
            result.cve_id,
            result.component_name,
            result.component_version,
            repo_url,
            repo_commit,
        )

        now = datetime.now(timezone.utc)
        expires_at = (
            now + timedelta(hours=self.cache_ttl_hours)
            if self.cache_ttl_hours > 0
            else None
        )

        result_json = json.dumps(result.to_dict())

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO reachability_results
            (id, cve_id, component_name, component_version, repo_url, repo_commit,
             result_json, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result_id,
                result.cve_id,
                result.component_name,
                result.component_version,
                repo_url,
                repo_commit,
                result_json,
                now,
                expires_at,
            ),
        )

        conn.commit()
        conn.close()

        logger.debug(f"Saved result for {result.cve_id}")

    def delete_result(
        self,
        cve_id: str,
        component_name: str,
        component_version: str,
        repo_url: str,
        repo_commit: Optional[str] = None,
    ) -> None:
        """Delete cached result.

        Parameters
        ----------
        cve_id
            CVE identifier.
        component_name
            Component name.
        component_version
            Component version.
        repo_url
            Repository URL.
        repo_commit
            Repository commit.
        """
        result_id = self._generate_result_id(
            cve_id, component_name, component_version, repo_url, repo_commit
        )

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("DELETE FROM reachability_results WHERE id = ?", (result_id,))

        conn.commit()
        conn.close()

        logger.debug(f"Deleted result for {cve_id}")

    def cleanup_expired(self) -> int:
        """Clean up expired results.

        Returns
        -------
        int
            Number of results deleted.
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute(
            "DELETE FROM reachability_results WHERE expires_at < ?",
            (datetime.now(timezone.utc),),
        )

        deleted = cursor.rowcount
        conn.commit()
        conn.close()

        logger.info(f"Cleaned up {deleted} expired results")
        return deleted

    def _generate_result_id(
        self,
        cve_id: str,
        component_name: str,
        component_version: str,
        repo_url: str,
        repo_commit: Optional[str] = None,
    ) -> str:
        """Generate unique result ID."""
        key_parts = [
            cve_id,
            component_name,
            component_version,
            repo_url,
            repo_commit or "HEAD",
        ]
        key_string = "|".join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()

    def health_check(self) -> str:
        """Health check for storage."""
        try:
            conn = sqlite3.connect(str(self.db_path), timeout=5)
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            conn.close()
            return "ok"
        except Exception as e:
            return f"error: {str(e)}"

    def get_metrics(self) -> Dict[str, Any]:
        """Get storage metrics."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # Total results
        cursor.execute("SELECT COUNT(*) FROM reachability_results")
        total_results = cursor.fetchone()[0]

        # Expired results
        cursor.execute(
            "SELECT COUNT(*) FROM reachability_results WHERE expires_at < ?",
            (datetime.now(timezone.utc),),
        )
        expired_results = cursor.fetchone()[0]

        # Database size
        db_size_mb = self.db_path.stat().st_size / (1024 * 1024)

        conn.close()

        return {
            "total_results": total_results,
            "expired_results": expired_results,
            "database_size_mb": round(db_size_mb, 2),
        }
