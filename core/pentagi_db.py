"""Database manager for Pentagi pen testing data."""
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from core.pentagi_models import (
    ExploitabilityLevel,
    PenTestConfig,
    PenTestPriority,
    PenTestRequest,
    PenTestResult,
    PenTestStatus,
)


class PentagiDB:
    """Database manager for Pentagi pen testing data."""

    def __init__(self, db_path: str = "data/pentagi.db"):
        """Initialize database manager."""
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialize database tables."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS pen_test_requests (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                target_url TEXT NOT NULL,
                vulnerability_type TEXT NOT NULL,
                test_case TEXT NOT NULL,
                priority TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                pentagi_job_id TEXT,
                metadata TEXT
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS pen_test_results (
                id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                exploitability TEXT NOT NULL,
                exploit_successful INTEGER NOT NULL,
                evidence TEXT NOT NULL,
                steps_taken TEXT,
                artifacts TEXT,
                confidence_score REAL,
                execution_time_seconds REAL,
                created_at TEXT NOT NULL,
                metadata TEXT,
                FOREIGN KEY (request_id) REFERENCES pen_test_requests(id)
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS pen_test_configs (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                pentagi_url TEXT NOT NULL,
                api_key TEXT,
                enabled INTEGER NOT NULL,
                max_concurrent_tests INTEGER NOT NULL,
                timeout_seconds INTEGER NOT NULL,
                auto_trigger INTEGER NOT NULL,
                target_environments TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                metadata TEXT
            )
        """
        )

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_requests_finding ON pen_test_requests(finding_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_requests_status ON pen_test_requests(status)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_results_finding ON pen_test_results(finding_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_results_exploitability ON pen_test_results(exploitability)"
        )

        conn.commit()
        conn.close()

    def create_request(self, request: PenTestRequest) -> PenTestRequest:
        """Create a new pen test request."""
        if not request.id:
            request.id = str(uuid.uuid4())

        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO pen_test_requests
            (id, finding_id, target_url, vulnerability_type, test_case, priority, status,
             created_at, started_at, completed_at, pentagi_job_id, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                request.id,
                request.finding_id,
                request.target_url,
                request.vulnerability_type,
                request.test_case,
                request.priority.value,
                request.status.value,
                request.created_at.isoformat(),
                request.started_at.isoformat() if request.started_at else None,
                request.completed_at.isoformat() if request.completed_at else None,
                request.pentagi_job_id,
                str(request.metadata),
            ),
        )

        conn.commit()
        conn.close()
        return request

    def get_request(self, request_id: str) -> Optional[PenTestRequest]:
        """Get a pen test request by ID."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM pen_test_requests WHERE id = ?", (request_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return PenTestRequest(
            id=row["id"],
            finding_id=row["finding_id"],
            target_url=row["target_url"],
            vulnerability_type=row["vulnerability_type"],
            test_case=row["test_case"],
            priority=PenTestPriority(row["priority"]),
            status=PenTestStatus(row["status"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            started_at=datetime.fromisoformat(row["started_at"])
            if row["started_at"]
            else None,
            completed_at=datetime.fromisoformat(row["completed_at"])
            if row["completed_at"]
            else None,
            pentagi_job_id=row["pentagi_job_id"],
            metadata=eval(row["metadata"]) if row["metadata"] else {},
        )

    def list_requests(
        self,
        finding_id: Optional[str] = None,
        status: Optional[PenTestStatus] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[PenTestRequest]:
        """List pen test requests."""
        conn = self._get_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM pen_test_requests WHERE 1=1"
        params = []

        if finding_id:
            query += " AND finding_id = ?"
            params.append(finding_id)

        if status:
            query += " AND status = ?"
            params.append(status.value)

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [
            PenTestRequest(
                id=row["id"],
                finding_id=row["finding_id"],
                target_url=row["target_url"],
                vulnerability_type=row["vulnerability_type"],
                test_case=row["test_case"],
                priority=PenTestPriority(row["priority"]),
                status=PenTestStatus(row["status"]),
                created_at=datetime.fromisoformat(row["created_at"]),
                started_at=datetime.fromisoformat(row["started_at"])
                if row["started_at"]
                else None,
                completed_at=datetime.fromisoformat(row["completed_at"])
                if row["completed_at"]
                else None,
                pentagi_job_id=row["pentagi_job_id"],
                metadata=eval(row["metadata"]) if row["metadata"] else {},
            )
            for row in rows
        ]

    def update_request(self, request: PenTestRequest) -> PenTestRequest:
        """Update a pen test request."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE pen_test_requests
            SET status = ?, started_at = ?, completed_at = ?, pentagi_job_id = ?, metadata = ?
            WHERE id = ?
        """,
            (
                request.status.value,
                request.started_at.isoformat() if request.started_at else None,
                request.completed_at.isoformat() if request.completed_at else None,
                request.pentagi_job_id,
                str(request.metadata),
                request.id,
            ),
        )

        conn.commit()
        conn.close()
        return request

    def create_result(self, result: PenTestResult) -> PenTestResult:
        """Create a new pen test result."""
        if not result.id:
            result.id = str(uuid.uuid4())

        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO pen_test_results
            (id, request_id, finding_id, exploitability, exploit_successful, evidence,
             steps_taken, artifacts, confidence_score, execution_time_seconds, created_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                result.id,
                result.request_id,
                result.finding_id,
                result.exploitability.value,
                1 if result.exploit_successful else 0,
                result.evidence,
                str(result.steps_taken),
                str(result.artifacts),
                result.confidence_score,
                result.execution_time_seconds,
                result.created_at.isoformat(),
                str(result.metadata),
            ),
        )

        conn.commit()
        conn.close()
        return result

    def get_result_by_request(self, request_id: str) -> Optional[PenTestResult]:
        """Get pen test result by request ID."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM pen_test_results WHERE request_id = ?", (request_id,)
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return PenTestResult(
            id=row["id"],
            request_id=row["request_id"],
            finding_id=row["finding_id"],
            exploitability=ExploitabilityLevel(row["exploitability"]),
            exploit_successful=bool(row["exploit_successful"]),
            evidence=row["evidence"],
            steps_taken=eval(row["steps_taken"]) if row["steps_taken"] else [],
            artifacts=eval(row["artifacts"]) if row["artifacts"] else [],
            confidence_score=row["confidence_score"],
            execution_time_seconds=row["execution_time_seconds"],
            created_at=datetime.fromisoformat(row["created_at"]),
            metadata=eval(row["metadata"]) if row["metadata"] else {},
        )

    def list_results(
        self,
        finding_id: Optional[str] = None,
        exploitability: Optional[ExploitabilityLevel] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[PenTestResult]:
        """List pen test results."""
        conn = self._get_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM pen_test_results WHERE 1=1"
        params = []

        if finding_id:
            query += " AND finding_id = ?"
            params.append(finding_id)

        if exploitability:
            query += " AND exploitability = ?"
            params.append(exploitability.value)

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [
            PenTestResult(
                id=row["id"],
                request_id=row["request_id"],
                finding_id=row["finding_id"],
                exploitability=ExploitabilityLevel(row["exploitability"]),
                exploit_successful=bool(row["exploit_successful"]),
                evidence=row["evidence"],
                steps_taken=eval(row["steps_taken"]) if row["steps_taken"] else [],
                artifacts=eval(row["artifacts"]) if row["artifacts"] else [],
                confidence_score=row["confidence_score"],
                execution_time_seconds=row["execution_time_seconds"],
                created_at=datetime.fromisoformat(row["created_at"]),
                metadata=eval(row["metadata"]) if row["metadata"] else {},
            )
            for row in rows
        ]

    def create_config(self, config: PenTestConfig) -> PenTestConfig:
        """Create a new Pentagi configuration."""
        if not config.id:
            config.id = str(uuid.uuid4())

        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO pen_test_configs
            (id, name, pentagi_url, api_key, enabled, max_concurrent_tests, timeout_seconds,
             auto_trigger, target_environments, created_at, updated_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                config.id,
                config.name,
                config.pentagi_url,
                config.api_key,
                1 if config.enabled else 0,
                config.max_concurrent_tests,
                config.timeout_seconds,
                1 if config.auto_trigger else 0,
                str(config.target_environments),
                config.created_at.isoformat(),
                config.updated_at.isoformat(),
                str(config.metadata),
            ),
        )

        conn.commit()
        conn.close()
        return config

    def get_config(self, config_id: str) -> Optional[PenTestConfig]:
        """Get Pentagi configuration by ID."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM pen_test_configs WHERE id = ?", (config_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return PenTestConfig(
            id=row["id"],
            name=row["name"],
            pentagi_url=row["pentagi_url"],
            api_key=row["api_key"],
            enabled=bool(row["enabled"]),
            max_concurrent_tests=row["max_concurrent_tests"],
            timeout_seconds=row["timeout_seconds"],
            auto_trigger=bool(row["auto_trigger"]),
            target_environments=eval(row["target_environments"])
            if row["target_environments"]
            else [],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            metadata=eval(row["metadata"]) if row["metadata"] else {},
        )

    def list_configs(self, limit: int = 100, offset: int = 0) -> List[PenTestConfig]:
        """List Pentagi configurations."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM pen_test_configs ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = cursor.fetchall()
        conn.close()

        return [
            PenTestConfig(
                id=row["id"],
                name=row["name"],
                pentagi_url=row["pentagi_url"],
                api_key=row["api_key"],
                enabled=bool(row["enabled"]),
                max_concurrent_tests=row["max_concurrent_tests"],
                timeout_seconds=row["timeout_seconds"],
                auto_trigger=bool(row["auto_trigger"]),
                target_environments=eval(row["target_environments"])
                if row["target_environments"]
                else [],
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
                metadata=eval(row["metadata"]) if row["metadata"] else {},
            )
            for row in rows
        ]

    def update_config(self, config: PenTestConfig) -> PenTestConfig:
        """Update Pentagi configuration."""
        config.updated_at = datetime.utcnow()

        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE pen_test_configs
            SET pentagi_url = ?, api_key = ?, enabled = ?, max_concurrent_tests = ?,
                timeout_seconds = ?, auto_trigger = ?, target_environments = ?,
                updated_at = ?, metadata = ?
            WHERE id = ?
        """,
            (
                config.pentagi_url,
                config.api_key,
                1 if config.enabled else 0,
                config.max_concurrent_tests,
                config.timeout_seconds,
                1 if config.auto_trigger else 0,
                str(config.target_environments),
                config.updated_at.isoformat(),
                str(config.metadata),
                config.id,
            ),
        )

        conn.commit()
        conn.close()
        return config

    def delete_config(self, config_id: str) -> bool:
        """Delete Pentagi configuration."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM pen_test_configs WHERE id = ?", (config_id,))
        deleted = cursor.rowcount > 0

        conn.commit()
        conn.close()
        return deleted
