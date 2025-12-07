"""Database manager for Pentagi pen testing data."""
import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from core.pentagi_models import (
    ApprovalState,
    ExploitabilityLevel,
    MicroTestCategory,
    MicroTestLifecycle,
    MicroTestPlaybook,
    MicroTestRun,
    MicroTestRunStatus,
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
            """
            CREATE TABLE IF NOT EXISTS micro_test_playbooks (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                category TEXT NOT NULL,
                lifecycle TEXT NOT NULL,
                severity_focus TEXT,
                target_types TEXT,
                prerequisites TEXT,
                tooling_profile TEXT,
                controls_required TEXT,
                estimated_runtime_seconds INTEGER,
                max_execution_seconds INTEGER,
                version TEXT,
                owner TEXT,
                enabled INTEGER NOT NULL,
                compliance_tags TEXT,
                guardrails TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                metadata TEXT
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS micro_test_runs (
                id TEXT PRIMARY KEY,
                playbook_id TEXT NOT NULL,
                request_id TEXT,
                tenant_id TEXT,
                status TEXT NOT NULL,
                priority TEXT NOT NULL,
                approval_state TEXT NOT NULL,
                runner_label TEXT,
                runner_location TEXT,
                scheduled_at TEXT,
                started_at TEXT,
                completed_at TEXT,
                evidence_path TEXT,
                artifacts TEXT,
                commands TEXT,
                results TEXT,
                policy_blockers TEXT,
                telemetry TEXT,
                risk_score REAL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(playbook_id) REFERENCES micro_test_playbooks(id)
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
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_micro_tests_category ON micro_test_playbooks(category)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_micro_runs_status ON micro_test_runs(status)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_micro_runs_playbook ON micro_test_runs(playbook_id)"
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
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
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
        params.extend([str(limit), str(offset)])

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
                metadata=json.loads(row["metadata"]) if row["metadata"] else {},
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
                json.dumps(request.metadata),
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
                json.dumps(result.steps_taken),
                json.dumps(result.artifacts),
                result.confidence_score,
                result.execution_time_seconds,
                result.created_at.isoformat(),
                json.dumps(result.metadata),
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
            steps_taken=json.loads(row["steps_taken"]) if row["steps_taken"] else [],
            artifacts=json.loads(row["artifacts"]) if row["artifacts"] else [],
            confidence_score=row["confidence_score"],
            execution_time_seconds=row["execution_time_seconds"],
            created_at=datetime.fromisoformat(row["created_at"]),
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
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
        params.extend([str(limit), str(offset)])

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
                steps_taken=json.loads(row["steps_taken"])
                if row["steps_taken"]
                else [],
                artifacts=json.loads(row["artifacts"]) if row["artifacts"] else [],
                confidence_score=row["confidence_score"],
                execution_time_seconds=row["execution_time_seconds"],
                created_at=datetime.fromisoformat(row["created_at"]),
                metadata=json.loads(row["metadata"]) if row["metadata"] else {},
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
                json.dumps(config.target_environments),
                config.created_at.isoformat(),
                config.updated_at.isoformat(),
                json.dumps(config.metadata),
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
            target_environments=json.loads(row["target_environments"])
            if row["target_environments"]
            else [],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
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
                target_environments=json.loads(row["target_environments"])
                if row["target_environments"]
                else [],
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
                metadata=json.loads(row["metadata"]) if row["metadata"] else {},
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
                json.dumps(config.target_environments),
                config.updated_at.isoformat(),
                json.dumps(config.metadata),
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

    # --- Micro Test Playbooks -------------------------------------------------

    def create_micro_test_playbook(
        self, playbook: MicroTestPlaybook
    ) -> MicroTestPlaybook:
        """Create a new micro test playbook."""
        if not playbook.id:
            playbook.id = str(uuid.uuid4())

        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO micro_test_playbooks
            (id, name, description, category, lifecycle, severity_focus, target_types,
             prerequisites, tooling_profile, controls_required, estimated_runtime_seconds,
             max_execution_seconds, version, owner, enabled, compliance_tags, guardrails,
             created_at, updated_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                playbook.id,
                playbook.name,
                playbook.description,
                playbook.category.value,
                playbook.lifecycle.value,
                json.dumps(playbook.severity_focus),
                json.dumps(playbook.target_types),
                json.dumps(playbook.prerequisites),
                json.dumps(playbook.tooling_profile),
                json.dumps(playbook.controls_required),
                playbook.estimated_runtime_seconds,
                playbook.max_execution_seconds,
                playbook.version,
                playbook.owner,
                1 if playbook.enabled else 0,
                json.dumps(playbook.compliance_tags),
                json.dumps(playbook.guardrails),
                playbook.created_at.isoformat(),
                playbook.updated_at.isoformat(),
                json.dumps(playbook.metadata),
            ),
        )

        conn.commit()
        conn.close()
        return playbook

    def list_micro_test_playbooks(
        self,
        category: Optional[MicroTestCategory] = None,
        lifecycle: Optional[MicroTestLifecycle] = None,
        enabled: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[MicroTestPlaybook]:
        """List micro test playbooks."""
        conn = self._get_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM micro_test_playbooks WHERE 1=1"
        params: List = []

        if category:
            query += " AND category = ?"
            params.append(category.value)

        if lifecycle:
            query += " AND lifecycle = ?"
            params.append(lifecycle.value)

        if enabled is not None:
            query += " AND enabled = ?"
            params.append(1 if enabled else 0)

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([str(limit), str(offset)])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [self._row_to_playbook(row) for row in rows]

    def get_micro_test_playbook(self, playbook_id: str) -> Optional[MicroTestPlaybook]:
        """Get a micro test playbook."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM micro_test_playbooks WHERE id = ?", (playbook_id,)
        )
        row = cursor.fetchone()
        conn.close()

        return self._row_to_playbook(row) if row else None

    def update_micro_test_playbook(
        self, playbook: MicroTestPlaybook
    ) -> MicroTestPlaybook:
        """Update a micro test playbook."""
        playbook.updated_at = datetime.utcnow()

        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE micro_test_playbooks
            SET description = ?, category = ?, lifecycle = ?, severity_focus = ?,
                target_types = ?, prerequisites = ?, tooling_profile = ?, controls_required = ?,
                estimated_runtime_seconds = ?, max_execution_seconds = ?, version = ?, owner = ?,
                enabled = ?, compliance_tags = ?, guardrails = ?, updated_at = ?, metadata = ?
            WHERE id = ?
        """,
            (
                playbook.description,
                playbook.category.value,
                playbook.lifecycle.value,
                json.dumps(playbook.severity_focus),
                json.dumps(playbook.target_types),
                json.dumps(playbook.prerequisites),
                json.dumps(playbook.tooling_profile),
                json.dumps(playbook.controls_required),
                playbook.estimated_runtime_seconds,
                playbook.max_execution_seconds,
                playbook.version,
                playbook.owner,
                1 if playbook.enabled else 0,
                json.dumps(playbook.compliance_tags),
                json.dumps(playbook.guardrails),
                playbook.updated_at.isoformat(),
                json.dumps(playbook.metadata),
                playbook.id,
            ),
        )

        conn.commit()
        conn.close()
        return playbook

    def delete_micro_test_playbook(self, playbook_id: str) -> bool:
        """Delete a micro test playbook."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM micro_test_playbooks WHERE id = ?", (playbook_id,))
        deleted = cursor.rowcount > 0

        conn.commit()
        conn.close()
        return deleted

    def _row_to_playbook(self, row: sqlite3.Row) -> MicroTestPlaybook:
        """Convert DB row to MicroTestPlaybook."""
        return MicroTestPlaybook(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            category=MicroTestCategory(row["category"]),
            lifecycle=MicroTestLifecycle(row["lifecycle"]),
            severity_focus=json.loads(row["severity_focus"])
            if row["severity_focus"]
            else [],
            target_types=json.loads(row["target_types"])
            if row["target_types"]
            else [],
            prerequisites=json.loads(row["prerequisites"])
            if row["prerequisites"]
            else [],
            tooling_profile=json.loads(row["tooling_profile"])
            if row["tooling_profile"]
            else [],
            controls_required=json.loads(row["controls_required"])
            if row["controls_required"]
            else [],
            estimated_runtime_seconds=row["estimated_runtime_seconds"],
            max_execution_seconds=row["max_execution_seconds"],
            version=row["version"],
            owner=row["owner"],
            enabled=bool(row["enabled"]),
            compliance_tags=json.loads(row["compliance_tags"])
            if row["compliance_tags"]
            else [],
            guardrails=json.loads(row["guardrails"]) if row["guardrails"] else {},
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        )

    # --- Micro Test Runs ------------------------------------------------------

    def create_micro_test_run(self, run: MicroTestRun) -> MicroTestRun:
        """Create a micro test run."""
        if not run.id:
            run.id = str(uuid.uuid4())

        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO micro_test_runs
            (id, playbook_id, request_id, tenant_id, status, priority, approval_state,
             runner_label, runner_location, scheduled_at, started_at, completed_at,
             evidence_path, artifacts, commands, results, policy_blockers, telemetry,
             risk_score, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                run.id,
                run.playbook_id,
                run.request_id,
                run.tenant_id,
                run.status.value,
                run.priority.value,
                run.approval_state.value,
                run.runner_label,
                run.runner_location,
                run.scheduled_at.isoformat() if run.scheduled_at else None,
                run.started_at.isoformat() if run.started_at else None,
                run.completed_at.isoformat() if run.completed_at else None,
                run.evidence_path,
                json.dumps(run.artifacts),
                json.dumps(run.commands),
                json.dumps(run.results),
                json.dumps(run.policy_blockers),
                json.dumps(run.telemetry),
                run.risk_score,
                run.created_at.isoformat(),
            ),
        )

        conn.commit()
        conn.close()
        return run

    def list_micro_test_runs(
        self,
        playbook_id: Optional[str] = None,
        status: Optional[MicroTestRunStatus] = None,
        request_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[MicroTestRun]:
        """List micro test runs."""
        conn = self._get_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM micro_test_runs WHERE 1=1"
        params: List = []

        if playbook_id:
            query += " AND playbook_id = ?"
            params.append(playbook_id)

        if status:
            query += " AND status = ?"
            params.append(status.value)

        if request_id:
            query += " AND request_id = ?"
            params.append(request_id)

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([str(limit), str(offset)])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [self._row_to_run(row) for row in rows]

    def get_micro_test_run(self, run_id: str) -> Optional[MicroTestRun]:
        """Get micro test run by ID."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM micro_test_runs WHERE id = ?", (run_id,))
        row = cursor.fetchone()
        conn.close()

        return self._row_to_run(row) if row else None

    def update_micro_test_run(self, run: MicroTestRun) -> MicroTestRun:
        """Update micro test run state."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE micro_test_runs
            SET status = ?, approval_state = ?, runner_label = ?, runner_location = ?,
                scheduled_at = ?, started_at = ?, completed_at = ?, evidence_path = ?,
                artifacts = ?, commands = ?, results = ?, policy_blockers = ?, telemetry = ?,
                risk_score = ?
            WHERE id = ?
        """,
            (
                run.status.value,
                run.approval_state.value,
                run.runner_label,
                run.runner_location,
                run.scheduled_at.isoformat() if run.scheduled_at else None,
                run.started_at.isoformat() if run.started_at else None,
                run.completed_at.isoformat() if run.completed_at else None,
                run.evidence_path,
                json.dumps(run.artifacts),
                json.dumps(run.commands),
                json.dumps(run.results),
                json.dumps(run.policy_blockers),
                json.dumps(run.telemetry),
                run.risk_score,
                run.id,
            ),
        )

        conn.commit()
        conn.close()
        return run

    def _row_to_run(self, row: sqlite3.Row) -> MicroTestRun:
        """Convert DB row to MicroTestRun."""
        return MicroTestRun(
            id=row["id"],
            playbook_id=row["playbook_id"],
            status=MicroTestRunStatus(row["status"]),
            priority=PenTestPriority(row["priority"]),
            approval_state=ApprovalState(row["approval_state"]),
            request_id=row["request_id"],
            tenant_id=row["tenant_id"],
            runner_label=row["runner_label"],
            runner_location=row["runner_location"],
            scheduled_at=datetime.fromisoformat(row["scheduled_at"])
            if row["scheduled_at"]
            else None,
            started_at=datetime.fromisoformat(row["started_at"])
            if row["started_at"]
            else None,
            completed_at=datetime.fromisoformat(row["completed_at"])
            if row["completed_at"]
            else None,
            evidence_path=row["evidence_path"],
            artifacts=json.loads(row["artifacts"]) if row["artifacts"] else [],
            commands=json.loads(row["commands"]) if row["commands"] else [],
            results=json.loads(row["results"]) if row["results"] else {},
            policy_blockers=json.loads(row["policy_blockers"])
            if row["policy_blockers"]
            else [],
            telemetry=json.loads(row["telemetry"]) if row["telemetry"] else {},
            risk_score=row["risk_score"] if row["risk_score"] else 0.0,
            created_at=datetime.fromisoformat(row["created_at"]),
        )
