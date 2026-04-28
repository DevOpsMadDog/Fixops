"""
Enterprise Audit Logging System for ALDECI Phase 5.

This module provides a comprehensive audit trail with:
- Structured event logging with UUID tracking
- SQLite-backed persistence with indexed queries
- FastAPI middleware for automatic API request logging
- Compliance event filtering (SOC2, HIPAA, PCI-DSS)
- CSV export for auditors

Compliance:
- SOC2 CC6.1: Logical access controls (role assignment, permission checks)
- SOC2 CC7.2: System monitoring (all API activity)
- HIPAA 164.312(b): Audit controls (data access logging)
- PCI-DSS 10.2: Audit trail (user activity recording)
"""

from __future__ import annotations

import csv
import io
import json
import logging
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import Response
    _STARLETTE_AVAILABLE = True
except ImportError:
    _STARLETTE_AVAILABLE = False
    BaseHTTPMiddleware = object  # type: ignore

_logger = logging.getLogger(__name__)


# ============================================================================
# AUDIT EVENT DATACLASS
# ============================================================================

@dataclass
class AuditEvent:
    """
    Immutable audit event record.

    Attributes:
        event_id: Unique UUID for event
        timestamp: When event occurred (UTC)
        actor_id: User or service performing action
        actor_role: Role of actor (for quick filtering)
        action: Event action code (e.g., "finding.triage", "council.override")
        resource_type: Type of resource affected (finding, connector, user, etc.)
        resource_id: ID of resource affected
        org_id: Organization ID for multi-tenancy
        result: "success", "denied", or "error"
        details: Action-specific metadata dict
        ip_address: Client IP address (if available)
        session_id: Session ID (if available)
        error_message: Error message if result is "error"
    """

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    actor_id: str = ""
    actor_role: str = "unknown"
    action: str = ""
    resource_type: str = ""
    resource_id: str = ""
    org_id: str = "default"
    result: str = "success"
    details: Dict[str, Any] = field(default_factory=dict)
    ip_address: Optional[str] = None
    session_id: Optional[str] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for JSON serialization."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "actor_id": self.actor_id,
            "actor_role": self.actor_role,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "org_id": self.org_id,
            "result": self.result,
            "details": self.details,
            "ip_address": self.ip_address,
            "session_id": self.session_id,
            "error_message": self.error_message,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuditEvent:
        """Create event from dict (e.g., loaded from DB)."""
        if isinstance(data.get("timestamp"), str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ============================================================================
# AUDIT LOGGER
# ============================================================================

class AuditLogger:
    """
    Enterprise audit logger with SQLite persistence.

    Provides:
    - Structured audit event logging
    - Indexed queries (org_id, actor_id, action, timestamp)
    - Compliance event filtering
    - CSV export for auditors
    - Thread-safe operations
    """

    def __init__(self, db_path: str | Path = ":memory:"):
        """
        Initialize audit logger.

        Args:
            db_path: Path to SQLite database file. Use ":memory:" for in-memory DB.
        """
        self.db_path = db_path if isinstance(db_path, Path) else Path(db_path)
        self._lock = threading.RLock()
        self._logger = logging.getLogger(__name__)
        self._in_memory_conn = None  # Keep single connection for in-memory DB

        # Create database and schema
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema with indices."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Main audit table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    actor_role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    result TEXT NOT NULL,
                    details TEXT NOT NULL,
                    ip_address TEXT,
                    session_id TEXT,
                    error_message TEXT
                )
            """)

            # Indices for common queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_org_timestamp
                ON audit_events (org_id, timestamp DESC)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_actor_timestamp
                ON audit_events (actor_id, timestamp DESC)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_action_timestamp
                ON audit_events (action, timestamp DESC)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_resource
                ON audit_events (resource_type, resource_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_result
                ON audit_events (result, timestamp DESC)
            """)

            conn.commit()

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        if str(self.db_path) == ":memory:":
            # In-memory DB — reuse single connection
            if self._in_memory_conn is None:
                self._in_memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
                self._in_memory_conn.row_factory = sqlite3.Row
            return self._in_memory_conn
        else:
            # Ensure parent directory exists
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            return conn

    def log(self, event: AuditEvent) -> str:
        """
        Log an audit event.

        Args:
            event: AuditEvent to log

        Returns:
            Event ID
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO audit_events
                    (event_id, timestamp, actor_id, actor_role, action,
                     resource_type, resource_id, org_id, result, details,
                     ip_address, session_id, error_message)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.actor_id,
                    event.actor_role,
                    event.action,
                    event.resource_type,
                    event.resource_id,
                    event.org_id,
                    event.result,
                    json.dumps(event.details),
                    event.ip_address,
                    event.session_id,
                    event.error_message,
                ))
                conn.commit()

        self._logger.debug(
            "Logged %s event: action=%s, actor=%s, result=%s",
            event.resource_type, event.action, event.actor_id, event.result,
        )
        return event.event_id

    def search(
        self,
        org_id: str,
        actor_id: Optional[str] = None,
        action: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        result: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """
        Search audit events.

        Args:
            org_id: Organization ID
            actor_id: Filter by actor
            action: Filter by action (exact match)
            since: Start timestamp (inclusive)
            until: End timestamp (inclusive)
            result: Filter by result (success/denied/error)
            limit: Max results

        Returns:
            List of AuditEvent objects
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                query = "SELECT * FROM audit_events WHERE org_id = ?"
                params: List[Any] = [org_id]

                if actor_id:
                    query += " AND actor_id = ?"
                    params.append(actor_id)

                if action:
                    query += " AND action = ?"
                    params.append(action)

                if since:
                    query += " AND timestamp >= ?"
                    params.append(since.isoformat())

                if until:
                    query += " AND timestamp <= ?"
                    params.append(until.isoformat())

                if result:
                    query += " AND result = ?"
                    params.append(result)

                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)

                cursor.execute(query, params)
                rows = cursor.fetchall()

        events = []
        for row in rows:
            event_dict = dict(row)
            event_dict["details"] = json.loads(event_dict["details"])
            events.append(AuditEvent.from_dict(event_dict))

        return events

    def get_actor_activity(
        self, actor_id: str, org_id: str, days: int = 30, limit: int = 500
    ) -> List[AuditEvent]:
        """
        Get activity for a user over time period.

        Args:
            actor_id: Actor ID
            org_id: Organization ID
            days: Look back N days
            limit: Max results

        Returns:
            List of AuditEvent objects
        """
        since = datetime.now(timezone.utc) - timedelta(days=days)
        return self.search(
            org_id=org_id,
            actor_id=actor_id,
            since=since,
            limit=limit,
        )

    def get_security_events(
        self, org_id: str, since: datetime, limit: int = 500
    ) -> List[AuditEvent]:
        """
        Get security-relevant events (denials, overrides, escalations).

        Args:
            org_id: Organization ID
            since: Start time (inclusive)
            limit: Max results

        Returns:
            List of AuditEvent objects
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Security-relevant: denials, overrides, escalations, errors
                security_actions = [
                    "permission_denied",
                    "council.override",
                    "role_escalation",
                    "api_key.created",
                    "api_key.revoked",
                    "policy.modified",
                ]

                query = """
                    SELECT * FROM audit_events
                    WHERE org_id = ?
                    AND (result IN ('denied', 'error') OR action IN ({}))
                    AND timestamp >= ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """.format(",".join(["?"] * len(security_actions)))  # nosec B608

                params = [org_id] + security_actions + [since.isoformat(), limit]
                cursor.execute(query, params)
                rows = cursor.fetchall()

        events = []
        for row in rows:
            event_dict = dict(row)
            event_dict["details"] = json.loads(event_dict["details"])
            events.append(AuditEvent.from_dict(event_dict))

        return events

    def get_compliance_trail(
        self, org_id: str, framework: str = "SOC2", limit: int = 10000
    ) -> List[AuditEvent]:
        """
        Get events relevant to compliance frameworks.

        Args:
            org_id: Organization ID
            framework: Compliance framework (SOC2, HIPAA, PCI-DSS)
            limit: Max results

        Returns:
            List of AuditEvent objects
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Map frameworks to relevant actions/resources
                compliance_map = {
                    "SOC2": [
                        "role_assignment",
                        "permission_check",
                        "api_request",
                        "council.override",
                    ],
                    "HIPAA": [
                        "finding.read",
                        "finding.write",
                        "role_assignment",
                        "permission_denied",
                    ],
                    "PCI_DSS": [
                        "connector.pull",
                        "findings.write",
                        "audit_log.export",
                        "report.create",
                    ],
                }

                relevant_actions = compliance_map.get(framework, [])

                query = """
                    SELECT * FROM audit_events
                    WHERE org_id = ?
                    AND action IN ({})
                    ORDER BY timestamp DESC
                    LIMIT ?
                """.format(",".join(["?"] * len(relevant_actions)))  # nosec B608

                params = [org_id] + relevant_actions + [limit]
                cursor.execute(query, params)
                rows = cursor.fetchall()

        events = []
        for row in rows:
            event_dict = dict(row)
            event_dict["details"] = json.loads(event_dict["details"])
            events.append(AuditEvent.from_dict(event_dict))

        return events

    def export_csv(
        self, org_id: str, since: datetime, until: datetime
    ) -> str:
        """
        Export audit events as CSV for auditors.

        Args:
            org_id: Organization ID
            since: Start timestamp
            until: End timestamp

        Returns:
            CSV content as string
        """
        events = self.search(
            org_id=org_id,
            since=since,
            until=until,
            limit=100000,
        )

        output = io.StringIO()
        if not events:
            output.write("No events found.\n")
            return output.getvalue()

        writer = csv.DictWriter(output, fieldnames=events[0].to_dict().keys())
        writer.writeheader()

        for event in events:
            row = event.to_dict()
            row["details"] = json.dumps(row["details"])
            writer.writerow(row)

        return output.getvalue()

    def get_event_count(self, org_id: str) -> int:
        """Get total audit events for org."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM audit_events WHERE org_id = ?", (org_id,))
                return cursor.fetchone()[0]


# ============================================================================
# FASTAPI AUDIT MIDDLEWARE
# ============================================================================

if _STARLETTE_AVAILABLE:
    class AuditMiddleware(BaseHTTPMiddleware):
        """
        FastAPI middleware that automatically logs API requests.

        Logs:
        - All API requests with status code
        - Permission denials (403)
        - Authentication failures (401)
        - Data access for classified resources
        - Errors (5xx)
        """

        def __init__(self, app, audit_logger: AuditLogger):
            """
            Initialize middleware.

            Args:
                app: FastAPI app
                audit_logger: AuditLogger instance
            """
            super().__init__(app)
            self.audit_logger = audit_logger
            self._logger = _logger

        async def dispatch(self, request: Request, call_next) -> Response:
            """Intercept request, log, and pass to handler."""
            # Extract request context
            method = request.method
            path = request.url.path
            client_ip = request.client.host if request.client else "unknown"
            actor_id = getattr(request.state, "user_id", "anonymous")
            actor_role = getattr(request.state, "user_role", "unknown")
            org_id = getattr(request.state, "org_id", "default")
            session_id = getattr(request.state, "session_id", None)

            # Call handler
            response = await call_next(request)

            # Determine if this is a security-relevant event
            action = f"api.{method.lower()}"
            result = "success"
            error_message = None

            if response.status_code == 401:
                result = "denied"
                action = "auth_failed"
            elif response.status_code == 403:
                result = "denied"
                action = "permission_denied"
            elif response.status_code >= 500:
                result = "error"
                error_message = f"HTTP {response.status_code}"
            elif response.status_code >= 400:
                result = "error"
                error_message = f"HTTP {response.status_code}"

            # Log audit event (skip noisy endpoints like /health)
            if path not in ["/health", "/metrics"]:
                event = AuditEvent(
                    actor_id=actor_id,
                    actor_role=actor_role,
                    action=action,
                    resource_type="api_request",
                    resource_id=path,
                    org_id=org_id,
                    result=result,
                    ip_address=client_ip,
                    session_id=session_id,
                    error_message=error_message,
                    details={
                        "method": method,
                        "path": path,
                        "status_code": response.status_code,
                    },
                )
                self.audit_logger.log(event)

            return response
else:
    # Starlette not available, create stub
    class AuditMiddleware:  # type: ignore
        """Stub when Starlette is not available."""
        def __init__(self, app, audit_logger: AuditLogger):
            self.audit_logger = audit_logger


# ============================================================================
# COMPLIANCE CONTROL MAPPING
# ============================================================================

class ComplianceControlMapping:
    """Map audit events to compliance control requirements."""

    # SOC2 CC6.1: Logical access controls
    SOC2_CC6_1_EVENTS = [
        "role_assignment",
        "role_escalation",
        "permission_check",
        "permission_denied",
        "users:manage",
        "users:rbac",
    ]

    # SOC2 CC7.2: System monitoring and anomalies
    SOC2_CC7_2_EVENTS = [
        "api_request",
        "auth_failed",
        "api_key.created",
        "api_key.revoked",
        "system_config_change",
    ]

    # HIPAA 164.312(b): Audit controls
    HIPAA_312B_EVENTS = [
        "finding.read",
        "finding.write",
        "compliance:evidence",
        "permission_denied",
        "role_assignment",
    ]

    # PCI-DSS 10.2: Audit trail for user activity
    PCI_DSS_10_2_EVENTS = [
        "connector.pull",
        "findings.write",
        "audit_log.export",
        "report.create",
        "council.override",
        "autofix.apply",
    ]

    @classmethod
    def get_controls_for_event(cls, event: AuditEvent) -> List[str]:
        """
        Get compliance controls associated with an audit event.

        Args:
            event: AuditEvent

        Returns:
            List of control identifiers (e.g., "SOC2_CC6_1")
        """
        controls = []

        if event.action in cls.SOC2_CC6_1_EVENTS:
            controls.append("SOC2_CC6_1")
        if event.action in cls.SOC2_CC7_2_EVENTS:
            controls.append("SOC2_CC7_2")
        if event.action in cls.HIPAA_312B_EVENTS:
            controls.append("HIPAA_312B")
        if event.action in cls.PCI_DSS_10_2_EVENTS:
            controls.append("PCI_DSS_10_2")

        return controls


# ============================================================================
# FACTORY FUNCTIONS
# ============================================================================

def create_audit_logger(db_path: str | Path = "data/audit.db") -> AuditLogger:
    """
    Factory function to create audit logger.

    Args:
        db_path: Path to audit database

    Returns:
        Initialized AuditLogger
    """
    return AuditLogger(db_path)


__all__ = [
    "AuditEvent",
    "AuditLogger",
    "AuditMiddleware",
    "ComplianceControlMapping",
    "create_audit_logger",
]
