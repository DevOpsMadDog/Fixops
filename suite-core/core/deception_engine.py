"""Deception Technology Engine — Honeypots and Canary Tokens.

Deploy:
1. Canary tokens: fake credentials/URLs/files that fire alerts when accessed
2. Honeypot endpoints: fake API endpoints that alert on access
3. DNS canaries: fake subdomains that alert on DNS lookup
4. File canaries: fake files with tracking UUIDs
5. Honeypot credentials: fake AWS keys/DB passwords that alert when used

All access attempts are logged, correlated with user sessions/IPs,
and trigger immediate high-severity alerts.

Compliance: SOC2 CC6.8 (unauthorized access detection), NIST SP 800-53 SC-26
"""

from __future__ import annotations

import json
import logging
import secrets
import sqlite3
import string
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default DB path — stored under .fixops_data/ relative to repo root
# ---------------------------------------------------------------------------
_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / ".fixops_data" / "deception.db")


# ============================================================================
# ENUMS
# ============================================================================


class CanaryType(str, Enum):
    """Types of canary / honeypot deception assets."""

    api_key = "api_key"
    aws_credential = "aws_credential"
    database_url = "database_url"
    file = "file"
    endpoint = "endpoint"
    dns_subdomain = "dns_subdomain"
    oauth_token = "oauth_token"


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class CanaryToken(BaseModel):
    """A deployed canary / honeypot asset."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: CanaryType
    token_value: str
    description: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    org_id: str
    alert_count: int = 0
    last_triggered_at: Optional[datetime] = None
    active: bool = True


class CanaryAlert(BaseModel):
    """Fired when a canary token is accessed / used."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    canary_id: str
    triggered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: str
    user_agent: str = ""
    request_headers: Dict[str, str] = Field(default_factory=dict)
    org_id: str
    severity: str = "critical"


# ============================================================================
# ENGINE
# ============================================================================


class DeceptionEngine:
    """
    SQLite-backed deception technology engine.

    Thread-safe via RLock. Multi-tenant via org_id.

    Args:
        db_path: Path to SQLite database file.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Create tables if they do not exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS canary_tokens (
                    id               TEXT PRIMARY KEY,
                    type             TEXT NOT NULL,
                    token_value      TEXT NOT NULL UNIQUE,
                    description      TEXT NOT NULL,
                    created_at       DATETIME NOT NULL,
                    org_id           TEXT NOT NULL,
                    alert_count      INTEGER DEFAULT 0,
                    last_triggered_at DATETIME,
                    active           INTEGER DEFAULT 1
                );

                CREATE INDEX IF NOT EXISTS idx_ct_org
                    ON canary_tokens (org_id, active);

                CREATE INDEX IF NOT EXISTS idx_ct_value
                    ON canary_tokens (token_value);

                CREATE TABLE IF NOT EXISTS canary_alerts (
                    id               TEXT PRIMARY KEY,
                    canary_id        TEXT NOT NULL,
                    triggered_at     DATETIME NOT NULL,
                    source_ip        TEXT NOT NULL,
                    user_agent       TEXT DEFAULT '',
                    request_headers  TEXT DEFAULT '{}',
                    org_id           TEXT NOT NULL,
                    severity         TEXT DEFAULT 'critical'
                );

                CREATE INDEX IF NOT EXISTS idx_ca_org_time
                    ON canary_alerts (org_id, triggered_at DESC);

                CREATE INDEX IF NOT EXISTS idx_ca_canary
                    ON canary_alerts (canary_id);

                CREATE TABLE IF NOT EXISTS honeypot_endpoints (
                    id       TEXT PRIMARY KEY,
                    path     TEXT NOT NULL UNIQUE,
                    org_id   TEXT NOT NULL,
                    created_at DATETIME NOT NULL,
                    active   INTEGER DEFAULT 1
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Canary generation helpers
    # ------------------------------------------------------------------

    def generate_canary_aws_key(self) -> str:
        """Return a fake AWS-style access key with ALDECI prefix (not AKIA)."""
        suffix = "".join(
            secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16)
        )
        return f"ALDECI{suffix}"

    def generate_canary_db_url(self) -> str:
        """Return a fake DB connection string with canary marker."""
        host = f"aldeci-canary-db-{uuid.uuid4().hex[:8]}.internal"
        password = secrets.token_urlsafe(20)
        return f"postgresql://aldeci_canary:{password}@{host}:5432/canary_db"

    def _generate_token_value(self, canary_type: CanaryType) -> str:
        """Generate a realistic-looking but clearly fake token for the given type."""
        unique = uuid.uuid4().hex[:12]
        if canary_type == CanaryType.api_key:
            return f"ALDECI_CANARY_KEY_{unique.upper()}"
        if canary_type == CanaryType.aws_credential:
            return self.generate_canary_aws_key()
        if canary_type == CanaryType.database_url:
            return self.generate_canary_db_url()
        if canary_type == CanaryType.file:
            return f"ALDECI_CANARY_FILE_{unique}"
        if canary_type == CanaryType.endpoint:
            return f"/api/v1/aldeci-canary-{unique}/data"
        if canary_type == CanaryType.dns_subdomain:
            return f"aldeci-canary-{unique}.internal.example.com"
        if canary_type == CanaryType.oauth_token:
            return f"ALDECI_CANARY_TOKEN_{secrets.token_urlsafe(24)}"
        # fallback
        return f"ALDECI_CANARY_{unique.upper()}"

    # ------------------------------------------------------------------
    # Public API — Canary tokens
    # ------------------------------------------------------------------

    def create_canary(
        self,
        type: CanaryType,
        description: str,
        org_id: str,
    ) -> CanaryToken:
        """Generate and persist a new canary token."""
        token = CanaryToken(
            type=type,
            token_value=self._generate_token_value(type),
            description=description,
            org_id=org_id,
        )
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO canary_tokens
                        (id, type, token_value, description, created_at, org_id, active)
                    VALUES (?, ?, ?, ?, ?, ?, 1)
                    """,
                    (
                        token.id,
                        token.type.value,
                        token.token_value,
                        token.description,
                        token.created_at.isoformat(),
                        token.org_id,
                    ),
                )
        _logger.info(
            "Created canary token id=%s type=%s org=%s", token.id, token.type, org_id
        )
        return token

    def check_canary(
        self,
        token_value: str,
        source_ip: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[CanaryAlert]:
        """
        Check whether token_value matches any active canary.

        Returns a CanaryAlert (already persisted) if matched, else None.
        """
        context = context or {}
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM canary_tokens WHERE token_value = ? AND active = 1",
                    (token_value,),
                ).fetchone()
                if row is None:
                    return None

                now = datetime.now(timezone.utc)
                alert = CanaryAlert(
                    canary_id=row["id"],
                    source_ip=source_ip,
                    user_agent=context.get("user_agent", ""),
                    request_headers=context.get("headers", {}),
                    org_id=row["org_id"],
                    severity="critical",
                )
                conn.execute(
                    """
                    INSERT INTO canary_alerts
                        (id, canary_id, triggered_at, source_ip, user_agent,
                         request_headers, org_id, severity)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.id,
                        alert.canary_id,
                        alert.triggered_at.isoformat(),
                        alert.source_ip,
                        alert.user_agent,
                        json.dumps(alert.request_headers),
                        alert.org_id,
                        alert.severity,
                    ),
                )
                conn.execute(
                    """
                    UPDATE canary_tokens
                    SET alert_count = alert_count + 1,
                        last_triggered_at = ?
                    WHERE id = ?
                    """,
                    (now.isoformat(), row["id"]),
                )

        _logger.warning(
            "CANARY TRIGGERED canary_id=%s source_ip=%s org=%s",
            alert.canary_id,
            source_ip,
            alert.org_id,
        )
        return alert

    def list_canaries(self, org_id: str) -> List[CanaryToken]:
        """Return all canaries for an org (active and inactive)."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM canary_tokens WHERE org_id = ? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
        return [self._row_to_canary(r) for r in rows]

    def deactivate_canary(self, canary_id: str, org_id: str) -> bool:
        """Deactivate a canary token. Returns True if found and updated."""
        with self._lock:
            with self._conn() as conn:
                cursor = conn.execute(
                    "UPDATE canary_tokens SET active = 0 WHERE id = ? AND org_id = ?",
                    (canary_id, org_id),
                )
                return cursor.rowcount > 0

    def get_alerts(self, org_id: str, hours: int = 24) -> List[CanaryAlert]:
        """Return canary alerts within the last N hours for an org."""
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM canary_alerts
                    WHERE org_id = ? AND triggered_at >= ?
                    ORDER BY triggered_at DESC
                    """,
                    (org_id, since),
                ).fetchall()
        return [self._row_to_alert(r) for r in rows]

    # ------------------------------------------------------------------
    # Honeypot endpoints
    # ------------------------------------------------------------------

    def list_honeypot_endpoints(self, org_id: str, active_only: bool = True) -> List[Dict[str, Any]]:
        """Return honeypot endpoints for an org.

        Args:
            org_id: Organisation ID.
            active_only: When True (default), return only active endpoints.

        Returns:
            List of dicts with keys: id, path, org_id, created_at, active.
        """
        query = "SELECT id, path, org_id, created_at, active FROM honeypot_endpoints WHERE org_id = ?"
        params: list = [org_id]
        if active_only:
            query += " AND active = 1"
        query += " ORDER BY created_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [
            {
                "id": r["id"],
                "path": r["path"],
                "org_id": r["org_id"],
                "created_at": r["created_at"],
                "active": bool(r["active"]),
            }
            for r in rows
        ]

    def deploy_honeypot_endpoint(self, path: str, org_id: str) -> Dict[str, str]:
        """Register a honeypot path. Returns info dict."""
        ep_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO honeypot_endpoints (id, path, org_id, created_at, active)
                    VALUES (?, ?, ?, ?, 1)
                    """,
                    (ep_id, path, org_id, now),
                )
        _logger.info("Deployed honeypot endpoint path=%s org=%s", path, org_id)
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("THREAT_DETECTED", {"entity_type": "deception_engine", "org_id": org_id, "source_engine": "deception_engine"})
            except Exception:
                pass
        return {"id": ep_id, "path": path, "org_id": org_id, "created_at": now}

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate statistics for an org."""
        with self._lock:
            with self._conn() as conn:
                total_canaries = conn.execute(
                    "SELECT COUNT(*) FROM canary_tokens WHERE org_id = ?", (org_id,)
                ).fetchone()[0]
                active_canaries = conn.execute(
                    "SELECT COUNT(*) FROM canary_tokens WHERE org_id = ? AND active = 1",
                    (org_id,),
                ).fetchone()[0]
                total_alerts = conn.execute(
                    "SELECT COUNT(*) FROM canary_alerts WHERE org_id = ?", (org_id,)
                ).fetchone()[0]
                alerts_24h = conn.execute(
                    """
                    SELECT COUNT(*) FROM canary_alerts
                    WHERE org_id = ? AND triggered_at >= ?
                    """,
                    (
                        org_id,
                        (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(),
                    ),
                ).fetchone()[0]
                honeypots = conn.execute(
                    "SELECT COUNT(*) FROM honeypot_endpoints WHERE org_id = ? AND active = 1",
                    (org_id,),
                ).fetchone()[0]
                by_type_rows = conn.execute(
                    """
                    SELECT type, COUNT(*) as cnt
                    FROM canary_tokens WHERE org_id = ?
                    GROUP BY type
                    """,
                    (org_id,),
                ).fetchall()

        by_type = {r["type"]: r["cnt"] for r in by_type_rows}
        return {
            "org_id": org_id,
            "total_canaries": total_canaries,
            "active_canaries": active_canaries,
            "total_alerts": total_alerts,
            "alerts_last_24h": alerts_24h,
            "honeypot_endpoints": honeypots,
            "canaries_by_type": by_type,
        }

    # ------------------------------------------------------------------
    # Row converters
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_canary(row: sqlite3.Row) -> CanaryToken:
        return CanaryToken(
            id=row["id"],
            type=CanaryType(row["type"]),
            token_value=row["token_value"],
            description=row["description"],
            created_at=datetime.fromisoformat(row["created_at"]),
            org_id=row["org_id"],
            alert_count=row["alert_count"],
            last_triggered_at=(
                datetime.fromisoformat(row["last_triggered_at"])
                if row["last_triggered_at"]
                else None
            ),
            active=bool(row["active"]),
        )

    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> CanaryAlert:
        headers = row["request_headers"]
        if isinstance(headers, str):
            try:
                headers = json.loads(headers)
            except (json.JSONDecodeError, TypeError):
                headers = {}
        return CanaryAlert(
            id=row["id"],
            canary_id=row["canary_id"],
            triggered_at=datetime.fromisoformat(row["triggered_at"]),
            source_ip=row["source_ip"],
            user_agent=row["user_agent"] or "",
            request_headers=headers,
            org_id=row["org_id"],
            severity=row["severity"],
        )
