"""Secrets Management Engine — ALDECI.

Track secret vaults, secrets inventory, rotation schedules, and expiry across
multi-tenant orgs. Supports HashiCorp Vault, AWS Secrets Manager, Azure Key Vault,
GCP Secret Manager, and local vaults.
"""

from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = structlog.get_logger()

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "secrets_manager.db"
)

VAULT_TYPES = {"hashicorp", "aws_secrets", "azure_kv", "gcp_sm", "local"}
SECRET_TYPES = {"api_key", "db_password", "tls_cert", "oauth_token", "ssh_key", "service_account"}
ENVIRONMENTS = {"prod", "staging", "dev"}
SECRET_STATUSES = {"active", "expiring_soon", "expired", "rotated"}
VAULT_STATUSES = {"active", "locked"}


def _now_ts() -> float:
    return time.time()


def _compute_secret_status(expires_at: Optional[float], rotation_days: int) -> str:
    """Determine status based on expiry timestamp."""
    if expires_at is None:
        return "active"
    now = _now_ts()
    if expires_at < now:
        return "expired"
    warn_threshold = now + (rotation_days * 0.25 * 86400)  # 25% of rotation window
    if expires_at < warn_threshold:
        return "expiring_soon"
    return "active"


class SecretsManagerEngine:
    """SQLite WAL-backed secrets inventory and rotation tracking engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS secret_vaults (
                    vault_id     TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    name         TEXT NOT NULL,
                    vault_type   TEXT NOT NULL DEFAULT 'local',
                    status       TEXT NOT NULL DEFAULT 'active',
                    secret_count INTEGER NOT NULL DEFAULT 0,
                    created_at   REAL NOT NULL,
                    updated_at   REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS secrets (
                    secret_id      TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    vault_id       TEXT NOT NULL,
                    name           TEXT NOT NULL,
                    secret_type    TEXT NOT NULL,
                    owner          TEXT NOT NULL DEFAULT '',
                    environment    TEXT NOT NULL DEFAULT 'prod',
                    last_rotated   REAL,
                    expires_at     REAL,
                    rotation_days  INTEGER NOT NULL DEFAULT 90,
                    status         TEXT NOT NULL DEFAULT 'active',
                    created_at     REAL NOT NULL,
                    updated_at     REAL NOT NULL,
                    FOREIGN KEY (vault_id) REFERENCES secret_vaults(vault_id)
                );

                CREATE TABLE IF NOT EXISTS rotation_schedules (
                    schedule_id   TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    secret_id     TEXT NOT NULL,
                    rotation_days INTEGER NOT NULL,
                    next_rotation REAL NOT NULL,
                    created_at    REAL NOT NULL,
                    updated_at    REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS rotation_history (
                    history_id     TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    secret_id      TEXT NOT NULL,
                    rotation_type  TEXT NOT NULL DEFAULT 'manual',
                    performed_by   TEXT NOT NULL DEFAULT '',
                    rotated_at     REAL NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_vaults_org ON secret_vaults(org_id);
                CREATE INDEX IF NOT EXISTS idx_secrets_org ON secrets(org_id);
                CREATE INDEX IF NOT EXISTS idx_secrets_vault ON secrets(vault_id);
                CREATE INDEX IF NOT EXISTS idx_secrets_expires ON secrets(org_id, expires_at);
                CREATE INDEX IF NOT EXISTS idx_rotation_history_secret ON rotation_history(secret_id);
                CREATE INDEX IF NOT EXISTS idx_rotation_schedules_secret ON rotation_schedules(secret_id);
            """)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Vaults
    # ------------------------------------------------------------------

    def create_vault(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new secret vault for an org."""
        vault_type = data.get("vault_type", "local")
        if vault_type not in VAULT_TYPES:
            raise ValueError(f"vault_type must be one of {sorted(VAULT_TYPES)}")

        vault_id = str(uuid.uuid4())
        now = _now_ts()
        name = data.get("name", "Unnamed Vault")
        status = data.get("status", "active")
        if status not in VAULT_STATUSES:
            status = "active"

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO secret_vaults
                       (vault_id, org_id, name, vault_type, status, secret_count, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, 0, ?, ?)""",
                    (vault_id, org_id, name, vault_type, status, now, now),
                )

        _logger.info("secrets.vault_created", vault_id=vault_id, org_id=org_id, name=name)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "secrets_manager", "org_id": org_id, "source_engine": "secrets_manager"})
            except Exception:
                pass

        return {
            "vault_id": vault_id,
            "org_id": org_id,
            "name": name,
            "vault_type": vault_type,
            "status": status,
            "secret_count": 0,
            "created_at": now,
            "updated_at": now,
        }

    def list_vaults(self, org_id: str) -> List[Dict[str, Any]]:
        """List all vaults for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM secret_vaults WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_vault(self, org_id: str, vault_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a vault by ID, scoped to org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM secret_vaults WHERE vault_id = ? AND org_id = ?",
                (vault_id, org_id),
            ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Secrets
    # ------------------------------------------------------------------

    def add_secret(self, org_id: str, vault_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a secret to a vault."""
        # Validate vault belongs to org
        vault = self.get_vault(org_id, vault_id)
        if vault is None:
            raise ValueError(f"Vault {vault_id} not found for org {org_id}")

        secret_type = data.get("secret_type", "api_key")
        if secret_type not in SECRET_TYPES:
            raise ValueError(f"secret_type must be one of {sorted(SECRET_TYPES)}")

        environment = data.get("environment", "prod")
        if environment not in ENVIRONMENTS:
            environment = "prod"

        rotation_days = int(data.get("rotation_days", 90))
        last_rotated = data.get("last_rotated") or _now_ts()
        expires_at = data.get("expires_at") or (last_rotated + rotation_days * 86400)

        secret_id = str(uuid.uuid4())
        now = _now_ts()
        name = data.get("name", "Unnamed Secret")
        owner = data.get("owner", "")
        status = _compute_secret_status(expires_at, rotation_days)

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO secrets
                       (secret_id, org_id, vault_id, name, secret_type, owner, environment,
                        last_rotated, expires_at, rotation_days, status, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (secret_id, org_id, vault_id, name, secret_type, owner, environment,
                     last_rotated, expires_at, rotation_days, status, now, now),
                )
                # Update vault secret_count
                conn.execute(
                    "UPDATE secret_vaults SET secret_count = secret_count + 1, updated_at = ? "
                    "WHERE vault_id = ?",
                    (now, vault_id),
                )

        _logger.info("secrets.secret_added", secret_id=secret_id, org_id=org_id,
                     vault_id=vault_id, secret_type=secret_type)
        return {
            "secret_id": secret_id,
            "org_id": org_id,
            "vault_id": vault_id,
            "name": name,
            "secret_type": secret_type,
            "owner": owner,
            "environment": environment,
            "last_rotated": last_rotated,
            "expires_at": expires_at,
            "rotation_days": rotation_days,
            "status": status,
            "created_at": now,
            "updated_at": now,
        }

    def list_secrets(
        self,
        org_id: str,
        vault_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List secrets for an org, optionally filtered by vault or status."""
        query = "SELECT * FROM secrets WHERE org_id = ?"
        params: List[Any] = [org_id]

        if vault_id:
            query += " AND vault_id = ?"
            params.append(vault_id)
        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_secret(self, org_id: str, secret_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a secret by ID, scoped to org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM secrets WHERE secret_id = ? AND org_id = ?",
                (secret_id, org_id),
            ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Rotation
    # ------------------------------------------------------------------

    def schedule_rotation(self, org_id: str, secret_id: str, rotation_days: int) -> Dict[str, Any]:
        """Set or update the rotation schedule for a secret."""
        secret = self.get_secret(org_id, secret_id)
        if secret is None:
            raise ValueError(f"Secret {secret_id} not found for org {org_id}")

        now = _now_ts()
        next_rotation = now + rotation_days * 86400

        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT schedule_id FROM rotation_schedules WHERE secret_id = ? AND org_id = ?",
                    (secret_id, org_id),
                ).fetchone()

                if existing:
                    schedule_id = existing["schedule_id"]
                    conn.execute(
                        """UPDATE rotation_schedules
                           SET rotation_days = ?, next_rotation = ?, updated_at = ?
                           WHERE schedule_id = ?""",
                        (rotation_days, next_rotation, now, schedule_id),
                    )
                else:
                    schedule_id = str(uuid.uuid4())
                    conn.execute(
                        """INSERT INTO rotation_schedules
                           (schedule_id, org_id, secret_id, rotation_days, next_rotation,
                            created_at, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (schedule_id, org_id, secret_id, rotation_days, next_rotation, now, now),
                    )

                # Update rotation_days on the secret itself
                conn.execute(
                    "UPDATE secrets SET rotation_days = ?, updated_at = ? WHERE secret_id = ?",
                    (rotation_days, now, secret_id),
                )

        _logger.info("secrets.schedule_set", secret_id=secret_id, rotation_days=rotation_days)
        return {
            "schedule_id": schedule_id,
            "org_id": org_id,
            "secret_id": secret_id,
            "rotation_days": rotation_days,
            "next_rotation": next_rotation,
        }

    def record_rotation(
        self,
        org_id: str,
        secret_id: str,
        rotation_type: str,
        performed_by: str,
    ) -> Dict[str, Any]:
        """Record that a secret was rotated and update its metadata."""
        secret = self.get_secret(org_id, secret_id)
        if secret is None:
            raise ValueError(f"Secret {secret_id} not found for org {org_id}")

        history_id = str(uuid.uuid4())
        now = _now_ts()
        rotation_days = secret.get("rotation_days", 90)
        new_expires_at = now + rotation_days * 86400

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO rotation_history
                       (history_id, org_id, secret_id, rotation_type, performed_by, rotated_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (history_id, org_id, secret_id, rotation_type, performed_by, now),
                )
                conn.execute(
                    """UPDATE secrets
                       SET last_rotated = ?, expires_at = ?, status = 'rotated', updated_at = ?
                       WHERE secret_id = ? AND org_id = ?""",
                    (now, new_expires_at, now, secret_id, org_id),
                )
                # Update next_rotation in schedule if exists
                conn.execute(
                    """UPDATE rotation_schedules
                       SET next_rotation = ?, updated_at = ?
                       WHERE secret_id = ? AND org_id = ?""",
                    (new_expires_at, now, secret_id, org_id),
                )

        _logger.info("secrets.rotated", secret_id=secret_id, rotation_type=rotation_type,
                     performed_by=performed_by)
        return {
            "history_id": history_id,
            "org_id": org_id,
            "secret_id": secret_id,
            "rotation_type": rotation_type,
            "performed_by": performed_by,
            "rotated_at": now,
            "new_expires_at": new_expires_at,
        }

    def get_rotation_history(self, org_id: str, secret_id: str) -> List[Dict[str, Any]]:
        """Get rotation history for a secret, scoped to org."""
        # Verify secret belongs to org
        secret = self.get_secret(org_id, secret_id)
        if secret is None:
            raise ValueError(f"Secret {secret_id} not found for org {org_id}")

        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM rotation_history
                   WHERE secret_id = ? AND org_id = ?
                   ORDER BY rotated_at DESC""",
                (secret_id, org_id),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Expiry
    # ------------------------------------------------------------------

    def get_expiring_secrets(self, org_id: str, days_ahead: int = 30) -> List[Dict[str, Any]]:
        """Return secrets expiring within the next N days for the org."""
        now = _now_ts()
        cutoff = now + days_ahead * 86400

        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM secrets
                   WHERE org_id = ? AND expires_at IS NOT NULL
                     AND expires_at >= ? AND expires_at <= ?
                   ORDER BY expires_at ASC""",
                (org_id, now, cutoff),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_secrets_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated stats for an org's secrets."""
        with self._conn() as conn:
            total_secrets = conn.execute(
                "SELECT COUNT(*) FROM secrets WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            vaults_count = conn.execute(
                "SELECT COUNT(*) FROM secret_vaults WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            expired = conn.execute(
                "SELECT COUNT(*) FROM secrets WHERE org_id = ? AND status = 'expired'",
                (org_id,),
            ).fetchone()[0]

            expiring_soon = conn.execute(
                "SELECT COUNT(*) FROM secrets WHERE org_id = ? AND status = 'expiring_soon'",
                (org_id,),
            ).fetchone()[0]

            active = conn.execute(
                "SELECT COUNT(*) FROM secrets WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT secret_type, COUNT(*) as cnt FROM secrets WHERE org_id = ? GROUP BY secret_type",
                (org_id,),
            ).fetchall()

            env_rows = conn.execute(
                "SELECT environment, COUNT(*) as cnt FROM secrets WHERE org_id = ? GROUP BY environment",
                (org_id,),
            ).fetchall()

        return {
            "total_secrets": total_secrets,
            "expired": expired,
            "expiring_soon": expiring_soon,
            "active": active,
            "by_type": {r["secret_type"]: r["cnt"] for r in type_rows},
            "by_environment": {r["environment"]: r["cnt"] for r in env_rows},
            "vaults_count": vaults_count,
        }
