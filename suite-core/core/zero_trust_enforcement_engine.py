"""Zero Trust Enforcement Engine — ALDECI.

Provides the policy enforcement backend for the Zero Trust security model.
Implements continuous verification: never trust, always verify.

Capabilities:
  - Policy CRUD with priority-ordered evaluation
  - Composite risk scoring (trust score, MFA, location, device)
  - Access request evaluation with decision audit trail
  - Trust score management per entity (user/device/service)
  - Session lifecycle management with revocation
  - Stats aggregation per org

Compliance: NIST SP 800-207 (Zero Trust Architecture), CISA Zero Trust Maturity Model
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_RESOURCE_TYPES = {
    "application", "api", "database", "network_segment", "cloud_service",
}
_VALID_ACTIONS = {"allow", "deny", "mfa_required", "device_check_required"}
_VALID_PRINCIPAL_TYPES = {"user", "group", "service_account", "device"}
_VALID_ENTITY_TYPES = {"user", "device", "service"}
_VALID_TRUST_STATUSES = {"trusted", "untrusted", "unknown", "probation"}
_VALID_SESSION_STATUSES = {"active", "expired", "revoked"}
_VALID_DECISIONS = {"allow", "deny", "mfa_required", "block"}

# Risk contribution constants
_RISK_LOW_TRUST_SCORE = 30       # user_trust_score < 50
_RISK_NO_MFA_SENSITIVE = 25      # no MFA for sensitive resources
_RISK_UNUSUAL_LOCATION = 20      # unusual/unknown location
_RISK_LOW_DEVICE_TRUST = 15      # device_trust_score < 50
_RISK_THRESHOLD_BLOCK = 60       # risk_score >= this → block (unless explicit allow)

# Sensitive resource types that require MFA
_SENSITIVE_RESOURCE_TYPES = {"database", "api", "cloud_service"}


class ZeroTrustEnforcementEngine:
    """SQLite-backed Zero Trust Enforcement Engine.

    Per-org database at .fixops_data/{org_id}_zero_trust.db.
    Thread-safe via per-org RLock.
    """

    def __init__(self) -> None:
        _DEFAULT_DB_DIR.mkdir(parents=True, exist_ok=True)
        # Per-org locks and connections cached lazily
        self._locks: Dict[str, threading.RLock] = {}
        self._locks_mu = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _lock(self, org_id: str) -> threading.RLock:
        with self._locks_mu:
            if org_id not in self._locks:
                self._locks[org_id] = threading.RLock()
            return self._locks[org_id]

    def _db_path(self, org_id: str) -> Path:
        return _DEFAULT_DB_DIR / f"{org_id}_zero_trust.db"

    def _connect(self, org_id: str) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path(org_id)), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_tables(self, org_id: str) -> None:
        conn = self._connect(org_id)
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS zt_policies (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    policy_name     TEXT NOT NULL,
                    resource_type   TEXT NOT NULL,
                    action          TEXT NOT NULL,
                    principal_type  TEXT NOT NULL,
                    conditions      TEXT NOT NULL DEFAULT '{}',
                    priority        INTEGER NOT NULL DEFAULT 50,
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    created_at      TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS access_requests (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    principal_id        TEXT NOT NULL,
                    principal_type      TEXT NOT NULL,
                    resource_id         TEXT NOT NULL,
                    resource_type       TEXT NOT NULL,
                    action_requested    TEXT NOT NULL,
                    source_ip           TEXT NOT NULL DEFAULT '',
                    device_trust_score  REAL NOT NULL DEFAULT 0.0,
                    user_trust_score    REAL NOT NULL DEFAULT 0.0,
                    mfa_verified        INTEGER NOT NULL DEFAULT 0,
                    location            TEXT NOT NULL DEFAULT '',
                    device_type         TEXT NOT NULL DEFAULT '',
                    timestamp           TEXT NOT NULL,
                    decision            TEXT NOT NULL,
                    matched_policy_id   TEXT,
                    risk_factors        TEXT NOT NULL DEFAULT '[]',
                    session_id          TEXT
                );

                CREATE TABLE IF NOT EXISTS trust_scores (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    entity_id       TEXT NOT NULL,
                    entity_type     TEXT NOT NULL,
                    trust_score     REAL NOT NULL DEFAULT 50.0,
                    score_factors   TEXT NOT NULL DEFAULT '{}',
                    last_updated    TEXT NOT NULL,
                    status          TEXT NOT NULL DEFAULT 'unknown',
                    UNIQUE(org_id, entity_id)
                );

                CREATE TABLE IF NOT EXISTS zt_sessions (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    principal_id            TEXT NOT NULL,
                    resource_id             TEXT NOT NULL,
                    session_token           TEXT NOT NULL UNIQUE,
                    started_at              TEXT NOT NULL,
                    last_activity_at        TEXT NOT NULL,
                    expires_at              TEXT NOT NULL,
                    status                  TEXT NOT NULL DEFAULT 'active',
                    continuous_auth_events  TEXT NOT NULL DEFAULT '[]'
                );

                CREATE INDEX IF NOT EXISTS idx_zt_policies_org_enabled
                    ON zt_policies(org_id, enabled, priority);
                CREATE INDEX IF NOT EXISTS idx_access_req_org_decision
                    ON access_requests(org_id, decision, timestamp);
                CREATE INDEX IF NOT EXISTS idx_trust_scores_org_entity
                    ON trust_scores(org_id, entity_id);
                CREATE INDEX IF NOT EXISTS idx_zt_sessions_org_principal
                    ON zt_sessions(org_id, principal_id, status);
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _ensure_db(self, org_id: str) -> None:
        """Initialise tables for org on first use."""
        if not self._db_path(org_id).exists():
            self._init_tables(org_id)
        else:
            # Ensure tables exist in case DB was created but not initialised
            self._init_tables(org_id)

    @staticmethod
    def _row_to_policy(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "policy_name": row["policy_name"],
            "resource_type": row["resource_type"],
            "action": row["action"],
            "principal_type": row["principal_type"],
            "conditions": json.loads(row["conditions"]),
            "priority": row["priority"],
            "enabled": bool(row["enabled"]),
            "created_at": row["created_at"],
        }

    @staticmethod
    def _row_to_access_request(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "principal_id": row["principal_id"],
            "principal_type": row["principal_type"],
            "resource_id": row["resource_id"],
            "resource_type": row["resource_type"],
            "action_requested": row["action_requested"],
            "source_ip": row["source_ip"],
            "device_trust_score": row["device_trust_score"],
            "user_trust_score": row["user_trust_score"],
            "mfa_verified": bool(row["mfa_verified"]),
            "location": row["location"],
            "device_type": row["device_type"],
            "timestamp": row["timestamp"],
            "decision": row["decision"],
            "matched_policy_id": row["matched_policy_id"],
            "risk_factors": json.loads(row["risk_factors"]),
            "session_id": row["session_id"],
        }

    @staticmethod
    def _row_to_trust_score(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "entity_id": row["entity_id"],
            "entity_type": row["entity_type"],
            "trust_score": row["trust_score"],
            "score_factors": json.loads(row["score_factors"]),
            "last_updated": row["last_updated"],
            "status": row["status"],
        }

    @staticmethod
    def _row_to_session(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "principal_id": row["principal_id"],
            "resource_id": row["resource_id"],
            "session_token": row["session_token"],
            "started_at": row["started_at"],
            "last_activity_at": row["last_activity_at"],
            "expires_at": row["expires_at"],
            "status": row["status"],
            "continuous_auth_events": json.loads(row["continuous_auth_events"]),
        }

    @staticmethod
    def _derive_trust_status(score: float) -> str:
        if score >= 75:
            return "trusted"
        if score >= 50:
            return "unknown"
        if score >= 25:
            return "probation"
        return "untrusted"

    # ------------------------------------------------------------------
    # Policy CRUD
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: dict) -> dict:
        """Create a Zero Trust access policy."""
        self._ensure_db(org_id)
        action = data.get("action", "deny")
        if action not in _VALID_ACTIONS:
            raise ValueError(f"Invalid action '{action}'. Must be one of: {_VALID_ACTIONS}")

        principal_type = data.get("principal_type", "user")
        if principal_type not in _VALID_PRINCIPAL_TYPES:
            raise ValueError(f"Invalid principal_type '{principal_type}'")

        resource_type = data.get("resource_type", "application")
        if resource_type not in _VALID_RESOURCE_TYPES:
            raise ValueError(f"Invalid resource_type '{resource_type}'")

        now = datetime.now(timezone.utc).isoformat()
        policy_id = str(uuid.uuid4())
        priority = int(data.get("priority", 50))
        priority = max(1, min(100, priority))
        conditions = data.get("conditions", {})

        with self._lock(org_id):
            conn = self._connect(org_id)
            try:
                conn.execute(
                    """
                    INSERT INTO zt_policies
                        (id, org_id, policy_name, resource_type, action,
                         principal_type, conditions, priority, enabled, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                    """,
                    (
                        policy_id, org_id,
                        data.get("policy_name", "Unnamed Policy"),
                        resource_type, action, principal_type,
                        json.dumps(conditions), priority, now,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

        _logger.info("zt.policy_created org=%s policy_id=%s action=%s", org_id, policy_id, action)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "zero_trust_enforcement", "org_id": org_id, "source_engine": "zero_trust_enforcement"})
            except Exception:
                pass

        return self.get_policy(org_id, policy_id)  # type: ignore[return-value]

    def list_policies(
        self,
        org_id: str,
        resource_type: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> List[dict]:
        """List policies for an org, ordered by priority."""
        self._ensure_db(org_id)
        clauses = ["org_id = ?"]
        params: List[Any] = [org_id]

        if resource_type is not None:
            clauses.append("resource_type = ?")
            params.append(resource_type)
        if enabled is not None:
            clauses.append("enabled = ?")
            params.append(1 if enabled else 0)

        where = " AND ".join(clauses)
        conn = self._connect(org_id)
        try:
            rows = conn.execute(
                f"SELECT * FROM zt_policies WHERE {where} ORDER BY priority ASC",  # nosec B608
                params,
            ).fetchall()
            return [self._row_to_policy(r) for r in rows]
        finally:
            conn.close()

    def get_policy(self, org_id: str, policy_id: str) -> Optional[dict]:
        """Get a single policy by ID."""
        self._ensure_db(org_id)
        conn = self._connect(org_id)
        try:
            row = conn.execute(
                "SELECT * FROM zt_policies WHERE id = ? AND org_id = ?",
                (policy_id, org_id),
            ).fetchone()
            return self._row_to_policy(row) if row else None
        finally:
            conn.close()

    def update_policy(self, org_id: str, policy_id: str, updates: dict) -> dict:
        """Update a policy. Returns the updated policy."""
        self._ensure_db(org_id)
        policy = self.get_policy(org_id, policy_id)
        if policy is None:
            raise ValueError(f"Policy {policy_id} not found in org {org_id}")

        allowed_fields = {
            "policy_name", "resource_type", "action", "principal_type",
            "conditions", "priority", "enabled",
        }
        set_parts: List[str] = []
        values: List[Any] = []

        for key, val in updates.items():
            if key not in allowed_fields:
                continue
            if key == "action" and val not in _VALID_ACTIONS:
                raise ValueError(f"Invalid action '{val}'")
            if key == "conditions" and isinstance(val, dict):
                val = json.dumps(val)
            elif key == "enabled":
                val = 1 if val else 0
            elif key == "priority":
                val = max(1, min(100, int(val)))
            set_parts.append(f"{key} = ?")
            values.append(val)

        if not set_parts:
            return policy

        values.append(policy_id)
        values.append(org_id)

        with self._lock(org_id):
            conn = self._connect(org_id)
            try:
                conn.execute(
                    f"UPDATE zt_policies SET {', '.join(set_parts)} WHERE id = ? AND org_id = ?",  # nosec B608
                    values,
                )
                conn.commit()
            finally:
                conn.close()

        return self.get_policy(org_id, policy_id)  # type: ignore[return-value]

    def delete_policy(self, org_id: str, policy_id: str) -> bool:
        """Delete a policy. Returns True if found and deleted."""
        self._ensure_db(org_id)
        with self._lock(org_id):
            conn = self._connect(org_id)
            try:
                cur = conn.execute(
                    "DELETE FROM zt_policies WHERE id = ? AND org_id = ?",
                    (policy_id, org_id),
                )
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Access evaluation
    # ------------------------------------------------------------------

    def evaluate_access(self, org_id: str, data: dict) -> dict:
        """Evaluate an access request against Zero Trust policies.

        data keys:
            principal_id, principal_type, resource_id, resource_type,
            action_requested, source_ip, device_trust_score (0-100),
            user_trust_score (0-100), mfa_verified (bool),
            location, device_type

        Returns:
            decision: allow | deny | mfa_required | block
            matched_policy_id: str | None
            risk_score: int (0-100)
            risk_factors: list[str]
            session_id: str (only if decision == allow)
        """
        self._ensure_db(org_id)

        principal_id = data.get("principal_id", "")
        principal_type = data.get("principal_type", "user")
        resource_id = data.get("resource_id", "")
        resource_type = data.get("resource_type", "application")
        action_requested = data.get("action_requested", "read")
        source_ip = data.get("source_ip", "")
        device_trust_score = float(data.get("device_trust_score", 50.0))
        user_trust_score = float(data.get("user_trust_score", 50.0))
        mfa_verified = bool(data.get("mfa_verified", False))
        location = data.get("location", "")
        device_type = data.get("device_type", "")
        now = datetime.now(timezone.utc).isoformat()

        # --- Compute composite risk score ---
        risk_score = 0
        risk_factors: List[str] = []

        if user_trust_score < 50:
            risk_score += _RISK_LOW_TRUST_SCORE
            risk_factors.append("low_user_trust_score")

        if not mfa_verified and resource_type in _SENSITIVE_RESOURCE_TYPES:
            risk_score += _RISK_NO_MFA_SENSITIVE
            risk_factors.append("no_mfa_for_sensitive_resource")

        if not location or location.lower() in ("unknown", ""):
            risk_score += _RISK_UNUSUAL_LOCATION
            risk_factors.append("unusual_or_unknown_location")

        if device_trust_score < 50:
            risk_score += _RISK_LOW_DEVICE_TRUST
            risk_factors.append("low_device_trust_score")

        # --- Load enabled policies ordered by priority ---
        policies = self.list_policies(org_id, resource_type=resource_type, enabled=True)

        decision = "allow"
        matched_policy_id: Optional[str] = None

        for policy in policies:
            cond = policy.get("conditions", {})
            action = policy["action"]

            # Check min_trust_score condition
            min_trust = cond.get("min_trust_score")
            if min_trust is not None and user_trust_score < float(min_trust):
                matched_policy_id = policy["id"]
                if action == "deny":
                    decision = "deny"
                    break
                if action == "mfa_required" and not mfa_verified:
                    decision = "mfa_required"
                    break

            # Check require_mfa condition
            if cond.get("require_mfa") and not mfa_verified:
                matched_policy_id = policy["id"]
                if action == "deny":
                    decision = "deny"
                    break
                decision = "mfa_required"
                # continue — a higher-priority DENY could still win

            # Check allowed_locations condition
            allowed_locs = cond.get("allowed_locations", [])
            if allowed_locs and location not in allowed_locs:
                matched_policy_id = policy["id"]
                if action == "deny":
                    decision = "deny"
                    break

            # Check allowed_device_types condition
            allowed_devices = cond.get("allowed_device_types", [])
            if allowed_devices and device_type not in allowed_devices:
                matched_policy_id = policy["id"]
                if action == "deny":
                    decision = "deny"
                    break

            # Check time_restrictions condition
            time_restrictions = cond.get("time_restrictions", {})
            if time_restrictions:
                now_dt = datetime.now(timezone.utc)
                start_h = time_restrictions.get("start_hour", 0)
                end_h = time_restrictions.get("end_hour", 24)
                if not (start_h <= now_dt.hour < end_h):
                    matched_policy_id = policy["id"]
                    if action == "deny":
                        decision = "deny"
                        break

        # Apply risk-based block if no explicit deny matched
        if decision == "allow" and risk_score >= _RISK_THRESHOLD_BLOCK:
            decision = "block"
            risk_factors.append("composite_risk_threshold_exceeded")

        # Create session if allowed
        session_id: Optional[str] = None
        if decision == "allow":
            session = self.create_session(org_id, principal_id, resource_id)
            session_id = session["id"]

        # Persist access request
        request_id = str(uuid.uuid4())
        with self._lock(org_id):
            conn = self._connect(org_id)
            try:
                conn.execute(
                    """
                    INSERT INTO access_requests
                        (id, org_id, principal_id, principal_type, resource_id,
                         resource_type, action_requested, source_ip,
                         device_trust_score, user_trust_score, mfa_verified,
                         location, device_type, timestamp, decision,
                         matched_policy_id, risk_factors, session_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request_id, org_id, principal_id, principal_type,
                        resource_id, resource_type, action_requested, source_ip,
                        device_trust_score, user_trust_score, int(mfa_verified),
                        location, device_type, now, decision,
                        matched_policy_id, json.dumps(risk_factors), session_id,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

        _logger.info(
            "zt.access_evaluated org=%s principal=%s resource=%s decision=%s risk=%d",
            org_id, principal_id, resource_id, decision, risk_score,
        )

        result: Dict[str, Any] = {
            "request_id": request_id,
            "decision": decision,
            "matched_policy_id": matched_policy_id,
            "risk_score": risk_score,
            "risk_factors": risk_factors,
        }
        if session_id:
            result["session_id"] = session_id
        return result

    # ------------------------------------------------------------------
    # Trust scores
    # ------------------------------------------------------------------

    def set_trust_score(
        self,
        org_id: str,
        entity_id: str,
        entity_type: str,
        score: float,
        factors: dict,
    ) -> dict:
        """Create or update the trust score for an entity."""
        self._ensure_db(org_id)
        if entity_type not in _VALID_ENTITY_TYPES:
            raise ValueError(f"Invalid entity_type '{entity_type}'")
        score = max(0.0, min(100.0, float(score)))
        status = self._derive_trust_status(score)
        now = datetime.now(timezone.utc).isoformat()
        record_id = str(uuid.uuid4())

        with self._lock(org_id):
            conn = self._connect(org_id)
            try:
                conn.execute(
                    """
                    INSERT INTO trust_scores
                        (id, org_id, entity_id, entity_type, trust_score,
                         score_factors, last_updated, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(org_id, entity_id) DO UPDATE SET
                        entity_type   = excluded.entity_type,
                        trust_score   = excluded.trust_score,
                        score_factors = excluded.score_factors,
                        last_updated  = excluded.last_updated,
                        status        = excluded.status
                    """,
                    (
                        record_id, org_id, entity_id, entity_type,
                        score, json.dumps(factors), now, status,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

        return self.get_trust_score(org_id, entity_id)  # type: ignore[return-value]

    def get_trust_score(self, org_id: str, entity_id: str) -> Optional[dict]:
        """Get the trust score record for a specific entity."""
        self._ensure_db(org_id)
        conn = self._connect(org_id)
        try:
            row = conn.execute(
                "SELECT * FROM trust_scores WHERE org_id = ? AND entity_id = ?",
                (org_id, entity_id),
            ).fetchone()
            return self._row_to_trust_score(row) if row else None
        finally:
            conn.close()

    def list_trust_scores(
        self,
        org_id: str,
        entity_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[dict]:
        """List trust scores for an org with optional filters."""
        self._ensure_db(org_id)
        clauses = ["org_id = ?"]
        params: List[Any] = [org_id]

        if entity_type is not None:
            clauses.append("entity_type = ?")
            params.append(entity_type)
        if status is not None:
            clauses.append("status = ?")
            params.append(status)

        where = " AND ".join(clauses)
        conn = self._connect(org_id)
        try:
            rows = conn.execute(
                f"SELECT * FROM trust_scores WHERE {where} ORDER BY trust_score ASC",  # nosec B608
                params,
            ).fetchall()
            return [self._row_to_trust_score(r) for r in rows]
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def create_session(
        self,
        org_id: str,
        principal_id: str,
        resource_id: str,
        duration_hours: int = 8,
    ) -> dict:
        """Create a new Zero Trust session."""
        self._ensure_db(org_id)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=duration_hours)
        session_id = str(uuid.uuid4())
        session_token = str(uuid.uuid4())

        with self._lock(org_id):
            conn = self._connect(org_id)
            try:
                conn.execute(
                    """
                    INSERT INTO zt_sessions
                        (id, org_id, principal_id, resource_id, session_token,
                         started_at, last_activity_at, expires_at, status,
                         continuous_auth_events)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', '[]')
                    """,
                    (
                        session_id, org_id, principal_id, resource_id,
                        session_token, now.isoformat(),
                        now.isoformat(), expires_at.isoformat(),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

        _logger.info(
            "zt.session_created org=%s principal=%s session=%s",
            org_id, principal_id, session_id,
        )
        return self.list_sessions(org_id, principal_id=principal_id, status="active")[0]

    def list_sessions(
        self,
        org_id: str,
        principal_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[dict]:
        """List sessions for an org with optional filters."""
        self._ensure_db(org_id)
        clauses = ["org_id = ?"]
        params: List[Any] = [org_id]

        if principal_id is not None:
            clauses.append("principal_id = ?")
            params.append(principal_id)
        if status is not None:
            clauses.append("status = ?")
            params.append(status)

        where = " AND ".join(clauses)
        conn = self._connect(org_id)
        try:
            rows = conn.execute(
                f"SELECT * FROM zt_sessions WHERE {where} ORDER BY started_at DESC",  # nosec B608
                params,
            ).fetchall()
            return [self._row_to_session(r) for r in rows]
        finally:
            conn.close()

    def revoke_session(self, org_id: str, session_id: str) -> bool:
        """Revoke a session by ID. Returns True if found and revoked."""
        self._ensure_db(org_id)
        with self._lock(org_id):
            conn = self._connect(org_id)
            try:
                cur = conn.execute(
                    "UPDATE zt_sessions SET status = 'revoked' WHERE id = ? AND org_id = ? AND status = 'active'",
                    (session_id, org_id),
                )
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Access log
    # ------------------------------------------------------------------

    def list_access_requests(
        self,
        org_id: str,
        decision: Optional[str] = None,
        resource_type: Optional[str] = None,
        limit: int = 50,
    ) -> List[dict]:
        """List access requests with optional filters."""
        self._ensure_db(org_id)
        clauses = ["org_id = ?"]
        params: List[Any] = [org_id]

        if decision is not None:
            clauses.append("decision = ?")
            params.append(decision)
        if resource_type is not None:
            clauses.append("resource_type = ?")
            params.append(resource_type)

        where = " AND ".join(clauses)
        params.append(limit)

        conn = self._connect(org_id)
        try:
            rows = conn.execute(
                f"SELECT * FROM access_requests WHERE {where} ORDER BY timestamp DESC LIMIT ?",  # nosec B608
                params,
            ).fetchall()
            return [self._row_to_access_request(r) for r in rows]
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, org_id: str) -> dict:
        """Return aggregate stats for the org."""
        self._ensure_db(org_id)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        conn = self._connect(org_id)
        try:
            total = conn.execute(
                "SELECT COUNT(*) FROM access_requests WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            today_row = conn.execute(
                "SELECT COUNT(*) FROM access_requests WHERE org_id = ? AND date(timestamp) = ?",
                (org_id, today),
            ).fetchone()[0]

            # Decision breakdown
            dec_rows = conn.execute(
                "SELECT decision, COUNT(*) as cnt FROM access_requests WHERE org_id = ? GROUP BY decision",
                (org_id,),
            ).fetchall()
            by_decision: Dict[str, int] = {r["decision"]: r["cnt"] for r in dec_rows}

            allow_count = by_decision.get("allow", 0)
            deny_count = by_decision.get("deny", 0)
            mfa_count = by_decision.get("mfa_required", 0)

            allow_rate = round(allow_count / total, 4) if total else 0.0
            deny_rate = round(deny_count / total, 4) if total else 0.0
            mfa_rate = round(mfa_count / total, 4) if total else 0.0

            # Active sessions
            active_sessions = conn.execute(
                "SELECT COUNT(*) FROM zt_sessions WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            # Avg trust score
            avg_row = conn.execute(
                "SELECT AVG(trust_score) FROM trust_scores WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            avg_trust = round(float(avg_row[0]), 2) if avg_row[0] is not None else 0.0

            # High risk principals (trust_score < 50)
            high_risk = conn.execute(
                "SELECT COUNT(*) FROM trust_scores WHERE org_id = ? AND trust_score < 50",
                (org_id,),
            ).fetchone()[0]

        finally:
            conn.close()

        return {
            "org_id": org_id,
            "total_requests": total,
            "requests_today": today_row,
            "allow_rate": allow_rate,
            "deny_rate": deny_rate,
            "mfa_required_rate": mfa_rate,
            "active_sessions": active_sessions,
            "avg_trust_score": avg_trust,
            "high_risk_principals": high_risk,
            "by_decision": by_decision,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }


    def get_compliance_posture(self, org_id: str) -> dict:
        """Return Zero Trust compliance posture: maturity score, pillar breakdown, recommendations.

        Derives pillar scores from enabled policy counts per resource_type and trust score health.
        Complies with NIST SP 800-207 and CISA Zero Trust Maturity Model.
        """
        self._ensure_db(org_id)
        policies = self.list_policies(org_id, enabled=True)

        by_type: Dict[str, int] = {}
        for p in policies:
            rt = p["resource_type"]
            by_type[rt] = by_type.get(rt, 0) + 1

        def _pillar_score(count: int) -> int:
            if count == 0:
                return 0
            if count == 1:
                return 35
            if count == 2:
                return 60
            if count == 3:
                return 80
            return min(95, 80 + (count - 3) * 5)

        # Map resource_types to ZT pillars
        identity_count = by_type.get("api", 0)
        device_count = by_type.get("network_segment", 0)
        network_count = by_type.get("cloud_service", 0)
        application_count = by_type.get("application", 0)
        data_count = by_type.get("database", 0)

        # Also check trust score health
        conn = self._connect(org_id)
        try:
            total_entities = conn.execute(
                "SELECT COUNT(*) FROM trust_scores WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            trusted_entities = conn.execute(
                "SELECT COUNT(*) FROM trust_scores WHERE org_id = ? AND status = 'trusted'",
                (org_id,),
            ).fetchone()[0]
        finally:
            conn.close()

        identity_bonus = min(20, trusted_entities * 5) if total_entities > 0 else 0

        pillar_weights = {
            "identity": 0.25,
            "device": 0.20,
            "network": 0.20,
            "application": 0.20,
            "data": 0.15,
        }
        pillars = {
            "identity": min(100, _pillar_score(identity_count) + identity_bonus),
            "device": _pillar_score(device_count),
            "network": _pillar_score(network_count),
            "application": _pillar_score(application_count),
            "data": _pillar_score(data_count),
        }

        zt_maturity_score = int(
            sum(pillars[pillar] * weight for pillar, weight in pillar_weights.items())
        )

        total_enabled = len(policies)
        recommendations: list = []
        if identity_count == 0:
            recommendations.append("Add API-scoped policies to enforce identity verification on all API access")
        if device_count == 0:
            recommendations.append("Implement network segment policies to enforce device posture checks")
        if application_count == 0:
            recommendations.append("Create application-level policies for sensitive data access control")
        if data_count == 0:
            recommendations.append("Add database policies to protect sensitive data at rest")
        if total_entities > 0 and trusted_entities / total_entities < 0.5:
            recommendations.append("More than half of tracked entities have low trust scores — investigate anomalies")
        if total_enabled == 0:
            recommendations = ["No active Zero Trust policies — enable policies across all resource types to begin enforcement"]
        if not recommendations:
            recommendations.append("Zero Trust posture is strong — review policies quarterly and update trust scores continuously")

        return {
            "zt_maturity_score": zt_maturity_score,
            "pillars": pillars,
            "total_enabled_policies": total_enabled,
            "recommendations": recommendations,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine_singleton: Optional[ZeroTrustEnforcementEngine] = None
_singleton_lock = threading.Lock()


def get_zero_trust_enforcement_engine() -> ZeroTrustEnforcementEngine:
    global _engine_singleton
    if _engine_singleton is None:
        with _singleton_lock:
            if _engine_singleton is None:
                _engine_singleton = ZeroTrustEnforcementEngine()
    return _engine_singleton
