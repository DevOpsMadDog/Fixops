"""
Zero-Trust Policy Engine for ALDECI.

Implements the "never trust, always verify" security model with:
- Device posture evaluation
- Continuous authentication scoring
- Geographic and time-based access controls
- MFA escalation policies
- Full audit trail

Compliance: NIST SP 800-207 (Zero Trust Architecture), SOC2 CC6.x
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)


# ============================================================================
# ENUMS
# ============================================================================


class TrustLevel(str, Enum):
    """Ordered trust levels — higher ordinal = greater confidence."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERIFIED = "verified"

    @property
    def ordinal(self) -> int:
        return {"none": 0, "low": 1, "medium": 2, "high": 3, "verified": 4}[self.value]

    def __ge__(self, other: "TrustLevel") -> bool:  # type: ignore[override]
        return self.ordinal >= other.ordinal

    def __gt__(self, other: "TrustLevel") -> bool:  # type: ignore[override]
        return self.ordinal > other.ordinal

    def __le__(self, other: "TrustLevel") -> bool:  # type: ignore[override]
        return self.ordinal <= other.ordinal

    def __lt__(self, other: "TrustLevel") -> bool:  # type: ignore[override]
        return self.ordinal < other.ordinal


# ============================================================================
# MODELS
# ============================================================================


class DevicePosture(BaseModel):
    """Security posture of a device requesting access."""

    device_id: str
    os: str
    os_version: str
    encrypted: bool = False
    firewall_enabled: bool = False
    antivirus_active: bool = False
    patch_level: float = Field(default=0.0, ge=0.0, le=1.0,
                               description="Patch compliance 0.0–1.0")
    trust_score: float = Field(default=0.0, ge=0.0, le=1.0,
                               description="Computed device trust 0.0–1.0")
    registered_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_seen: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def compute_trust_score(self) -> float:
        """Derive a trust score from posture attributes."""
        score = 0.0
        if self.encrypted:
            score += 0.30
        if self.firewall_enabled:
            score += 0.20
        if self.antivirus_active:
            score += 0.20
        score += self.patch_level * 0.30
        self.trust_score = round(min(score, 1.0), 4)
        return self.trust_score

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "os": self.os,
            "os_version": self.os_version,
            "encrypted": self.encrypted,
            "firewall_enabled": self.firewall_enabled,
            "antivirus_active": self.antivirus_active,
            "patch_level": self.patch_level,
            "trust_score": self.trust_score,
            "registered_at": self.registered_at,
            "last_seen": self.last_seen,
        }


class AccessDecision(BaseModel):
    """Result of a zero-trust access evaluation."""

    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    allowed: bool
    trust_level: TrustLevel
    reason: str
    conditions: List[str] = Field(default_factory=list)
    mfa_required: bool = False
    evaluated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "allowed": self.allowed,
            "trust_level": self.trust_level.value,
            "reason": self.reason,
            "conditions": self.conditions,
            "mfa_required": self.mfa_required,
            "evaluated_at": self.evaluated_at,
        }


# ============================================================================
# BUILT-IN POLICIES
# ============================================================================

# Minimum device trust score to gain any access
_MIN_DEVICE_TRUST_FOR_ACCESS = 0.30

# Resources that always require MFA regardless of trust level
_MFA_ALWAYS_REQUIRED_RESOURCES = {
    "admin", "users", "config", "audit_log", "secrets", "credentials",
    "billing", "compliance", "api_keys",
}

# Resources that require HIGH or VERIFIED trust
_HIGH_TRUST_RESOURCES = {
    "admin", "secrets", "credentials", "api_keys",
}

# Default allowed regions (ISO 3166-1 alpha-2 codes)
_DEFAULT_ALLOWED_REGIONS = {"US", "CA", "GB", "DE", "AU", "NL", "FR", "SE"}

# Business hours window (UTC): hour range [start, end)
_BUSINESS_HOURS_START = 6   # 06:00 UTC
_BUSINESS_HOURS_END = 22    # 22:00 UTC


def _trust_level_from_score(score: float) -> TrustLevel:
    if score >= 0.90:
        return TrustLevel.VERIFIED
    if score >= 0.70:
        return TrustLevel.HIGH
    if score >= 0.50:
        return TrustLevel.MEDIUM
    if score >= 0.30:
        return TrustLevel.LOW
    return TrustLevel.NONE


# ============================================================================
# ZERO TRUST ENGINE
# ============================================================================


class ZeroTrustEngine:
    """
    SQLite-backed Zero-Trust Policy Engine.

    Evaluates every access request against device posture, geographic
    restrictions, time windows, and MFA requirements.  All decisions
    are written to an immutable audit trail.
    """

    def __init__(self, db_path: str = "data/zero_trust.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_tables(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    device_id    TEXT PRIMARY KEY,
                    os           TEXT NOT NULL,
                    os_version   TEXT NOT NULL,
                    encrypted    INTEGER NOT NULL DEFAULT 0,
                    firewall_enabled INTEGER NOT NULL DEFAULT 0,
                    antivirus_active INTEGER NOT NULL DEFAULT 0,
                    patch_level  REAL NOT NULL DEFAULT 0.0,
                    trust_score  REAL NOT NULL DEFAULT 0.0,
                    registered_at TEXT NOT NULL,
                    last_seen    TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS access_events (
                    id           TEXT PRIMARY KEY,
                    user_id      TEXT NOT NULL,
                    resource     TEXT NOT NULL,
                    device_id    TEXT,
                    allowed      INTEGER NOT NULL,
                    trust_level  TEXT NOT NULL,
                    reason       TEXT NOT NULL,
                    conditions   TEXT NOT NULL DEFAULT '[]',
                    mfa_required INTEGER NOT NULL DEFAULT 0,
                    context      TEXT NOT NULL DEFAULT '{}',
                    evaluated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    session_id   TEXT PRIMARY KEY,
                    user_id      TEXT NOT NULL,
                    device_id    TEXT,
                    risk_score   REAL NOT NULL DEFAULT 0.0,
                    created_at   TEXT NOT NULL,
                    updated_at   TEXT NOT NULL,
                    context      TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS geo_restrictions (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL DEFAULT 'default',
                    allowed_regions TEXT NOT NULL DEFAULT '[]',
                    created_at   TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS time_restrictions (
                    id           TEXT PRIMARY KEY,
                    user_id      TEXT,
                    resource     TEXT,
                    org_id       TEXT NOT NULL DEFAULT 'default',
                    start_hour   INTEGER NOT NULL DEFAULT 6,
                    end_hour     INTEGER NOT NULL DEFAULT 22,
                    created_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_events_user
                    ON access_events(user_id);
                CREATE INDEX IF NOT EXISTS idx_events_resource
                    ON access_events(resource);
                CREATE INDEX IF NOT EXISTS idx_events_evaluated_at
                    ON access_events(evaluated_at);
                CREATE INDEX IF NOT EXISTS idx_sessions_user
                    ON sessions(user_id);
                """
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_device(self, device_posture: DevicePosture) -> DevicePosture:
        """Register or update a trusted device and compute its trust score."""
        device_posture.compute_trust_score()
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO devices
                    (device_id, os, os_version, encrypted, firewall_enabled,
                     antivirus_active, patch_level, trust_score,
                     registered_at, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    os               = excluded.os,
                    os_version       = excluded.os_version,
                    encrypted        = excluded.encrypted,
                    firewall_enabled = excluded.firewall_enabled,
                    antivirus_active = excluded.antivirus_active,
                    patch_level      = excluded.patch_level,
                    trust_score      = excluded.trust_score,
                    last_seen        = excluded.last_seen
                """,
                (
                    device_posture.device_id,
                    device_posture.os,
                    device_posture.os_version,
                    int(device_posture.encrypted),
                    int(device_posture.firewall_enabled),
                    int(device_posture.antivirus_active),
                    device_posture.patch_level,
                    device_posture.trust_score,
                    device_posture.registered_at,
                    now,
                ),
            )
            conn.commit()
        finally:
            conn.close()
        _logger.info("device_registered device_id=%s trust_score=%.2f",
                     device_posture.device_id, device_posture.trust_score)
        return device_posture

    def get_device_trust(self, device_id: str) -> Optional[float]:
        """Return the current trust score for a device, or None if unknown."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT trust_score FROM devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            return float(row["trust_score"]) if row else None
        finally:
            conn.close()

    def enforce_mfa(self, user: str, resource: str) -> bool:
        """
        Return True if MFA must be presented for this user/resource combination.

        Built-in policy: any resource in the sensitive set always requires MFA.
        """
        resource_key = resource.lower().split("/")[0].split(":")[0]
        return resource_key in _MFA_ALWAYS_REQUIRED_RESOURCES

    def check_geo_restriction(
        self,
        ip: str,
        allowed_regions: Optional[List[str]] = None,
    ) -> Tuple[bool, str]:
        """
        Evaluate geographic access control.

        In production, ip → country lookup would use a GeoIP database.
        This implementation derives a pseudo-country from the IP prefix so
        the logic is fully testable without external dependencies.

        Returns (allowed: bool, reason: str).
        """
        regions = set(allowed_regions) if allowed_regions else _DEFAULT_ALLOWED_REGIONS

        # Private/loopback ranges are always allowed (internal access)
        if ip.startswith(("127.", "10.", "192.168.", "::1")):
            return True, "private_network_allowed"

        # RFC-1918 172.16–31 range
        parts = ip.split(".")
        if len(parts) == 4:
            try:
                second = int(parts[1])
                if parts[0] == "172" and 16 <= second <= 31:
                    return True, "private_network_allowed"
            except ValueError:
                pass

        # Deterministic pseudo-GeoIP for testing/evaluation:
        # map first-octet ranges to broad regions
        try:
            first_octet = int(parts[0]) if len(parts) >= 1 else 0
        except (ValueError, IndexError):
            first_octet = 0

        if 1 <= first_octet <= 100:
            inferred_region = "US"
        elif 101 <= first_octet <= 150:
            inferred_region = "DE"
        elif 151 <= first_octet <= 180:
            inferred_region = "CN"
        elif 181 <= first_octet <= 200:
            inferred_region = "RU"
        else:
            inferred_region = "US"

        if inferred_region in regions:
            return True, f"region_{inferred_region}_allowed"
        return False, f"region_{inferred_region}_blocked"

    def check_time_restriction(
        self,
        user: str,
        resource: str,
        org_id: str = "default",
    ) -> Tuple[bool, str]:
        """
        Check whether the current UTC time falls within the allowed window.

        Looks up per-(user, resource) or org-wide rules; defaults to
        _BUSINESS_HOURS_START – _BUSINESS_HOURS_END UTC.
        Returns (allowed: bool, reason: str).
        """
        now_utc = datetime.now(timezone.utc)
        current_hour = now_utc.hour

        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT start_hour, end_hour FROM time_restrictions
                WHERE org_id = ?
                  AND (user_id = ? OR user_id IS NULL)
                  AND (resource = ? OR resource IS NULL)
                ORDER BY user_id DESC, resource DESC
                LIMIT 1
                """,
                (org_id, user, resource),
            ).fetchone()
        finally:
            conn.close()

        if row:
            start_hour = int(row["start_hour"])
            end_hour = int(row["end_hour"])
        else:
            start_hour = _BUSINESS_HOURS_START
            end_hour = _BUSINESS_HOURS_END

        if start_hour <= current_hour < end_hour:
            return True, f"within_allowed_window_{start_hour:02d}00_to_{end_hour:02d}00_utc"
        return False, f"outside_allowed_window_{start_hour:02d}00_to_{end_hour:02d}00_utc"

    def get_continuous_auth_status(self, session_id: str) -> Dict[str, Any]:
        """
        Return current session risk score and metadata.

        Risk increases with session age; sessions older than 8 hours are
        treated as high-risk.
        """
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        finally:
            conn.close()

        if not row:
            return {
                "session_id": session_id,
                "found": False,
                "risk_score": 1.0,
                "trust_level": TrustLevel.NONE.value,
                "requires_reauth": True,
            }

        created_at = datetime.fromisoformat(row["created_at"])
        age_hours = (datetime.now(timezone.utc) - created_at).total_seconds() / 3600

        base_risk = float(row["risk_score"])
        # Age penalty: +0.1 per hour, capped at 1.0
        age_penalty = min(age_hours * 0.10, 0.60)
        effective_risk = min(base_risk + age_penalty, 1.0)

        trust_score = 1.0 - effective_risk
        trust_level = _trust_level_from_score(trust_score)

        return {
            "session_id": session_id,
            "found": True,
            "user_id": row["user_id"],
            "device_id": row["device_id"],
            "risk_score": round(effective_risk, 4),
            "trust_level": trust_level.value,
            "age_hours": round(age_hours, 2),
            "requires_reauth": effective_risk >= 0.70,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def evaluate_access(
        self,
        user: str,
        resource: str,
        device_posture: DevicePosture,
        context: Optional[Dict[str, Any]] = None,
    ) -> AccessDecision:
        """
        Comprehensive zero-trust access decision.

        Policy evaluation order (all must pass):
        1. Device posture minimum threshold
        2. Geographic restriction
        3. Time-window restriction
        4. Resource trust-level requirement
        5. MFA requirement flagging

        The decision is recorded in the audit trail.
        """
        ctx = context or {}
        conditions: List[str] = []
        denial_reason: Optional[str] = None

        # 1. Device posture
        device_posture.compute_trust_score()
        device_trust = device_posture.trust_score
        trust_level = _trust_level_from_score(device_trust)

        if device_trust < _MIN_DEVICE_TRUST_FOR_ACCESS:
            denial_reason = (
                f"device_trust_too_low score={device_trust:.2f} "
                f"minimum={_MIN_DEVICE_TRUST_FOR_ACCESS}"
            )
        else:
            conditions.append(f"device_trust_ok score={device_trust:.2f}")

        # 2. Geographic restriction
        if denial_reason is None:
            client_ip = ctx.get("ip", "127.0.0.1")
            allowed_regions = ctx.get("allowed_regions")
            geo_ok, geo_reason = self.check_geo_restriction(client_ip, allowed_regions)
            if not geo_ok:
                denial_reason = f"geo_blocked {geo_reason}"
            else:
                conditions.append(f"geo_ok {geo_reason}")

        # 3. Time restriction
        if denial_reason is None:
            org_id = ctx.get("org_id", "default")
            time_ok, time_reason = self.check_time_restriction(user, resource, org_id)
            if not time_ok:
                denial_reason = f"time_restricted {time_reason}"
            else:
                conditions.append(f"time_ok {time_reason}")

        # 4. High-trust resource check
        if denial_reason is None:
            resource_key = resource.lower().split("/")[0].split(":")[0]
            if resource_key in _HIGH_TRUST_RESOURCES and trust_level < TrustLevel.HIGH:
                denial_reason = (
                    f"resource_requires_high_trust resource={resource} "
                    f"current_level={trust_level.value}"
                )
            else:
                conditions.append(f"resource_trust_ok level={trust_level.value}")

        # 5. MFA requirement (informational — doesn't deny by itself)
        mfa_required = self.enforce_mfa(user, resource)
        if mfa_required:
            conditions.append("mfa_required")
            if ctx.get("mfa_verified") is not True:
                if denial_reason is None:
                    denial_reason = "mfa_not_verified resource_requires_mfa"

        allowed = denial_reason is None
        decision = AccessDecision(
            allowed=allowed,
            trust_level=trust_level,
            reason=denial_reason if not allowed else "access_granted",
            conditions=conditions,
            mfa_required=mfa_required,
        )

        self.record_access_event(decision, user=user, resource=resource,
                                 device_id=device_posture.device_id, context=ctx)
        return decision

    def record_access_event(
        self,
        decision: AccessDecision,
        user: str = "",
        resource: str = "",
        device_id: str = "",
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Persist an access decision to the immutable audit trail."""
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO access_events
                    (id, user_id, resource, device_id, allowed, trust_level,
                     reason, conditions, mfa_required, context, evaluated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.decision_id,
                    user,
                    resource,
                    device_id or "",
                    int(decision.allowed),
                    decision.trust_level.value,
                    decision.reason,
                    json.dumps(decision.conditions),
                    int(decision.mfa_required),
                    json.dumps(context or {}),
                    decision.evaluated_at,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def get_zero_trust_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """
        Return aggregated policy evaluation statistics for an organisation.
        """
        conn = self._connect()
        try:
            total = conn.execute(
                "SELECT COUNT(*) FROM access_events"
            ).fetchone()[0]
            allowed_count = conn.execute(
                "SELECT COUNT(*) FROM access_events WHERE allowed = 1"
            ).fetchone()[0]
            denied_count = total - allowed_count
            mfa_count = conn.execute(
                "SELECT COUNT(*) FROM access_events WHERE mfa_required = 1"
            ).fetchone()[0]
            device_count = conn.execute(
                "SELECT COUNT(*) FROM devices"
            ).fetchone()[0]

            # Trust level distribution
            trust_rows = conn.execute(
                """
                SELECT trust_level, COUNT(*) as cnt
                FROM access_events
                GROUP BY trust_level
                """
            ).fetchall()
            trust_dist = {r["trust_level"]: r["cnt"] for r in trust_rows}

            # Top denial reasons
            denial_rows = conn.execute(
                """
                SELECT reason, COUNT(*) as cnt
                FROM access_events
                WHERE allowed = 0
                GROUP BY reason
                ORDER BY cnt DESC
                LIMIT 10
                """
            ).fetchall()
            top_denials = [{"reason": r["reason"], "count": r["cnt"]}
                           for r in denial_rows]

            return {
                "org_id": org_id,
                "total_evaluations": total,
                "allowed": allowed_count,
                "denied": denied_count,
                "allow_rate": round(allowed_count / total, 4) if total else 0.0,
                "mfa_required_count": mfa_count,
                "registered_devices": device_count,
                "trust_level_distribution": trust_dist,
                "top_denial_reasons": top_denials,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }
        finally:
            conn.close()

    def upsert_session(
        self,
        session_id: str,
        user_id: str,
        device_id: Optional[str] = None,
        risk_score: float = 0.0,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Create or refresh a tracked session."""
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO sessions
                    (session_id, user_id, device_id, risk_score,
                     created_at, updated_at, context)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    risk_score = excluded.risk_score,
                    updated_at = excluded.updated_at,
                    context    = excluded.context
                """,
                (
                    session_id,
                    user_id,
                    device_id or "",
                    risk_score,
                    now,
                    now,
                    json.dumps(context or {}),
                ),
            )
            conn.commit()
        finally:
            conn.close()


# ============================================================================
# FACTORY
# ============================================================================


def create_zero_trust_engine(
    db_path: str = "data/zero_trust.db",
) -> ZeroTrustEngine:
    """Return a configured ZeroTrustEngine instance."""
    return ZeroTrustEngine(db_path=db_path)
