"""Zero Trust Policy Engine — never trust, always verify.

Manages Zero Trust network/identity/device/application policies with
access evaluation, event logging, maturity scoring, and compliance posture.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = structlog.get_logger()

_VALID_POLICY_TYPES = {"network", "identity", "device", "application"}
_VALID_ACTIONS = {"allow", "deny", "mfa_required"}

# Compliance maturity pillar weights (sum = 1.0)
_PILLAR_WEIGHTS = {
    "identity": 0.25,
    "device": 0.20,
    "network": 0.20,
    "application": 0.20,
    "data": 0.15,
}


class ZeroTrustPolicyEngine:
    """SQLite-backed Zero Trust policy engine with access evaluation and maturity scoring."""

    def __init__(self, db_path: str = ".fixops_data/zero_trust_policy.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_tables()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_tables(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS zt_policies (
                        policy_id           TEXT PRIMARY KEY,
                        org_id              TEXT NOT NULL,
                        name                TEXT NOT NULL,
                        description         TEXT NOT NULL DEFAULT '',
                        policy_type         TEXT NOT NULL,
                        action              TEXT NOT NULL,
                        source_conditions   TEXT NOT NULL DEFAULT '{}',
                        destination_conditions TEXT NOT NULL DEFAULT '{}',
                        priority            INTEGER NOT NULL DEFAULT 50,
                        enabled             INTEGER NOT NULL DEFAULT 1,
                        created_at          TEXT NOT NULL,
                        updated_at          TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS zt_access_events (
                        event_id    TEXT PRIMARY KEY,
                        org_id      TEXT NOT NULL,
                        user        TEXT,
                        device      TEXT,
                        resource    TEXT,
                        decision    TEXT NOT NULL,
                        policy_id   TEXT,
                        source_ip   TEXT,
                        recorded_at TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_zt_pol_org
                        ON zt_policies(org_id, enabled, priority);
                    CREATE INDEX IF NOT EXISTS idx_zt_evt_org
                        ON zt_access_events(org_id, recorded_at);
                    CREATE INDEX IF NOT EXISTS idx_zt_evt_decision
                        ON zt_access_events(org_id, decision);
                    """
                )
                conn.commit()
            finally:
                conn.close()

    @staticmethod
    def _row_to_policy(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "policy_id": row["policy_id"],
            "org_id": row["org_id"],
            "name": row["name"],
            "description": row["description"],
            "policy_type": row["policy_type"],
            "action": row["action"],
            "source_conditions": json.loads(row["source_conditions"]),
            "destination_conditions": json.loads(row["destination_conditions"]),
            "priority": row["priority"],
            "enabled": bool(row["enabled"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "event_id": row["event_id"],
            "org_id": row["org_id"],
            "user": row["user"],
            "device": row["device"],
            "resource": row["resource"],
            "decision": row["decision"],
            "policy_id": row["policy_id"],
            "source_ip": row["source_ip"],
            "recorded_at": row["recorded_at"],
        }

    # ------------------------------------------------------------------
    # Policy CRUD
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: dict) -> dict:
        """Create a Zero Trust policy.

        data keys:
            name (required), description, policy_type (network/identity/device/application),
            action (allow/deny/mfa_required), source_conditions (dict),
            destination_conditions (dict), priority (int), enabled (bool)
        """
        policy_type = data.get("policy_type", "network")
        action = data.get("action", "deny")
        if policy_type not in _VALID_POLICY_TYPES:
            raise ValueError(f"Invalid policy_type '{policy_type}'. Must be one of: {sorted(_VALID_POLICY_TYPES)}")
        if action not in _VALID_ACTIONS:
            raise ValueError(f"Invalid action '{action}'. Must be one of: {sorted(_VALID_ACTIONS)}")

        now = datetime.now(timezone.utc).isoformat()
        policy_id = str(uuid.uuid4())

        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO zt_policies
                        (policy_id, org_id, name, description, policy_type, action,
                         source_conditions, destination_conditions, priority, enabled,
                         created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        policy_id,
                        org_id,
                        data.get("name", "Unnamed Policy"),
                        data.get("description", ""),
                        policy_type,
                        action,
                        json.dumps(data.get("source_conditions", {})),
                        json.dumps(data.get("destination_conditions", {})),
                        int(data.get("priority", 50)),
                        1 if data.get("enabled", True) else 0,
                        now,
                        now,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

        _logger.info("zt_policy.created", policy_id=policy_id, org_id=org_id, name=data.get("name"))
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "zero_trust_policy", "org_id": org_id, "source_engine": "zero_trust_policy"})
            except Exception:
                pass

        return self.get_policy(org_id, policy_id)  # type: ignore[return-value]

    def list_policies(
        self,
        org_id: str,
        policy_type: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> List[dict]:
        """List policies for an org, optionally filtered by type and enabled state."""
        clauses = ["org_id = ?"]
        params: List[Any] = [org_id]

        if policy_type is not None:
            clauses.append("policy_type = ?")
            params.append(policy_type)
        if enabled is not None:
            clauses.append("enabled = ?")
            params.append(1 if enabled else 0)

        where = " AND ".join(clauses)
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    f"SELECT * FROM zt_policies WHERE {where} ORDER BY priority ASC, created_at ASC",  # nosec B608
                    params,
                ).fetchall()
                return [self._row_to_policy(r) for r in rows]
            finally:
                conn.close()

    def get_policy(self, org_id: str, policy_id: str) -> Optional[dict]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM zt_policies WHERE org_id = ? AND policy_id = ?",
                    (org_id, policy_id),
                ).fetchone()
                return self._row_to_policy(row) if row else None
            finally:
                conn.close()

    def update_policy(self, org_id: str, policy_id: str, updates: dict) -> dict:
        """Update allowed fields on a policy. Returns updated policy."""
        existing = self.get_policy(org_id, policy_id)
        if existing is None:
            raise ValueError(f"Policy {policy_id!r} not found for org {org_id!r}")

        allowed = {"name", "description", "policy_type", "action",
                   "source_conditions", "destination_conditions", "priority", "enabled"}
        filtered: Dict[str, Any] = {}
        for k, v in updates.items():
            if k not in allowed:
                continue
            if k == "policy_type" and v not in _VALID_POLICY_TYPES:
                raise ValueError(f"Invalid policy_type '{v}'")
            if k == "action" and v not in _VALID_ACTIONS:
                raise ValueError(f"Invalid action '{v}'")
            filtered[k] = v

        if not filtered:
            return existing

        now = datetime.now(timezone.utc).isoformat()
        filtered["updated_at"] = now

        set_clause = ", ".join(f"{k} = ?" for k in filtered)
        values: List[Any] = []
        for k, v in filtered.items():
            if k in ("source_conditions", "destination_conditions") and isinstance(v, dict):
                values.append(json.dumps(v))
            elif k == "enabled" and isinstance(v, bool):
                values.append(1 if v else 0)
            else:
                values.append(v)
        values.extend([org_id, policy_id])

        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    f"UPDATE zt_policies SET {set_clause} WHERE org_id = ? AND policy_id = ?",  # nosec B608
                    values,
                )
                conn.commit()
            finally:
                conn.close()

        return self.get_policy(org_id, policy_id)  # type: ignore[return-value]

    def delete_policy(self, org_id: str, policy_id: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "DELETE FROM zt_policies WHERE org_id = ? AND policy_id = ?",
                    (org_id, policy_id),
                )
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Access evaluation
    # ------------------------------------------------------------------

    def evaluate_access(self, org_id: str, request: dict) -> dict:
        """Evaluate an access request against active policies.

        request keys: user, device, source_ip, destination, resource

        Returns: {decision, matched_policy_id, reason}
        """
        policies = self.list_policies(org_id, enabled=True)

        user = request.get("user", "")
        device = request.get("device", "")
        source_ip = request.get("source_ip", "")
        resource = request.get("resource", request.get("destination", ""))

        decision = "allow"
        matched_policy_id: Optional[str] = None
        reason = "No policies matched — default allow"

        for policy in policies:
            if self._policy_matches(policy, request):
                decision = policy["action"]
                matched_policy_id = policy["policy_id"]
                reason = (
                    f"Policy '{policy['name']}' (priority={policy['priority']}, "
                    f"type={policy['policy_type']}) matched — action: {decision}"
                )
                # First matching policy wins (already sorted by priority ASC)
                break

        # Record the event
        self.record_access_event(
            org_id,
            {
                "user": user,
                "device": device,
                "resource": resource,
                "decision": decision,
                "policy_id": matched_policy_id,
                "source_ip": source_ip,
            },
        )

        return {
            "decision": decision,
            "matched_policy_id": matched_policy_id,
            "reason": reason,
        }

    @staticmethod
    def _policy_matches(policy: dict, request: dict) -> bool:
        """Return True if the request triggers this policy."""
        src = policy.get("source_conditions", {})
        dst = policy.get("destination_conditions", {})

        # Source IP condition
        if "source_ip" in src:
            if request.get("source_ip", "") != src["source_ip"]:
                return False

        # User condition
        if "user" in src:
            if request.get("user", "") != src["user"]:
                return False

        # Device condition
        if "device" in src:
            if request.get("device", "") != src["device"]:
                return False

        # Resource/destination condition
        if "resource" in dst:
            if request.get("resource", request.get("destination", "")) != dst["resource"]:
                return False
        if "destination" in dst:
            if request.get("destination", request.get("resource", "")) != dst["destination"]:
                return False

        # If all specified conditions match (or none were specified), policy fires
        return True

    # ------------------------------------------------------------------
    # Access event logging
    # ------------------------------------------------------------------

    def record_access_event(self, org_id: str, data: dict) -> dict:
        """Log an access decision event."""
        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO zt_access_events
                        (event_id, org_id, user, device, resource, decision,
                         policy_id, source_ip, recorded_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        org_id,
                        data.get("user"),
                        data.get("device"),
                        data.get("resource"),
                        data.get("decision", "allow"),
                        data.get("policy_id"),
                        data.get("source_ip"),
                        now,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

        return {
            "event_id": event_id,
            "org_id": org_id,
            "decision": data.get("decision", "allow"),
            "recorded_at": now,
            **{k: data.get(k) for k in ("user", "device", "resource", "policy_id", "source_ip")},
        }

    def list_access_events(
        self,
        org_id: str,
        decision: Optional[str] = None,
        limit: int = 50,
    ) -> List[dict]:
        clauses = ["org_id = ?"]
        params: List[Any] = [org_id]

        if decision is not None:
            clauses.append("decision = ?")
            params.append(decision)

        where = " AND ".join(clauses)
        params.append(limit)

        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    f"SELECT * FROM zt_access_events WHERE {where} ORDER BY recorded_at DESC LIMIT ?",  # nosec B608
                    params,
                ).fetchall()
                return [self._row_to_event(r) for r in rows]
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Statistics & compliance
    # ------------------------------------------------------------------

    def get_policy_stats(self, org_id: str) -> dict:
        """Return policy and access event statistics."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

        with self._lock:
            conn = self._connect()
            try:
                total_policies = conn.execute(
                    "SELECT COUNT(*) FROM zt_policies WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                enabled_policies = conn.execute(
                    "SELECT COUNT(*) FROM zt_policies WHERE org_id = ? AND enabled = 1", (org_id,)
                ).fetchone()[0]

                type_rows = conn.execute(
                    "SELECT policy_type, COUNT(*) as cnt FROM zt_policies WHERE org_id = ? GROUP BY policy_type",
                    (org_id,),
                ).fetchall()
                by_type = {r["policy_type"]: r["cnt"] for r in type_rows}

                events_24h = conn.execute(
                    "SELECT COUNT(*) FROM zt_access_events WHERE org_id = ? AND recorded_at >= ?",
                    (org_id, cutoff),
                ).fetchone()[0]

                decision_rows = conn.execute(
                    """
                    SELECT decision, COUNT(*) as cnt
                    FROM zt_access_events
                    WHERE org_id = ? AND recorded_at >= ?
                    GROUP BY decision
                    """,
                    (org_id, cutoff),
                ).fetchall()
                by_decision = {r["decision"]: r["cnt"] for r in decision_rows}
            finally:
                conn.close()

        total_events = max(events_24h, 1)  # avoid div-by-zero
        allow_count = by_decision.get("allow", 0)
        deny_count = by_decision.get("deny", 0)
        mfa_count = by_decision.get("mfa_required", 0)

        return {
            "total_policies": total_policies,
            "enabled_policies": enabled_policies,
            "by_type": by_type,
            "access_events_24h": events_24h,
            "allow_rate": round(allow_count / total_events, 4),
            "deny_rate": round(deny_count / total_events, 4),
            "mfa_rate": round(mfa_count / total_events, 4),
        }

    def get_compliance_posture(self, org_id: str) -> dict:
        """Return Zero Trust maturity posture with pillar scores and recommendations.

        Returns:
            zt_maturity_score (0-100), pillars (identity/device/network/application/data),
            recommendations (list of strings)
        """
        policies = self.list_policies(org_id)
        enabled_policies = [p for p in policies if p["enabled"]]

        # Count enabled policies per pillar type
        by_type: Dict[str, int] = {}
        for p in enabled_policies:
            pt = p["policy_type"]
            by_type[pt] = by_type.get(pt, 0) + 1

        total_enabled = len(enabled_policies)

        # Pillar scoring heuristic: each pillar gets a score based on policy coverage
        # Identity maps to "identity" type; data inferred from application + network
        identity_count = by_type.get("identity", 0)
        device_count = by_type.get("device", 0)
        network_count = by_type.get("network", 0)
        application_count = by_type.get("application", 0)

        def _pillar_score(count: int) -> int:
            """Score 0-100 based on number of active policies for this pillar."""
            if count == 0:
                return 0
            if count == 1:
                return 35
            if count == 2:
                return 60
            if count == 3:
                return 80
            return min(95, 80 + (count - 3) * 5)

        pillars = {
            "identity": _pillar_score(identity_count),
            "device": _pillar_score(device_count),
            "network": _pillar_score(network_count),
            "application": _pillar_score(application_count),
            # Data pillar derived from combined coverage
            "data": _pillar_score((identity_count + network_count) // 2),
        }

        # Weighted maturity score
        zt_maturity_score = int(
            sum(pillars[pillar] * weight for pillar, weight in _PILLAR_WEIGHTS.items())
        )

        # Recommendations based on gaps
        recommendations: List[str] = []
        if identity_count == 0:
            recommendations.append("Add identity-based policies to enforce MFA and user context verification")
        elif identity_count < 2:
            recommendations.append("Expand identity policies to cover all user roles and privilege levels")

        if device_count == 0:
            recommendations.append("Implement device trust policies to enforce endpoint compliance checks")
        elif device_count < 2:
            recommendations.append("Add device health attestation policies for BYOD and unmanaged endpoints")

        if network_count == 0:
            recommendations.append("Define network micro-segmentation policies to restrict lateral movement")
        elif network_count < 2:
            recommendations.append("Extend network policies to cover all sensitive network segments")

        if application_count == 0:
            recommendations.append("Create application-level policies for sensitive data access control")

        if total_enabled == 0:
            recommendations = [
                "No active Zero Trust policies found — begin by enabling at least one policy per pillar"
            ]

        if not recommendations:
            recommendations.append("Zero Trust posture is strong — consider continuous monitoring and quarterly reviews")

        return {
            "zt_maturity_score": zt_maturity_score,
            "pillars": pillars,
            "recommendations": recommendations,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine_instance: Optional[ZeroTrustPolicyEngine] = None
_engine_lock = threading.Lock()


def get_zero_trust_policy_engine() -> ZeroTrustPolicyEngine:
    global _engine_instance
    if _engine_instance is None:
        with _engine_lock:
            if _engine_instance is None:
                _engine_instance = ZeroTrustPolicyEngine()
    return _engine_instance
