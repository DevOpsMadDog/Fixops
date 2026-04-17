"""Zero-trust policy engine — continuous verification for all access requests."""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = structlog.get_logger()

TRUST_LEVELS = ["untrusted", "low", "medium", "high", "trusted"]
POLICY_ACTIONS = ["allow", "deny", "step_up_auth", "quarantine", "monitor"]
RISK_SIGNALS = [
    "device_compliance",
    "user_behavior",
    "network_location",
    "time_of_access",
    "data_sensitivity",
]

_SCORE_TO_LEVEL_THRESHOLDS = [
    (80.0, "trusted"),
    (60.0, "high"),
    (40.0, "medium"),
    (20.0, "low"),
    (0.0, "untrusted"),
]

_ACTION_PRECEDENCE = {
    "deny": 5,
    "quarantine": 4,
    "step_up_auth": 3,
    "monitor": 2,
    "allow": 1,
}


def _score_to_level(score: float) -> str:
    for threshold, level in _SCORE_TO_LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "untrusted"


def _level_to_index(level: str) -> int:
    try:
        return TRUST_LEVELS.index(level)
    except ValueError:
        return 0


def _ip_in_networks(ip: str, networks: List[str]) -> bool:
    """Return True if ip falls within any CIDR range in networks."""
    if not networks:
        return True
    try:
        addr = ip_address(ip)
        for cidr in networks:
            try:
                if addr in ip_network(cidr, strict=False):
                    return True
            except ValueError:
                pass
    except ValueError:
        pass
    return False


def _time_in_ranges(ts: str, ranges: List[str]) -> bool:
    """Return True if the HH:MM portion of ts falls within any 'HH:MM-HH:MM' range."""
    if not ranges:
        return True
    try:
        dt = datetime.fromisoformat(ts)
        hhmm = dt.hour * 60 + dt.minute
        for r in ranges:
            parts = r.split("-")
            if len(parts) != 2:
                continue
            start_h, start_m = map(int, parts[0].split(":"))
            end_h, end_m = map(int, parts[1].split(":"))
            start_min = start_h * 60 + start_m
            end_min = end_h * 60 + end_m
            if start_min <= hhmm <= end_min:
                return True
    except (ValueError, AttributeError):
        pass
    return False


class ZeroTrustEngine:
    """SQLite-backed zero-trust policy engine — never trust, always verify."""

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
                CREATE TABLE IF NOT EXISTS zt_policies (
                    policy_id   TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    conditions  TEXT NOT NULL DEFAULT '{}',
                    action      TEXT NOT NULL,
                    priority    INTEGER NOT NULL DEFAULT 50,
                    org_id      TEXT NOT NULL DEFAULT 'default',
                    active      INTEGER NOT NULL DEFAULT 1,
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS zt_access_log (
                    request_id       TEXT PRIMARY KEY,
                    user_id          TEXT,
                    org_id           TEXT NOT NULL DEFAULT 'default',
                    resource         TEXT,
                    device_id        TEXT,
                    network_ip       TEXT,
                    decision         TEXT NOT NULL,
                    trust_level      TEXT NOT NULL,
                    trust_score      REAL NOT NULL DEFAULT 0,
                    policies_matched TEXT NOT NULL DEFAULT '[]',
                    risk_factors     TEXT NOT NULL DEFAULT '[]',
                    reasoning        TEXT NOT NULL DEFAULT '',
                    evaluated_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_zt_policies_org
                    ON zt_policies(org_id, active);
                CREATE INDEX IF NOT EXISTS idx_zt_policies_priority
                    ON zt_policies(priority);
                CREATE INDEX IF NOT EXISTS idx_zt_log_user
                    ON zt_access_log(user_id);
                CREATE INDEX IF NOT EXISTS idx_zt_log_org
                    ON zt_access_log(org_id);
                CREATE INDEX IF NOT EXISTS idx_zt_log_decision
                    ON zt_access_log(decision);
                CREATE INDEX IF NOT EXISTS idx_zt_log_evaluated
                    ON zt_access_log(evaluated_at);
                """
            )
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _row_to_policy(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "policy_id": row["policy_id"],
            "name": row["name"],
            "conditions": json.loads(row["conditions"]),
            "action": row["action"],
            "priority": row["priority"],
            "org_id": row["org_id"],
            "active": bool(row["active"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _row_to_log(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "request_id": row["request_id"],
            "user_id": row["user_id"],
            "org_id": row["org_id"],
            "resource": row["resource"],
            "device_id": row["device_id"],
            "network_ip": row["network_ip"],
            "decision": row["decision"],
            "trust_level": row["trust_level"],
            "trust_score": row["trust_score"],
            "policies_matched": json.loads(row["policies_matched"]),
            "risk_factors": json.loads(row["risk_factors"]),
            "reasoning": row["reasoning"],
            "evaluated_at": row["evaluated_at"],
        }

    # ------------------------------------------------------------------
    # Policy CRUD
    # ------------------------------------------------------------------

    def create_policy(
        self,
        name: str,
        conditions: dict,
        action: str,
        priority: int = 50,
        org_id: str = "default",
    ) -> dict:
        """Create a zero-trust access policy.

        conditions keys (all optional):
            min_trust_level: str — one of TRUST_LEVELS
            require_mfa: bool
            allowed_networks: list[str]  — CIDR ranges
            allowed_time_ranges: list[str]  — "HH:MM-HH:MM"
            require_compliant_device: bool
            max_risk_score: float  — deny if user_risk_score > this value

        action: allow | deny | step_up_auth | quarantine | monitor
        """
        if action not in POLICY_ACTIONS:
            raise ValueError(
                f"Invalid action '{action}'. Must be one of: {POLICY_ACTIONS}"
            )

        now = datetime.now(timezone.utc).isoformat()
        policy_id = str(uuid.uuid4())
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO zt_policies
                    (policy_id, name, conditions, action, priority, org_id, active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    policy_id,
                    name,
                    json.dumps(conditions),
                    action,
                    priority,
                    org_id,
                    now,
                    now,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        _logger.info("zero_trust.policy_created", policy_id=policy_id, name=name, action=action)
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "zero_trust_engine", "org_id": "unknown", "source_engine": "zero_trust_engine"})
            except Exception:
                pass
        return {
            "policy_id": policy_id,
            "name": name,
            "conditions": conditions,
            "action": action,
            "priority": priority,
            "org_id": org_id,
            "active": True,
            "created_at": now,
            "updated_at": now,
        }

    def get_policy(self, policy_id: str) -> Optional[dict]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM zt_policies WHERE policy_id = ?", (policy_id,)
            ).fetchone()
            return self._row_to_policy(row) if row else None
        finally:
            conn.close()

    def list_policies(
        self, org_id: str = "default", active_only: bool = True
    ) -> List[dict]:
        conn = self._connect()
        try:
            if active_only:
                rows = conn.execute(
                    "SELECT * FROM zt_policies WHERE org_id = ? AND active = 1 ORDER BY priority ASC",
                    (org_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM zt_policies WHERE org_id = ? ORDER BY priority ASC",
                    (org_id,),
                ).fetchall()
            return [self._row_to_policy(r) for r in rows]
        finally:
            conn.close()

    def update_policy(self, policy_id: str, **kwargs) -> dict:
        policy = self.get_policy(policy_id)
        if policy is None:
            raise ValueError(f"Policy {policy_id} not found")

        allowed_fields = {"name", "conditions", "action", "priority", "org_id", "active"}
        updates: Dict[str, Any] = {}
        for key, val in kwargs.items():
            if key not in allowed_fields:
                continue
            if key == "action" and val not in POLICY_ACTIONS:
                raise ValueError(f"Invalid action '{val}'")
            updates[key] = val

        if not updates:
            return policy

        now = datetime.now(timezone.utc).isoformat()
        updates["updated_at"] = now

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values: List[Any] = []
        for k, v in updates.items():
            if k == "conditions" and isinstance(v, dict):
                values.append(json.dumps(v))
            elif k == "active" and isinstance(v, bool):
                values.append(1 if v else 0)
            else:
                values.append(v)
        values.append(policy_id)

        conn = self._connect()
        try:
            conn.execute(
                f"UPDATE zt_policies SET {set_clause} WHERE policy_id = ?", values  # nosec B608
            )
            conn.commit()
        finally:
            conn.close()

        return self.get_policy(policy_id)  # type: ignore[return-value]

    def delete_policy(self, policy_id: str) -> bool:
        conn = self._connect()
        try:
            cur = conn.execute(
                "DELETE FROM zt_policies WHERE policy_id = ?", (policy_id,)
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Trust scoring
    # ------------------------------------------------------------------

    def compute_trust_score(self, request: dict) -> dict:
        """Compute trust level for a request context.

        Returns {trust_level: str, trust_score: float 0-100, signals: dict}
        """
        signals: Dict[str, Any] = {}
        score = 50.0  # neutral baseline

        # MFA verification — strong positive signal
        mfa_verified = bool(request.get("mfa_verified", False))
        signals["mfa_verified"] = mfa_verified
        if mfa_verified:
            score += 20.0
        else:
            score -= 15.0

        # Device compliance
        device_compliant = bool(request.get("device_compliant", False))
        signals["device_compliant"] = device_compliant
        if device_compliant:
            score += 15.0
        else:
            score -= 20.0

        # User risk score (0-100, higher = riskier)
        user_risk_score = float(request.get("user_risk_score", 0.0))
        signals["user_risk_score"] = user_risk_score
        # 0 risk adds nothing, 100 risk subtracts 30 pts
        score -= (user_risk_score / 100.0) * 30.0

        # Clamp to [0, 100]
        score = max(0.0, min(100.0, score))
        trust_level = _score_to_level(score)

        return {
            "trust_level": trust_level,
            "trust_score": round(score, 2),
            "signals": signals,
        }

    # ------------------------------------------------------------------
    # Access evaluation
    # ------------------------------------------------------------------

    def _policy_fires(self, policy: dict, request: dict, trust_info: dict) -> bool:
        """Return True if any policy condition is violated (policy should trigger)."""
        cond = policy.get("conditions", {})

        # min_trust_level: fires if trust is below minimum
        min_level = cond.get("min_trust_level")
        if min_level:
            req_idx = _level_to_index(trust_info["trust_level"])
            min_idx = _level_to_index(min_level)
            if req_idx < min_idx:
                return True

        # require_mfa: fires if MFA not verified
        if cond.get("require_mfa") and not request.get("mfa_verified", False):
            return True

        # allowed_networks: fires if IP not in allowed ranges
        allowed_nets = cond.get("allowed_networks", [])
        if allowed_nets:
            ip = request.get("network_ip", "")
            if not _ip_in_networks(ip, allowed_nets):
                return True

        # allowed_time_ranges: fires if timestamp outside ranges
        time_ranges = cond.get("allowed_time_ranges", [])
        if time_ranges:
            ts = request.get("timestamp", datetime.now(timezone.utc).isoformat())
            if not _time_in_ranges(ts, time_ranges):
                return True

        # require_compliant_device: fires if device not compliant
        if cond.get("require_compliant_device") and not request.get("device_compliant", False):
            return True

        # max_risk_score: fires if user risk exceeds threshold
        max_risk = cond.get("max_risk_score")
        if max_risk is not None:
            user_risk = float(request.get("user_risk_score", 0.0))
            if user_risk > float(max_risk):
                return True

        return False

    def evaluate_access(self, request: dict) -> dict:
        """Evaluate an access request against all active policies.

        request keys:
            user_id, org_id, resource, device_id, device_compliant,
            network_ip, mfa_verified, user_risk_score, timestamp

        Returns:
            decision: allow | deny | step_up_auth | quarantine
            trust_level: str
            policies_matched: list[str]
            risk_factors: list[str]
            reasoning: str
            request_id: str
        """
        request_id = str(uuid.uuid4())
        org_id = request.get("org_id", "default")
        trust_info = self.compute_trust_score(request)

        # Policies sorted by priority ASC (lower number = higher priority)
        policies = self.list_policies(org_id=org_id, active_only=True)

        matched_policies: List[str] = []
        risk_factors: List[str] = []
        decision = "allow"
        reasoning_parts: List[str] = []

        for policy in policies:
            if self._policy_fires(policy, request, trust_info):
                matched_policies.append(policy["policy_id"])
                action = policy["action"]
                cond = policy.get("conditions", {})

                # Collect risk factors
                if cond.get("require_mfa") and not request.get("mfa_verified", False):
                    risk_factors.append("mfa_not_verified")
                if cond.get("require_compliant_device") and not request.get("device_compliant", False):
                    risk_factors.append("non_compliant_device")
                allowed_nets = cond.get("allowed_networks", [])
                if allowed_nets and not _ip_in_networks(request.get("network_ip", ""), allowed_nets):
                    risk_factors.append("untrusted_network")
                max_risk = cond.get("max_risk_score")
                if max_risk is not None and float(request.get("user_risk_score", 0)) > float(max_risk):
                    risk_factors.append("high_user_risk_score")
                min_level = cond.get("min_trust_level")
                if min_level:
                    if _level_to_index(trust_info["trust_level"]) < _level_to_index(min_level):
                        risk_factors.append("insufficient_trust_level")

                reasoning_parts.append(
                    f"Policy '{policy['name']}' (priority={policy['priority']}) matched -> {action}"
                )

                # Higher-precedence action wins
                if _ACTION_PRECEDENCE.get(action, 0) > _ACTION_PRECEDENCE.get(decision, 0):
                    decision = action

        if not matched_policies:
            reasoning_parts.append(
                f"No policies matched. Trust level: {trust_info['trust_level']} "
                f"(score={trust_info['trust_score']}). Default: allow."
            )
        else:
            reasoning_parts.append(
                f"Final decision: {decision}. Trust level: {trust_info['trust_level']} "
                f"(score={trust_info['trust_score']})."
            )

        reasoning = " | ".join(reasoning_parts)
        # Deduplicate risk factors, preserve order
        risk_factors = list(dict.fromkeys(risk_factors))

        # Persist evaluation
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO zt_access_log
                    (request_id, user_id, org_id, resource, device_id, network_ip,
                     decision, trust_level, trust_score, policies_matched,
                     risk_factors, reasoning, evaluated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    request.get("user_id"),
                    org_id,
                    request.get("resource"),
                    request.get("device_id"),
                    request.get("network_ip"),
                    decision,
                    trust_info["trust_level"],
                    trust_info["trust_score"],
                    json.dumps(matched_policies),
                    json.dumps(risk_factors),
                    reasoning,
                    now,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        _logger.info(
            "zero_trust.evaluated",
            request_id=request_id,
            user_id=request.get("user_id"),
            decision=decision,
            trust_level=trust_info["trust_level"],
        )

        return {
            "request_id": request_id,
            "decision": decision,
            "trust_level": trust_info["trust_level"],
            "policies_matched": matched_policies,
            "risk_factors": risk_factors,
            "reasoning": reasoning,
        }

    # ------------------------------------------------------------------
    # Access log
    # ------------------------------------------------------------------

    def get_access_log(
        self,
        user_id: Optional[str] = None,
        org_id: str = "default",
        decision: Optional[str] = None,
        limit: int = 100,
    ) -> List[dict]:
        clauses = ["org_id = ?"]
        params: List[Any] = [org_id]

        if user_id is not None:
            clauses.append("user_id = ?")
            params.append(user_id)
        if decision is not None:
            clauses.append("decision = ?")
            params.append(decision)

        where = " AND ".join(clauses)
        params.append(limit)

        conn = self._connect()
        try:
            rows = conn.execute(
                f"SELECT * FROM zt_access_log WHERE {where} ORDER BY evaluated_at DESC LIMIT ?",  # nosec B608
                params,
            ).fetchall()
            return [self._row_to_log(r) for r in rows]
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    def get_trust_score(self, subject_id: str, org_id: str = "default") -> dict:
        """Return trust score factors for a subject (user or device).

        Factors are derived from the most recent access log entries for this subject.
        Returns {score: 0-100, factors: {device_health, location_risk, behavior_anomaly,
        identity_confidence, data_sensitivity}}
        """
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT trust_score, risk_factors, decision, evaluated_at
                FROM zt_access_log
                WHERE org_id = ? AND user_id = ?
                ORDER BY evaluated_at DESC
                LIMIT 20
                """,
                (org_id, subject_id),
            ).fetchall()
        finally:
            conn.close()

        if not rows:
            # No history — return neutral defaults
            return {
                "subject_id": subject_id,
                "score": 50,
                "factors": {
                    "device_health": 50,
                    "location_risk": 50,
                    "behavior_anomaly": 50,
                    "identity_confidence": 50,
                    "data_sensitivity": 50,
                },
            }

        # Aggregate signals from recent entries
        trust_scores = [float(r["trust_score"]) for r in rows]
        avg_trust = sum(trust_scores) / len(trust_scores)

        all_risk_factors: List[str] = []
        for r in rows:
            try:
                all_risk_factors.extend(json.loads(r["risk_factors"]))
            except (json.JSONDecodeError, TypeError):
                pass

        deny_count = sum(1 for r in rows if r["decision"] in ("deny", "quarantine"))
        deny_rate = deny_count / len(rows)

        # Derive factor scores (0-100, higher = healthier)
        device_health = max(0.0, 100.0 - 50.0 * all_risk_factors.count("non_compliant_device") / max(len(rows), 1))
        location_risk = max(0.0, 100.0 - 60.0 * all_risk_factors.count("untrusted_network") / max(len(rows), 1))
        behavior_anomaly = max(0.0, 100.0 - 80.0 * deny_rate)
        identity_confidence = max(0.0, 100.0 - 50.0 * all_risk_factors.count("mfa_not_verified") / max(len(rows), 1))
        data_sensitivity = max(0.0, 100.0 - 40.0 * all_risk_factors.count("insufficient_trust_level") / max(len(rows), 1))

        return {
            "subject_id": subject_id,
            "score": round(avg_trust, 1),
            "factors": {
                "device_health": round(device_health, 1),
                "location_risk": round(location_risk, 1),
                "behavior_anomaly": round(behavior_anomaly, 1),
                "identity_confidence": round(identity_confidence, 1),
                "data_sensitivity": round(data_sensitivity, 1),
            },
        }

    def get_policy_stats(self, org_id: str = "default") -> dict:
        """Return policy effectiveness statistics for today.

        Returns {total_policies, allows_today, denies_today, challenges_today,
        top_denied_resources}
        """
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        conn = self._connect()
        try:
            total_policies = conn.execute(
                "SELECT COUNT(*) FROM zt_policies WHERE org_id = ? AND active = 1",
                (org_id,),
            ).fetchone()[0]

            rows = conn.execute(
                """
                SELECT decision, COUNT(*) as cnt
                FROM zt_access_log
                WHERE org_id = ? AND date(evaluated_at) = ?
                GROUP BY decision
                """,
                (org_id, today),
            ).fetchall()
            by_decision: Dict[str, int] = {r["decision"]: r["cnt"] for r in rows}

            denied_resources = conn.execute(
                """
                SELECT resource, COUNT(*) as cnt
                FROM zt_access_log
                WHERE org_id = ? AND decision IN ('deny', 'quarantine')
                  AND resource IS NOT NULL AND resource != ''
                GROUP BY resource
                ORDER BY cnt DESC
                LIMIT 5
                """,
                (org_id,),
            ).fetchall()
        finally:
            conn.close()

        allows_today = by_decision.get("allow", 0)
        denies_today = by_decision.get("deny", 0) + by_decision.get("quarantine", 0)
        challenges_today = by_decision.get("step_up_auth", 0) + by_decision.get("monitor", 0)

        return {
            "total_policies": total_policies,
            "allows_today": allows_today,
            "denies_today": denies_today,
            "challenges_today": challenges_today,
            "top_denied_resources": [
                {"resource": r["resource"], "count": r["cnt"]} for r in denied_resources
            ],
        }

    def get_micro_segmentation_map(self, org_id: str = "default") -> dict:
        """Return network zones and allowed paths between them.

        Derives zones from access log traffic patterns. Returns
        {zones: list, paths: list, segment_count: int}
        """
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT network_ip, resource, decision
                FROM zt_access_log
                WHERE org_id = ? AND network_ip IS NOT NULL AND network_ip != ''
                ORDER BY evaluated_at DESC
                LIMIT 500
                """,
                (org_id,),
            ).fetchall()
        finally:
            conn.close()

        # Classify IPs into zones based on RFC-1918 ranges
        zone_traffic: Dict[str, Dict[str, int]] = {}
        resource_zone: Dict[str, str] = {}

        for r in rows:
            ip = r["network_ip"] or ""
            resource = r["resource"] or "unknown"
            decision = r["decision"]

            # Classify source zone
            if ip.startswith("10."):
                src_zone = "internal-corporate"
            elif ip.startswith("172.16.") or ip.startswith("172.31."):
                src_zone = "internal-dmz"
            elif ip.startswith("192.168."):
                src_zone = "internal-office"
            elif ip == "":
                src_zone = "unknown"
            else:
                src_zone = "external-internet"

            # Classify destination zone by resource name heuristics
            res_lower = resource.lower()
            if any(k in res_lower for k in ("db", "database", "sql", "postgres", "mysql")):
                dst_zone = "data-tier"
            elif any(k in res_lower for k in ("api", "service", "backend", "app")):
                dst_zone = "app-tier"
            elif any(k in res_lower for k in ("admin", "mgmt", "manage")):
                dst_zone = "management"
            elif any(k in res_lower for k in ("vpn", "gateway", "router")):
                dst_zone = "network-perimeter"
            else:
                dst_zone = "general-services"

            resource_zone[resource] = dst_zone

            key = f"{src_zone}->{dst_zone}"
            if key not in zone_traffic:
                zone_traffic[key] = {"allow": 0, "deny": 0}
            if decision in ("allow", "monitor"):
                zone_traffic[key]["allow"] += 1
            else:
                zone_traffic[key]["deny"] += 1

        # Build zone list
        all_zone_names = set()
        for k in zone_traffic:
            src, dst = k.split("->")
            all_zone_names.add(src)
            all_zone_names.add(dst)

        # Add default zones even if no traffic yet
        default_zones = [
            {"id": "external-internet", "label": "External Internet", "risk": "high", "color": "red"},
            {"id": "network-perimeter", "label": "Network Perimeter", "risk": "medium", "color": "orange"},
            {"id": "internal-corporate", "label": "Corporate Network", "risk": "low", "color": "blue"},
            {"id": "internal-office", "label": "Office Network", "risk": "low", "color": "blue"},
            {"id": "internal-dmz", "label": "DMZ", "risk": "medium", "color": "yellow"},
            {"id": "app-tier", "label": "Application Tier", "risk": "medium", "color": "purple"},
            {"id": "data-tier", "label": "Data Tier", "risk": "high", "color": "red"},
            {"id": "management", "label": "Management Zone", "risk": "high", "color": "red"},
            {"id": "general-services", "label": "General Services", "risk": "low", "color": "green"},
        ]

        paths = [
            {
                "from": k.split("->")[0],
                "to": k.split("->")[1],
                "allowed": v["allow"],
                "denied": v["deny"],
                "status": "active" if v["allow"] > 0 else "blocked",
            }
            for k, v in zone_traffic.items()
        ]

        return {
            "zones": default_zones,
            "paths": paths,
            "segment_count": len(default_zones),
        }

    def get_trust_analytics(self, org_id: str = "default") -> dict:
        """Return trust analytics for the org."""
        conn = self._connect()
        try:
            total = conn.execute(
                "SELECT COUNT(*) FROM zt_access_log WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            if total == 0:
                return {
                    "total_evaluations": 0,
                    "allow_rate": 0.0,
                    "deny_rate": 0.0,
                    "step_up_rate": 0.0,
                    "by_decision": {},
                    "avg_trust_score": 0.0,
                }

            rows = conn.execute(
                "SELECT decision, COUNT(*) as cnt FROM zt_access_log WHERE org_id = ? GROUP BY decision",
                (org_id,),
            ).fetchall()
            by_decision: Dict[str, int] = {r["decision"]: r["cnt"] for r in rows}

            avg_row = conn.execute(
                "SELECT AVG(trust_score) FROM zt_access_log WHERE org_id = ?", (org_id,)
            ).fetchone()
            avg_score = float(avg_row[0]) if avg_row[0] is not None else 0.0
        finally:
            conn.close()

        return {
            "total_evaluations": total,
            "allow_rate": round(by_decision.get("allow", 0) / total, 4),
            "deny_rate": round(by_decision.get("deny", 0) / total, 4),
            "step_up_rate": round(by_decision.get("step_up_auth", 0) / total, 4),
            "by_decision": by_decision,
            "avg_trust_score": round(avg_score, 2),
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine_singleton: Optional[ZeroTrustEngine] = None


def get_zero_trust_engine() -> ZeroTrustEngine:
    global _engine_singleton
    if _engine_singleton is None:
        _engine_singleton = ZeroTrustEngine()
    return _engine_singleton
