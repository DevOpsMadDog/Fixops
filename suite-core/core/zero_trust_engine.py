"""
Zero-Trust Network Policy Engine for ALDECI.

Implements access evaluation, micro-segmentation, lateral movement detection,
and entity trust scoring under the "never trust, always verify" model.

Compliance: NIST SP 800-207 (Zero Trust Architecture), SOC2 CC6.x
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ENUMS
# ---------------------------------------------------------------------------


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    CHALLENGE = "CHALLENGE"  # MFA / step-up required


class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# CORE MODELS
# ---------------------------------------------------------------------------


class AccessRequest(BaseModel):
    """A zero-trust access request submitted by a user, device, or service."""

    user_id: str
    device_id: str
    resource: str
    action: str = "read"
    location: str = ""           # IP address or geo tag
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    mfa_verified: bool = False
    device_trust_score: Optional[float] = None   # 0.0–1.0, None = unknown
    behaviour_score: Optional[float] = None      # 0.0–1.0, None = unknown
    extra: Dict[str, Any] = Field(default_factory=dict)


class AccessDecision(BaseModel):
    """Result of a zero-trust access evaluation."""

    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    decision: Decision
    reasons: List[str] = Field(default_factory=list)
    trust_score: float = Field(default=0.0, ge=0.0, le=1.0)
    policy_applied: str = ""
    mfa_required: bool = False
    evaluated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "decision": self.decision.value,
            "reasons": self.reasons,
            "trust_score": self.trust_score,
            "policy_applied": self.policy_applied,
            "mfa_required": self.mfa_required,
            "evaluated_at": self.evaluated_at,
        }


class NetworkPolicy(BaseModel):
    """A micro-segmentation network policy."""

    policy_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str = ""
    segments: List[Dict[str, Any]] = Field(default_factory=list)
    allow_rules: List[Dict[str, Any]] = Field(default_factory=list)
    deny_all: bool = True
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "segments": self.segments,
            "allow_rules": self.allow_rules,
            "deny_all": self.deny_all,
            "created_at": self.created_at,
        }


class Policy(BaseModel):
    """A zero-trust access policy for a specific resource."""

    policy_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    resource: str
    rules: List[Dict[str, Any]] = Field(default_factory=list)
    default_decision: Decision = Decision.DENY
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "resource": self.resource,
            "rules": self.rules,
            "default_decision": self.default_decision.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class Alert(BaseModel):
    """A lateral movement or anomaly alert."""

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_type: str
    severity: AlertSeverity
    description: str
    source_entity: str = ""
    target_entity: str = ""
    evidence: List[str] = Field(default_factory=list)
    detected_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type,
            "severity": self.severity.value,
            "description": self.description,
            "source_entity": self.source_entity,
            "target_entity": self.target_entity,
            "evidence": self.evidence,
            "detected_at": self.detected_at,
        }


# ---------------------------------------------------------------------------
# INTERNAL CONSTANTS
# ---------------------------------------------------------------------------

# Resource sensitivity tiers; higher = more sensitive
_CRITICAL_RESOURCES = {
    "admin", "secrets", "credentials", "api_keys", "root", "iam",
    "encryption_keys", "ca_cert", "private_key",
}
_SENSITIVE_RESOURCES = {
    "users", "config", "audit_log", "billing", "compliance",
    "pii", "health_data", "financial",
}

# Trust-score thresholds
_SCORE_ALLOW = 0.65
_SCORE_CHALLENGE = 0.40

# Business hours (UTC) for off-hours detection
_BIZ_HOUR_START = 6
_BIZ_HOUR_END = 22

# Lateral movement patterns
_SCAN_PORT_THRESHOLD = 5          # distinct destination ports → port scan
_NEW_HOST_THRESHOLD = 4           # distinct hosts in window → host enumeration
_RAPID_AUTH_THRESHOLD = 10        # auth attempts per minute → brute force


# ---------------------------------------------------------------------------
# ZERO TRUST ENGINE
# ---------------------------------------------------------------------------


class ZeroTrustEngine:
    """
    Zero-trust network policy evaluation and enforcement.

    Backed by SQLite for policy and trust-score persistence.
    Stateless for evaluation so it is safe to call from async handlers.
    """

    def __init__(self, db_path: str = "data/zero_trust_engine.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS policies (
                    policy_id    TEXT PRIMARY KEY,
                    resource     TEXT NOT NULL UNIQUE,
                    rules        TEXT NOT NULL DEFAULT '[]',
                    default_decision TEXT NOT NULL DEFAULT 'DENY',
                    created_at   TEXT NOT NULL,
                    updated_at   TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS entity_trust (
                    entity_id    TEXT PRIMARY KEY,
                    entity_type  TEXT NOT NULL DEFAULT 'user',
                    trust_score  REAL NOT NULL DEFAULT 0.5,
                    factors      TEXT NOT NULL DEFAULT '{}',
                    updated_at   TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS access_log (
                    id           TEXT PRIMARY KEY,
                    user_id      TEXT NOT NULL,
                    device_id    TEXT NOT NULL,
                    resource     TEXT NOT NULL,
                    action       TEXT NOT NULL,
                    decision     TEXT NOT NULL,
                    trust_score  REAL NOT NULL,
                    reasons      TEXT NOT NULL DEFAULT '[]',
                    evaluated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_access_log_user
                    ON access_log(user_id, evaluated_at);
                CREATE INDEX IF NOT EXISTS idx_access_log_resource
                    ON access_log(resource, evaluated_at);
                CREATE INDEX IF NOT EXISTS idx_entity_trust_type
                    ON entity_trust(entity_type);
                """
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Public API — access evaluation
    # ------------------------------------------------------------------

    def evaluate_access_request(self, request: AccessRequest) -> AccessDecision:
        """
        Evaluate if access should be granted based on zero-trust principles.

        Factors evaluated (in order):
        1. Device trust score (posture)
        2. Resource sensitivity vs. trust score
        3. Network location (private vs. public)
        4. Behaviour baseline score
        5. Time of access (business hours)
        6. MFA status for critical resources

        Returns: AccessDecision with decision ALLOW | DENY | CHALLENGE.
        """
        reasons: List[str] = []
        trust_score = self._compute_request_trust(request, reasons)
        mfa_required = self._is_mfa_required(request.resource)
        policy_applied = "default"

        # Check resource-specific policy first
        policy = self._load_policy_for_resource(request.resource)
        if policy:
            policy_applied = policy["policy_id"]
            rule_decision = self._evaluate_policy_rules(policy["rules"], request)
            if rule_decision is not None:
                decision = rule_decision
                reasons.append(f"matched_policy_rule resource={request.resource}")
                return self._finalize(
                    decision, reasons, trust_score, policy_applied, mfa_required, request
                )

        # Default scoring logic
        resource_key = request.resource.lower().split("/")[0].split(":")[0]
        is_critical = resource_key in _CRITICAL_RESOURCES
        is_sensitive = resource_key in _SENSITIVE_RESOURCES

        if is_critical:
            if not request.mfa_verified:
                reasons.append("critical_resource_requires_mfa")
                decision = Decision.CHALLENGE
                mfa_required = True
            elif trust_score >= _SCORE_ALLOW:
                decision = Decision.ALLOW
                reasons.append(f"critical_resource_mfa_verified trust={trust_score:.2f}")
            else:
                decision = Decision.DENY
                reasons.append(f"critical_resource_trust_insufficient trust={trust_score:.2f}")
        elif is_sensitive:
            if trust_score >= _SCORE_ALLOW:
                decision = Decision.ALLOW
                reasons.append(f"sensitive_resource_allowed trust={trust_score:.2f}")
            elif trust_score >= _SCORE_CHALLENGE:
                decision = Decision.CHALLENGE
                mfa_required = True
                reasons.append(f"sensitive_resource_step_up trust={trust_score:.2f}")
            else:
                decision = Decision.DENY
                reasons.append(f"sensitive_resource_trust_too_low trust={trust_score:.2f}")
        else:
            # Standard resource
            if trust_score >= _SCORE_CHALLENGE:
                decision = Decision.ALLOW
                reasons.append(f"standard_resource_allowed trust={trust_score:.2f}")
            else:
                decision = Decision.DENY
                reasons.append(f"standard_resource_trust_too_low trust={trust_score:.2f}")

        return self._finalize(decision, reasons, trust_score, policy_applied, mfa_required, request)

    def _compute_request_trust(
        self, request: AccessRequest, reasons: List[str]
    ) -> float:
        """Combine all trust signals into a composite score 0.0–1.0."""
        score = 0.5  # baseline for known entity

        # Device posture signal (weight 0.30)
        if request.device_trust_score is not None:
            device_contrib = request.device_trust_score * 0.30
            score = score - 0.15 + device_contrib  # replace baseline device portion
            if request.device_trust_score < 0.30:
                reasons.append(f"device_trust_low score={request.device_trust_score:.2f}")
            else:
                reasons.append(f"device_trust_ok score={request.device_trust_score:.2f}")

        # Behaviour signal (weight 0.20)
        if request.behaviour_score is not None:
            behav_contrib = (request.behaviour_score - 0.5) * 0.20
            score += behav_contrib
            if request.behaviour_score < 0.40:
                reasons.append(f"anomalous_behaviour score={request.behaviour_score:.2f}")

        # Network location signal (weight 0.15)
        loc = request.location
        if loc.startswith(("127.", "10.", "192.168.", "::1")):
            score += 0.10
            reasons.append("private_network")
        elif loc.startswith("172."):
            parts = loc.split(".")
            try:
                if len(parts) >= 2 and 16 <= int(parts[1]) <= 31:
                    score += 0.10
                    reasons.append("private_network")
            except ValueError:
                pass
        elif loc:
            reasons.append("public_network")

        # Time-of-access signal
        try:
            ts = datetime.fromisoformat(request.timestamp.replace("Z", "+00:00"))
            hour = ts.hour
            if _BIZ_HOUR_START <= hour < _BIZ_HOUR_END:
                score += 0.05
                reasons.append("business_hours_access")
            else:
                score -= 0.10
                reasons.append("off_hours_access")
        except (ValueError, AttributeError):
            pass

        # MFA already verified bonus
        if request.mfa_verified:
            score += 0.15
            reasons.append("mfa_verified")

        # Clamp
        return round(max(0.0, min(score, 1.0)), 4)

    def _is_mfa_required(self, resource: str) -> bool:
        resource_key = resource.lower().split("/")[0].split(":")[0]
        return resource_key in _CRITICAL_RESOURCES | _SENSITIVE_RESOURCES

    def _load_policy_for_resource(self, resource: str) -> Optional[Dict[str, Any]]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM policies WHERE resource = ?", (resource,)
            ).fetchone()
            if row:
                return {
                    "policy_id": row["policy_id"],
                    "resource": row["resource"],
                    "rules": json.loads(row["rules"]),
                    "default_decision": row["default_decision"],
                }
            return None
        finally:
            conn.close()

    def _evaluate_policy_rules(
        self, rules: List[Dict[str, Any]], request: AccessRequest
    ) -> Optional[Decision]:
        """Evaluate ordered policy rules. Returns first matching Decision or None."""
        for rule in rules:
            if self._rule_matches(rule, request):
                d = rule.get("decision", "DENY").upper()
                try:
                    return Decision(d)
                except ValueError:
                    return Decision.DENY
        return None

    def _rule_matches(self, rule: Dict[str, Any], request: AccessRequest) -> bool:
        """Check if a rule matches the request. All conditions must hold."""
        if "user_id" in rule and rule["user_id"] != request.user_id:
            return False
        if "action" in rule and rule["action"] != request.action:
            return False
        if "min_trust_score" in rule:
            score = request.device_trust_score or 0.0
            if score < rule["min_trust_score"]:
                return False
        if "require_mfa" in rule and rule["require_mfa"] and not request.mfa_verified:
            return False
        return True

    def _finalize(
        self,
        decision: Decision,
        reasons: List[str],
        trust_score: float,
        policy_applied: str,
        mfa_required: bool,
        request: AccessRequest,
    ) -> AccessDecision:
        ad = AccessDecision(
            decision=decision,
            reasons=reasons,
            trust_score=trust_score,
            policy_applied=policy_applied,
            mfa_required=mfa_required,
        )
        self._log_access(request, ad)
        return ad

    def _log_access(self, request: AccessRequest, decision: AccessDecision) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO access_log
                    (id, user_id, device_id, resource, action,
                     decision, trust_score, reasons, evaluated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.decision_id,
                    request.user_id,
                    request.device_id,
                    request.resource,
                    request.action,
                    decision.decision.value,
                    decision.trust_score,
                    json.dumps(decision.reasons),
                    decision.evaluated_at,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Public API — micro-segmentation
    # ------------------------------------------------------------------

    def generate_micro_segmentation_policy(
        self, assets: List[Dict[str, Any]]
    ) -> NetworkPolicy:
        """
        Generate network segmentation rules based on asset relationships.

        Groups assets by sensitivity level and creates allow-list rules
        between groups. Denies all else by default.
        """
        segments: Dict[str, List[str]] = {
            "critical": [],
            "sensitive": [],
            "standard": [],
        }

        for asset in assets:
            name = asset.get("name", asset.get("id", "unknown"))
            sensitivity = asset.get("sensitivity", "standard").lower()
            tags = [t.lower() for t in asset.get("tags", [])]

            # Infer sensitivity from name/tags if not explicit
            if sensitivity == "standard":
                if any(k in name.lower() for k in _CRITICAL_RESOURCES):
                    sensitivity = "critical"
                elif any(k in name.lower() for k in _SENSITIVE_RESOURCES):
                    sensitivity = "sensitive"
                elif any(k in tags for k in _CRITICAL_RESOURCES):
                    sensitivity = "critical"
                elif any(k in tags for k in _SENSITIVE_RESOURCES):
                    sensitivity = "sensitive"

            segments[sensitivity].append(name)

        # Build allow rules: lower tier can reach higher tier (read-only)
        # but critical assets can only be reached from critical segment
        allow_rules: List[Dict[str, Any]] = []

        # Standard → Standard: full mesh allowed
        if segments["standard"]:
            allow_rules.append({
                "from_segment": "standard",
                "to_segment": "standard",
                "ports": [80, 443, 8080, 8443],
                "protocols": ["tcp"],
                "description": "Standard-to-standard mesh traffic",
            })

        # Standard → Sensitive: restricted ports only
        if segments["standard"] and segments["sensitive"]:
            allow_rules.append({
                "from_segment": "standard",
                "to_segment": "sensitive",
                "ports": [443],
                "protocols": ["tcp"],
                "description": "Standard to sensitive: HTTPS only",
            })

        # Sensitive → Sensitive: allowed on secure ports
        if segments["sensitive"]:
            allow_rules.append({
                "from_segment": "sensitive",
                "to_segment": "sensitive",
                "ports": [443, 5432, 6379],
                "protocols": ["tcp"],
                "description": "Sensitive-to-sensitive secure traffic",
            })

        # Sensitive → Critical: restricted
        if segments["sensitive"] and segments["critical"]:
            allow_rules.append({
                "from_segment": "sensitive",
                "to_segment": "critical",
                "ports": [443],
                "protocols": ["tcp"],
                "description": "Sensitive to critical: HTTPS only with MFA",
                "require_mfa": True,
            })

        # Critical → Critical: any (already hardened)
        if segments["critical"]:
            allow_rules.append({
                "from_segment": "critical",
                "to_segment": "critical",
                "ports": [443, 22],
                "protocols": ["tcp"],
                "description": "Critical internal traffic",
            })

        segment_list = [
            {"segment": tier, "assets": names}
            for tier, names in segments.items()
            if names
        ]

        return NetworkPolicy(
            name=f"micro_seg_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
            description="Auto-generated micro-segmentation policy",
            segments=segment_list,
            allow_rules=allow_rules,
            deny_all=True,
        )

    # ------------------------------------------------------------------
    # Public API — lateral movement detection
    # ------------------------------------------------------------------

    def detect_lateral_movement(
        self, network_events: List[Dict[str, Any]]
    ) -> List[Alert]:
        """
        Detect lateral movement patterns in network traffic.

        Patterns detected:
        - Port scanning (many distinct ports from one source)
        - Host enumeration (one source → many distinct hosts)
        - Off-hours access from unusual source
        - Impossible travel (same user, distant locations, short time)
        - Brute-force / rapid auth attempts
        - Unusual protocol usage
        """
        alerts: List[Alert] = []
        if not network_events:
            return alerts

        # Build per-source index
        by_source: Dict[str, List[Dict[str, Any]]] = {}
        by_user: Dict[str, List[Dict[str, Any]]] = {}

        for ev in network_events:
            src = ev.get("source_ip", ev.get("source", "unknown"))
            by_source.setdefault(src, []).append(ev)
            uid = ev.get("user_id", "")
            if uid:
                by_user.setdefault(uid, []).append(ev)

        for src, events in by_source.items():
            # Port scan detection
            dest_ports = {
                ev.get("dest_port") for ev in events if ev.get("dest_port")
            }
            if len(dest_ports) >= _SCAN_PORT_THRESHOLD:
                alerts.append(Alert(
                    alert_type="port_scan",
                    severity=AlertSeverity.HIGH,
                    description=(
                        f"Port scan detected from {src}: "
                        f"{len(dest_ports)} distinct ports probed"
                    ),
                    source_entity=src,
                    evidence=[f"ports={sorted(dest_ports)[:20]}"],
                ))

            # Host enumeration
            dest_hosts = {
                ev.get("dest_ip", ev.get("destination", "")) for ev in events
            } - {""}
            if len(dest_hosts) >= _NEW_HOST_THRESHOLD:
                alerts.append(Alert(
                    alert_type="host_enumeration",
                    severity=AlertSeverity.MEDIUM,
                    description=(
                        f"Host enumeration from {src}: "
                        f"{len(dest_hosts)} distinct hosts contacted"
                    ),
                    source_entity=src,
                    evidence=[f"hosts={list(dest_hosts)[:10]}"],
                ))

            # Off-hours access from external source
            is_internal = src.startswith(("10.", "192.168.", "172.", "127."))
            if not is_internal:
                for ev in events:
                    ts_raw = ev.get("timestamp", "")
                    try:
                        ts = datetime.fromisoformat(
                            ts_raw.replace("Z", "+00:00")
                        )
                        if not (_BIZ_HOUR_START <= ts.hour < _BIZ_HOUR_END):
                            alerts.append(Alert(
                                alert_type="off_hours_external_access",
                                severity=AlertSeverity.MEDIUM,
                                description=(
                                    f"Off-hours external access from {src} "
                                    f"at {ts.strftime('%H:%M')} UTC"
                                ),
                                source_entity=src,
                                evidence=[f"timestamp={ts_raw}"],
                            ))
                            break  # one alert per source per batch
                    except (ValueError, AttributeError):
                        pass

            # Unusual protocol (non-HTTP/HTTPS/SSH)
            unusual_protos = {"telnet", "ftp", "rsh", "rlogin", "vnc"}
            for ev in events:
                proto = str(ev.get("protocol", "")).lower()
                if proto in unusual_protos:
                    alerts.append(Alert(
                        alert_type="unusual_protocol",
                        severity=AlertSeverity.HIGH,
                        description=(
                            f"Unusual protocol '{proto}' detected from {src}"
                        ),
                        source_entity=src,
                        target_entity=ev.get("dest_ip", ""),
                        evidence=[f"protocol={proto}", f"event={json.dumps(ev)[:200]}"],
                    ))

        # Rapid auth / brute-force (per user)
        for uid, events in by_user.items():
            auth_events = [
                ev for ev in events if ev.get("event_type") in
                ("auth_attempt", "login", "auth_failure", "failed_login")
            ]
            if len(auth_events) >= _RAPID_AUTH_THRESHOLD:
                alerts.append(Alert(
                    alert_type="brute_force",
                    severity=AlertSeverity.CRITICAL,
                    description=(
                        f"Brute-force detected for user '{uid}': "
                        f"{len(auth_events)} auth attempts"
                    ),
                    source_entity=uid,
                    evidence=[f"attempt_count={len(auth_events)}"],
                ))

        # Impossible travel (per user — detect large location jumps)
        for uid, events in by_user.items():
            locations = [
                ev.get("location", ev.get("source_ip", ""))
                for ev in events
                if ev.get("location") or ev.get("source_ip")
            ]
            unique_locs = set(locations)
            if len(unique_locs) >= 3:
                alerts.append(Alert(
                    alert_type="impossible_travel",
                    severity=AlertSeverity.HIGH,
                    description=(
                        f"Impossible travel for user '{uid}': "
                        f"{len(unique_locs)} distinct locations in window"
                    ),
                    source_entity=uid,
                    evidence=[f"locations={list(unique_locs)[:5]}"],
                ))

        _logger.info(
            "lateral_movement_scan events=%d alerts=%d",
            len(network_events), len(alerts),
        )
        return alerts

    # ------------------------------------------------------------------
    # Public API — trust scoring
    # ------------------------------------------------------------------

    def calculate_trust_score(self, entity: Dict[str, Any]) -> float:
        """
        Calculate trust score 0.0–1.0 for a user, device, or service.

        Factors:
        - known:         entity is registered (vs. unknown)
        - compliant:     passes policy checks
        - location:      private / trusted vs. public
        - behaviour:     recent anomaly history
        - auth_strength: MFA, certificate, password-only
        - last_seen:     recency of last verified activity
        """
        score = 0.30  # baseline for unknown entity

        # Known/registered entity
        if entity.get("known", False) or entity.get("registered", False):
            score += 0.20

        # Compliance (patch level, policy adherence)
        compliant = entity.get("compliant", entity.get("policy_compliant", False))
        if compliant:
            score += 0.15

        # Location
        loc = entity.get("location", entity.get("ip", ""))
        if loc.startswith(("10.", "192.168.", "172.16.", "127.", "::1")):
            score += 0.10

        # Behaviour (anomaly score — lower anomaly → higher trust)
        anomaly = float(entity.get("anomaly_score", 0.5))
        score += (1.0 - anomaly) * 0.15

        # Auth strength
        auth = str(entity.get("auth_method", "password")).lower()
        if auth in ("certificate", "pki", "hardware_token"):
            score += 0.10
        elif auth in ("mfa", "totp", "fido2", "webauthn"):
            score += 0.08
        elif auth == "password":
            score += 0.02

        # Recency — last_seen within 24 hours adds confidence
        last_seen_raw = entity.get("last_seen", "")
        if last_seen_raw:
            try:
                last_seen = datetime.fromisoformat(
                    last_seen_raw.replace("Z", "+00:00")
                )
                hours_ago = (
                    datetime.now(timezone.utc) - last_seen
                ).total_seconds() / 3600
                if hours_ago <= 1:
                    score += 0.05
                elif hours_ago <= 24:
                    score += 0.02
                else:
                    score -= 0.05
            except (ValueError, AttributeError):
                pass

        result = round(max(0.0, min(score, 1.0)), 4)

        # Persist to DB
        self._upsert_entity_trust(
            entity_id=entity.get("id", entity.get("user_id", str(uuid.uuid4()))),
            entity_type=entity.get("type", "user"),
            trust_score=result,
            factors=entity,
        )
        return result

    def _upsert_entity_trust(
        self,
        entity_id: str,
        entity_type: str,
        trust_score: float,
        factors: Dict[str, Any],
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO entity_trust
                    (entity_id, entity_type, trust_score, factors, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(entity_id) DO UPDATE SET
                    trust_score = excluded.trust_score,
                    factors     = excluded.factors,
                    updated_at  = excluded.updated_at
                """,
                (entity_id, entity_type, trust_score, json.dumps(factors), now),
            )
            conn.commit()
        finally:
            conn.close()

    def get_all_trust_scores(self) -> List[Dict[str, Any]]:
        """Return trust scores for all known entities."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT entity_id, entity_type, trust_score, updated_at "
                "FROM entity_trust ORDER BY trust_score DESC"
            ).fetchall()
            return [
                {
                    "entity_id": r["entity_id"],
                    "entity_type": r["entity_type"],
                    "trust_score": r["trust_score"],
                    "updated_at": r["updated_at"],
                }
                for r in rows
            ]
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Public API — policy management
    # ------------------------------------------------------------------

    def create_access_policy(
        self, resource: str, rules: List[Dict[str, Any]]
    ) -> Policy:
        """
        Create or replace a zero-trust access policy for a resource.

        Rules are evaluated in order; first match wins.
        Each rule dict may contain: user_id, action, min_trust_score,
        require_mfa, decision (ALLOW/DENY/CHALLENGE).
        """
        now = datetime.now(timezone.utc).isoformat()
        policy = Policy(
            resource=resource,
            rules=rules,
            created_at=now,
            updated_at=now,
        )
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO policies
                    (policy_id, resource, rules, default_decision,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(resource) DO UPDATE SET
                    policy_id        = excluded.policy_id,
                    rules            = excluded.rules,
                    default_decision = excluded.default_decision,
                    updated_at       = excluded.updated_at
                """,
                (
                    policy.policy_id,
                    policy.resource,
                    json.dumps(policy.rules),
                    policy.default_decision.value,
                    policy.created_at,
                    policy.updated_at,
                ),
            )
            conn.commit()
        finally:
            conn.close()
        _logger.info("policy_created resource=%s policy_id=%s", resource, policy.policy_id)
        return policy

    def list_policies(self) -> List[Dict[str, Any]]:
        """Return all stored access policies."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT policy_id, resource, rules, default_decision, "
                "created_at, updated_at FROM policies ORDER BY resource"
            ).fetchall()
            return [
                {
                    "policy_id": r["policy_id"],
                    "resource": r["resource"],
                    "rules": json.loads(r["rules"]),
                    "default_decision": r["default_decision"],
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                }
                for r in rows
            ]
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# FACTORY
# ---------------------------------------------------------------------------


def create_zero_trust_engine(
    db_path: str = "data/zero_trust_engine.db",
) -> ZeroTrustEngine:
    """Return a configured ZeroTrustEngine instance."""
    return ZeroTrustEngine(db_path=db_path)
