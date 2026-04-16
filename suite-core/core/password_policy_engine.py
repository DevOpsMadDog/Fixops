"""Password Policy Analyzer Engine — ALDECI.

Manage password policies, evaluate compliance, track violations, audits,
and MFA enrollment.

Compliance: NIST SP 800-63B, CIS Controls v8 5.2, PCI DSS 4.0 req 8.3
"""

from __future__ import annotations

import json
import logging
import math
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "password_policy.db"
)

_VALID_VIOLATION_TYPES = {
    "weak_password", "expired_password", "shared_password",
    "dictionary_word", "reused_password", "no_mfa", "lockout_exceeded",
    # legacy/flexible types kept for backward compat
    "short", "expired", "reused", "unknown",
}
_VALID_MFA_TYPES = {"totp", "sms", "hardware_key", "push", "email_otp"}


class PasswordPolicyEngine:
    """SQLite WAL-backed password policy management and compliance engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS password_policies (
                    policy_id               TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    name                    TEXT NOT NULL,
                    policy_name             TEXT NOT NULL DEFAULT '',
                    min_length              INTEGER NOT NULL DEFAULT 8,
                    require_uppercase       INTEGER NOT NULL DEFAULT 0,
                    require_lowercase       INTEGER NOT NULL DEFAULT 0,
                    require_numbers         INTEGER NOT NULL DEFAULT 0,
                    require_symbols         INTEGER NOT NULL DEFAULT 0,
                    require_digits          INTEGER NOT NULL DEFAULT 0,
                    require_special         INTEGER NOT NULL DEFAULT 0,
                    max_age_days            INTEGER NOT NULL DEFAULT 90,
                    min_age_days            INTEGER NOT NULL DEFAULT 1,
                    min_history             INTEGER NOT NULL DEFAULT 5,
                    history_count           INTEGER NOT NULL DEFAULT 10,
                    lockout_attempts        INTEGER NOT NULL DEFAULT 5,
                    lockout_duration_minutes INTEGER NOT NULL DEFAULT 30,
                    complexity_score        INTEGER NOT NULL DEFAULT 0,
                    complexity_score_min    INTEGER NOT NULL DEFAULT 60,
                    is_active               INTEGER NOT NULL DEFAULT 0,
                    applies_to              TEXT NOT NULL DEFAULT '[]',
                    created_at              DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pp_org
                    ON password_policies (org_id);

                CREATE INDEX IF NOT EXISTS idx_pp_org_active
                    ON password_policies (org_id, is_active);

                CREATE TABLE IF NOT EXISTS policy_violations (
                    violation_id    TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    policy_id       TEXT NOT NULL,
                    user_id         TEXT NOT NULL,
                    user_email      TEXT NOT NULL DEFAULT '',
                    violation_type  TEXT NOT NULL,
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    status          TEXT NOT NULL DEFAULT 'open',
                    detected_at     DATETIME,
                    remediated_at   DATETIME,
                    created_at      DATETIME NOT NULL,
                    updated_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pv_org
                    ON policy_violations (org_id, status);

                CREATE INDEX IF NOT EXISTS idx_pv_org_user
                    ON policy_violations (org_id, user_id);

                CREATE TABLE IF NOT EXISTS password_audits (
                    audit_id                TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    policy_id               TEXT NOT NULL,
                    users_audited           INTEGER NOT NULL DEFAULT 0,
                    total_users_checked     INTEGER NOT NULL DEFAULT 0,
                    violations_found        INTEGER NOT NULL DEFAULT 0,
                    compliant               INTEGER NOT NULL DEFAULT 0,
                    non_compliant           INTEGER NOT NULL DEFAULT 0,
                    weak_count              INTEGER NOT NULL DEFAULT 0,
                    expired_count           INTEGER NOT NULL DEFAULT 0,
                    no_mfa_count            INTEGER NOT NULL DEFAULT 0,
                    compliance_rate         REAL NOT NULL DEFAULT 0.0,
                    audit_date              DATE NOT NULL DEFAULT '',
                    created_at              DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pa_org
                    ON password_audits (org_id);

                CREATE TABLE IF NOT EXISTS mfa_enrollment (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    user_id       TEXT NOT NULL,
                    user_email    TEXT NOT NULL DEFAULT '',
                    mfa_type      TEXT NOT NULL DEFAULT 'totp',
                    enrolled      INTEGER NOT NULL DEFAULT 0,
                    enrolled_date DATETIME,
                    last_used     DATETIME,
                    created_at    DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_mfa_org_user
                    ON mfa_enrollment (org_id, user_id);

                CREATE INDEX IF NOT EXISTS idx_mfa_org_enrolled
                    ON mfa_enrollment (org_id, enrolled);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_complexity_score(data: Dict[str, Any]) -> int:
        """Compute a 0-100 complexity score based on policy rules."""
        score = 0

        min_length = int(data.get("min_length", 8))
        # Length scoring: 8=20pts, 12=40pts, 16+=60pts
        if min_length >= 16:
            score += 60
        elif min_length >= 12:
            score += 40
        elif min_length >= 8:
            score += 20
        else:
            score += 5

        # Character class requirements (10 pts each)
        if data.get("require_uppercase"):
            score += 10
        if data.get("require_lowercase"):
            score += 10
        if data.get("require_numbers") or data.get("require_digits"):
            score += 10
        if data.get("require_symbols") or data.get("require_special"):
            score += 10

        # Bonus for short max_age_days (rotate more often = higher score)
        max_age = int(data.get("max_age_days", 90))
        if max_age <= 30:
            score += 5
        elif max_age <= 60:
            score += 3

        # History prevents reuse
        history = max(int(data.get("min_history", 5)), int(data.get("history_count", 5)))
        if history >= 10:
            score += 5

        return min(score, 100)

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        # Coerce booleans
        for field in ("require_uppercase", "require_lowercase", "require_numbers",
                      "require_symbols", "require_digits", "require_special", "is_active"):
            if field in d:
                d[field] = bool(d[field])
        # Deserialise JSON fields
        for field in ("applies_to",):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    d[field] = []
        return d

    # ------------------------------------------------------------------
    # Password strength (static — no DB needed)
    # ------------------------------------------------------------------

    @staticmethod
    def check_password_strength(password: str) -> Dict[str, Any]:
        """Score a password 0-100 based on length, char classes, and entropy.

        Returns dict with score (int 0-100), grade (A-F), and breakdown.
        """
        score = 0
        breakdown: Dict[str, Any] = {}

        length = len(password)
        # Length contribution (max 30 pts)
        if length >= 20:
            length_pts = 30
        elif length >= 16:
            length_pts = 25
        elif length >= 12:
            length_pts = 20
        elif length >= 8:
            length_pts = 10
        else:
            length_pts = 0
        breakdown["length"] = {"chars": length, "points": length_pts}
        score += length_pts

        # Character class contribution (max 40 pts, 10 each)
        has_lower = bool(re.search(r"[a-z]", password))
        has_upper = bool(re.search(r"[A-Z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_special = bool(re.search(r"[^a-zA-Z0-9]", password))
        char_pts = (10 if has_lower else 0) + (10 if has_upper else 0) + \
                   (10 if has_digit else 0) + (10 if has_special else 0)
        breakdown["char_classes"] = {
            "lower": has_lower, "upper": has_upper,
            "digit": has_digit, "special": has_special,
            "points": char_pts,
        }
        score += char_pts

        # Entropy contribution (max 30 pts)
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 32
        if charset_size > 0 and length > 0:
            entropy = length * math.log2(charset_size)
        else:
            entropy = 0.0
        if entropy >= 80:
            entropy_pts = 30
        elif entropy >= 60:
            entropy_pts = 22
        elif entropy >= 40:
            entropy_pts = 14
        elif entropy >= 20:
            entropy_pts = 7
        else:
            entropy_pts = 0
        breakdown["entropy"] = {"bits": round(entropy, 2), "points": entropy_pts}
        score += entropy_pts

        score = min(100, max(0, score))

        if score >= 90:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 40:
            grade = "D"
        else:
            grade = "F"

        return {"score": score, "grade": grade, "breakdown": breakdown}

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new password policy. Returns the created policy dict."""
        policy_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        complexity_score = self._compute_complexity_score(data)
        # Support both old field names and new spec field names
        policy_name = data.get("policy_name") or data.get("name", "Default Policy")

        row = {
            "policy_id": policy_id,
            "org_id": org_id,
            "name": policy_name,
            "policy_name": policy_name,
            "min_length": int(data.get("min_length", 8)),
            "require_uppercase": 1 if data.get("require_uppercase") else 0,
            "require_lowercase": 1 if data.get("require_lowercase") else 0,
            "require_numbers": 1 if data.get("require_numbers") else 0,
            "require_symbols": 1 if data.get("require_symbols") else 0,
            "require_digits": 1 if data.get("require_digits") else 0,
            "require_special": 1 if data.get("require_special") else 0,
            "max_age_days": int(data.get("max_age_days", 90)),
            "min_age_days": int(data.get("min_age_days", 1)),
            "min_history": int(data.get("min_history", 5)),
            "history_count": int(data.get("history_count", 10)),
            "lockout_attempts": int(data.get("lockout_attempts", 5)),
            "lockout_duration_minutes": int(data.get("lockout_duration_minutes", 30)),
            "complexity_score": complexity_score,
            "complexity_score_min": int(data.get("complexity_score_min", 60)),
            "is_active": 1 if data.get("is_active", False) else 0,
            "applies_to": json.dumps(data.get("applies_to", [])),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO password_policies
                        (policy_id, org_id, name, policy_name, min_length, require_uppercase,
                         require_lowercase, require_numbers, require_symbols,
                         require_digits, require_special,
                         max_age_days, min_age_days, min_history, history_count,
                         lockout_attempts, lockout_duration_minutes,
                         complexity_score, complexity_score_min, is_active, applies_to, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        row["policy_id"], row["org_id"], row["name"], row["policy_name"],
                        row["min_length"], row["require_uppercase"],
                        row["require_lowercase"], row["require_numbers"],
                        row["require_symbols"], row["require_digits"], row["require_special"],
                        row["max_age_days"], row["min_age_days"],
                        row["min_history"], row["history_count"],
                        row["lockout_attempts"], row["lockout_duration_minutes"],
                        row["complexity_score"], row["complexity_score_min"],
                        row["is_active"], row["applies_to"], row["created_at"],
                    ),
                )

        # Return with bool coercion
        row["require_uppercase"] = bool(row["require_uppercase"])
        row["require_lowercase"] = bool(row["require_lowercase"])
        row["require_numbers"] = bool(row["require_numbers"])
        row["require_symbols"] = bool(row["require_symbols"])
        row["require_digits"] = bool(row["require_digits"])
        row["require_special"] = bool(row["require_special"])
        row["is_active"] = bool(row["is_active"])
        row["applies_to"] = json.loads(row["applies_to"])
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "password_policy", "org_id": org_id, "source_engine": "password_policy"})
            except Exception:
                pass

        return row

    def list_policies(self, org_id: str, is_active: Optional[bool] = None) -> List[Dict[str, Any]]:
        """Return password policies for the given org, optionally filtered by is_active."""
        sql = "SELECT * FROM password_policies WHERE org_id=?"
        params: list = [org_id]
        if is_active is not None:
            sql += " AND is_active=?"
            params.append(1 if is_active else 0)
        sql += " ORDER BY created_at ASC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def activate_policy(self, org_id: str, policy_id: str) -> bool:
        """Activate a policy; deactivates all other org policies. Returns True if found."""
        with self._lock:
            with self._conn() as conn:
                # Deactivate all
                conn.execute(
                    "UPDATE password_policies SET is_active=0 WHERE org_id=?",
                    (org_id,),
                )
                # Activate target
                cur = conn.execute(
                    "UPDATE password_policies SET is_active=1 WHERE org_id=? AND policy_id=?",
                    (org_id, policy_id),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Password Evaluation
    # ------------------------------------------------------------------

    def evaluate_password(
        self, org_id: str, policy_id: str, password_hash_hint: str
    ) -> Dict[str, Any]:
        """Evaluate a password hint against a policy.

        password_hash_hint is an entropy descriptor such as:
          "length:12,upper:1,lower:1,digits:1,symbols:0,entropy:45"
        or a simple length hint like "length:8".
        Returns meets_policy, issues list, and strength_score (0-100).
        """
        # Fetch the policy
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM password_policies WHERE policy_id=? AND org_id=?",
                (policy_id, org_id),
            ).fetchone()

        if not row:
            return {"meets_policy": False, "issues": ["Policy not found"], "strength_score": 0}

        policy = self._row_to_dict(row)

        # Parse hint
        hints: Dict[str, Any] = {}
        for part in password_hash_hint.split(","):
            if ":" in part:
                k, _, v = part.partition(":")
                hints[k.strip()] = v.strip()

        length = int(hints.get("length", 0))
        has_upper = hints.get("upper", "0") not in ("0", "false", "False", "")
        has_lower = hints.get("lower", "0") not in ("0", "false", "False", "")
        has_digits = hints.get("digits", "0") not in ("0", "false", "False", "")
        has_symbols = hints.get("symbols", "0") not in ("0", "false", "False", "")
        entropy = float(hints.get("entropy", 0))

        issues: List[str] = []

        if length < policy["min_length"]:
            issues.append(f"Password too short (min {policy['min_length']} chars, hint says {length})")

        if policy["require_uppercase"] and not has_upper:
            issues.append("Uppercase letter required")

        if policy["require_lowercase"] and not has_lower:
            issues.append("Lowercase letter required")

        if policy["require_numbers"] and not has_digits:
            issues.append("Numeric digit required")

        if policy["require_symbols"] and not has_symbols:
            issues.append("Symbol character required")

        # Compute strength score (0-100) based on entropy and char classes
        char_class_count = sum([has_upper, has_lower, has_digits, has_symbols])
        if entropy > 0:
            # entropy in bits → scale: 0 bits=0, 60+ bits=100
            entropy_score = min(int(entropy / 60 * 70), 70)
        else:
            # Estimate from length and char classes
            pool = 0
            if has_upper: pool += 26
            if has_lower: pool += 26
            if has_digits: pool += 10
            if has_symbols: pool += 32
            if pool == 0: pool = 26
            estimated_entropy = length * math.log2(pool) if length > 0 else 0
            entropy_score = min(int(estimated_entropy / 60 * 70), 70)

        class_bonus = char_class_count * 7  # max 28 pts
        length_bonus = min(int(length / 20 * 20), 20)  # up to 20 pts (at 20+ chars)
        # Ensure class_bonus + length_bonus capped at 30 (since entropy_score max 70)
        strength_score = min(entropy_score + class_bonus + length_bonus, 100)

        return {
            "meets_policy": len(issues) == 0,
            "issues": issues,
            "strength_score": max(0, strength_score),
        }

    # ------------------------------------------------------------------
    # Audits
    # ------------------------------------------------------------------

    def record_audit(
        self,
        org_id: str,
        policy_id: str,
        users_audited: int,
        violations_found: int,
        compliance_rate: float,
    ) -> Dict[str, Any]:
        """Record an audit run (positional-arg form). Returns the created audit record."""
        return self.run_audit(org_id, policy_id, {
            "total_users_checked": users_audited,
            "users_audited": users_audited,
            "compliant": max(0, users_audited - violations_found),
            "non_compliant": violations_found,
            "violations_found": violations_found,
            "compliance_rate": compliance_rate,
        })

    def run_audit(self, org_id: str, policy_id: str, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a rich audit record with full compliance metrics. Returns the created record."""
        audit_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        users_audited = int(audit_data.get("users_audited", audit_data.get("total_users_checked", 0)))
        total_users_checked = int(audit_data.get("total_users_checked", users_audited))
        violations_found = int(audit_data.get("violations_found", 0))
        compliant = int(audit_data.get("compliant", max(0, users_audited - violations_found)))
        non_compliant = int(audit_data.get("non_compliant", violations_found))
        weak_count = int(audit_data.get("weak_count", 0))
        expired_count = int(audit_data.get("expired_count", 0))
        no_mfa_count = int(audit_data.get("no_mfa_count", 0))
        # Derive compliance_rate if not supplied
        if "compliance_rate" in audit_data:
            compliance_rate = float(audit_data["compliance_rate"])
        elif total_users_checked > 0:
            compliance_rate = round(compliant / total_users_checked * 100.0, 2)
        else:
            compliance_rate = 0.0

        audit_date = audit_data.get("audit_date", now[:10])

        record = {
            "audit_id": audit_id,
            "org_id": org_id,
            "policy_id": policy_id,
            "users_audited": users_audited,
            "total_users_checked": total_users_checked,
            "violations_found": violations_found,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "weak_count": weak_count,
            "expired_count": expired_count,
            "no_mfa_count": no_mfa_count,
            "compliance_rate": compliance_rate,
            "audit_date": audit_date,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO password_audits
                        (audit_id, org_id, policy_id, users_audited, total_users_checked,
                         violations_found, compliant, non_compliant, weak_count,
                         expired_count, no_mfa_count, compliance_rate, audit_date, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["audit_id"], record["org_id"], record["policy_id"],
                        record["users_audited"], record["total_users_checked"],
                        record["violations_found"], record["compliant"], record["non_compliant"],
                        record["weak_count"], record["expired_count"], record["no_mfa_count"],
                        record["compliance_rate"], record["audit_date"], record["created_at"],
                    ),
                )

        return record

    def list_audits(self, org_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Return audit records for the given org, most recent first."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM password_audits WHERE org_id=? ORDER BY created_at DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # MFA Enrollment
    # ------------------------------------------------------------------

    def register_mfa(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register or record MFA enrollment for a user."""
        user_id = (data.get("user_id") or "").strip()
        if not user_id:
            raise ValueError("user_id is required.")
        mfa_type = data.get("mfa_type", "totp")
        if mfa_type not in _VALID_MFA_TYPES:
            raise ValueError(f"Invalid mfa_type: {mfa_type}. Must be one of {_VALID_MFA_TYPES}")

        now = datetime.now(timezone.utc).isoformat()
        enrolled = data.get("enrolled", True)
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "user_id": user_id,
            "user_email": data.get("user_email", ""),
            "mfa_type": mfa_type,
            "enrolled": 1 if enrolled else 0,
            "enrolled_date": data.get("enrolled_date", now if enrolled else None),
            "last_used": data.get("last_used"),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO mfa_enrollment
                       (id, org_id, user_id, user_email, mfa_type, enrolled,
                        enrolled_date, last_used, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        record["id"], record["org_id"], record["user_id"],
                        record["user_email"], record["mfa_type"], record["enrolled"],
                        record["enrolled_date"], record["last_used"], record["created_at"],
                    ),
                )
        result = dict(record)
        result["enrolled"] = bool(record["enrolled"])
        return result

    def list_mfa_enrollments(
        self, org_id: str, enrolled: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """List MFA enrollments, optionally filtered by enrolled status."""
        sql = "SELECT * FROM mfa_enrollment WHERE org_id=?"
        params: list = [org_id]
        if enrolled is not None:
            sql += " AND enrolled=?"
            params.append(1 if enrolled else 0)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["enrolled"] = bool(d["enrolled"])
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # Violations
    # ------------------------------------------------------------------

    def create_violation(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a policy violation. Returns the created violation dict."""
        violation_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        row = {
            "violation_id": violation_id,
            "org_id": org_id,
            "policy_id": data.get("policy_id", ""),
            "user_id": data.get("user_id", ""),
            "user_email": data.get("user_email", ""),
            "violation_type": data.get("violation_type", "unknown"),
            "severity": data.get("severity", "medium"),
            "status": data.get("status", "open"),
            "detected_at": data.get("detected_at", now),
            "remediated_at": None,
            "created_at": now,
            "updated_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO policy_violations
                        (violation_id, org_id, policy_id, user_id, user_email,
                         violation_type, severity, status, detected_at, remediated_at,
                         created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        row["violation_id"], row["org_id"], row["policy_id"],
                        row["user_id"], row["user_email"], row["violation_type"],
                        row["severity"], row["status"], row["detected_at"],
                        row["remediated_at"], row["created_at"], row["updated_at"],
                    ),
                )

        return row

    # Spec-aligned alias
    def report_violation(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Alias for create_violation — spec-aligned name."""
        return self.create_violation(org_id, data)

    def list_violations(
        self,
        org_id: str,
        status: Optional[str] = None,
        violation_type: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return violations for an org. Optionally filter by status, violation_type, user_id."""
        sql = "SELECT * FROM policy_violations WHERE org_id=?"
        params: list = [org_id]
        if status:
            sql += " AND status=?"
            params.append(status)
        if violation_type:
            sql += " AND violation_type=?"
            params.append(violation_type)
        if user_id:
            sql += " AND user_id=?"
            params.append(user_id)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def remediate_violation(self, org_id: str, violation_id: str) -> bool:
        """Mark a violation as remediated. Returns True if updated."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """
                    UPDATE policy_violations
                    SET status='remediated', remediated_at=?, updated_at=?
                    WHERE violation_id=? AND org_id=?
                    """,
                    (now, now, violation_id, org_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_policy_stats(self, org_id: str) -> Dict[str, Any]:
        """Return summary statistics for the org's password policy posture."""
        with self._conn() as conn:
            total_policies = conn.execute(
                "SELECT COUNT(*) FROM password_policies WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            total_violations = conn.execute(
                "SELECT COUNT(*) FROM policy_violations WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            open_violations = conn.execute(
                "SELECT COUNT(*) FROM policy_violations WHERE org_id=? AND status='open'",
                (org_id,),
            ).fetchone()[0]

            avg_complexity = conn.execute(
                "SELECT AVG(complexity_score) FROM password_policies WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]

            # Active policy
            active_row = conn.execute(
                "SELECT * FROM password_policies WHERE org_id=? AND is_active=1 LIMIT 1",
                (org_id,),
            ).fetchone()
            active_policy = self._row_to_dict(active_row) if active_row else None

            # Compliance rate from latest audit
            latest_audit = conn.execute(
                """
                SELECT AVG(compliance_rate) FROM password_audits
                WHERE org_id=? AND audit_id IN (
                    SELECT audit_id FROM password_audits
                    WHERE org_id=? GROUP BY policy_id
                    HAVING created_at = MAX(created_at)
                )
                """,
                (org_id, org_id),
            ).fetchone()[0]

            # Violations by type
            by_type_rows = conn.execute(
                """SELECT violation_type, COUNT(*) as cnt
                   FROM policy_violations WHERE org_id=?
                   GROUP BY violation_type""",
                (org_id,),
            ).fetchall()
            by_type = {r["violation_type"]: r["cnt"] for r in by_type_rows}

            # MFA stats
            total_mfa_users = conn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM mfa_enrollment WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]
            enrolled_mfa = conn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM mfa_enrollment WHERE org_id=? AND enrolled=1",
                (org_id,),
            ).fetchone()[0]
            not_enrolled_mfa = conn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM mfa_enrollment WHERE org_id=? AND enrolled=0",
                (org_id,),
            ).fetchone()[0]
            mfa_enrollment_rate = (enrolled_mfa / total_mfa_users * 100.0) if total_mfa_users > 0 else 0.0

        compliance_rate = round(latest_audit or 0.0, 2)
        avg_complexity_score = round(avg_complexity or 0.0, 1)

        return {
            "total_policies": total_policies,
            "active_policy": active_policy,
            "total_violations": total_violations,
            "open_violations": open_violations,
            "by_type": by_type,
            "compliance_rate": compliance_rate,
            "compliance_rate_latest": compliance_rate,
            "avg_complexity_score": avg_complexity_score,
            "mfa_enrollment_rate": round(mfa_enrollment_rate, 2),
            "users_without_mfa": not_enrolled_mfa,
        }
