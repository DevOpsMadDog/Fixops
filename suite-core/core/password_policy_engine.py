"""Password Policy Analyzer Engine — ALDECI.

Manage password policies, evaluate compliance, track violations and audits.

Compliance: NIST SP 800-63B, CIS Controls v8 5.2, PCI DSS 4.0 req 8.3
"""

from __future__ import annotations

import json
import logging
import math
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "password_policy.db"
)


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
                    policy_id         TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    name              TEXT NOT NULL,
                    min_length        INTEGER NOT NULL DEFAULT 8,
                    require_uppercase INTEGER NOT NULL DEFAULT 0,
                    require_lowercase INTEGER NOT NULL DEFAULT 0,
                    require_numbers   INTEGER NOT NULL DEFAULT 0,
                    require_symbols   INTEGER NOT NULL DEFAULT 0,
                    max_age_days      INTEGER NOT NULL DEFAULT 90,
                    min_history       INTEGER NOT NULL DEFAULT 5,
                    lockout_attempts  INTEGER NOT NULL DEFAULT 5,
                    complexity_score  INTEGER NOT NULL DEFAULT 0,
                    created_at        DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pp_org
                    ON password_policies (org_id);

                CREATE TABLE IF NOT EXISTS policy_violations (
                    violation_id    TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    policy_id       TEXT NOT NULL,
                    user_id         TEXT NOT NULL,
                    violation_type  TEXT NOT NULL,
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    status          TEXT NOT NULL DEFAULT 'open',
                    created_at      DATETIME NOT NULL,
                    updated_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pv_org
                    ON policy_violations (org_id, status);

                CREATE TABLE IF NOT EXISTS password_audits (
                    audit_id         TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    policy_id        TEXT NOT NULL,
                    users_audited    INTEGER NOT NULL DEFAULT 0,
                    violations_found INTEGER NOT NULL DEFAULT 0,
                    compliance_rate  REAL NOT NULL DEFAULT 0.0,
                    created_at       DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pa_org
                    ON password_audits (org_id);
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
        if data.get("require_numbers"):
            score += 10
        if data.get("require_symbols"):
            score += 10

        # Bonus for short max_age_days (rotate more often = higher score)
        max_age = int(data.get("max_age_days", 90))
        if max_age <= 30:
            score += 5
        elif max_age <= 60:
            score += 3

        # History prevents reuse
        if int(data.get("min_history", 5)) >= 10:
            score += 5

        return min(score, 100)

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        # Coerce booleans
        for field in ("require_uppercase", "require_lowercase", "require_numbers", "require_symbols"):
            if field in d:
                d[field] = bool(d[field])
        return d

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new password policy. Returns the created policy dict."""
        policy_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        complexity_score = self._compute_complexity_score(data)

        row = {
            "policy_id": policy_id,
            "org_id": org_id,
            "name": data.get("name", "Default Policy"),
            "min_length": int(data.get("min_length", 8)),
            "require_uppercase": 1 if data.get("require_uppercase") else 0,
            "require_lowercase": 1 if data.get("require_lowercase") else 0,
            "require_numbers": 1 if data.get("require_numbers") else 0,
            "require_symbols": 1 if data.get("require_symbols") else 0,
            "max_age_days": int(data.get("max_age_days", 90)),
            "min_history": int(data.get("min_history", 5)),
            "lockout_attempts": int(data.get("lockout_attempts", 5)),
            "complexity_score": complexity_score,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO password_policies
                        (policy_id, org_id, name, min_length, require_uppercase,
                         require_lowercase, require_numbers, require_symbols,
                         max_age_days, min_history, lockout_attempts,
                         complexity_score, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        row["policy_id"], row["org_id"], row["name"],
                        row["min_length"], row["require_uppercase"],
                        row["require_lowercase"], row["require_numbers"],
                        row["require_symbols"], row["max_age_days"],
                        row["min_history"], row["lockout_attempts"],
                        row["complexity_score"], row["created_at"],
                    ),
                )

        # Return with bool coercion
        row["require_uppercase"] = bool(row["require_uppercase"])
        row["require_lowercase"] = bool(row["require_lowercase"])
        row["require_numbers"] = bool(row["require_numbers"])
        row["require_symbols"] = bool(row["require_symbols"])
        return row

    def list_policies(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all password policies for the given org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM password_policies WHERE org_id=? ORDER BY created_at ASC",
                (org_id,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

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
        """Record an audit run. Returns the created audit record."""
        audit_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO password_audits
                        (audit_id, org_id, policy_id, users_audited,
                         violations_found, compliance_rate, created_at)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (audit_id, org_id, policy_id, users_audited,
                     violations_found, compliance_rate, now),
                )

        return {
            "audit_id": audit_id,
            "org_id": org_id,
            "policy_id": policy_id,
            "users_audited": users_audited,
            "violations_found": violations_found,
            "compliance_rate": compliance_rate,
            "created_at": now,
        }

    def list_audits(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all audit records for the given org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM password_audits WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

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
            "violation_type": data.get("violation_type", "unknown"),
            "severity": data.get("severity", "medium"),
            "status": data.get("status", "open"),
            "created_at": now,
            "updated_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO policy_violations
                        (violation_id, org_id, policy_id, user_id,
                         violation_type, severity, status, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        row["violation_id"], row["org_id"], row["policy_id"],
                        row["user_id"], row["violation_type"], row["severity"],
                        row["status"], row["created_at"], row["updated_at"],
                    ),
                )

        return row

    def list_violations(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return violations for an org. Optionally filter by status."""
        if status:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM policy_violations WHERE org_id=? AND status=? ORDER BY created_at DESC",
                    (org_id, status),
                ).fetchall()
        else:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM policy_violations WHERE org_id=? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
        return [dict(r) for r in rows]

    def remediate_violation(self, org_id: str, violation_id: str) -> bool:
        """Mark a violation as remediated. Returns True if updated."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """
                    UPDATE policy_violations
                    SET status='remediated', updated_at=?
                    WHERE violation_id=? AND org_id=?
                    """,
                    (now, violation_id, org_id),
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

            # Compliance rate from latest audit per policy
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

        compliance_rate = round(latest_audit or 0.0, 2)
        avg_complexity_score = round(avg_complexity or 0.0, 1)

        return {
            "total_policies": total_policies,
            "total_violations": total_violations,
            "open_violations": open_violations,
            "compliance_rate": compliance_rate,
            "avg_complexity_score": avg_complexity_score,
        }
