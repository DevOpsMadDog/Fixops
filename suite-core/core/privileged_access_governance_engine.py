"""Privileged Access Governance Engine — ALDECI.

Manages privileged accounts, access sessions, and behavioral anomaly
detection for service, admin, root, service-account, and break-glass accounts.

Capabilities:
  - Privileged account registration with type and owner
  - Access session recording with command and duration tracking
  - Anomaly flagging with severity classification
  - Stats: active accounts, sessions today, open anomalies, high-risk accounts

Compliance: CyberArk PAM model, NIST SP 800-53 AC-17, PCI-DSS 10.2.2
"""

from __future__ import annotations

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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_ACCOUNT_TYPES = {"service", "admin", "root", "sa", "break_glass"}
_VALID_ANOMALY_TYPES = {
    "off_hours",
    "unusual_commands",
    "excessive_access",
    "unauthorized_system",
    "policy_violation",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class PrivilegedAccessGovernanceEngine:
    """SQLite WAL-backed Privileged Access Governance engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/privileged_access_governance.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "privileged_access_governance.db")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS pag_accounts (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    username     TEXT NOT NULL DEFAULT '',
                    account_type TEXT NOT NULL DEFAULT 'service',
                    system       TEXT NOT NULL DEFAULT '',
                    owner        TEXT NOT NULL DEFAULT '',
                    justification TEXT NOT NULL DEFAULT '',
                    last_used    DATETIME,
                    status       TEXT NOT NULL DEFAULT 'active',
                    risk_score   REAL NOT NULL DEFAULT 50.0,
                    created_at   DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_pag_accounts_org
                    ON pag_accounts (org_id, account_type, status);

                CREATE TABLE IF NOT EXISTS pag_sessions (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    account_id        TEXT NOT NULL,
                    accessed_by       TEXT NOT NULL DEFAULT '',
                    system            TEXT NOT NULL DEFAULT '',
                    duration_minutes  INTEGER NOT NULL DEFAULT 0,
                    commands_executed INTEGER NOT NULL DEFAULT 0,
                    justification     TEXT NOT NULL DEFAULT '',
                    approved_by       TEXT NOT NULL DEFAULT '',
                    session_at        DATETIME,
                    status            TEXT NOT NULL DEFAULT 'completed'
                );

                CREATE INDEX IF NOT EXISTS idx_pag_sessions_org
                    ON pag_sessions (org_id, account_id, status);

                CREATE TABLE IF NOT EXISTS pag_anomalies (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    account_id   TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL DEFAULT 'off_hours',
                    severity     TEXT NOT NULL DEFAULT 'medium',
                    description  TEXT NOT NULL DEFAULT '',
                    status       TEXT NOT NULL DEFAULT 'open',
                    detected_at  DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_pag_anomalies_org
                    ON pag_anomalies (org_id, account_id, severity, status);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Privileged Accounts
    # ------------------------------------------------------------------

    def register_privileged_account(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Register a new privileged account."""
        username = (data.get("username") or "").strip()
        if not username:
            raise ValueError("username is required")

        account_type = data.get("account_type", "service")
        if account_type not in _VALID_ACCOUNT_TYPES:
            raise ValueError(
                f"Invalid account_type: {account_type}. "
                f"Must be one of {sorted(_VALID_ACCOUNT_TYPES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "username": username,
            "account_type": account_type,
            "system": data.get("system", ""),
            "owner": data.get("owner", ""),
            "justification": data.get("justification", ""),
            "last_used": None,
            "status": "active",
            "risk_score": 50.0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO pag_accounts
                       (id, org_id, username, account_type, system, owner, justification,
                        last_used, status, risk_score, created_at)
                       VALUES
                       (:id, :org_id, :username, :account_type, :system, :owner, :justification,
                        :last_used, :status, :risk_score, :created_at)""",
                    record,
                )
        return record

    def list_privileged_accounts(
        self,
        org_id: str,
        account_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List privileged accounts with optional filters."""
        sql = "SELECT * FROM pag_accounts WHERE org_id = ?"
        params: list = [org_id]
        if account_type is not None:
            sql += " AND account_type = ?"
            params.append(account_type)
        if status is not None:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def list_privileged_accounts_with_okta_fallback(
        self,
        org_id: str,
        account_type: Optional[str] = None,
        status: Optional[str] = None,
        okta_connector: Any = None,
    ) -> Dict[str, Any]:
        """List PAG accounts; when the org has zero rows AND Okta credentials
        are configured, project privileged Okta users (admins, locked-out
        accounts, suspended accounts) as derived PAG account rows.

        Behaviour:
            - Org-registered rows always take precedence (returns
              ``source="org_registered"``).
            - When the org has no accounts AND ``OKTA_API_KEY`` /
              ``OKTA_DOMAIN`` env vars are set, the connector is invoked
              and **privileged** Okta users (status in {LOCKED_OUT,
              SUSPENDED, RECOVERY, PASSWORD_EXPIRED} OR admin titles) are
              projected one-per-account.
            - When credentials absent, returns
              ``{"accounts": [], "source": "needs_credentials", "hint": ...}``.
            - Each derived row carries provenance fields ``source="okta"``
              and ``okta_user_id`` so the UI can badge it.

        Args:
            org_id:          Tenant identifier.
            account_type:    Optional filter (forwarded to org rows; for
                             derived rows we set type="admin").
            status:          Optional filter (org rows only).
            okta_connector:  Override for testing — must expose .sync().

        Returns:
            ``{accounts, total, source, hint?, okta_users_synced?}``.
        """
        # Org-registered rows first.
        rows = self.list_privileged_accounts(
            org_id, account_type=account_type, status=status
        )
        if rows:
            return {
                "accounts": rows,
                "total": len(rows),
                "source": "org_registered",
            }

        # Resolve connector (lazy import — never crash on absence).
        if okta_connector is None:
            try:
                from connectors.okta_connector import get_okta_connector
                okta_connector = get_okta_connector()
            except ImportError:
                return {
                    "accounts": [],
                    "total": 0,
                    "source": "needs_credentials",
                    "hint": (
                        "Install the Okta connector or register accounts "
                        "manually via POST /api/v1/pag/accounts."
                    ),
                }

        try:
            sync_result = okta_connector.sync(org_id=org_id)
        except (ValueError, RuntimeError, OSError) as exc:
            _logger.warning(
                "PAG: Okta connector sync failed for org=%s: %s",
                org_id,
                exc,
            )
            return {
                "accounts": [],
                "total": 0,
                "source": "okta_error",
                "hint": f"Okta sync failed: {exc}",
            }

        if sync_result.get("status") == "needs_credentials":
            return {
                "accounts": [],
                "total": 0,
                "source": "needs_credentials",
                "hint": sync_result.get("hint", (
                    "Set OKTA_API_KEY and OKTA_DOMAIN environment variables "
                    "to enable live Okta identity integration, or register "
                    "accounts manually via POST /api/v1/pag/accounts."
                )),
            }

        # Project privileged Okta users to PAG account shape.
        users = sync_result.get("users") or []
        derived: List[Dict[str, Any]] = []
        # Title patterns indicating privileged role
        _PRIV_TITLE_TOKENS = (
            "admin", "root", "sre", "devops", "owner", "operator",
            "engineer", "security", "infra",
        )
        # Status values that always signal high-risk privileged accounts
        _PRIV_STATUSES = {
            "LOCKED_OUT", "SUSPENDED", "RECOVERY", "PASSWORD_EXPIRED"
        }
        now = _now_iso()
        for u in users:
            okta_status = (u.get("status") or "").upper()
            title = (u.get("title") or "").lower()
            email = u.get("email") or ""
            is_privileged_status = okta_status in _PRIV_STATUSES
            is_privileged_title = any(t in title for t in _PRIV_TITLE_TOKENS)
            if not (is_privileged_status or is_privileged_title):
                continue
            okta_uid = u.get("okta_user_id") or ""
            derived_type = "admin" if is_privileged_title else "service"
            # Optional account_type filter applies to derived rows too.
            if account_type is not None and derived_type != account_type:
                continue
            risk_label = u.get("risk_level", "low")
            risk_score = {
                "high": 80.0,
                "medium": 60.0,
                "low": 40.0,
            }.get(risk_label, 50.0)
            derived.append({
                "id": f"okta:{okta_uid}",
                "org_id": org_id,
                "username": email or u.get("display_name", okta_uid),
                "account_type": derived_type,
                "system": "okta",
                "owner": u.get("display_name", ""),
                "justification": (
                    f"Derived from Okta (status={okta_status}, "
                    f"title={u.get('title', '')}, "
                    f"department={u.get('department', '')})"
                ),
                "last_used": u.get("last_login") or None,
                "status": "active" if okta_status == "ACTIVE" else "inactive",
                "risk_score": risk_score,
                "created_at": u.get("created_at") or now,
                # Provenance fields (derived rows only)
                "source": "okta",
                "okta_user_id": okta_uid,
                "okta_status": okta_status,
                "title": u.get("title", ""),
                "department": u.get("department", ""),
            })

        return {
            "accounts": derived,
            "total": len(derived),
            "source": "okta-derived" if derived else "okta_no_privileged_users",
            "okta_users_synced": len(users),
            "hint": (
                None
                if derived
                else (
                    "Okta sync returned 0 privileged users. Register "
                    "privileged accounts manually via POST /api/v1/pag/accounts."
                )
            ),
        }

    def get_privileged_account(
        self, org_id: str, account_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get a single privileged account by id, scoped to org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM pag_accounts WHERE id = ? AND org_id = ?",
                (account_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def record_access_session(
        self, org_id: str, account_id: str, session_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record a privileged access session and update account last_used."""
        now = _now_iso()
        session_at = session_data.get("session_at", now)
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "account_id": account_id,
            "accessed_by": session_data.get("accessed_by", ""),
            "system": session_data.get("system", ""),
            "duration_minutes": int(session_data.get("duration_minutes", 0)),
            "commands_executed": int(session_data.get("commands_executed", 0)),
            "justification": session_data.get("justification", ""),
            "approved_by": session_data.get("approved_by", ""),
            "session_at": session_at,
            "status": "completed",
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO pag_sessions
                       (id, org_id, account_id, accessed_by, system, duration_minutes,
                        commands_executed, justification, approved_by, session_at, status)
                       VALUES
                       (:id, :org_id, :account_id, :accessed_by, :system, :duration_minutes,
                        :commands_executed, :justification, :approved_by, :session_at, :status)""",
                    record,
                )
                # Update account last_used
                conn.execute(
                    "UPDATE pag_accounts SET last_used = ? WHERE id = ? AND org_id = ?",
                    (session_at, account_id, org_id),
                )
        return record

    def list_sessions(
        self,
        org_id: str,
        account_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List access sessions with optional filters."""
        sql = "SELECT * FROM pag_sessions WHERE org_id = ?"
        params: list = [org_id]
        if account_id is not None:
            sql += " AND account_id = ?"
            params.append(account_id)
        if status is not None:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY session_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Anomalies
    # ------------------------------------------------------------------

    def flag_anomaly(
        self, org_id: str, account_id: str, anomaly_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Flag a behavioral anomaly on a privileged account."""
        anomaly_type = anomaly_data.get("anomaly_type", "off_hours")
        if anomaly_type not in _VALID_ANOMALY_TYPES:
            raise ValueError(
                f"Invalid anomaly_type: {anomaly_type}. "
                f"Must be one of {sorted(_VALID_ANOMALY_TYPES)}"
            )

        severity = anomaly_data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity}. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "account_id": account_id,
            "anomaly_type": anomaly_type,
            "severity": severity,
            "description": anomaly_data.get("description", ""),
            "status": "open",
            "detected_at": anomaly_data.get("detected_at", now),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO pag_anomalies
                       (id, org_id, account_id, anomaly_type, severity,
                        description, status, detected_at)
                       VALUES
                       (:id, :org_id, :account_id, :anomaly_type, :severity,
                        :description, :status, :detected_at)""",
                    record,
                )
        return record

    def list_anomalies(
        self,
        org_id: str,
        account_id: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List anomalies with optional filters."""
        sql = "SELECT * FROM pag_anomalies WHERE org_id = ?"
        params: list = [org_id]
        if account_id is not None:
            sql += " AND account_id = ?"
            params.append(account_id)
        if severity is not None:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY detected_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Standing privilege + JIT (GAP-032: MERGE CIEM+AD)
    # ------------------------------------------------------------------

    def detect_standing_privilege(
        self, org_id: str, stale_days: int = 30
    ) -> List[Dict[str, Any]]:
        """Detect privileged accounts with standing (always-on) entitlements.

        Any active account that is NOT a break_glass type qualifies as
        "standing privilege" — a direct violation of least-standing-privilege.
        Accounts unused for `stale_days` are flagged as highest risk
        because they represent persistent attack surface with no
        compensating usage signal.
        """
        findings: List[Dict[str, Any]] = []
        now_ts = datetime.now(timezone.utc).timestamp()
        stale_cutoff = now_ts - (stale_days * 86400)

        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM pag_accounts
                   WHERE org_id = ? AND status = 'active'""",
                (org_id,),
            ).fetchall()

        for row in rows:
            rec = dict(row)
            acct_type = rec.get("account_type", "")
            last_used = rec.get("last_used")
            is_break_glass = acct_type == "break_glass"
            if is_break_glass:
                # Break-glass is allowed to have standing privilege but gets lowest severity
                severity = "low"
                reason = "break_glass_account_standing_by_design"
            else:
                stale = True
                if last_used:
                    try:
                        last_ts = datetime.fromisoformat(
                            str(last_used).replace("Z", "+00:00")
                        ).timestamp()
                        stale = last_ts < stale_cutoff
                    except ValueError:
                        stale = True
                severity = "critical" if stale else "high"
                reason = (
                    f"stale_no_activity_in_{stale_days}d"
                    if stale
                    else "active_standing_privilege"
                )

            findings.append(
                {
                    "org_id": org_id,
                    "account_id": rec.get("id"),
                    "username": rec.get("username", ""),
                    "account_type": acct_type,
                    "system": rec.get("system", ""),
                    "last_used": last_used,
                    "severity": severity,
                    "reason": reason,
                    "recommendation": (
                        "Disable and convert to Just-In-Time access via "
                        "approval workflow." if not is_break_glass else
                        "Leave as-is; audit monthly and ensure alerting is "
                        "tied to break-glass activation."
                    ),
                }
            )
        return findings

    def just_in_time_recommendations(
        self, org_id: str, lookback_days: int = 30
    ) -> Dict[str, Any]:
        """Produce JIT (Just-In-Time) conversion recommendations.

        For every non-break-glass standing-privilege account, compute a
        suggested JIT window based on historical session cadence:
          - median session duration over the lookback window
          - typical time-of-day (hour bucket)
          - recommended max_duration_minutes (p95 or 4h, whichever is less)
          - suggested approval_tier (dual-approval if critical system)
        """
        cutoff_iso = (
            datetime.now(timezone.utc) - timedelta(days=lookback_days)
        ).isoformat() if False else _now_iso()  # runtime-safe fallback

        # Compute cutoff properly
        cutoff_dt = datetime.now(timezone.utc)
        cutoff_dt = cutoff_dt.replace(microsecond=0)
        cutoff_iso = (
            datetime.fromtimestamp(
                cutoff_dt.timestamp() - (lookback_days * 86400), tz=timezone.utc
            ).isoformat()
        )

        standing = self.detect_standing_privilege(org_id)
        recommendations: List[Dict[str, Any]] = []

        with self._conn() as conn:
            for finding in standing:
                if finding.get("account_type") == "break_glass":
                    continue
                account_id = finding["account_id"]
                sessions = conn.execute(
                    """SELECT duration_minutes, session_at FROM pag_sessions
                       WHERE org_id = ? AND account_id = ?
                         AND session_at >= ?
                       ORDER BY session_at DESC""",
                    (org_id, account_id, cutoff_iso),
                ).fetchall()
                durations = sorted(
                    [int(s["duration_minutes"]) for s in sessions if s["duration_minutes"]]
                )
                session_count = len(durations)
                if durations:
                    median = durations[len(durations) // 2]
                    p95_idx = max(0, int(len(durations) * 0.95) - 1)
                    p95 = durations[p95_idx]
                    max_duration = min(p95, 240)  # cap 4h
                else:
                    median = 0
                    p95 = 0
                    max_duration = 60  # default to 1h JIT

                system = finding.get("system", "")
                critical_system = any(
                    k in system.lower()
                    for k in ("prod", "production", "domain-controller", "dc-", "root")
                )
                approval_tier = "dual" if critical_system else "single"

                recommendations.append(
                    {
                        "account_id": account_id,
                        "username": finding.get("username", ""),
                        "system": system,
                        "current_severity": finding.get("severity"),
                        "session_count_30d": session_count,
                        "median_duration_minutes": median,
                        "p95_duration_minutes": p95,
                        "recommended_max_duration_minutes": max_duration,
                        "recommended_approval_tier": approval_tier,
                        "recommendation": (
                            f"Convert to JIT with max duration {max_duration} min "
                            f"and {approval_tier} approval. Revoke standing access."
                        ),
                    }
                )

        return {
            "org_id": org_id,
            "analysed_at": _now_iso(),
            "lookback_days": lookback_days,
            "standing_privilege_count": len(standing),
            "jit_candidates": len(recommendations),
            "recommendations": recommendations,
        }

    def get_pag_stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregated privileged access governance statistics for an org."""
        today = _today_str()
        with self._conn() as conn:
            total_accounts = conn.execute(
                "SELECT COUNT(*) FROM pag_accounts WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_accounts = conn.execute(
                "SELECT COUNT(*) FROM pag_accounts WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            sessions_today = conn.execute(
                "SELECT COUNT(*) FROM pag_sessions WHERE org_id = ? AND session_at LIKE ?",
                (org_id, f"{today}%"),
            ).fetchone()[0]

            anomalies_open = conn.execute(
                "SELECT COUNT(*) FROM pag_anomalies WHERE org_id = ? AND status = 'open'",
                (org_id,),
            ).fetchone()[0]

            type_rows = conn.execute(
                """SELECT account_type, COUNT(*) as cnt
                   FROM pag_accounts WHERE org_id = ?
                   GROUP BY account_type""",
                (org_id,),
            ).fetchall()
            by_account_type = {r["account_type"]: r["cnt"] for r in type_rows}

            high_risk_accounts = conn.execute(
                "SELECT COUNT(*) FROM pag_accounts WHERE org_id = ? AND risk_score > 70",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_accounts": total_accounts,
            "active_accounts": active_accounts,
            "sessions_today": sessions_today,
            "anomalies_open": anomalies_open,
            "by_account_type": by_account_type,
            "high_risk_accounts": high_risk_accounts,
        }
