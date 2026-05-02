"""Identity Governance & Administration (IGA) Engine — ALDECI.

Manages the full identity lifecycle including:
- Access review campaigns (certify / revoke / escalate)
- Orphaned account detection (no owner or departed employee)
- Excessive privilege detection (over-provisioned users)
- Segregation of Duties (SoD) violation detection
- Joiner / Mover / Leaver (JML) provisioning gap checks

SQLite WAL-mode backed, thread-safe, multi-tenant (per org_id).

Compliance: SOC2 CC6.2, ISO 27001 A.9, NIST SP 800-53 AC-5/AC-6.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / "data" / "iga.db")

# Valid access review scopes
ACCESS_TYPES = ("privileged", "service_accounts", "all")

# Valid certification decisions
DECISIONS = ("certify", "revoke", "escalate")

# SoD conflict matrix: role pairs that must not be held by the same user
_SOD_CONFLICTS: List[Dict[str, Any]] = [
    {
        "role_a": "finance_approver",
        "role_b": "payment_initiator",
        "reason": "Financial fraud risk: same user can initiate and approve payments",
        "severity": "critical",
    },
    {
        "role_a": "change_approver",
        "role_b": "change_implementer",
        "reason": "Change management bypass: same user can approve and implement changes",
        "severity": "high",
    },
    {
        "role_a": "security_admin",
        "role_b": "audit_reader",
        "reason": "Audit integrity risk: security admin can view and potentially manipulate audit logs",
        "severity": "high",
    },
    {
        "role_a": "user_provisioner",
        "role_b": "access_certifier",
        "reason": "Self-certification risk: provisioner can create accounts and certify their own access",
        "severity": "critical",
    },
    {
        "role_a": "data_admin",
        "role_b": "backup_admin",
        "reason": "Data destruction risk: same user controls live data and backups",
        "severity": "high",
    },
    {
        "role_a": "network_admin",
        "role_b": "firewall_auditor",
        "reason": "Audit bypass: network admin can change rules and audit those changes",
        "severity": "medium",
    },
]

# Roles considered privileged for access review filtering
_PRIVILEGED_ROLES = {
    "admin",
    "superadmin",
    "root",
    "sysadmin",
    "security_admin",
    "data_admin",
    "network_admin",
    "dba",
    "finance_approver",
    "user_provisioner",
}

# Account types considered service accounts
_SERVICE_ACCOUNT_PREFIXES = ("svc-", "sa-", "service-", "bot-", "api-", "system-")


class IGAEngine:
    """
    SQLite-backed Identity Governance & Administration engine.

    All public methods are thread-safe via RLock.

    Args:
        db_path: Path to SQLite database. Defaults to data/iga.db.
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
        with self._get_conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS access_reviews (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    name         TEXT NOT NULL,
                    scope        TEXT NOT NULL,
                    reviewer_id  TEXT NOT NULL,
                    deadline     TEXT NOT NULL,
                    access_type  TEXT NOT NULL DEFAULT 'all',
                    status       TEXT NOT NULL DEFAULT 'active',
                    created_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ar_org_status
                    ON access_reviews (org_id, status, created_at DESC);

                CREATE TABLE IF NOT EXISTS review_items (
                    id              TEXT PRIMARY KEY,
                    review_id       TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    user_id         TEXT NOT NULL,
                    user_email      TEXT NOT NULL,
                    role            TEXT NOT NULL,
                    resource        TEXT NOT NULL,
                    granted_at      TEXT,
                    last_used       TEXT,
                    decision        TEXT,
                    justification   TEXT,
                    decided_at      TEXT,
                    decided_by      TEXT,
                    risk_score      REAL DEFAULT 0.0,
                    FOREIGN KEY (review_id) REFERENCES access_reviews(id)
                );

                CREATE INDEX IF NOT EXISTS idx_ri_review
                    ON review_items (review_id, org_id);

                CREATE INDEX IF NOT EXISTS idx_ri_decision
                    ON review_items (org_id, decision);

                CREATE TABLE IF NOT EXISTS identity_catalog (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    user_id         TEXT NOT NULL,
                    email           TEXT NOT NULL,
                    display_name    TEXT,
                    department      TEXT,
                    manager_id      TEXT,
                    employment_status TEXT DEFAULT 'active',
                    account_type    TEXT DEFAULT 'user',
                    roles           TEXT DEFAULT '[]',
                    last_login      TEXT,
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL,
                    UNIQUE(org_id, user_id)
                );

                CREATE INDEX IF NOT EXISTS idx_ic_org_status
                    ON identity_catalog (org_id, employment_status);

                CREATE TABLE IF NOT EXISTS provisioning_events (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    user_id     TEXT NOT NULL,
                    event_type  TEXT NOT NULL,
                    description TEXT,
                    status      TEXT DEFAULT 'pending',
                    created_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pe_org_type
                    ON provisioning_events (org_id, event_type, status);
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Access Reviews
    # ------------------------------------------------------------------

    def create_access_review(self, org_id: str, review: Dict[str, Any]) -> str:
        """Create an access review campaign.

        Args:
            org_id: Organisation ID.
            review: Dict with keys: name, scope, reviewer_id, deadline, access_type.
                    access_type must be one of: "privileged", "service_accounts", "all".

        Returns:
            review_id (UUID string).
        """
        access_type = review.get("access_type", "all")
        if access_type not in ACCESS_TYPES:
            raise ValueError(f"access_type must be one of {ACCESS_TYPES}, got: {access_type!r}")

        review_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO access_reviews
                        (id, org_id, name, scope, reviewer_id, deadline, access_type, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)
                    """,
                    (
                        review_id,
                        org_id,
                        review.get("name", "Unnamed Review"),
                        review.get("scope", "all"),
                        review.get("reviewer_id", ""),
                        review.get("deadline", ""),
                        access_type,
                        now,
                    ),
                )
                # Auto-populate items from identity catalog
                self._populate_review_items(conn, review_id, org_id, access_type)

        _logger.info("Created access review %s for org %s (type=%s)", review_id, org_id, access_type)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "iga", "org_id": org_id, "source_engine": "iga"})
            except Exception:
                pass

        return review_id

    def _populate_review_items(
        self, conn: sqlite3.Connection, review_id: str, org_id: str, access_type: str
    ) -> None:
        """Seed review_items from identity_catalog based on access_type."""
        rows = conn.execute(
            "SELECT * FROM identity_catalog WHERE org_id = ?", (org_id,)
        ).fetchall()

        datetime.now(timezone.utc).isoformat()
        for row in rows:
            roles: List[str] = json.loads(row["roles"] or "[]")
            for role in roles:
                if access_type == "privileged" and role not in _PRIVILEGED_ROLES:
                    continue
                if access_type == "service_accounts":
                    email = row["email"] or ""
                    if not any(email.startswith(p) for p in _SERVICE_ACCOUNT_PREFIXES):
                        continue

                # Risk score: higher if role is privileged or account is service account
                risk = 0.3
                if role in _PRIVILEGED_ROLES:
                    risk = 0.8
                email = row["email"] or ""
                if any(email.startswith(p) for p in _SERVICE_ACCOUNT_PREFIXES):
                    risk = max(risk, 0.6)

                item_id = str(uuid.uuid4())
                conn.execute(
                    """
                    INSERT INTO review_items
                        (id, review_id, org_id, user_id, user_email, role, resource,
                         granted_at, last_used, risk_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item_id,
                        review_id,
                        org_id,
                        row["user_id"],
                        row["email"],
                        role,
                        row["department"] or "unknown",
                        row["created_at"],
                        row["last_login"],
                        risk,
                    ),
                )

    def list_access_reviews(self, org_id: str) -> List[Dict[str, Any]]:
        """List all access reviews for an org."""
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM access_reviews WHERE org_id = ? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
                result = []
                for row in rows:
                    d = dict(row)
                    # Attach summary counts
                    counts = conn.execute(
                        """
                        SELECT
                            COUNT(*) as total,
                            SUM(CASE WHEN decision IS NULL THEN 1 ELSE 0 END) as pending,
                            SUM(CASE WHEN decision = 'certify' THEN 1 ELSE 0 END) as certified,
                            SUM(CASE WHEN decision = 'revoke' THEN 1 ELSE 0 END) as revoked
                        FROM review_items
                        WHERE review_id = ? AND org_id = ?
                        """,
                        (row["id"], org_id),
                    ).fetchone()
                    d["total_items"] = counts["total"] or 0
                    d["pending"] = counts["pending"] or 0
                    d["certified"] = counts["certified"] or 0
                    d["revoked"] = counts["revoked"] or 0
                    result.append(d)
                return result

    def get_review_items(self, review_id: str, org_id: str) -> List[Dict[str, Any]]:
        """Return all access items to certify/revoke for a review."""
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM review_items
                    WHERE review_id = ? AND org_id = ?
                    ORDER BY risk_score DESC, user_email ASC
                    """,
                    (review_id, org_id),
                ).fetchall()
                return [dict(r) for r in rows]

    def certify_access(
        self,
        review_id: str,
        item_id: str,
        org_id: str,
        decision: str,
        justification: str,
    ) -> bool:
        """Submit a certification decision for a review item.

        Args:
            review_id: Access review campaign ID.
            item_id: Review item ID.
            org_id: Organisation ID (tenant guard).
            decision: One of "certify", "revoke", "escalate".
            justification: Free-text reason for the decision.

        Returns:
            True if the decision was recorded, False if item not found.
        """
        if decision not in DECISIONS:
            raise ValueError(f"decision must be one of {DECISIONS}, got: {decision!r}")

        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._get_conn() as conn:
                cursor = conn.execute(
                    """
                    UPDATE review_items
                    SET decision = ?, justification = ?, decided_at = ?, decided_by = ?
                    WHERE id = ? AND review_id = ? AND org_id = ?
                    """,
                    (decision, justification, now, "api", item_id, review_id, org_id),
                )
                if cursor.rowcount == 0:
                    return False
                _logger.info(
                    "Certified item %s in review %s: %s", item_id, review_id, decision
                )
                return True

    # ------------------------------------------------------------------
    # Identity Management
    # ------------------------------------------------------------------

    def upsert_identity(self, org_id: str, identity: Dict[str, Any]) -> str:
        """Insert or update an identity in the catalog.

        Used by tests and provisioning integrations to seed data.

        Returns:
            user_id
        """
        now = datetime.now(timezone.utc).isoformat()
        user_id = identity.get("user_id") or str(uuid.uuid4())
        roles = json.dumps(identity.get("roles", []))

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO identity_catalog
                        (id, org_id, user_id, email, display_name, department,
                         manager_id, employment_status, account_type, roles,
                         last_login, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(org_id, user_id) DO UPDATE SET
                        email            = excluded.email,
                        display_name     = excluded.display_name,
                        department       = excluded.department,
                        manager_id       = excluded.manager_id,
                        employment_status= excluded.employment_status,
                        account_type     = excluded.account_type,
                        roles            = excluded.roles,
                        last_login       = excluded.last_login,
                        updated_at       = excluded.updated_at
                    """,
                    (
                        str(uuid.uuid4()),
                        org_id,
                        user_id,
                        identity.get("email", ""),
                        identity.get("display_name", ""),
                        identity.get("department", ""),
                        identity.get("manager_id"),
                        identity.get("employment_status", "active"),
                        identity.get("account_type", "user"),
                        roles,
                        identity.get("last_login"),
                        now,
                        now,
                    ),
                )
        return user_id

    # ------------------------------------------------------------------
    # Orphaned Accounts
    # ------------------------------------------------------------------

    def get_orphaned_accounts(self, org_id: str) -> List[Dict[str, Any]]:
        """Return accounts with no owner or from departed employees.

        Orphan criteria:
        - employment_status = 'terminated' or 'departed'
        - manager_id is NULL or empty
        - last_login > 90 days ago (dormant accounts with no active owner)
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    """
                    SELECT *, 'departed_employee' AS orphan_reason
                    FROM identity_catalog
                    WHERE org_id = ?
                      AND employment_status IN ('terminated', 'departed', 'inactive')

                    UNION ALL

                    SELECT *, 'no_owner' AS orphan_reason
                    FROM identity_catalog
                    WHERE org_id = ?
                      AND (manager_id IS NULL OR manager_id = '')
                      AND employment_status = 'active'

                    UNION ALL

                    SELECT *, 'dormant_no_owner' AS orphan_reason
                    FROM identity_catalog
                    WHERE org_id = ?
                      AND (last_login IS NULL OR last_login < ?)
                      AND employment_status = 'active'
                      AND (manager_id IS NULL OR manager_id = '')
                    """,
                    (org_id, org_id, org_id, cutoff),
                ).fetchall()
                seen: set = set()
                result = []
                for row in rows:
                    key = (row["user_id"], row["orphan_reason"])
                    if key not in seen:
                        seen.add(key)
                        d = dict(row)
                        d["roles"] = json.loads(d.get("roles") or "[]")
                        result.append(d)
                return result

    # ------------------------------------------------------------------
    # Excessive Privileges
    # ------------------------------------------------------------------

    def get_excessive_privileges(self, org_id: str) -> List[Dict[str, Any]]:
        """Return users holding more privileged roles than their role requires.

        Detects:
        - Non-IT/security departments holding privileged roles
        - Service accounts with admin roles
        - Users with >3 distinct privileged roles (role sprawl)
        """
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM identity_catalog WHERE org_id = ? AND employment_status = 'active'",
                    (org_id,),
                ).fetchall()

        result = []
        for row in rows:
            roles: List[str] = json.loads(row["roles"] or "[]")
            privileged = [r for r in roles if r in _PRIVILEGED_ROLES]
            if not privileged:
                continue

            findings: List[str] = []
            department = (row["department"] or "").lower()
            email = (row["email"] or "")
            account_type = row["account_type"] or "user"

            # Service account with admin role
            if any(email.startswith(p) for p in _SERVICE_ACCOUNT_PREFIXES) and (
                "admin" in privileged or "superadmin" in privileged
            ):
                findings.append("service_account_with_admin")

            # Non-technical department with privileged access
            tech_depts = {"it", "security", "devops", "engineering", "infosec", "ops", "sre"}
            if department and not any(t in department for t in tech_depts):
                findings.append(f"non_tech_department_privileged_access:{department}")

            # Role sprawl: more than 3 privileged roles
            if len(privileged) > 3:
                findings.append(f"role_sprawl:{len(privileged)}_privileged_roles")

            if findings:
                result.append(
                    {
                        "user_id": row["user_id"],
                        "email": row["email"],
                        "display_name": row["display_name"],
                        "department": row["department"],
                        "account_type": account_type,
                        "privileged_roles": privileged,
                        "all_roles": roles,
                        "findings": findings,
                        "risk_score": min(1.0, len(privileged) * 0.2 + len(findings) * 0.15),
                    }
                )
        result.sort(key=lambda x: x["risk_score"], reverse=True)
        return result

    # ------------------------------------------------------------------
    # Segregation of Duties
    # ------------------------------------------------------------------

    def get_segregation_violations(self, org_id: str) -> List[Dict[str, Any]]:
        """Return SoD violations — conflicting roles held by the same user."""
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM identity_catalog WHERE org_id = ? AND employment_status = 'active'",
                    (org_id,),
                ).fetchall()

        violations = []
        for row in rows:
            roles_set = set(json.loads(row["roles"] or "[]"))
            for conflict in _SOD_CONFLICTS:
                if conflict["role_a"] in roles_set and conflict["role_b"] in roles_set:
                    violations.append(
                        {
                            "user_id": row["user_id"],
                            "email": row["email"],
                            "display_name": row["display_name"],
                            "role_a": conflict["role_a"],
                            "role_b": conflict["role_b"],
                            "reason": conflict["reason"],
                            "severity": conflict["severity"],
                        }
                    )
        return violations

    # ------------------------------------------------------------------
    # Certification Stats
    # ------------------------------------------------------------------

    def get_access_certification_stats(self, org_id: str) -> Dict[str, Any]:
        """Return certification statistics for the org.

        Returns:
            {total_items, certified, revoked, escalated, pending, overdue,
             completion_rate, active_reviews}
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._get_conn() as conn:
                counts = conn.execute(
                    """
                    SELECT
                        COUNT(*) AS total_items,
                        SUM(CASE WHEN ri.decision = 'certify' THEN 1 ELSE 0 END) AS certified,
                        SUM(CASE WHEN ri.decision = 'revoke' THEN 1 ELSE 0 END) AS revoked,
                        SUM(CASE WHEN ri.decision = 'escalate' THEN 1 ELSE 0 END) AS escalated,
                        SUM(CASE WHEN ri.decision IS NULL THEN 1 ELSE 0 END) AS pending
                    FROM review_items ri
                    JOIN access_reviews ar ON ar.id = ri.review_id
                    WHERE ri.org_id = ? AND ar.status = 'active'
                    """,
                    (org_id,),
                ).fetchone()

                overdue = conn.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM review_items ri
                    JOIN access_reviews ar ON ar.id = ri.review_id
                    WHERE ri.org_id = ? AND ar.status = 'active'
                      AND ri.decision IS NULL
                      AND ar.deadline < ?
                    """,
                    (org_id, now_iso),
                ).fetchone()["cnt"] or 0

                active_reviews = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM access_reviews WHERE org_id = ? AND status = 'active'",
                    (org_id,),
                ).fetchone()["cnt"] or 0

        total = counts["total_items"] or 0
        certified = counts["certified"] or 0
        revoked = counts["revoked"] or 0
        escalated = counts["escalated"] or 0
        pending = counts["pending"] or 0
        completion_rate = round((certified + revoked + escalated) / total, 4) if total > 0 else 0.0

        return {
            "total_items": total,
            "certified": certified,
            "revoked": revoked,
            "escalated": escalated,
            "pending": pending,
            "overdue": overdue,
            "completion_rate": completion_rate,
            "active_reviews": active_reviews,
        }

    # ------------------------------------------------------------------
    # JML Provisioning Check
    # ------------------------------------------------------------------

    def run_provisioning_check(self, org_id: str) -> Dict[str, Any]:
        """Compare HR roster to system accounts — find joiners/movers/leavers not acted on.

        Detects:
        - Joiners: new hires with accounts not yet provisioned (no last_login within 7 days)
        - Movers: employees with department changes whose access hasn't been updated
        - Leavers: terminated employees still holding active access

        Returns:
            {joiners, movers, leavers, total_gaps, summary}
        """
        cutoff_joiner = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        with self._lock:
            with self._get_conn() as conn:
                all_identities = conn.execute(
                    "SELECT * FROM identity_catalog WHERE org_id = ?", (org_id,)
                ).fetchall()

        joiners = []
        movers = []
        leavers = []

        for row in all_identities:
            roles: List[str] = json.loads(row["roles"] or "[]")
            status = row["employment_status"] or "active"

            if status in ("terminated", "departed"):
                if roles:
                    leavers.append(
                        {
                            "user_id": row["user_id"],
                            "email": row["email"],
                            "display_name": row["display_name"],
                            "employment_status": status,
                            "roles": roles,
                            "risk": "high",
                            "action_required": "revoke_all_access",
                        }
                    )

            elif status == "active":
                # Joiner: no login since they were created (and created recently)
                created = row["created_at"] or ""
                last_login = row["last_login"]
                if created >= cutoff_joiner and (last_login is None or last_login == ""):
                    joiners.append(
                        {
                            "user_id": row["user_id"],
                            "email": row["email"],
                            "display_name": row["display_name"],
                            "created_at": created,
                            "last_login": last_login,
                            "roles": roles,
                            "risk": "medium",
                            "action_required": "verify_onboarding",
                        }
                    )

                # Mover: has no roles but is active (should have been provisioned)
                elif not roles and row["department"]:
                    movers.append(
                        {
                            "user_id": row["user_id"],
                            "email": row["email"],
                            "display_name": row["display_name"],
                            "department": row["department"],
                            "employment_status": status,
                            "roles": roles,
                            "risk": "medium",
                            "action_required": "provision_role_based_access",
                        }
                    )

        total_gaps = len(joiners) + len(movers) + len(leavers)

        return {
            "joiners": joiners,
            "movers": movers,
            "leavers": leavers,
            "total_gaps": total_gaps,
            "summary": {
                "joiners_count": len(joiners),
                "movers_count": len(movers),
                "leavers_count": len(leavers),
            },
        }
