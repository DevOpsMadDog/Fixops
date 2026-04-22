"""Identity Risk Engine — ALDECI.

Tracks identity risk scoring, risk factors, and access reviews across
human, service account, machine, federated, guest, and privileged identities.

Capabilities:
  - Identity registration with type, department, MFA status
  - Risk factor recording (stale credentials, excess privileges, MFA bypass, etc.)
  - Automatic risk_level computation from risk_score
  - Access review lifecycle (approved/revoked/modified/deferred)
  - Stats: totals, high-risk count, MFA coverage, factor breakdown

Compliance: NIST SP 800-63, ISO/IEC 24760, NIST CSF (PR.AC)
"""

from __future__ import annotations

import logging
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_IDENTITY_TYPES = {
    "human",
    "service_account",
    "machine",
    "federated",
    "guest",
    "privileged",
}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low"}
_VALID_STATUSES = {"active", "inactive", "suspended", "terminated"}
_VALID_FACTOR_TYPES = {
    "stale_credentials",
    "excess_privileges",
    "mfa_bypass",
    "suspicious_location",
    "after_hours_access",
    "failed_auth_spike",
    "data_access_anomaly",
    "lateral_movement",
    "account_sharing",
    "password_reuse",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_FACTOR_STATUSES = {"active", "mitigated", "accepted"}
_VALID_DECISIONS = {"approved", "revoked", "modified", "deferred"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _risk_level_from_score(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


class IdentityRiskEngine:
    """SQLite WAL-backed Identity Risk engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/identity_risk.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "identity_risk.db")
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
                CREATE TABLE IF NOT EXISTS ir_identities (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    username        TEXT NOT NULL DEFAULT '',
                    email           TEXT NOT NULL DEFAULT '',
                    identity_type   TEXT NOT NULL DEFAULT 'human',
                    department      TEXT NOT NULL DEFAULT '',
                    risk_score      REAL NOT NULL DEFAULT 0.0,
                    risk_level      TEXT NOT NULL DEFAULT 'low',
                    mfa_enabled     INTEGER NOT NULL DEFAULT 0,
                    last_activity   TEXT,
                    status          TEXT NOT NULL DEFAULT 'active',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ir_identities_org
                    ON ir_identities (org_id, identity_type, risk_level, status);

                CREATE TABLE IF NOT EXISTS ir_risk_factors (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    identity_id  TEXT NOT NULL,
                    factor_type  TEXT NOT NULL,
                    severity     TEXT NOT NULL DEFAULT 'medium',
                    score_impact REAL NOT NULL DEFAULT 0.0,
                    description  TEXT NOT NULL DEFAULT '',
                    detected_at  TEXT NOT NULL,
                    status       TEXT NOT NULL DEFAULT 'active',
                    created_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ir_risk_factors_org
                    ON ir_risk_factors (org_id, identity_id, severity, status);

                CREATE TABLE IF NOT EXISTS ir_access_reviews (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    identity_id   TEXT NOT NULL,
                    reviewer      TEXT NOT NULL DEFAULT '',
                    decision      TEXT NOT NULL DEFAULT 'deferred',
                    resource      TEXT NOT NULL DEFAULT '',
                    access_level  TEXT NOT NULL DEFAULT '',
                    review_reason TEXT NOT NULL DEFAULT '',
                    reviewed_at   TEXT NOT NULL,
                    created_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ir_access_reviews_org
                    ON ir_access_reviews (org_id, identity_id, decision);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        if "mfa_enabled" in d:
            d["mfa_enabled"] = bool(d["mfa_enabled"])
        return d

    # ------------------------------------------------------------------
    # Identities
    # ------------------------------------------------------------------

    def register_identity(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new identity."""
        identity_type = data.get("identity_type", "human")
        if identity_type not in _VALID_IDENTITY_TYPES:
            raise ValueError(
                f"Invalid identity_type: {identity_type}. "
                f"Must be one of {sorted(_VALID_IDENTITY_TYPES)}"
            )

        status = data.get("status", "active")
        if status not in _VALID_STATUSES:
            raise ValueError(
                f"Invalid status: {status}. Must be one of {sorted(_VALID_STATUSES)}"
            )

        risk_score = float(data.get("risk_score", 0.0))
        risk_score = max(0.0, min(100.0, risk_score))
        risk_level = _risk_level_from_score(risk_score)

        mfa_enabled = bool(data.get("mfa_enabled", False))
        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "username": data.get("username", ""),
            "email": data.get("email", ""),
            "identity_type": identity_type,
            "department": data.get("department", ""),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "mfa_enabled": 1 if mfa_enabled else 0,
            "last_activity": data.get("last_activity"),
            "status": status,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO ir_identities
                       (id, org_id, username, email, identity_type, department,
                        risk_score, risk_level, mfa_enabled, last_activity, status, created_at)
                       VALUES
                       (:id, :org_id, :username, :email, :identity_type, :department,
                        :risk_score, :risk_level, :mfa_enabled, :last_activity, :status, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus:
                    bus.emit("IDENTITY_UPDATED", {"entity_type": "identity", "entity_id": str(record["id"]), "org_id": org_id, "source_engine": "identity_risk_engine"})
            except Exception:
                pass  # Event emission should never break the main operation
        record["mfa_enabled"] = mfa_enabled
        return record

    def list_identities(
        self,
        org_id: str,
        identity_type: Optional[str] = None,
        risk_level: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List identities with optional filters."""
        sql = "SELECT * FROM ir_identities WHERE org_id = ?"
        params: list = [org_id]
        if identity_type is not None:
            sql += " AND identity_type = ?"
            params.append(identity_type)
        if risk_level is not None:
            sql += " AND risk_level = ?"
            params.append(risk_level)
        if status is not None:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_identity(self, org_id: str, identity_id: str) -> Optional[Dict[str, Any]]:
        """Get a single identity by id, scoped to org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ir_identities WHERE id = ? AND org_id = ?",
                (identity_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_risk_score(
        self, org_id: str, identity_id: str, risk_score: float
    ) -> Dict[str, Any]:
        """Update risk_score and auto-compute risk_level. Clamps 0-100."""
        risk_score = max(0.0, min(100.0, float(risk_score)))
        risk_level = _risk_level_from_score(risk_score)
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE ir_identities
                       SET risk_score = ?, risk_level = ?
                       WHERE id = ? AND org_id = ?""",
                    (risk_score, risk_level, identity_id, org_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(
                        f"Identity {identity_id} not found in org {org_id}"
                    )
                row = conn.execute(
                    "SELECT * FROM ir_identities WHERE id = ? AND org_id = ?",
                    (identity_id, org_id),
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Risk Factors
    # ------------------------------------------------------------------

    def record_risk_factor(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a risk factor for an identity."""
        factor_type = data.get("factor_type", "")
        if factor_type not in _VALID_FACTOR_TYPES:
            raise ValueError(
                f"Invalid factor_type: {factor_type}. "
                f"Must be one of {sorted(_VALID_FACTOR_TYPES)}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity}. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        score_impact = float(data.get("score_impact", 0.0))
        score_impact = max(0.0, min(50.0, score_impact))

        status = data.get("status", "active")
        if status not in _VALID_FACTOR_STATUSES:
            raise ValueError(
                f"Invalid status: {status}. "
                f"Must be one of {sorted(_VALID_FACTOR_STATUSES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "identity_id": data.get("identity_id", ""),
            "factor_type": factor_type,
            "severity": severity,
            "score_impact": score_impact,
            "description": data.get("description", ""),
            "detected_at": data.get("detected_at", now),
            "status": status,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO ir_risk_factors
                       (id, org_id, identity_id, factor_type, severity, score_impact,
                        description, detected_at, status, created_at)
                       VALUES
                       (:id, :org_id, :identity_id, :factor_type, :severity, :score_impact,
                        :description, :detected_at, :status, :created_at)""",
                    record,
                )
        return record

    def list_risk_factors(
        self,
        org_id: str,
        identity_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List risk factors with optional filters."""
        sql = "SELECT * FROM ir_risk_factors WHERE org_id = ?"
        params: list = [org_id]
        if identity_id is not None:
            sql += " AND identity_id = ?"
            params.append(identity_id)
        if severity is not None:
            sql += " AND severity = ?"
            params.append(severity)
        if status is not None:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def mitigate_factor(self, org_id: str, factor_id: str) -> Dict[str, Any]:
        """Set a risk factor status to mitigated."""
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE ir_risk_factors SET status = 'mitigated'
                       WHERE id = ? AND org_id = ?""",
                    (factor_id, org_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(
                        f"Risk factor {factor_id} not found in org {org_id}"
                    )
                row = conn.execute(
                    "SELECT * FROM ir_risk_factors WHERE id = ? AND org_id = ?",
                    (factor_id, org_id),
                ).fetchone()
        return dict(row)

    # ------------------------------------------------------------------
    # Access Reviews
    # ------------------------------------------------------------------

    def record_access_review(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record an access review decision."""
        identity_id = (data.get("identity_id") or "").strip()
        if not identity_id:
            raise ValueError("identity_id is required")

        reviewer = (data.get("reviewer") or "").strip()
        if not reviewer:
            raise ValueError("reviewer is required")

        decision = data.get("decision", "deferred")
        if decision not in _VALID_DECISIONS:
            raise ValueError(
                f"Invalid decision: {decision}. "
                f"Must be one of {sorted(_VALID_DECISIONS)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "identity_id": identity_id,
            "reviewer": reviewer,
            "decision": decision,
            "resource": data.get("resource", ""),
            "access_level": data.get("access_level", ""),
            "review_reason": data.get("review_reason", ""),
            "reviewed_at": data.get("reviewed_at", now),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO ir_access_reviews
                       (id, org_id, identity_id, reviewer, decision, resource,
                        access_level, review_reason, reviewed_at, created_at)
                       VALUES
                       (:id, :org_id, :identity_id, :reviewer, :decision, :resource,
                        :access_level, :review_reason, :reviewed_at, :created_at)""",
                    record,
                )
        return record

    def list_access_reviews(
        self,
        org_id: str,
        identity_id: Optional[str] = None,
        decision: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List access reviews with optional filters."""
        sql = "SELECT * FROM ir_access_reviews WHERE org_id = ?"
        params: list = [org_id]
        if identity_id is not None:
            sql += " AND identity_id = ?"
            params.append(identity_id)
        if decision is not None:
            sql += " AND decision = ?"
            params.append(decision)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Active Directory / Entra ID risk predicates (GAP-033)
    # ------------------------------------------------------------------

    _AD_HIGH_PRIV_GROUPS = {
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administrators",
        "account operators",
        "backup operators",
        "server operators",
        "print operators",
        "dnsadmins",
        "group policy creator owners",
    }

    @staticmethod
    def _coerce_list(value: Any) -> List[Any]:
        if value is None:
            return []
        if isinstance(value, (list, tuple, set)):
            return list(value)
        return [value]

    def kerberoastable_service_accounts(
        self, org_id: str, ad_objects: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Detect Kerberoastable service accounts.

        An object is flagged if it has a non-empty servicePrincipalName (SPN)
        AND its account is enabled AND the account is not a machine account.
        Optionally flags stronger risk when tied to a high-privilege group
        or uses a weak RC4_HMAC-only encryption type (msDS-SupportedEncryptionTypes).
        """
        if not isinstance(ad_objects, list):
            return []
        findings: List[Dict[str, Any]] = []
        for obj in ad_objects:
            if not isinstance(obj, dict):
                continue
            if obj.get("org_id") and obj.get("org_id") != org_id:
                continue
            spns = self._coerce_list(
                obj.get("servicePrincipalName") or obj.get("spn")
            )
            if not spns:
                continue
            enabled = bool(obj.get("enabled", True))
            if not enabled:
                continue
            is_machine = bool(obj.get("is_machine_account"))
            if is_machine:
                continue
            groups = [
                str(g).lower()
                for g in self._coerce_list(obj.get("memberOf") or obj.get("groups"))
            ]
            in_privileged = any(
                any(h in g for h in self._AD_HIGH_PRIV_GROUPS) for g in groups
            )
            enc_types = obj.get("msDS-SupportedEncryptionTypes")
            rc4_only = False
            try:
                if enc_types is not None:
                    enc_int = int(enc_types)
                    # 0x04 = RC4_HMAC ; anything else (AES128=0x08, AES256=0x10) is stronger
                    rc4_only = (enc_int & 0x18) == 0
            except (TypeError, ValueError):
                rc4_only = False

            severity = "high" if in_privileged or rc4_only else "medium"
            findings.append(
                {
                    "org_id": org_id,
                    "risk_type": "kerberoastable_service_account",
                    "sam_account_name": obj.get("sAMAccountName")
                    or obj.get("account_name", ""),
                    "spn_count": len(spns),
                    "spns": spns,
                    "in_privileged_group": in_privileged,
                    "rc4_only_encryption": rc4_only,
                    "severity": severity,
                    "mitre_technique": "T1558.003",
                    "explanation": (
                        "Service account has registered SPNs and is enabled — "
                        "an attacker can request a Kerberos TGS ticket and crack "
                        "the service account password offline."
                    ),
                    "remediation": (
                        "Rotate to a 25+ char random password, enforce AES-only "
                        "encryption, and consider gMSA where possible."
                    ),
                }
            )
        return findings

    def dcsync_privileges(
        self, org_id: str, ad_objects: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Detect identities that hold DCSync rights.

        Flags principals whose DACL on the domain object grants any of:
          - Replicating Directory Changes (DS-Replication-Get-Changes)
          - Replicating Directory Changes All
          - Replicating Directory Changes In Filtered Set
        Accepts either a pre-computed list of rights (field: 'extended_rights')
        or explicit booleans.
        """
        dcsync_rights = {
            "ds-replication-get-changes",
            "ds-replication-get-changes-all",
            "ds-replication-get-changes-in-filtered-set",
        }
        findings: List[Dict[str, Any]] = []
        for obj in ad_objects or []:
            if not isinstance(obj, dict):
                continue
            rights = {
                str(r).lower().strip()
                for r in self._coerce_list(obj.get("extended_rights"))
            }
            has_get = "ds-replication-get-changes" in rights or bool(
                obj.get("has_replicating_directory_changes")
            )
            has_all = "ds-replication-get-changes-all" in rights or bool(
                obj.get("has_replicating_directory_changes_all")
            )
            if not (has_get or has_all or (rights & dcsync_rights)):
                continue
            # DCSync requires BOTH rights — GetChanges-All alone still very high
            can_dcsync = has_get and has_all
            severity = "critical" if can_dcsync else "high"
            findings.append(
                {
                    "org_id": org_id,
                    "risk_type": "dcsync_privileges",
                    "principal": obj.get("sAMAccountName")
                    or obj.get("principal")
                    or obj.get("distinguishedName", ""),
                    "has_get_changes": has_get,
                    "has_get_changes_all": has_all,
                    "can_dcsync": can_dcsync,
                    "severity": severity,
                    "mitre_technique": "T1003.006",
                    "explanation": (
                        "Principal holds directory replication rights — can "
                        "dump NTDS.dit (krbtgt, all password hashes) from any "
                        "domain controller without interactive login."
                    ),
                    "remediation": (
                        "Remove GetChanges / GetChangesAll from non-tier-0 "
                        "principals. Audit with Repadmin /showobjmeta. Only "
                        "Domain Admins and AAD Connect should have this."
                    ),
                }
            )
        return findings

    def admin_count_attribute_mismatch(
        self, org_id: str, ad_objects: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Find stale adminCount=1 objects that are no longer protected.

        adminCount=1 is set when an object is a member of a protected group,
        but AD does NOT clear it when the object is removed. Result: stale
        ACLs + inheritance disabled on an ordinary account = privilege
        carry-over risk (shadow admin).
        """
        findings: List[Dict[str, Any]] = []
        for obj in ad_objects or []:
            if not isinstance(obj, dict):
                continue
            admin_count = obj.get("adminCount") or obj.get("admin_count")
            try:
                admin_count_val = int(admin_count) if admin_count is not None else 0
            except (TypeError, ValueError):
                admin_count_val = 0
            if admin_count_val != 1:
                continue
            groups = [
                str(g).lower()
                for g in self._coerce_list(obj.get("memberOf") or obj.get("groups"))
            ]
            in_protected = any(
                any(h in g for h in self._AD_HIGH_PRIV_GROUPS) for g in groups
            )
            # Mismatch = adminCount=1 but NOT currently in a protected group
            if in_protected:
                continue
            findings.append(
                {
                    "org_id": org_id,
                    "risk_type": "admin_count_attribute_mismatch",
                    "principal": obj.get("sAMAccountName")
                    or obj.get("distinguishedName", ""),
                    "admin_count": admin_count_val,
                    "currently_protected": False,
                    "severity": "high",
                    "mitre_technique": "T1078.002",
                    "explanation": (
                        "Object has adminCount=1 but is no longer a member "
                        "of any protected group. Legacy ACLs and disabled "
                        "inheritance may still grant elevated privileges."
                    ),
                    "remediation": (
                        "Reset adminCount to 0, re-enable ACL inheritance "
                        "with dsacls, and re-validate effective permissions."
                    ),
                }
            )
        return findings

    def unconstrained_delegation(
        self, org_id: str, ad_objects: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Detect accounts trusted for unconstrained Kerberos delegation.

        userAccountControl bit TRUSTED_FOR_DELEGATION (0x80000 / 524288)
        allows the account's host to impersonate any user that authenticates
        to it — a direct path to Domain Admin compromise.
        """
        UAC_TRUSTED_FOR_DELEGATION = 0x80000  # 524288
        UAC_NOT_DELEGATED = 0x100000  # 1048576 — sensitive accounts should set this
        findings: List[Dict[str, Any]] = []
        for obj in ad_objects or []:
            if not isinstance(obj, dict):
                continue
            uac = obj.get("userAccountControl") or obj.get("uac") or 0
            try:
                uac_int = int(uac)
            except (TypeError, ValueError):
                continue
            if not (uac_int & UAC_TRUSTED_FOR_DELEGATION):
                continue
            is_dc = bool(obj.get("is_domain_controller"))
            if is_dc:
                # DCs legitimately have this flag — skip unless caller forces
                continue
            findings.append(
                {
                    "org_id": org_id,
                    "risk_type": "unconstrained_delegation",
                    "principal": obj.get("sAMAccountName")
                    or obj.get("dnsHostName")
                    or obj.get("distinguishedName", ""),
                    "uac_value": uac_int,
                    "trusted_for_delegation": True,
                    "sensitive_protected": bool(uac_int & UAC_NOT_DELEGATED),
                    "severity": "critical",
                    "mitre_technique": "T1558.001",
                    "explanation": (
                        "Account has TRUSTED_FOR_DELEGATION (0x80000) set. "
                        "Any user authenticating to this host has their TGT "
                        "cached and can be extracted to impersonate Domain "
                        "Admins when they connect (Printer Bug / SpoolSample)."
                    ),
                    "remediation": (
                        "Replace with constrained or resource-based constrained "
                        "delegation. Add high-privilege accounts to 'Protected "
                        "Users' group and set 'Account is sensitive and cannot "
                        "be delegated' (UAC 0x100000)."
                    ),
                }
            )
        return findings

    def evaluate_ad_risks(
        self, org_id: str, ad_objects: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Run all AD predicates against a snapshot and return a combined report."""
        kerb = self.kerberoastable_service_accounts(org_id, ad_objects)
        dcsync = self.dcsync_privileges(org_id, ad_objects)
        admin_mis = self.admin_count_attribute_mismatch(org_id, ad_objects)
        uncon = self.unconstrained_delegation(org_id, ad_objects)
        all_findings = kerb + dcsync + admin_mis + uncon
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in all_findings:
            sev = f.get("severity", "medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        return {
            "org_id": org_id,
            "analysed_at": _now_iso(),
            "objects_evaluated": len(ad_objects or []),
            "kerberoastable_count": len(kerb),
            "dcsync_count": len(dcsync),
            "admin_count_mismatch_count": len(admin_mis),
            "unconstrained_delegation_count": len(uncon),
            "total_findings": len(all_findings),
            "severity_breakdown": severity_counts,
            "findings": all_findings,
        }

    def get_identity_risk_stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregated identity risk statistics for an org."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM ir_identities WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            high_risk = conn.execute(
                "SELECT COUNT(*) FROM ir_identities WHERE org_id = ? AND risk_score >= 60",
                (org_id,),
            ).fetchone()[0]

            mfa_count = conn.execute(
                "SELECT COUNT(*) FROM ir_identities WHERE org_id = ? AND mfa_enabled = 1",
                (org_id,),
            ).fetchone()[0]

            active_factors = conn.execute(
                "SELECT COUNT(*) FROM ir_risk_factors WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            critical_factors = conn.execute(
                "SELECT COUNT(*) FROM ir_risk_factors WHERE org_id = ? AND severity = 'critical'",
                (org_id,),
            ).fetchone()[0]

            avg_score_row = conn.execute(
                "SELECT AVG(risk_score) FROM ir_identities WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            avg_risk_score = round(float(avg_score_row), 2) if avg_score_row else 0.0

            type_rows = conn.execute(
                """SELECT identity_type, COUNT(*) as cnt
                   FROM ir_identities WHERE org_id = ?
                   GROUP BY identity_type""",
                (org_id,),
            ).fetchall()
            by_identity_type = {r["identity_type"]: r["cnt"] for r in type_rows}

            level_rows = conn.execute(
                """SELECT risk_level, COUNT(*) as cnt
                   FROM ir_identities WHERE org_id = ?
                   GROUP BY risk_level""",
                (org_id,),
            ).fetchall()
            by_risk_level = {r["risk_level"]: r["cnt"] for r in level_rows}

        return {
            "total_identities": total,
            "high_risk_identities": high_risk,
            "mfa_enabled_count": mfa_count,
            "active_risk_factors": active_factors,
            "critical_factors": critical_factors,
            "avg_risk_score": avg_risk_score,
            "by_identity_type": by_identity_type,
            "by_risk_level": by_risk_level,
        }
