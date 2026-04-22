"""ITDR Engine — ALDECI (Identity Threat Detection and Response).

Detects and responds to identity-based attacks: credential stuffing,
account takeover, privilege abuse, lateral movement via compromised identities.

Capabilities:
  - Threat detection: 8 threat types with confidence scoring
  - Behavior recording: user activity anomaly tracking
  - Response actions: 7 action types with execution lifecycle
  - Stats: totals, by type/severity, active threats, high-risk users

Compliance: NIST SP 800-63B, ISO 27001 A.9 (Access Control), MITRE ATT&CK TA0006
"""

from __future__ import annotations

import json
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

_VALID_THREAT_TYPES = {
    "credential_stuffing",
    "account_takeover",
    "privilege_abuse",
    "lateral_movement",
    "impossible_travel",
    "mfa_bypass",
    "session_hijacking",
    "password_spray",
}

_VALID_SEVERITIES = {"critical", "high", "medium", "low"}

_VALID_THREAT_STATUSES = {
    "detected",
    "investigating",
    "confirmed",
    "false_positive",
    "contained",
}

_VALID_BEHAVIOR_TYPES = {
    "login_attempt",
    "failed_login",
    "mfa_challenge",
    "privilege_escalation",
    "data_access",
    "lateral_move",
    "anomalous_time",
    "new_location",
}

_VALID_ACTION_TYPES = {
    "block_ip",
    "force_mfa",
    "disable_account",
    "revoke_session",
    "alert_security",
    "reset_password",
    "notify_user",
}

_VALID_ACTION_STATUSES = {"pending", "executed", "failed", "cancelled"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ITDREngine:
    """SQLite WAL-backed Identity Threat Detection and Response engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/itdr.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "itdr.db")
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
                CREATE TABLE IF NOT EXISTS identity_threats (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    user_id     TEXT NOT NULL,
                    source_ip   TEXT NOT NULL DEFAULT '',
                    severity    TEXT NOT NULL DEFAULT 'medium',
                    confidence  REAL NOT NULL DEFAULT 50.0,
                    status      TEXT NOT NULL DEFAULT 'detected',
                    indicators  TEXT NOT NULL DEFAULT '[]',
                    detected_at TEXT NOT NULL,
                    updated_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_threats_org
                    ON identity_threats (org_id, threat_type, status, severity, detected_at DESC);

                CREATE TABLE IF NOT EXISTS identity_behaviors (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    user_id       TEXT NOT NULL,
                    behavior_type TEXT NOT NULL,
                    risk_score    INTEGER NOT NULL DEFAULT 50,
                    details       TEXT NOT NULL DEFAULT '{}',
                    recorded_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_behaviors_org
                    ON identity_behaviors (org_id, user_id, behavior_type, recorded_at DESC);

                CREATE TABLE IF NOT EXISTS response_actions (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    threat_id   TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    status      TEXT NOT NULL DEFAULT 'pending',
                    executed_at TEXT,
                    notes       TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_actions_org
                    ON response_actions (org_id, threat_id, status);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        # Parse JSON fields
        for field in ("indicators", "details"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    # ------------------------------------------------------------------
    # Threats
    # ------------------------------------------------------------------

    def detect_threat(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a new identity threat detection."""
        threat_type = data.get("threat_type", "")
        if threat_type not in _VALID_THREAT_TYPES:
            raise ValueError(
                f"Invalid threat_type: {threat_type!r}. "
                f"Must be one of {sorted(_VALID_THREAT_TYPES)}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity!r}. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        user_id = (data.get("user_id") or "").strip()
        if not user_id:
            raise ValueError("user_id is required.")

        try:
            confidence = float(data.get("confidence", 50.0))
        except (TypeError, ValueError):
            raise ValueError("confidence must be a number between 0 and 100.")
        confidence = max(0.0, min(100.0, confidence))

        indicators = data.get("indicators", [])
        if not isinstance(indicators, list):
            indicators = []

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "threat_type": threat_type,
            "user_id": user_id,
            "source_ip": data.get("source_ip", ""),
            "severity": severity,
            "confidence": confidence,
            "status": "detected",
            "indicators": json.dumps(indicators),
            "detected_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO identity_threats
                       (id, org_id, threat_type, user_id, source_ip, severity,
                        confidence, status, indicators, detected_at, updated_at)
                       VALUES (:id, :org_id, :threat_type, :user_id, :source_ip, :severity,
                               :confidence, :status, :indicators, :detected_at, :updated_at)""",
                    record,
                )
        # Return with parsed indicators
        record["indicators"] = indicators
        return record

    def list_threats(
        self,
        org_id: str,
        threat_type: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List identity threats with optional filters."""
        sql = "SELECT * FROM identity_threats WHERE org_id = ?"
        params: list = [org_id]
        if threat_type:
            sql += " AND threat_type = ?"
            params.append(threat_type)
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY detected_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_threat(self, org_id: str, threat_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single threat by ID. Returns None if not found or wrong org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM identity_threats WHERE org_id = ? AND id = ?",
                (org_id, threat_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_threat_status(
        self, org_id: str, threat_id: str, new_status: str
    ) -> Dict[str, Any]:
        """Update the status of a threat. Raises KeyError if not found."""
        if new_status not in _VALID_THREAT_STATUSES:
            raise ValueError(
                f"Invalid status: {new_status!r}. "
                f"Must be one of {sorted(_VALID_THREAT_STATUSES)}"
            )
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE identity_threats SET status = ?, updated_at = ? "
                    "WHERE org_id = ? AND id = ?",
                    (new_status, now, org_id, threat_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(f"Threat not found: {threat_id}")
                row = conn.execute(
                    "SELECT * FROM identity_threats WHERE org_id = ? AND id = ?",
                    (org_id, threat_id),
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Behaviors
    # ------------------------------------------------------------------

    def record_behavior(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record an identity behavior event."""
        user_id = (data.get("user_id") or "").strip()
        if not user_id:
            raise ValueError("user_id is required.")

        behavior_type = data.get("behavior_type", "")
        if behavior_type not in _VALID_BEHAVIOR_TYPES:
            raise ValueError(
                f"Invalid behavior_type: {behavior_type!r}. "
                f"Must be one of {sorted(_VALID_BEHAVIOR_TYPES)}"
            )

        try:
            risk_score = int(data.get("risk_score", 50))
        except (TypeError, ValueError):
            raise ValueError("risk_score must be an integer between 0 and 100.")
        risk_score = max(0, min(100, risk_score))

        details = data.get("details", {})
        if not isinstance(details, dict):
            details = {}

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "user_id": user_id,
            "behavior_type": behavior_type,
            "risk_score": risk_score,
            "details": json.dumps(details),
            "recorded_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO identity_behaviors
                       (id, org_id, user_id, behavior_type, risk_score, details, recorded_at)
                       VALUES (:id, :org_id, :user_id, :behavior_type, :risk_score,
                               :details, :recorded_at)""",
                    record,
                )
        record["details"] = details
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "itdr", "org_id": org_id, "source_engine": "itdr"})
            except Exception:
                pass

        return record

    def list_behaviors(
        self,
        org_id: str,
        user_id: Optional[str] = None,
        behavior_type: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List identity behaviors with optional filters."""
        sql = "SELECT * FROM identity_behaviors WHERE org_id = ?"
        params: list = [org_id]
        if user_id:
            sql += " AND user_id = ?"
            params.append(user_id)
        if behavior_type:
            sql += " AND behavior_type = ?"
            params.append(behavior_type)
        sql += " ORDER BY recorded_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Response Actions
    # ------------------------------------------------------------------

    def create_response_action(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a response action for a threat."""
        threat_id = (data.get("threat_id") or "").strip()
        if not threat_id:
            raise ValueError("threat_id is required.")

        # Validate threat exists in org
        threat = self.get_threat(org_id, threat_id)
        if not threat:
            raise ValueError(f"Threat not found: {threat_id}")

        action_type = data.get("action_type", "")
        if action_type not in _VALID_ACTION_TYPES:
            raise ValueError(
                f"Invalid action_type: {action_type!r}. "
                f"Must be one of {sorted(_VALID_ACTION_TYPES)}"
            )

        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "threat_id": threat_id,
            "action_type": action_type,
            "status": "pending",
            "executed_at": None,
            "notes": data.get("notes", ""),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO response_actions
                       (id, org_id, threat_id, action_type, status, executed_at, notes)
                       VALUES (:id, :org_id, :threat_id, :action_type, :status,
                               :executed_at, :notes)""",
                    record,
                )
        return record

    def execute_response_action(
        self, org_id: str, action_id: str
    ) -> Dict[str, Any]:
        """Mark a response action as executed. Raises KeyError if not found or wrong org."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE response_actions SET status = 'executed', executed_at = ? "
                    "WHERE org_id = ? AND id = ?",
                    (now, org_id, action_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(f"Response action not found: {action_id}")
                row = conn.execute(
                    "SELECT * FROM response_actions WHERE org_id = ? AND id = ?",
                    (org_id, action_id),
                ).fetchone()
        return self._row(row)

    def list_response_actions(
        self,
        org_id: str,
        threat_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List response actions with optional filters."""
        sql = "SELECT * FROM response_actions WHERE org_id = ?"
        params: list = [org_id]
        if threat_id:
            sql += " AND threat_id = ?"
            params.append(threat_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY rowid DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # AD attack detection (GAP-033 MERGE) — ADCS ESC + ticket attacks
    # ------------------------------------------------------------------

    # Dangerous AD CS template flags / EKUs
    _ADCS_ANY_PURPOSE_EKU = "2.5.29.37.0"
    _ADCS_CLIENT_AUTH_EKU = "1.3.6.1.5.5.7.3.2"
    _ADCS_SMART_CARD_LOGON_EKU = "1.3.6.1.4.1.311.20.2.2"
    # msPKI-Certificate-Name-Flag bit: ENROLLEE_SUPPLIES_SUBJECT = 1
    _ADCS_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001

    def esc1_template_misconfig(
        self, org_id: str, templates: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Detect AD CS ESC1 — templates that allow enrollee-supplied subject + client auth.

        ESC1 conditions (all must hold):
          1. manager_approval = False
          2. EKU permits client auth (Client Auth, Smart Card Logon, or Any Purpose)
          3. msPKI-Certificate-Name-Flag has ENROLLEE_SUPPLIES_SUBJECT (bit 0x1)
          4. Low-priv principal has 'Enroll' extended right
        """
        findings: List[Dict[str, Any]] = []
        client_auth_ekus = {
            self._ADCS_ANY_PURPOSE_EKU,
            self._ADCS_CLIENT_AUTH_EKU,
            self._ADCS_SMART_CARD_LOGON_EKU,
        }
        for tpl in templates or []:
            if not isinstance(tpl, dict):
                continue
            manager_approval = bool(tpl.get("manager_approval", False))
            if manager_approval:
                continue
            ekus = {str(e) for e in tpl.get("ekus", [])}
            # Some callers pass friendly names too
            friendly = {str(e).lower() for e in tpl.get("ekus", [])}
            has_client_auth = bool(ekus & client_auth_ekus) or (
                "client authentication" in friendly
                or "smart card logon" in friendly
                or "any purpose" in friendly
            )
            if not has_client_auth:
                continue
            name_flag = tpl.get("msPKI_Certificate_Name_Flag") or tpl.get(
                "name_flag", 0
            )
            try:
                name_flag_int = int(name_flag)
            except (TypeError, ValueError):
                name_flag_int = 0
            enrollee_subject = bool(
                name_flag_int & self._ADCS_ENROLLEE_SUPPLIES_SUBJECT
            ) or bool(tpl.get("enrollee_supplies_subject"))
            if not enrollee_subject:
                continue
            low_priv_enroll = bool(tpl.get("low_priv_enroll_allowed", True))
            if not low_priv_enroll:
                continue
            findings.append(
                {
                    "org_id": org_id,
                    "rule": "esc1_template_misconfig",
                    "template_name": tpl.get("name", ""),
                    "template_oid": tpl.get("oid", ""),
                    "severity": "critical",
                    "mitre_technique": "T1649",
                    "explanation": (
                        "ADCS ESC1: template allows enrollee-supplied subject "
                        "+ client auth EKU + no manager approval + low-priv "
                        "enrollment. Any authenticated user can request a "
                        "certificate impersonating Domain Admin."
                    ),
                    "remediation": (
                        "Disable ENROLLEE_SUPPLIES_SUBJECT on the template OR "
                        "require manager approval OR restrict Enroll permission."
                    ),
                }
            )
        return findings

    def esc4_vulnerable_acl(
        self, org_id: str, templates: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Detect AD CS ESC4 — low-priv principals with write ACLs on certificate templates.

        If a non-admin has Write, WriteDACL, WriteOwner, or FullControl on a
        template they can re-configure it to be ESC1-exploitable.
        """
        dangerous_rights = {
            "write", "writedacl", "writeowner", "fullcontrol", "genericall",
            "generic_write",
        }
        findings: List[Dict[str, Any]] = []
        for tpl in templates or []:
            if not isinstance(tpl, dict):
                continue
            acl_entries = tpl.get("acl") or tpl.get("dacl") or []
            if not isinstance(acl_entries, list):
                continue
            for ace in acl_entries:
                if not isinstance(ace, dict):
                    continue
                principal = (
                    ace.get("principal")
                    or ace.get("sid")
                    or ace.get("trustee", "")
                )
                principal_lc = str(principal).lower()
                if any(
                    p in principal_lc
                    for p in (
                        "domain admins",
                        "enterprise admins",
                        "administrators",
                        "s-1-5-18",  # LocalSystem
                        "s-1-5-32-544",  # BUILTIN\Administrators
                    )
                ):
                    continue
                rights = {
                    str(r).lower().strip() for r in ace.get("rights", [])
                }
                if rights & dangerous_rights:
                    findings.append(
                        {
                            "org_id": org_id,
                            "rule": "esc4_vulnerable_acl",
                            "template_name": tpl.get("name", ""),
                            "principal": principal,
                            "dangerous_rights": sorted(rights & dangerous_rights),
                            "severity": "high",
                            "mitre_technique": "T1484.001",
                            "explanation": (
                                "Low-privilege principal has write-level ACL "
                                "on an ADCS template. They can rewrite the "
                                "template into an ESC1 configuration and "
                                "impersonate any user."
                            ),
                            "remediation": (
                                "Remove Write/WriteDACL/WriteOwner/FullControl "
                                "from non-administrative principals on this "
                                "template."
                            ),
                        }
                    )
        return findings

    def golden_ticket_heuristic(
        self, org_id: str, auth_events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Heuristic detector for Golden Ticket (forged Kerberos TGT) usage.

        Signals (any two = flag):
          - Event 4624 with logon type 3 but no preceding 4768 TGT request
          - TGT lifetime > domain policy (default 10h) — e.g. 10 years
          - Anomalous account (e.g. krbtgt, SYSTEM, or non-existent SID)
          - Ticket encryption type RC4 (0x17) when AES-only is enforced
        """
        findings: List[Dict[str, Any]] = []
        for event in auth_events or []:
            if not isinstance(event, dict):
                continue
            signals: List[str] = []
            # 1. Network logon (type 3) without a prior TGT request
            if (
                int(event.get("event_id", 0) or 0) == 4624
                and int(event.get("logon_type", 0) or 0) == 3
                and not event.get("had_prior_tgt_request", True)
            ):
                signals.append("network_logon_without_tgt_request")
            # 2. TGT lifetime > policy
            lifetime = event.get("tgt_lifetime_hours")
            policy_max = int(event.get("policy_max_tgt_hours", 10) or 10)
            if lifetime is not None:
                try:
                    if float(lifetime) > policy_max:
                        signals.append(f"tgt_lifetime_{int(float(lifetime))}h_exceeds_policy")
                except (TypeError, ValueError):
                    pass
            # 3. Nonexistent / suspicious account
            if event.get("account_exists") is False:
                signals.append("nonexistent_account_in_ticket")
            if str(event.get("account_name", "")).lower() == "krbtgt":
                signals.append("krbtgt_account_usage")
            # 4. RC4 when AES-only
            enc = str(event.get("encryption_type", "")).lower()
            if enc in ("rc4", "0x17", "rc4_hmac") and event.get(
                "aes_only_required"
            ):
                signals.append("rc4_ticket_when_aes_required")

            if len(signals) >= 2:
                findings.append(
                    {
                        "org_id": org_id,
                        "rule": "golden_ticket_heuristic",
                        "event_id": event.get("event_id"),
                        "account_name": event.get("account_name", ""),
                        "signals": signals,
                        "severity": "critical",
                        "mitre_technique": "T1558.001",
                        "explanation": (
                            "Multiple Kerberos anomalies consistent with a "
                            "forged TGT (Golden Ticket). Attackers use this to "
                            "maintain persistent domain dominance."
                        ),
                        "remediation": (
                            "Rotate the krbtgt password TWICE (at least 10h "
                            "apart). Investigate all authentications from the "
                            "affected account. Force AES-only Kerberos."
                        ),
                    }
                )
        return findings

    def skeleton_key_heuristic(
        self, org_id: str, auth_events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Heuristic detector for Skeleton Key malware implant on a DC.

        Signals:
          - Successful logon using a password that was never reset in AD
            (password-hash mismatch flag from DC audit)
          - Kerberos downgrade to RC4_HMAC_MD5 for accounts whose
            msDS-SupportedEncryptionTypes excludes RC4
          - lsass.exe handle modification event (4673) by non-SYSTEM
          - WMI call to inject into lsass
        """
        findings: List[Dict[str, Any]] = []
        for event in auth_events or []:
            if not isinstance(event, dict):
                continue
            signals: List[str] = []
            if event.get("password_hash_mismatch"):
                signals.append("password_hash_mismatch_on_successful_auth")
            enc = str(event.get("encryption_type", "")).lower()
            if enc in ("rc4", "rc4_hmac", "0x17") and bool(
                event.get("account_disallows_rc4")
            ):
                signals.append("rc4_downgrade_on_aes_only_account")
            if (
                int(event.get("event_id", 0) or 0) == 4673
                and str(event.get("target_process", "")).lower() == "lsass.exe"
                and str(event.get("subject_sid", "")) not in ("S-1-5-18", "")
            ):
                signals.append("non_system_handle_to_lsass")
            if event.get("wmi_injection_lsass"):
                signals.append("wmi_injection_into_lsass")

            if signals:
                # Require ≥1 DC-specific signal (mismatch, rc4 downgrade) OR
                # lsass injection to avoid noise
                dc_signal = any(
                    s in signals
                    for s in (
                        "password_hash_mismatch_on_successful_auth",
                        "rc4_downgrade_on_aes_only_account",
                        "non_system_handle_to_lsass",
                        "wmi_injection_into_lsass",
                    )
                )
                if not dc_signal:
                    continue
                findings.append(
                    {
                        "org_id": org_id,
                        "rule": "skeleton_key_heuristic",
                        "event_id": event.get("event_id"),
                        "host": event.get("host", ""),
                        "signals": signals,
                        "severity": "critical",
                        "mitre_technique": "T1556.001",
                        "explanation": (
                            "Indicators consistent with a Skeleton Key implant "
                            "on a domain controller — attacker can authenticate "
                            "as any domain user with a master password."
                        ),
                        "remediation": (
                            "Isolate the DC. Reboot (Skeleton Key is memory-only "
                            "and does not survive reboot). Reset krbtgt twice. "
                            "Audit for persistence mechanisms."
                        ),
                    }
                )
        return findings

    def detect_ad_attacks(
        self,
        org_id: str,
        templates: Optional[List[Dict[str, Any]]] = None,
        auth_events: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Run all AD attack rules and return aggregated findings."""
        templates = templates or []
        auth_events = auth_events or []
        esc1 = self.esc1_template_misconfig(org_id, templates)
        esc4 = self.esc4_vulnerable_acl(org_id, templates)
        golden = self.golden_ticket_heuristic(org_id, auth_events)
        skeleton = self.skeleton_key_heuristic(org_id, auth_events)
        all_findings = esc1 + esc4 + golden + skeleton
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in all_findings:
            sev = f.get("severity", "medium")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        return {
            "org_id": org_id,
            "analysed_at": _now_iso(),
            "esc1_count": len(esc1),
            "esc4_count": len(esc4),
            "golden_ticket_count": len(golden),
            "skeleton_key_count": len(skeleton),
            "total_findings": len(all_findings),
            "severity_breakdown": sev_counts,
            "findings": all_findings,
        }

    def get_itdr_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated ITDR statistics for an org."""
        with self._conn() as conn:
            total_threats = conn.execute(
                "SELECT COUNT(*) FROM identity_threats WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT threat_type, COUNT(*) as cnt FROM identity_threats "
                "WHERE org_id = ? GROUP BY threat_type",
                (org_id,),
            ).fetchall()
            by_type = {r["threat_type"]: r["cnt"] for r in type_rows}

            active_threats = conn.execute(
                "SELECT COUNT(*) FROM identity_threats "
                "WHERE org_id = ? AND status IN ('detected', 'investigating', 'confirmed')",
                (org_id,),
            ).fetchone()[0]

            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM identity_threats "
                "WHERE org_id = ? GROUP BY severity",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

            total_behaviors = conn.execute(
                "SELECT COUNT(*) FROM identity_behaviors WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            pending_actions = conn.execute(
                "SELECT COUNT(*) FROM response_actions WHERE org_id = ? AND status = 'pending'",
                (org_id,),
            ).fetchone()[0]

            high_risk_users = conn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM identity_behaviors "
                "WHERE org_id = ? AND risk_score >= 80",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_threats": total_threats,
            "by_type": by_type,
            "active_threats": active_threats,
            "by_severity": by_severity,
            "total_behaviors": total_behaviors,
            "pending_actions": pending_actions,
            "high_risk_users": high_risk_users,
        }
