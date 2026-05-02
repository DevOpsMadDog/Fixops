"""Compliance Evidence Collector Engine — ALDECI.

Automatically collects and organises compliance evidence for audits.
Supports SOC2, ISO27001, PCI-DSS, and HIPAA frameworks.

Compliance: ISO/IEC 27001 A.18.2, SOC 2 CC2.2, NIST CSF ID.GV-1
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "compliance_evidence.db"
)

_VALID_FRAMEWORKS = {"SOC2", "ISO27001", "PCI-DSS", "HIPAA"}
_VALID_STATUSES = {"pending", "collecting", "submitted", "approved", "rejected"}
_VALID_EVIDENCE_TYPES = {"document", "screenshot", "log", "config", "attestation"}

# Auto-collect source systems per framework
_AUTO_COLLECT_SOURCES: Dict[str, List[Dict[str, Any]]] = {
    "SOC2": [
        {"source_system": "IAM", "control_id": "CC6.1", "control_name": "Logical Access Controls", "evidence_type": "config"},
        {"source_system": "SIEM", "control_id": "CC7.2", "control_name": "Security Event Monitoring", "evidence_type": "log"},
        {"source_system": "Vulnerability Scanner", "control_id": "CC7.1", "control_name": "Vulnerability Management", "evidence_type": "document"},
        {"source_system": "Change Management", "control_id": "CC8.1", "control_name": "Change Control Process", "evidence_type": "document"},
        {"source_system": "Backup System", "control_id": "A1.2", "control_name": "Backup and Recovery", "evidence_type": "log"},
    ],
    "ISO27001": [
        {"source_system": "Asset Management", "control_id": "A.8.1", "control_name": "Inventory of Assets", "evidence_type": "document"},
        {"source_system": "Access Control", "control_id": "A.9.1", "control_name": "Access Control Policy", "evidence_type": "config"},
        {"source_system": "Incident Management", "control_id": "A.16.1", "control_name": "Incident Response", "evidence_type": "log"},
        {"source_system": "Risk Register", "control_id": "A.6.1", "control_name": "Risk Assessment", "evidence_type": "document"},
        {"source_system": "Supplier Contracts", "control_id": "A.15.1", "control_name": "Supplier Relationships", "evidence_type": "document"},
    ],
    "PCI-DSS": [
        {"source_system": "Firewall", "control_id": "Req-1", "control_name": "Install and Maintain Network Security Controls", "evidence_type": "config"},
        {"source_system": "Encryption", "control_id": "Req-3", "control_name": "Protect Stored Account Data", "evidence_type": "config"},
        {"source_system": "Antivirus", "control_id": "Req-5", "control_name": "Protect All Systems Against Malware", "evidence_type": "log"},
        {"source_system": "Access Control", "control_id": "Req-7", "control_name": "Restrict Access to System Components", "evidence_type": "config"},
        {"source_system": "Audit Logs", "control_id": "Req-10", "control_name": "Log and Monitor All Access", "evidence_type": "log"},
    ],
    "HIPAA": [
        {"source_system": "EHR System", "control_id": "164.312(a)", "control_name": "Access Control", "evidence_type": "config"},
        {"source_system": "Audit System", "control_id": "164.312(b)", "control_name": "Audit Controls", "evidence_type": "log"},
        {"source_system": "Encryption Layer", "control_id": "164.312(e)", "control_name": "Transmission Security", "evidence_type": "config"},
        {"source_system": "Training Platform", "control_id": "164.308(a)(5)", "control_name": "Security Awareness Training", "evidence_type": "attestation"},
        {"source_system": "BAA Repository", "control_id": "164.308(b)", "control_name": "Business Associate Contracts", "evidence_type": "document"},
    ],
}


class ComplianceEvidenceCollector:
    """SQLite WAL-backed Compliance Evidence Collector.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS evidence_requests (
                    request_id    TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    framework     TEXT NOT NULL DEFAULT 'SOC2',
                    control_id    TEXT NOT NULL DEFAULT '',
                    control_name  TEXT NOT NULL DEFAULT '',
                    description   TEXT NOT NULL DEFAULT '',
                    due_date      TEXT NOT NULL DEFAULT '',
                    assignee      TEXT NOT NULL DEFAULT '',
                    status        TEXT NOT NULL DEFAULT 'pending',
                    created_at    TEXT NOT NULL,
                    updated_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_er_org
                    ON evidence_requests (org_id, framework, status);

                CREATE TABLE IF NOT EXISTS evidence_items (
                    evidence_id      TEXT PRIMARY KEY,
                    request_id       TEXT NOT NULL,
                    org_id           TEXT NOT NULL,
                    evidence_type    TEXT NOT NULL DEFAULT 'document',
                    filename         TEXT NOT NULL DEFAULT '',
                    content_summary  TEXT NOT NULL DEFAULT '',
                    source_system    TEXT NOT NULL DEFAULT '',
                    collected_at     TEXT NOT NULL,
                    auto_collected   INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY (request_id) REFERENCES evidence_requests(request_id)
                );

                CREATE INDEX IF NOT EXISTS idx_ei_request
                    ON evidence_items (request_id, org_id);

                CREATE TABLE IF NOT EXISTS evidence_approvals (
                    approval_id   TEXT PRIMARY KEY,
                    request_id    TEXT NOT NULL,
                    org_id        TEXT NOT NULL,
                    action        TEXT NOT NULL,
                    actor         TEXT NOT NULL DEFAULT '',
                    notes         TEXT NOT NULL DEFAULT '',
                    created_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ea_request
                    ON evidence_approvals (request_id, org_id);
                """
            )

    # ------------------------------------------------------------------
    # Evidence Requests
    # ------------------------------------------------------------------

    def create_evidence_request(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new evidence collection request."""
        framework = data.get("framework", "SOC2")
        if framework not in _VALID_FRAMEWORKS:
            raise ValueError(f"Invalid framework: {framework}. Must be one of {_VALID_FRAMEWORKS}")

        request_id = str(uuid.uuid4())
        now = self._now()
        row = {
            "request_id": request_id,
            "org_id": org_id,
            "framework": framework,
            "control_id": data.get("control_id", ""),
            "control_name": data.get("control_name", ""),
            "description": data.get("description", ""),
            "due_date": data.get("due_date", ""),
            "assignee": data.get("assignee", ""),
            "status": "pending",
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO evidence_requests
                       (request_id,org_id,framework,control_id,control_name,
                        description,due_date,assignee,status,created_at,updated_at)
                       VALUES (:request_id,:org_id,:framework,:control_id,:control_name,
                               :description,:due_date,:assignee,:status,:created_at,:updated_at)""",
                    row,
                )
        _logger.info("Created evidence request %s for org %s framework %s", request_id, org_id, framework)
        return dict(row)

    def list_evidence_requests(
        self,
        org_id: str,
        framework: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List evidence requests, optionally filtered by framework and status."""
        query = "SELECT * FROM evidence_requests WHERE org_id = ?"
        params: list = [org_id]
        if framework:
            query += " AND framework = ?"
            params.append(framework)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def _get_request(self, conn: sqlite3.Connection, org_id: str, request_id: str) -> Dict[str, Any]:
        row = conn.execute(
            "SELECT * FROM evidence_requests WHERE request_id = ? AND org_id = ?",
            (request_id, org_id),
        ).fetchone()
        if not row:
            raise ValueError(f"Evidence request {request_id} not found for org {org_id}")
        return dict(row)

    # ------------------------------------------------------------------
    # Evidence Items
    # ------------------------------------------------------------------

    def submit_evidence(self, org_id: str, request_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Submit evidence for a request."""
        evidence_type = data.get("evidence_type", "document")
        if evidence_type not in _VALID_EVIDENCE_TYPES:
            raise ValueError(f"Invalid evidence_type: {evidence_type}. Must be one of {_VALID_EVIDENCE_TYPES}")

        evidence_id = str(uuid.uuid4())
        now = self._now()
        row = {
            "evidence_id": evidence_id,
            "request_id": request_id,
            "org_id": org_id,
            "evidence_type": evidence_type,
            "filename": data.get("filename", ""),
            "content_summary": data.get("content_summary", ""),
            "source_system": data.get("source_system", ""),
            "collected_at": data.get("collected_at", now),
            "auto_collected": 0,
        }
        with self._lock:
            with self._conn() as conn:
                # Verify request exists and belongs to org
                self._get_request(conn, org_id, request_id)
                conn.execute(
                    """INSERT INTO evidence_items
                       (evidence_id,request_id,org_id,evidence_type,filename,
                        content_summary,source_system,collected_at,auto_collected)
                       VALUES (:evidence_id,:request_id,:org_id,:evidence_type,:filename,
                               :content_summary,:source_system,:collected_at,:auto_collected)""",
                    row,
                )
                # Advance status to collecting if still pending
                conn.execute(
                    """UPDATE evidence_requests SET status='collecting', updated_at=?
                       WHERE request_id=? AND org_id=? AND status='pending'""",
                    (now, request_id, org_id),
                )
        return dict(row)

    def list_evidence(self, org_id: str, request_id: str) -> List[Dict[str, Any]]:
        """List all evidence items for a request."""
        with self._conn() as conn:
            self._get_request(conn, org_id, request_id)
            rows = conn.execute(
                "SELECT * FROM evidence_items WHERE request_id=? AND org_id=? ORDER BY collected_at DESC",
                (request_id, org_id),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Approve / Reject
    # ------------------------------------------------------------------

    def approve_evidence(
        self, org_id: str, request_id: str, approved_by: str, notes: str = ""
    ) -> Dict[str, Any]:
        """Approve evidence for a request."""
        now = self._now()
        approval_id = str(uuid.uuid4())
        with self._lock:
            with self._conn() as conn:
                self._get_request(conn, org_id, request_id)
                conn.execute(
                    "UPDATE evidence_requests SET status='approved', updated_at=? WHERE request_id=? AND org_id=?",
                    (now, request_id, org_id),
                )
                conn.execute(
                    """INSERT INTO evidence_approvals
                       (approval_id,request_id,org_id,action,actor,notes,created_at)
                       VALUES (?,?,?,'approved',?,?,?)""",
                    (approval_id, request_id, org_id, approved_by, notes, now),
                )
        return {"approval_id": approval_id, "request_id": request_id, "action": "approved", "approved_by": approved_by}

    def reject_evidence(
        self, org_id: str, request_id: str, rejected_by: str, reason: str = ""
    ) -> Dict[str, Any]:
        """Reject evidence for a request."""
        now = self._now()
        approval_id = str(uuid.uuid4())
        with self._lock:
            with self._conn() as conn:
                self._get_request(conn, org_id, request_id)
                conn.execute(
                    "UPDATE evidence_requests SET status='rejected', updated_at=? WHERE request_id=? AND org_id=?",
                    (now, request_id, org_id),
                )
                conn.execute(
                    """INSERT INTO evidence_approvals
                       (approval_id,request_id,org_id,action,actor,notes,created_at)
                       VALUES (?,?,?,'rejected',?,?,?)""",
                    (approval_id, request_id, org_id, rejected_by, reason, now),
                )
        return {"approval_id": approval_id, "request_id": request_id, "action": "rejected", "rejected_by": rejected_by}

    # ------------------------------------------------------------------
    # Auto-collect
    # ------------------------------------------------------------------

    def auto_collect(self, org_id: str, framework: str) -> List[Dict[str, Any]]:
        """Simulate auto-collection from connected systems for a framework.

        Creates evidence requests and populates evidence items automatically.
        Returns list of auto-collected evidence items.
        """
        if framework not in _VALID_FRAMEWORKS:
            raise ValueError(f"Invalid framework: {framework}. Must be one of {_VALID_FRAMEWORKS}")

        sources = _AUTO_COLLECT_SOURCES.get(framework, [])
        collected: List[Dict[str, Any]] = []
        now = self._now()

        with self._lock:
            with self._conn() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                for source in sources:
                    request_id = str(uuid.uuid4())
                    evidence_id = str(uuid.uuid4())

                    # Create request
                    conn.execute(
                        """INSERT INTO evidence_requests
                           (request_id,org_id,framework,control_id,control_name,
                            description,due_date,assignee,status,created_at,updated_at)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            request_id, org_id, framework,
                            source["control_id"], source["control_name"],
                            f"Auto-collected from {source['source_system']}",
                            "", "system", "submitted", now, now,
                        ),
                    )

                    # Create evidence item
                    filename = f"{source['source_system'].lower().replace(' ', '_')}_{framework.lower()}_evidence.json"
                    item = {
                        "evidence_id": evidence_id,
                        "request_id": request_id,
                        "org_id": org_id,
                        "evidence_type": source["evidence_type"],
                        "filename": filename,
                        "content_summary": f"Auto-collected {source['evidence_type']} from {source['source_system']} for {framework} {source['control_id']}",
                        "source_system": source["source_system"],
                        "collected_at": now,
                        "auto_collected": 1,
                        "control_id": source["control_id"],
                        "control_name": source["control_name"],
                        "framework": framework,
                    }
                    conn.execute(
                        """INSERT INTO evidence_items
                           (evidence_id,request_id,org_id,evidence_type,filename,
                            content_summary,source_system,collected_at,auto_collected)
                           VALUES (?,?,?,?,?,?,?,?,?)""",
                        (
                            evidence_id, request_id, org_id,
                            source["evidence_type"], filename,
                            item["content_summary"], source["source_system"], now, 1,
                        ),
                    )
                    collected.append(item)

        _logger.info("Auto-collected %d evidence items for org %s framework %s", len(collected), org_id, framework)
        return collected

    # ------------------------------------------------------------------
    # Audit readiness
    # ------------------------------------------------------------------

    def get_audit_readiness(self, org_id: str, framework: str) -> Dict[str, Any]:
        """Calculate audit readiness for a framework."""
        if framework not in _VALID_FRAMEWORKS:
            raise ValueError(f"Invalid framework: {framework}. Must be one of {_VALID_FRAMEWORKS}")

        sources = _AUTO_COLLECT_SOURCES.get(framework, [])
        all_controls = {s["control_id"] for s in sources}
        total_controls = len(all_controls)

        with self._conn() as conn:
            rows = conn.execute(
                "SELECT control_id, status FROM evidence_requests WHERE org_id=? AND framework=?",
                (org_id, framework),
            ).fetchall()

        controls_with_evidence: set = set()
        controls_approved: set = set()
        for row in rows:
            cid = row["control_id"]
            controls_with_evidence.add(cid)
            if row["status"] == "approved":
                controls_approved.add(cid)

        # Also count any control IDs outside the default set
        all_seen = all_controls | controls_with_evidence
        total_controls = max(total_controls, len(all_seen))

        missing = sorted(all_controls - controls_with_evidence)
        readiness_pct = round((len(controls_approved) / total_controls * 100) if total_controls else 0, 1)

        return {
            "framework": framework,
            "total_controls": total_controls,
            "controls_with_evidence": len(controls_with_evidence),
            "controls_approved": len(controls_approved),
            "readiness_pct": readiness_pct,
            "missing_controls": missing,
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_collection_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate collection statistics for an org."""
        with self._conn() as conn:
            total_requests = conn.execute(
                "SELECT COUNT(*) FROM evidence_requests WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            status_rows = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM evidence_requests WHERE org_id=? GROUP BY status",
                (org_id,),
            ).fetchall()

            framework_rows = conn.execute(
                "SELECT framework, COUNT(*) as cnt FROM evidence_requests WHERE org_id=? GROUP BY framework",
                (org_id,),
            ).fetchall()

            auto_count = conn.execute(
                "SELECT COUNT(*) FROM evidence_items WHERE org_id=? AND auto_collected=1", (org_id,)
            ).fetchone()[0]

            manual_count = conn.execute(
                "SELECT COUNT(*) FROM evidence_items WHERE org_id=? AND auto_collected=0", (org_id,)
            ).fetchone()[0]

        by_status = {r["status"]: r["cnt"] for r in status_rows}
        by_framework = {r["framework"]: r["cnt"] for r in framework_rows}
        approved = by_status.get("approved", 0)
        overall_readiness_pct = round((approved / total_requests * 100) if total_requests else 0, 1)

        return {
            "total_requests": total_requests,
            "by_status": by_status,
            "by_framework": by_framework,
            "auto_collected_count": auto_count,
            "manual_count": manual_count,
            "overall_readiness_pct": overall_readiness_pct,
        }

    # ------------------------------------------------------------------
    # Collect-all from live engines
    # ------------------------------------------------------------------

    def collect_all(self, org_id: str) -> Dict[str, Any]:
        """Collect compliance evidence from all wired security engines.

        Gathers evidence from:
        - AlertTriageEngine    → SOC2 CC7.2 (alert monitoring)
        - AccessControlEngine  → SOC2 CC6.1 (access controls)
        - PasswordPolicyEngine → NIST AC-7  (password enforcement)
        - VulnScanEngine       → PCI-DSS 11.2 (vulnerability scanning)
        - SecurityTrainingEngine → SOC2 CC1.4 (security training)
        - IncidentResponseEngine → SOC2 CC7.3 (IR procedures)

        Returns summary with per-source results and total evidence collected.
        """
        from core.access_control_engine import AccessControlEngine
        from core.alert_triage_engine import AlertTriageEngine
        from core.incident_response_engine import IncidentResponseEngine
        from core.password_policy_engine import PasswordPolicyEngine
        from core.security_training_engine import SecurityTrainingEngine
        from core.vuln_scan_engine import VulnScanEngine

        results: List[Dict[str, Any]] = []
        now = self._now()

        # Each source: (label, framework, control_id, control_name, evidence_type, stat_fn)
        sources = [
            {
                "source_system": "AlertTriageEngine",
                "framework": "SOC2",
                "control_id": "CC7.2",
                "control_name": "Security Event Monitoring",
                "evidence_type": "log",
                "stat_fn": lambda: AlertTriageEngine().get_triage_stats(org_id),
            },
            {
                "source_system": "AccessControlEngine",
                "framework": "SOC2",
                "control_id": "CC6.1",
                "control_name": "Logical Access Controls",
                "evidence_type": "config",
                "stat_fn": lambda: AccessControlEngine().get_access_stats(org_id),
            },
            {
                "source_system": "PasswordPolicyEngine",
                "framework": "SOC2",
                "control_id": "AC-7",
                "control_name": "Password Enforcement",
                "evidence_type": "config",
                "stat_fn": lambda: PasswordPolicyEngine().get_policy_stats(org_id),
            },
            {
                "source_system": "VulnScanEngine",
                "framework": "PCI-DSS",
                "control_id": "Req-11.2",
                "control_name": "Vulnerability Scanning",
                "evidence_type": "document",
                "stat_fn": lambda: VulnScanEngine().get_scan_stats(org_id),
            },
            {
                "source_system": "SecurityTrainingEngine",
                "framework": "SOC2",
                "control_id": "CC1.4",
                "control_name": "Security Awareness Training",
                "evidence_type": "attestation",
                "stat_fn": lambda: SecurityTrainingEngine().get_training_stats(org_id),
            },
            {
                "source_system": "IncidentResponseEngine",
                "framework": "SOC2",
                "control_id": "CC7.3",
                "control_name": "Incident Response Procedures",
                "evidence_type": "log",
                "stat_fn": lambda: IncidentResponseEngine().get_incident_stats(org_id),
            },
        ]

        with self._lock:
            with self._conn() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                for src in sources:
                    request_id = str(uuid.uuid4())
                    evidence_id = str(uuid.uuid4())
                    stat_summary: Dict[str, Any] = {}
                    collection_status = "submitted"

                    try:
                        stat_summary = src["stat_fn"]()
                    except Exception as exc:  # noqa: BLE001
                        _logger.warning(
                            "collect_all: %s stats failed: %s", src["source_system"], exc
                        )
                        collection_status = "pending"

                    filename = (
                        f"{src['source_system'].lower()}_{src['control_id'].lower()}_evidence.json"
                    )
                    content_summary = (
                        f"Auto-collected from {src['source_system']} for "
                        f"{src['framework']} {src['control_id']}: {src['control_name']}"
                    )

                    conn.execute(
                        """INSERT INTO evidence_requests
                           (request_id,org_id,framework,control_id,control_name,
                            description,due_date,assignee,status,created_at,updated_at)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            request_id, org_id, src["framework"],
                            src["control_id"], src["control_name"],
                            content_summary,
                            "", "system", collection_status, now, now,
                        ),
                    )
                    conn.execute(
                        """INSERT INTO evidence_items
                           (evidence_id,request_id,org_id,evidence_type,filename,
                            content_summary,source_system,collected_at,auto_collected)
                           VALUES (?,?,?,?,?,?,?,?,?)""",
                        (
                            evidence_id, request_id, org_id,
                            src["evidence_type"], filename,
                            content_summary, src["source_system"], now, 1,
                        ),
                    )

                    results.append({
                        "source_system": src["source_system"],
                        "framework": src["framework"],
                        "control_id": src["control_id"],
                        "control_name": src["control_name"],
                        "evidence_type": src["evidence_type"],
                        "evidence_id": evidence_id,
                        "request_id": request_id,
                        "status": collection_status,
                        "stats_snapshot": stat_summary,
                    })

        _logger.info(
            "collect_all: gathered %d evidence items for org %s", len(results), org_id
        )
        return {
            "org_id": org_id,
            "collected_at": now,
            "total_collected": len(results),
            "results": results,
        }
