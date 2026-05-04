"""
Incident Response Playbook System.

Provides predefined runbooks, timeline tracking, and post-incident review for:
- 8 incident types with built-in playbook templates (5-8 steps each)
- State-machine status transitions
- Step assignment and completion tracking
- Timeline event logging
- Finding/evidence linking
- Post-mortem documentation

Compliance: NIST CSF RS.RP, ISO 27035, SOC2 CC7.3
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class IncidentType(str, Enum):
    DATA_BREACH = "data_breach"
    RANSOMWARE = "ransomware"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    DDOS = "ddos"
    MALWARE = "malware"
    INSIDER_THREAT = "insider_threat"
    PHISHING = "phishing"
    SUPPLY_CHAIN = "supply_chain"


class IncidentSeverity(str, Enum):
    SEV1 = "sev1"
    SEV2 = "sev2"
    SEV3 = "sev3"
    SEV4 = "sev4"


class IncidentStatus(str, Enum):
    DETECTED = "detected"
    TRIAGING = "triaging"
    CONTAINING = "containing"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    CLOSED = "closed"
    POST_MORTEM = "post_mortem"


# Valid state machine transitions
_VALID_TRANSITIONS: Dict[IncidentStatus, List[IncidentStatus]] = {
    IncidentStatus.DETECTED: [IncidentStatus.TRIAGING],
    IncidentStatus.TRIAGING: [IncidentStatus.CONTAINING, IncidentStatus.CLOSED],
    IncidentStatus.CONTAINING: [IncidentStatus.ERADICATING, IncidentStatus.CLOSED],
    IncidentStatus.ERADICATING: [IncidentStatus.RECOVERING, IncidentStatus.CLOSED],
    IncidentStatus.RECOVERING: [IncidentStatus.CLOSED],
    IncidentStatus.CLOSED: [IncidentStatus.POST_MORTEM],
    IncidentStatus.POST_MORTEM: [],
}


class IRStepStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class IRStep(BaseModel):
    order: int
    name: str
    description: str
    assignee: Optional[str] = None
    status: IRStepStatus = IRStepStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    notes: Optional[str] = None


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    type: IncidentType
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.DETECTED
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reported_by: str
    lead_responder: Optional[str] = None
    steps: List[IRStep] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    findings_linked: List[str] = Field(default_factory=list)
    closed_at: Optional[datetime] = None
    org_id: str = "default"


class PostMortem(BaseModel):
    incident_id: str
    summary: str
    root_cause: str
    impact: str = ""
    timeline_summary: str = ""
    lessons_learned: List[str] = Field(default_factory=list)
    action_items: List[Dict[str, Any]] = Field(default_factory=list)
    authored_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Built-in playbook templates
# ---------------------------------------------------------------------------

_PLAYBOOK_TEMPLATES: Dict[IncidentType, List[Dict[str, Any]]] = {
    IncidentType.DATA_BREACH: [
        {"order": 1, "name": "Confirm breach scope", "description": "Identify what data was accessed or exfiltrated and by whom."},
        {"order": 2, "name": "Isolate affected systems", "description": "Quarantine systems involved in the breach to prevent further data loss."},
        {"order": 3, "name": "Preserve forensic evidence", "description": "Capture logs, memory dumps, and disk images before remediation."},
        {"order": 4, "name": "Notify legal and compliance", "description": "Engage legal counsel and determine regulatory notification obligations (GDPR, CCPA, etc.)."},
        {"order": 5, "name": "Patch the attack vector", "description": "Close the vulnerability or misconfiguration that enabled the breach."},
        {"order": 6, "name": "Notify affected parties", "description": "Send breach notifications to affected users and regulators per applicable law."},
        {"order": 7, "name": "Monitor for recurrence", "description": "Set up enhanced monitoring and alerting to detect any follow-on attacks."},
    ],
    IncidentType.RANSOMWARE: [
        {"order": 1, "name": "Isolate infected hosts", "description": "Immediately disconnect infected systems from the network to stop lateral spread."},
        {"order": 2, "name": "Identify ransomware variant", "description": "Determine the ransomware family to check for known decryptors."},
        {"order": 3, "name": "Assess backup integrity", "description": "Verify that backups exist, are clean, and can be restored."},
        {"order": 4, "name": "Notify leadership and legal", "description": "Brief executives, legal counsel, and cyber insurance carrier."},
        {"order": 5, "name": "Eradicate ransomware", "description": "Wipe infected systems and rebuild from clean images."},
        {"order": 6, "name": "Restore from backup", "description": "Restore data from verified clean backups in priority order."},
        {"order": 7, "name": "Patch initial access vector", "description": "Remediate the vulnerability or misconfiguration used to gain entry."},
        {"order": 8, "name": "Conduct tabletop review", "description": "Run a post-incident exercise to test improved defenses."},
    ],
    IncidentType.CREDENTIAL_COMPROMISE: [
        {"order": 1, "name": "Identify compromised accounts", "description": "Determine which credentials were exposed or misused."},
        {"order": 2, "name": "Force password reset", "description": "Reset all compromised passwords and invalidate active sessions."},
        {"order": 3, "name": "Revoke API keys and tokens", "description": "Rotate or revoke any API keys, OAuth tokens, or service account credentials."},
        {"order": 4, "name": "Enable MFA", "description": "Enforce multi-factor authentication on all affected accounts."},
        {"order": 5, "name": "Audit access logs", "description": "Review authentication logs to identify unauthorized access and exfiltrated data."},
        {"order": 6, "name": "Notify affected users", "description": "Inform users of the compromise and required actions."},
    ],
    IncidentType.DDOS: [
        {"order": 1, "name": "Activate DDoS mitigation", "description": "Enable upstream scrubbing, CDN rate limiting, or anycast routing."},
        {"order": 2, "name": "Identify attack vector", "description": "Classify the attack type (volumetric, protocol, application layer) to select countermeasures."},
        {"order": 3, "name": "Block attack sources", "description": "Apply IP blocks, geo-restrictions, or challenge pages at the edge."},
        {"order": 4, "name": "Scale infrastructure", "description": "Spin up additional capacity or activate auto-scaling to absorb traffic."},
        {"order": 5, "name": "Notify upstream provider", "description": "Contact ISP or CDN provider for upstream filtering assistance."},
        {"order": 6, "name": "Monitor traffic normalization", "description": "Confirm attack has subsided and service is fully restored."},
    ],
    IncidentType.MALWARE: [
        {"order": 1, "name": "Quarantine infected systems", "description": "Isolate hosts showing signs of malware infection."},
        {"order": 2, "name": "Identify malware family", "description": "Run AV/EDR analysis and submit samples to sandboxes for classification."},
        {"order": 3, "name": "Collect forensic evidence", "description": "Capture memory, disk images, and network captures for investigation."},
        {"order": 4, "name": "Remove malware artifacts", "description": "Execute removal scripts, clean registry entries, and delete malicious files."},
        {"order": 5, "name": "Patch exploitation vector", "description": "Apply patches or configuration changes to close the initial access path."},
        {"order": 6, "name": "Restore affected systems", "description": "Reimage or restore systems from clean backups."},
        {"order": 7, "name": "Harden endpoint controls", "description": "Update EDR policies, application whitelisting, and monitoring coverage."},
    ],
    IncidentType.INSIDER_THREAT: [
        {"order": 1, "name": "Preserve evidence covertly", "description": "Collect logs and evidence without alerting the suspected insider."},
        {"order": 2, "name": "Engage HR and legal", "description": "Involve HR, legal counsel, and security leadership before taking action."},
        {"order": 3, "name": "Revoke access", "description": "Terminate the insider's access to systems, data, and facilities."},
        {"order": 4, "name": "Assess data exposure", "description": "Determine what data was accessed, copied, or exfiltrated."},
        {"order": 5, "name": "Conduct forensic investigation", "description": "Perform full forensic analysis of the insider's activity."},
        {"order": 6, "name": "Implement access controls review", "description": "Audit and tighten least-privilege access across the organization."},
        {"order": 7, "name": "Report to authorities if warranted", "description": "File law enforcement report if criminal activity is confirmed."},
    ],
    IncidentType.PHISHING: [
        {"order": 1, "name": "Identify phishing campaign", "description": "Gather all phishing emails and identify affected recipients."},
        {"order": 2, "name": "Block phishing infrastructure", "description": "Blacklist phishing domains, URLs, and sender addresses."},
        {"order": 3, "name": "Check for credential entry", "description": "Determine if any recipients entered credentials on the phishing site."},
        {"order": 4, "name": "Reset compromised credentials", "description": "Force password resets for users who clicked or submitted credentials."},
        {"order": 5, "name": "Quarantine phishing emails", "description": "Remove phishing emails from all mailboxes."},
        {"order": 6, "name": "Notify all recipients", "description": "Alert all targeted users about the phishing campaign and warning signs."},
    ],
    IncidentType.SUPPLY_CHAIN: [
        {"order": 1, "name": "Identify compromised component", "description": "Determine which third-party library, vendor, or update was compromised."},
        {"order": 2, "name": "Assess blast radius", "description": "Map all systems and applications that consume the affected component."},
        {"order": 3, "name": "Isolate affected deployments", "description": "Quarantine or take offline systems running the compromised component."},
        {"order": 4, "name": "Remove or pin the component", "description": "Uninstall or pin to a known-good version; remove from supply chain."},
        {"order": 5, "name": "Hunt for indicators of compromise", "description": "Search for IOCs across all affected systems to detect exploitation."},
        {"order": 6, "name": "Notify vendor and CISA", "description": "Inform the upstream vendor and relevant authorities of the supply chain compromise."},
        {"order": 7, "name": "Restore from clean builds", "description": "Rebuild and redeploy affected services from verified clean sources."},
        {"order": 8, "name": "Harden software supply chain", "description": "Implement SBOM tracking, dependency pinning, and integrity verification."},
    ],
}


# ---------------------------------------------------------------------------
# Database schema
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS incidents (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    type        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    status      TEXT NOT NULL,
    data        TEXT NOT NULL,
    detected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS post_mortems (
    incident_id TEXT PRIMARY KEY,
    data        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
"""


# ---------------------------------------------------------------------------
# IncidentResponseManager
# ---------------------------------------------------------------------------


class IncidentResponseManager:
    """SQLite-backed incident response manager with playbook templates."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = "data/incident_response.db"
        self._db_path = str(db_path)
        self._lock = threading.RLock()
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_DDL)

    def _save_incident(self, incident: Incident) -> None:
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO incidents (id, org_id, type, severity, status, data, detected_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        incident.id,
                        incident.org_id,
                        incident.type.value,
                        incident.severity.value,
                        incident.status.value,
                        incident.model_dump_json(),
                        incident.detected_at.isoformat(),
                    ),
                )

    def _load_incident(self, row: sqlite3.Row) -> Incident:
        return Incident.model_validate_json(row["data"])

    # ------------------------------------------------------------------
    # Playbook templates
    # ------------------------------------------------------------------

    def get_playbook_template(self, incident_type: IncidentType) -> List[IRStep]:
        """Return built-in playbook steps for the given incident type."""
        raw_steps = _PLAYBOOK_TEMPLATES.get(incident_type, [])
        return [
            IRStep(
                order=s["order"],
                name=s["name"],
                description=s["description"],
            )
            for s in raw_steps
        ]

    # ------------------------------------------------------------------
    # Incident CRUD
    # ------------------------------------------------------------------

    def create_incident(
        self,
        title: str,
        type: IncidentType,  # noqa: A002
        severity: IncidentSeverity,
        reported_by: str,
        org_id: str = "default",
    ) -> Incident:
        """Create a new incident with auto-populated playbook steps."""
        steps = self.get_playbook_template(type)
        incident = Incident(
            title=title,
            type=type,
            severity=severity,
            reported_by=reported_by,
            org_id=org_id,
            steps=steps,
            timeline=[
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event": f"Incident created: {title}",
                    "author": reported_by,
                }
            ],
        )
        self._save_incident(incident)
        _logger.info(
            "incident_response.created id=%s type=%s severity=%s",
            incident.id,
            type.value,
            severity.value,
        )
        return incident

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Fetch a single incident by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
        if row is None:
            return None
        return self._load_incident(row)

    def list_incidents(
        self,
        org_id: Optional[str] = None,
        status_filter: Optional[IncidentStatus] = None,
        severity_filter: Optional[IncidentSeverity] = None,
    ) -> List[Incident]:
        """List incidents with optional filters."""
        query = "SELECT * FROM incidents WHERE 1=1"
        params: List[Any] = []
        if org_id:
            query += " AND org_id = ?"
            params.append(org_id)
        if status_filter:
            query += " AND status = ?"
            params.append(status_filter.value)
        if severity_filter:
            query += " AND severity = ?"
            params.append(severity_filter.value)
        query += " ORDER BY detected_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._load_incident(r) for r in rows]

    def get_active_incidents(self, org_id: str = "default") -> List[Incident]:
        """Return all non-closed incidents for an org."""
        terminal = {IncidentStatus.CLOSED.value, IncidentStatus.POST_MORTEM.value}
        all_incidents = self.list_incidents(org_id=org_id)
        return [i for i in all_incidents if i.status.value not in terminal]

    # ------------------------------------------------------------------
    # Status transitions
    # ------------------------------------------------------------------

    def update_status(self, incident_id: str, new_status: IncidentStatus) -> Incident:
        """Advance incident status via state machine."""
        incident = self.get_incident(incident_id)
        if incident is None:
            raise ValueError(f"Incident {incident_id} not found")

        allowed = _VALID_TRANSITIONS.get(incident.status, [])
        if new_status not in allowed:
            raise ValueError(
                f"Invalid transition {incident.status.value} -> {new_status.value}. "
                f"Allowed: {[s.value for s in allowed]}"
            )

        incident.status = new_status
        if new_status in (IncidentStatus.CLOSED, IncidentStatus.POST_MORTEM):
            incident.closed_at = datetime.now(timezone.utc)

        incident.timeline.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": f"Status changed to {new_status.value}",
                "author": "system",
            }
        )
        self._save_incident(incident)
        _logger.info(
            "incident_response.status_updated id=%s status=%s",
            incident_id,
            new_status.value,
        )
        return incident

    # ------------------------------------------------------------------
    # Step management
    # ------------------------------------------------------------------

    def assign_step(
        self, incident_id: str, step_order: int, assignee: str
    ) -> Incident:
        """Assign a responder to a playbook step."""
        incident = self.get_incident(incident_id)
        if incident is None:
            raise ValueError(f"Incident {incident_id} not found")

        step = next((s for s in incident.steps if s.order == step_order), None)
        if step is None:
            raise ValueError(f"Step {step_order} not found in incident {incident_id}")

        step.assignee = assignee
        if step.status == IRStepStatus.PENDING:
            step.status = IRStepStatus.IN_PROGRESS
            step.started_at = datetime.now(timezone.utc)

        self._save_incident(incident)
        return incident

    def complete_step(
        self, incident_id: str, step_order: int, notes: Optional[str] = None
    ) -> Incident:
        """Mark a playbook step as completed."""
        incident = self.get_incident(incident_id)
        if incident is None:
            raise ValueError(f"Incident {incident_id} not found")

        step = next((s for s in incident.steps if s.order == step_order), None)
        if step is None:
            raise ValueError(f"Step {step_order} not found in incident {incident_id}")

        step.status = IRStepStatus.COMPLETED
        step.completed_at = datetime.now(timezone.utc)
        if notes:
            step.notes = notes

        incident.timeline.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": f"Step {step_order} '{step.name}' completed",
                "author": step.assignee or "system",
            }
        )
        self._save_incident(incident)
        return incident

    # ------------------------------------------------------------------
    # Timeline and linking
    # ------------------------------------------------------------------

    def add_timeline_event(
        self, incident_id: str, event_description: str, author: str
    ) -> Incident:
        """Append an event to the incident timeline."""
        incident = self.get_incident(incident_id)
        if incident is None:
            raise ValueError(f"Incident {incident_id} not found")

        incident.timeline.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": event_description,
                "author": author,
            }
        )
        self._save_incident(incident)
        return incident

    def link_finding(self, incident_id: str, finding_id: str) -> Incident:
        """Link a security finding to the incident."""
        incident = self.get_incident(incident_id)
        if incident is None:
            raise ValueError(f"Incident {incident_id} not found")

        if finding_id not in incident.findings_linked:
            incident.findings_linked.append(finding_id)
            self._save_incident(incident)
        return incident

    def link_evidence(self, incident_id: str, evidence_id: str) -> Incident:
        """Link an evidence artifact to the incident."""
        incident = self.get_incident(incident_id)
        if incident is None:
            raise ValueError(f"Incident {incident_id} not found")

        if evidence_id not in incident.evidence_ids:
            incident.evidence_ids.append(evidence_id)
            self._save_incident(incident)
        return incident

    # ------------------------------------------------------------------
    # Post-mortem
    # ------------------------------------------------------------------

    def create_post_mortem(
        self,
        incident_id: str,
        summary: str,
        root_cause: str,
        lessons: List[str],
        action_items: List[Dict[str, Any]],
        author: str,
        impact: str = "",
        timeline_summary: str = "",
    ) -> PostMortem:
        """Create a post-mortem for a closed incident."""
        incident = self.get_incident(incident_id)
        if incident is None:
            raise ValueError(f"Incident {incident_id} not found")
        if incident.status not in (IncidentStatus.CLOSED, IncidentStatus.POST_MORTEM):
            raise ValueError(
                f"Cannot create post-mortem for incident in status {incident.status.value}. "
                "Incident must be CLOSED first."
            )

        pm = PostMortem(
            incident_id=incident_id,
            summary=summary,
            root_cause=root_cause,
            impact=impact,
            timeline_summary=timeline_summary,
            lessons_learned=lessons,
            action_items=action_items,
            authored_by=author,
        )
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO post_mortems (incident_id, data, created_at) VALUES (?, ?, ?)",
                (incident_id, pm.model_dump_json(), pm.created_at.isoformat()),
            )

        # Advance status to POST_MORTEM if still CLOSED
        if incident.status == IncidentStatus.CLOSED:
            incident.status = IncidentStatus.POST_MORTEM
            incident.timeline.append(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event": "Post-mortem created",
                    "author": author,
                }
            )
            self._save_incident(incident)

        _logger.info("incident_response.post_mortem.created incident_id=%s", incident_id)
        return pm

    def get_post_mortem(self, incident_id: str) -> Optional[PostMortem]:
        """Fetch post-mortem for an incident."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM post_mortems WHERE incident_id = ?", (incident_id,)
            ).fetchone()
        if row is None:
            return None
        return PostMortem.model_validate_json(row["data"])

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_incident_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return incident statistics via SQL aggregates (no Python-side iteration)."""
        terminal = {IncidentStatus.CLOSED.value, IncidentStatus.POST_MORTEM.value}
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_count = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE org_id = ? AND status NOT IN (?,?)",
                (org_id, IncidentStatus.CLOSED.value, IncidentStatus.POST_MORTEM.value),
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT type, COUNT(*) as cnt FROM incidents WHERE org_id = ? GROUP BY type",
                (org_id,),
            ).fetchall()
            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM incidents WHERE org_id = ? GROUP BY severity",
                (org_id,),
            ).fetchall()
            status_rows = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM incidents WHERE org_id = ? GROUP BY status",
                (org_id,),
            ).fetchall()

            # avg resolution: detected_at and closed_at are ISO strings stored in data blob,
            # but detected_at is also a top-level column. We compute via Python only on the
            # closed subset (typically small). Filter in SQL to avoid full table scan.
            closed_rows = conn.execute(
                "SELECT data FROM incidents WHERE org_id = ? AND status IN (?,?)",
                (org_id, IncidentStatus.CLOSED.value, IncidentStatus.POST_MORTEM.value),
            ).fetchall()

        by_type: Dict[str, int] = {t.value: 0 for t in IncidentType}
        by_type.update({r["type"]: r["cnt"] for r in type_rows})
        by_severity: Dict[str, int] = {s.value: 0 for s in IncidentSeverity}
        by_severity.update({r["severity"]: r["cnt"] for r in sev_rows})
        by_status: Dict[str, int] = {s.value: 0 for s in IncidentStatus}
        by_status.update({r["status"]: r["cnt"] for r in status_rows})

        resolution_times: List[float] = []
        for row in closed_rows:
            try:
                inc = Incident.model_validate_json(row["data"])
                if inc.closed_at:
                    resolution_times.append(
                        (inc.closed_at - inc.detected_at).total_seconds() / 3600
                    )
            except Exception:
                pass

        avg_resolution_hours = (
            round(sum(resolution_times) / len(resolution_times), 2)
            if resolution_times
            else None
        )

        return {
            "total": total,
            "by_type": by_type,
            "by_severity": by_severity,
            "by_status": by_status,
            "avg_resolution_hours": avg_resolution_hours,
            "active_count": active_count,
        }
