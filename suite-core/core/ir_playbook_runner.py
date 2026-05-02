"""
IR Playbook Runner — Incident Response Playbook Automation Engine for ALDECI.

Executes 5 built-in IR playbooks with real automated actions:
  - phishing_response
  - ransomware_response
  - data_exfiltration
  - unauthorized_access
  - malware_detected

Real actions (local/safe only):
  - send_notification    → ntfy.sh push notification (via NtfyNotifier)
  - create_ticket        → GitHub Issue via GitHubIssuesClient
  - block_ip             → add to SQLite blocklist
  - quarantine_asset     → mark asset quarantined in SQLite
  - escalate_to_team     → ntfy.sh CRITICAL priority push
  - log_iocs             → write IOCs to SQLite ioc table
  - disable_account      → mark account disabled in SQLite
  - force_password_reset → mark account requiring reset in SQLite

Compliance: NIST 800-61r2, SOC2 CC7.2
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from dataclasses import asdict, dataclass, field

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:
    _get_tg_bus = None  # type: ignore


def _tg_emit(event_type: str, payload: dict) -> None:
    try:
        if _get_tg_bus is None:
            return
        bus = _get_tg_bus()
        if bus:
            bus.emit(event_type, payload)
    except Exception:
        pass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

_logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# DB path
# ---------------------------------------------------------------------------

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / "data" / "ir_playbook_runner.db")

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS executions (
    execution_id   TEXT PRIMARY KEY,
    playbook_id    TEXT NOT NULL,
    incident_id    TEXT NOT NULL,
    started_at     TEXT NOT NULL,
    completed_at   TEXT,
    status         TEXT NOT NULL DEFAULT 'running',
    steps_total    INTEGER NOT NULL DEFAULT 0,
    steps_completed INTEGER NOT NULL DEFAULT 0,
    current_step   TEXT,
    step_results   TEXT NOT NULL DEFAULT '[]',
    incident_data  TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_exec_playbook ON executions(playbook_id);
CREATE INDEX IF NOT EXISTS idx_exec_incident ON executions(incident_id);
CREATE INDEX IF NOT EXISTS idx_exec_status   ON executions(status);

CREATE TABLE IF NOT EXISTS ip_blocklist (
    ip         TEXT PRIMARY KEY,
    reason     TEXT NOT NULL,
    blocked_at TEXT NOT NULL,
    incident_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quarantined_assets (
    asset_id      TEXT PRIMARY KEY,
    asset_name    TEXT NOT NULL,
    reason        TEXT NOT NULL,
    quarantined_at TEXT NOT NULL,
    incident_id   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS disabled_accounts (
    account_id    TEXT PRIMARY KEY,
    username      TEXT NOT NULL,
    reason        TEXT NOT NULL,
    disabled_at   TEXT NOT NULL,
    incident_id   TEXT NOT NULL,
    reset_required INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS iocs (
    ioc_id       TEXT PRIMARY KEY,
    ioc_type     TEXT NOT NULL,
    value        TEXT NOT NULL,
    source       TEXT NOT NULL,
    incident_id  TEXT NOT NULL,
    logged_at    TEXT NOT NULL
);
"""


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ExecutionStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class StepStatus(str, Enum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    OVERRIDDEN = "overridden"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class PlaybookStep:
    """Single step in a playbook."""

    step_id: str
    name: str
    action: str
    description: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    continue_on_failure: bool = True


@dataclass
class PlaybookDef:
    """Definition of an IR playbook."""

    playbook_id: str
    name: str
    description: str
    trigger_conditions: List[str]
    steps: List[PlaybookStep]
    severity_threshold: str = "medium"


@dataclass
class StepResult:
    """Result of executing one playbook step."""

    step_id: str
    step_name: str
    action: str
    status: str  # StepStatus value
    started_at: str
    completed_at: str
    output: str = ""
    error: Optional[str] = None


@dataclass
class PlaybookExecution:
    """Record of a playbook execution."""

    execution_id: str
    playbook_id: str
    incident_id: str
    started_at: str
    status: str  # ExecutionStatus value
    steps_total: int
    steps_completed: int
    current_step: Optional[str]
    step_results: List[StepResult]
    incident_data: Dict[str, Any]
    completed_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Built-in playbook library
# ---------------------------------------------------------------------------

_PLAYBOOKS: Dict[str, PlaybookDef] = {
    "phishing_response": PlaybookDef(
        playbook_id="phishing_response",
        name="Phishing Response",
        description="Automated response to phishing and credential theft incidents.",
        trigger_conditions=["phishing", "credential_theft", "suspicious_email", "spear_phishing"],
        severity_threshold="medium",
        steps=[
            PlaybookStep(
                step_id="disable_account",
                name="Disable Compromised Account",
                action="disable_account",
                description="Disable user account to prevent further credential abuse.",
                params={"reason": "Suspected phishing/credential compromise"},
            ),
            PlaybookStep(
                step_id="log_iocs",
                name="Extract and Log IOCs",
                action="log_iocs",
                description="Extract indicators of compromise from incident data.",
                params={"ioc_types": ["email", "domain", "url", "ip"]},
            ),
            PlaybookStep(
                step_id="block_sender_ip",
                name="Block Sender IP",
                action="block_ip",
                description="Add phishing sender IP to blocklist.",
                params={"reason": "Phishing source IP"},
            ),
            PlaybookStep(
                step_id="notify_user",
                name="Notify Affected User",
                action="send_notification",
                description="Push alert to security team via ntfy.sh.",
                params={"priority": "high", "title": "Phishing Incident Detected"},
            ),
            PlaybookStep(
                step_id="force_password_reset",
                name="Force Password Reset",
                action="force_password_reset",
                description="Flag account for mandatory password reset on next login.",
                params={"reason": "Phishing credential compromise"},
            ),
            PlaybookStep(
                step_id="create_ticket",
                name="Create Incident Ticket",
                action="create_ticket",
                description="File GitHub Issue for incident tracking.",
                params={"severity": "high", "finding_type": "network"},
            ),
        ],
    ),
    "ransomware_response": PlaybookDef(
        playbook_id="ransomware_response",
        name="Ransomware Response",
        description="Containment and eradication response to ransomware detection.",
        trigger_conditions=["ransomware", "encryption_detected", "ransom_note", "mass_file_encryption"],
        severity_threshold="critical",
        steps=[
            PlaybookStep(
                step_id="escalate_critical",
                name="Escalate to Security Team (CRITICAL)",
                action="escalate_to_team",
                description="Immediately page security team with CRITICAL priority.",
                params={"priority": "critical", "message": "RANSOMWARE DETECTED — Immediate response required"},
                continue_on_failure=False,
            ),
            PlaybookStep(
                step_id="quarantine_asset",
                name="Quarantine Infected Asset",
                action="quarantine_asset",
                description="Isolate infected host to prevent lateral spread.",
                params={"reason": "Ransomware infection"},
            ),
            PlaybookStep(
                step_id="block_c2_ip",
                name="Block C2 IP",
                action="block_ip",
                description="Block known C2 server IP addresses.",
                params={"reason": "Ransomware C2 server"},
            ),
            PlaybookStep(
                step_id="log_ransomware_iocs",
                name="Log Ransomware IOCs",
                action="log_iocs",
                description="Record file hashes, C2 domains, encryption extensions.",
                params={"ioc_types": ["hash", "domain", "ip", "file_extension"]},
            ),
            PlaybookStep(
                step_id="create_ticket",
                name="Create Critical Incident Ticket",
                action="create_ticket",
                description="File critical GitHub Issue for ransomware incident.",
                params={"severity": "critical", "finding_type": "malware"},
            ),
            PlaybookStep(
                step_id="notify_ransomware",
                name="Notify All Stakeholders",
                action="send_notification",
                description="Broadcast ransomware alert to all subscribed channels.",
                params={"priority": "critical", "title": "RANSOMWARE INCIDENT ACTIVE"},
            ),
        ],
    ),
    "data_exfiltration": PlaybookDef(
        playbook_id="data_exfiltration",
        name="Data Exfiltration Response",
        description="Response to suspected or confirmed data exfiltration.",
        trigger_conditions=["data_exfiltration", "data_theft", "dlp_alert", "large_data_transfer", "exfil"],
        severity_threshold="high",
        steps=[
            PlaybookStep(
                step_id="block_exfil_ip",
                name="Block Exfiltration Destination IP",
                action="block_ip",
                description="Block IP addresses receiving exfiltrated data.",
                params={"reason": "Data exfiltration destination"},
            ),
            PlaybookStep(
                step_id="quarantine_source",
                name="Quarantine Source Asset",
                action="quarantine_asset",
                description="Isolate asset that is the source of exfiltration.",
                params={"reason": "Data exfiltration source"},
            ),
            PlaybookStep(
                step_id="disable_exfil_account",
                name="Disable Involved Account",
                action="disable_account",
                description="Suspend account involved in data exfiltration.",
                params={"reason": "Suspected data exfiltration"},
            ),
            PlaybookStep(
                step_id="log_exfil_iocs",
                name="Log Exfiltration IOCs",
                action="log_iocs",
                description="Record destination IPs, domains, file hashes transferred.",
                params={"ioc_types": ["ip", "domain", "hash", "url"]},
            ),
            PlaybookStep(
                step_id="escalate_exfil",
                name="Escalate to Security Team",
                action="escalate_to_team",
                description="Alert security team of confirmed data exfiltration.",
                params={"priority": "high", "message": "Data exfiltration confirmed — investigation required"},
            ),
            PlaybookStep(
                step_id="create_ticket",
                name="Create Exfiltration Ticket",
                action="create_ticket",
                description="File high-priority GitHub Issue for data exfiltration.",
                params={"severity": "high", "finding_type": "network"},
            ),
        ],
    ),
    "unauthorized_access": PlaybookDef(
        playbook_id="unauthorized_access",
        name="Unauthorized Access Response",
        description="Response to unauthorized access attempts or confirmed intrusions.",
        trigger_conditions=["unauthorized_access", "brute_force", "account_takeover", "privilege_escalation", "intrusion"],
        severity_threshold="high",
        steps=[
            PlaybookStep(
                step_id="block_attacker_ip",
                name="Block Attacker IP",
                action="block_ip",
                description="Add attacker source IP to blocklist.",
                params={"reason": "Unauthorized access source"},
            ),
            PlaybookStep(
                step_id="disable_compromised_account",
                name="Disable Compromised Account",
                action="disable_account",
                description="Lock account subject to unauthorized access.",
                params={"reason": "Unauthorized access / account takeover"},
            ),
            PlaybookStep(
                step_id="force_reset",
                name="Force Password Reset",
                action="force_password_reset",
                description="Require password reset on next authentication.",
                params={"reason": "Unauthorized access — password reset required"},
            ),
            PlaybookStep(
                step_id="log_access_iocs",
                name="Log Access IOCs",
                action="log_iocs",
                description="Record attacker IPs, user-agents, session tokens.",
                params={"ioc_types": ["ip", "user_agent", "session_token"]},
            ),
            PlaybookStep(
                step_id="notify_access",
                name="Notify Security Team",
                action="send_notification",
                description="Alert security team of unauthorized access.",
                params={"priority": "high", "title": "Unauthorized Access Detected"},
            ),
            PlaybookStep(
                step_id="create_ticket",
                name="Create Access Incident Ticket",
                action="create_ticket",
                description="File GitHub Issue for unauthorized access incident.",
                params={"severity": "high", "finding_type": "network"},
            ),
        ],
    ),
    "malware_detected": PlaybookDef(
        playbook_id="malware_detected",
        name="Malware Detection Response",
        description="Response to malware detection on endpoints or servers.",
        trigger_conditions=["malware", "malware_detected", "trojan", "rootkit", "spyware", "backdoor", "cryptominer"],
        severity_threshold="high",
        steps=[
            PlaybookStep(
                step_id="quarantine_malware_host",
                name="Quarantine Infected Host",
                action="quarantine_asset",
                description="Isolate infected endpoint to prevent malware spread.",
                params={"reason": "Malware infection detected"},
            ),
            PlaybookStep(
                step_id="block_malware_c2",
                name="Block Malware C2 IP",
                action="block_ip",
                description="Block command-and-control IP addresses.",
                params={"reason": "Malware C2 IP"},
            ),
            PlaybookStep(
                step_id="log_malware_iocs",
                name="Log Malware IOCs",
                action="log_iocs",
                description="Record malware file hashes, C2 domains, registry keys.",
                params={"ioc_types": ["hash", "domain", "ip", "registry_key"]},
            ),
            PlaybookStep(
                step_id="notify_malware",
                name="Notify Security Team",
                action="send_notification",
                description="Send malware detection alert to security team.",
                params={"priority": "high", "title": "Malware Detected"},
            ),
            PlaybookStep(
                step_id="escalate_if_critical",
                name="Escalate if Critical Malware",
                action="escalate_to_team",
                description="Escalate to leadership if malware is ransomware/APT.",
                params={"priority": "high", "message": "Malware detected — containment in progress"},
            ),
            PlaybookStep(
                step_id="create_ticket",
                name="Create Malware Incident Ticket",
                action="create_ticket",
                description="File GitHub Issue for malware incident tracking.",
                params={"severity": "high", "finding_type": "malware"},
            ),
        ],
    ),
}


# ---------------------------------------------------------------------------
# DB helper
# ---------------------------------------------------------------------------


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ---------------------------------------------------------------------------
# IRPlaybookRunner
# ---------------------------------------------------------------------------


class IRPlaybookRunner:
    """
    Executes incident response playbooks with real automated actions.

    Actions:
      - send_notification   → ntfy.sh push (NtfyNotifier)
      - create_ticket       → GitHub Issue (GitHubIssuesClient)
      - block_ip            → SQLite ip_blocklist
      - quarantine_asset    → SQLite quarantined_assets
      - escalate_to_team    → ntfy.sh CRITICAL push (NtfyNotifier)
      - log_iocs            → SQLite iocs table
      - disable_account     → SQLite disabled_accounts
      - force_password_reset → SQLite disabled_accounts.reset_required
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._db_path = db_path or _DEFAULT_DB
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = _connect(self._db_path)
        self._init_schema()

        # Lazy-loaded integrations (None until first use)
        self._ntfy: Optional[Any] = None
        self._gh: Optional[Any] = None

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # ── Integration helpers ───────────────────────────────────────────────

    def _get_ntfy(self) -> Any:
        """Lazy-load NtfyNotifier."""
        if self._ntfy is None:
            try:
                from core.webhook_notifier import NtfyNotifier
                self._ntfy = NtfyNotifier()
            except Exception as exc:
                _logger.warning("NtfyNotifier unavailable", error=str(exc))
        return self._ntfy

    def _get_gh(self) -> Any:
        """Lazy-load GitHubIssuesClient."""
        if self._gh is None:
            try:
                from core.github_issues_integration import get_github_issues_client
                self._gh = get_github_issues_client()
            except Exception as exc:
                _logger.warning("GitHubIssuesClient unavailable", error=str(exc))
        return self._gh

    # ── Playbook library ──────────────────────────────────────────────────

    def list_playbooks(self) -> List[PlaybookDef]:
        """Return all built-in playbooks."""
        return list(_PLAYBOOKS.values())

    def get_playbook(self, playbook_id: str) -> Optional[PlaybookDef]:
        """Return a specific playbook by ID."""
        return _PLAYBOOKS.get(playbook_id)

    def select_playbook(self, incident: Dict[str, Any]) -> Optional[PlaybookDef]:
        """
        Select the most appropriate playbook for an incident.

        Matches against trigger_conditions using incident type, tags,
        title, and description keywords. Returns highest-scoring match.
        """
        text_fields = " ".join([
            str(incident.get("incident_type", "")),
            str(incident.get("title", "")),
            str(incident.get("description", "")),
            " ".join(incident.get("tags", [])),
        ]).lower()

        best: Optional[PlaybookDef] = None
        best_score = 0

        for pb in _PLAYBOOKS.values():
            score = sum(1 for kw in pb.trigger_conditions if kw in text_fields)
            if score > best_score:
                best_score = score
                best = pb

        return best

    # ── Execution ─────────────────────────────────────────────────────────

    def execute_playbook(
        self,
        playbook_id: str,
        incident: Dict[str, Any],
        *,
        incident_id: Optional[str] = None,
    ) -> PlaybookExecution:
        """
        Execute a playbook synchronously.

        Each step is attempted; failures are logged and execution continues
        unless step.continue_on_failure is False.

        Args:
            playbook_id: ID of the playbook to execute.
            incident: Incident context dict with keys like title, severity,
                      affected_assets, affected_users, attacker_ip, etc.
            incident_id: Optional caller-supplied incident ID.

        Returns:
            PlaybookExecution record with all step results.
        """
        pb = _PLAYBOOKS.get(playbook_id)
        if pb is None:
            raise ValueError(f"Unknown playbook: {playbook_id!r}. "
                             f"Available: {list(_PLAYBOOKS)}")

        exec_id = str(uuid.uuid4())
        inc_id = incident_id or incident.get("incident_id", str(uuid.uuid4()))
        started = datetime.now(timezone.utc).isoformat()

        execution = PlaybookExecution(
            execution_id=exec_id,
            playbook_id=playbook_id,
            incident_id=inc_id,
            started_at=started,
            status=ExecutionStatus.RUNNING.value,
            steps_total=len(pb.steps),
            steps_completed=0,
            current_step=None,
            step_results=[],
            incident_data=incident,
        )

        self._save_execution(execution)

        _logger.info(
            "playbook_execution_started",
            execution_id=exec_id,
            playbook_id=playbook_id,
            incident_id=inc_id,
            steps=len(pb.steps),
        )

        aborted = False
        for step in pb.steps:
            execution.current_step = step.step_id
            self._save_execution(execution)

            result = self._execute_step(step, incident, inc_id)
            execution.step_results.append(result)

            if result.status == StepStatus.SUCCESS.value:
                execution.steps_completed += 1
            elif not step.continue_on_failure and result.status == StepStatus.FAILED.value:
                _logger.error(
                    "playbook_aborted_on_step_failure",
                    execution_id=exec_id,
                    step_id=step.step_id,
                )
                aborted = True
                break

        execution.current_step = None
        execution.completed_at = datetime.now(timezone.utc).isoformat()

        if aborted:
            execution.status = ExecutionStatus.FAILED.value
        elif execution.steps_completed == execution.steps_total:
            execution.status = ExecutionStatus.COMPLETED.value
        else:
            execution.status = ExecutionStatus.PARTIAL.value

        self._save_execution(execution)

        _logger.info(
            "playbook_execution_finished",
            execution_id=exec_id,
            status=execution.status,
            steps_completed=execution.steps_completed,
            steps_total=execution.steps_total,
        )
        _tg_emit("ir_playbook_runner.execution_finished", {
            "execution_id": exec_id,
            "playbook_id": execution.playbook_id,
            "status": execution.status.value if hasattr(execution.status, "value") else str(execution.status),
            "steps_completed": execution.steps_completed,
            "steps_total": execution.steps_total,
        })

        return execution

    def _execute_step(
        self,
        step: PlaybookStep,
        incident: Dict[str, Any],
        incident_id: str,
    ) -> StepResult:
        """Execute a single playbook step, returning a StepResult."""
        started = datetime.now(timezone.utc).isoformat()

        _logger.info(
            "playbook_step_starting",
            step_id=step.step_id,
            action=step.action,
        )

        try:
            output = self._dispatch_action(step.action, step.params, incident, incident_id)
            status = StepStatus.SUCCESS.value
            error = None
        except Exception as exc:
            _logger.warning(
                "playbook_step_failed",
                step_id=step.step_id,
                action=step.action,
                error=str(exc),
            )
            output = ""
            status = StepStatus.FAILED.value
            error = str(exc)

        completed = datetime.now(timezone.utc).isoformat()
        return StepResult(
            step_id=step.step_id,
            step_name=step.name,
            action=step.action,
            status=status,
            started_at=started,
            completed_at=completed,
            output=output,
            error=error,
        )

    # ── Action dispatcher ─────────────────────────────────────────────────

    def _dispatch_action(
        self,
        action: str,
        params: Dict[str, Any],
        incident: Dict[str, Any],
        incident_id: str,
    ) -> str:
        """Route an action name to its implementation. Returns output string."""
        handlers = {
            "send_notification": self._action_send_notification,
            "escalate_to_team": self._action_escalate_to_team,
            "create_ticket": self._action_create_ticket,
            "block_ip": self._action_block_ip,
            "quarantine_asset": self._action_quarantine_asset,
            "disable_account": self._action_disable_account,
            "force_password_reset": self._action_force_password_reset,
            "log_iocs": self._action_log_iocs,
        }
        handler = handlers.get(action)
        if handler is None:
            raise ValueError(f"Unknown action: {action!r}")
        return handler(params, incident, incident_id)

    # ── Action implementations ────────────────────────────────────────────

    def _action_send_notification(
        self,
        params: Dict[str, Any],
        incident: Dict[str, Any],
        incident_id: str,
    ) -> str:
        """Send ntfy.sh push notification."""
        ntfy = self._get_ntfy()
        if ntfy is None:
            raise RuntimeError("NtfyNotifier not available")

        from core.webhook_notifier import FindingPayload
        title = params.get("title", incident.get("title", "ALDECI Incident Alert"))
        severity = params.get("priority", incident.get("severity", "medium"))

        finding = FindingPayload(
            finding_id=incident_id,
            title=title,
            severity=severity,
            affected_asset=", ".join(incident.get("affected_assets", ["unknown"])),
            source="ir_playbook_runner",
            org_id=incident.get("org_id", "default"),
            description=incident.get("description", ""),
        )
        status_code, elapsed_ms, error = ntfy.notify(finding)
        if error:
            raise RuntimeError(f"ntfy.sh notification failed: {error}")
        return f"Notification sent via ntfy.sh (HTTP {status_code}, {elapsed_ms:.0f}ms)"

    def _action_escalate_to_team(
        self,
        params: Dict[str, Any],
        incident: Dict[str, Any],
        incident_id: str,
    ) -> str:
        """Send CRITICAL priority escalation via ntfy.sh."""
        ntfy = self._get_ntfy()
        if ntfy is None:
            raise RuntimeError("NtfyNotifier not available")

        from core.webhook_notifier import FindingPayload
        message = params.get("message", f"ESCALATION: {incident.get('title', 'Security Incident')}")

        finding = FindingPayload(
            finding_id=incident_id,
            title=f"ESCALATION: {message}",
            severity="critical",
            affected_asset=", ".join(incident.get("affected_assets", ["unknown"])),
            source="ir_playbook_runner",
            org_id=incident.get("org_id", "default"),
            description=message,
        )
        status_code, elapsed_ms, error = ntfy.notify(finding)
        if error:
            raise RuntimeError(f"Escalation notification failed: {error}")
        return f"CRITICAL escalation sent via ntfy.sh (HTTP {status_code}, {elapsed_ms:.0f}ms)"

    def _action_create_ticket(
        self,
        params: Dict[str, Any],
        incident: Dict[str, Any],
        incident_id: str,
    ) -> str:
        """Create GitHub Issue for incident tracking."""
        gh = self._get_gh()
        if gh is None:
            raise RuntimeError("GitHubIssuesClient not available")

        from core.github_issues_integration import Finding
        severity = params.get("severity", incident.get("severity", "high"))
        finding_type = params.get("finding_type", "network")
        title = incident.get("title", "Security Incident")
        description = incident.get("description", "")

        finding = Finding(
            finding_id=incident_id,
            title=f"[IR] {title}",
            severity=severity if severity != "medium" else "medium",
            finding_type=finding_type,
            description=f"Automated IR playbook ticket.\n\n{description}",
            extra={"incident_id": incident_id, "playbook": incident.get("playbook_id", "")},
        )
        result = gh.create_issue_from_finding(finding)
        if not result.success and result.action != "skipped":
            raise RuntimeError(f"GitHub issue creation failed: {result.error}")
        if result.action == "skipped":
            return f"GitHub issue already exists: #{result.issue_number}"
        return f"GitHub issue created: #{result.issue_number} — {result.issue_url}"

    def _action_block_ip(
        self,
        params: Dict[str, Any],
        incident: Dict[str, Any],
        incident_id: str,
    ) -> str:
        """Add IP(s) from incident to the SQLite blocklist."""
        ips = incident.get("attacker_ips", [])
        if not ips and incident.get("attacker_ip"):
            ips = [incident["attacker_ip"]]
        if not ips:
            # Extract any IPs from affected_assets
            ips = [
                a for a in incident.get("affected_assets", [])
                if self._looks_like_ip(a)
            ]
        if not ips:
            return "No IPs to block (none found in incident data)"

        reason = params.get("reason", "IR playbook block")
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            for ip in ips:
                self._conn.execute(
                    """INSERT OR REPLACE INTO ip_blocklist
                       (ip, reason, blocked_at, incident_id) VALUES (?,?,?,?)""",
                    (ip, reason, now, incident_id),
                )
            self._conn.commit()

        return f"Blocked {len(ips)} IP(s): {', '.join(ips)}"

    def _action_quarantine_asset(
        self,
        params: Dict[str, Any],
        incident: Dict[str, Any],
        incident_id: str,
    ) -> str:
        """Mark asset(s) as quarantined in SQLite."""
        assets = incident.get("affected_assets", [])
        if not assets:
            return "No assets to quarantine (none in incident data)"

        reason = params.get("reason", "IR playbook quarantine")
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            for asset in assets:
                asset_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{incident_id}:{asset}"))
                self._conn.execute(
                    """INSERT OR REPLACE INTO quarantined_assets
                       (asset_id, asset_name, reason, quarantined_at, incident_id)
                       VALUES (?,?,?,?,?)""",
                    (asset_id, asset, reason, now, incident_id),
                )
            self._conn.commit()

        return f"Quarantined {len(assets)} asset(s): {', '.join(assets)}"

    def _action_disable_account(
        self,
        params: Dict[str, Any],
        incident: Dict[str, Any],
        incident_id: str,
    ) -> str:
        """Mark account(s) as disabled in SQLite."""
        users = incident.get("affected_users", [])
        if not users:
            return "No accounts to disable (none in incident data)"

        reason = params.get("reason", "IR playbook account disable")
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            for username in users:
                acct_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"account:{username}"))
                self._conn.execute(
                    """INSERT OR REPLACE INTO disabled_accounts
                       (account_id, username, reason, disabled_at, incident_id, reset_required)
                       VALUES (?,?,?,?,?,0)""",
                    (acct_id, username, reason, now, incident_id),
                )
            self._conn.commit()

        return f"Disabled {len(users)} account(s): {', '.join(users)}"

    def _action_force_password_reset(
        self,
        params: Dict[str, Any],
        incident: Dict[str, Any],
        incident_id: str,
    ) -> str:
        """Flag account(s) as requiring password reset in SQLite."""
        users = incident.get("affected_users", [])
        if not users:
            return "No accounts for password reset (none in incident data)"

        reason = params.get("reason", "IR playbook force reset")
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            for username in users:
                acct_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"account:{username}"))
                self._conn.execute(
                    """INSERT INTO disabled_accounts
                       (account_id, username, reason, disabled_at, incident_id, reset_required)
                       VALUES (?,?,?,?,?,1)
                       ON CONFLICT(account_id) DO UPDATE SET reset_required=1""",
                    (acct_id, username, reason, now, incident_id),
                )
            self._conn.commit()

        return f"Password reset flagged for {len(users)} account(s): {', '.join(users)}"

    def _action_log_iocs(
        self,
        params: Dict[str, Any],
        incident: Dict[str, Any],
        incident_id: str,
    ) -> str:
        """Write IOCs from incident data to SQLite iocs table."""
        ioc_types = params.get("ioc_types", ["ip", "domain", "hash"])
        now = datetime.now(timezone.utc).isoformat()
        logged: List[str] = []

        field_map = {
            "ip": ["attacker_ips", "attacker_ip", "c2_ips"],
            "domain": ["domains", "c2_domains"],
            "hash": ["file_hashes", "hashes"],
            "url": ["urls", "phishing_urls"],
            "email": ["sender_email", "emails"],
            "user_agent": ["user_agents"],
            "session_token": ["session_tokens"],
            "file_extension": ["ransomware_extensions"],
            "registry_key": ["registry_keys"],
        }

        with self._lock:
            for ioc_type in ioc_types:
                fields = field_map.get(ioc_type, [ioc_type + "s"])
                for fld in fields:
                    raw = incident.get(fld, [])
                    if isinstance(raw, str):
                        raw = [raw] if raw else []
                    for value in raw:
                        ioc_id = str(uuid.uuid4())
                        self._conn.execute(
                            """INSERT OR IGNORE INTO iocs
                               (ioc_id, ioc_type, value, source, incident_id, logged_at)
                               VALUES (?,?,?,?,?,?)""",
                            (ioc_id, ioc_type, str(value), "ir_playbook_runner", incident_id, now),
                        )
                        logged.append(f"{ioc_type}:{value}")
            self._conn.commit()

        if not logged:
            return "No IOCs found in incident data to log"
        return f"Logged {len(logged)} IOC(s): {', '.join(logged[:5])}{'...' if len(logged) > 5 else ''}"

    # ── Utility ───────────────────────────────────────────────────────────

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        """Rough check if a string looks like an IPv4 address."""
        import re
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value))

    # ── Persistence ───────────────────────────────────────────────────────

    def _save_execution(self, execution: PlaybookExecution) -> None:
        step_results_json = json.dumps([asdict(sr) for sr in execution.step_results])
        incident_json = json.dumps(execution.incident_data)
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO executions
                   (execution_id, playbook_id, incident_id, started_at, completed_at,
                    status, steps_total, steps_completed, current_step,
                    step_results, incident_data)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    execution.execution_id,
                    execution.playbook_id,
                    execution.incident_id,
                    execution.started_at,
                    execution.completed_at,
                    execution.status,
                    execution.steps_total,
                    execution.steps_completed,
                    execution.current_step,
                    step_results_json,
                    incident_json,
                ),
            )
            self._conn.commit()

    def _row_to_execution(self, row: sqlite3.Row) -> PlaybookExecution:
        step_results_raw = json.loads(row["step_results"])
        step_results = [StepResult(**sr) for sr in step_results_raw]
        return PlaybookExecution(
            execution_id=row["execution_id"],
            playbook_id=row["playbook_id"],
            incident_id=row["incident_id"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            status=row["status"],
            steps_total=row["steps_total"],
            steps_completed=row["steps_completed"],
            current_step=row["current_step"],
            step_results=step_results,
            incident_data=json.loads(row["incident_data"]),
        )

    # ── Query API ─────────────────────────────────────────────────────────

    def get_execution_status(self, execution_id: str) -> Optional[PlaybookExecution]:
        """Get current execution status by ID."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM executions WHERE execution_id=?", (execution_id,)
            ).fetchone()
        if row is None:
            return None
        return self._row_to_execution(row)

    def list_executions(
        self,
        limit: int = 50,
        playbook_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[PlaybookExecution]:
        """List executions, optionally filtered by playbook or status."""
        where_clauses = []
        params: List[Any] = []
        if playbook_id:
            where_clauses.append("playbook_id=?")
            params.append(playbook_id)
        if status:
            where_clauses.append("status=?")
            params.append(status)

        where = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        params.append(limit)

        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM executions {where} ORDER BY started_at DESC LIMIT ?",  # nosec B608
                params,
            ).fetchall()
        return [self._row_to_execution(r) for r in rows]

    def manual_step_override(
        self,
        execution_id: str,
        step_id: str,
        result: str,
    ) -> None:
        """
        Analyst manually marks a step as complete or skipped.

        Adds an OVERRIDDEN StepResult to the execution's step_results
        and increments steps_completed if marking as complete.
        """
        execution = self.get_execution_status(execution_id)
        if execution is None:
            raise ValueError(f"Execution {execution_id!r} not found")

        now = datetime.now(timezone.utc).isoformat()
        status = StepStatus.OVERRIDDEN.value

        # Check if step already exists; if so, update it; else append
        existing_ids = [sr.step_id for sr in execution.step_results]
        if step_id in existing_ids:
            for sr in execution.step_results:
                if sr.step_id == step_id:
                    sr.status = status
                    sr.output = f"Manually overridden: {result}"
                    sr.completed_at = now
        else:
            execution.step_results.append(StepResult(
                step_id=step_id,
                step_name=step_id,
                action="manual_override",
                status=status,
                started_at=now,
                completed_at=now,
                output=f"Manually overridden: {result}",
            ))
            execution.steps_completed += 1

        self._save_execution(execution)
        _logger.info("manual_step_override", execution_id=execution_id, step_id=step_id)

    # ── Blocklist / quarantine query helpers ──────────────────────────────

    def get_blocked_ips(self, incident_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return blocked IPs, optionally filtered by incident."""
        with self._lock:
            if incident_id:
                rows = self._conn.execute(
                    "SELECT * FROM ip_blocklist WHERE incident_id=?", (incident_id,)
                ).fetchall()
            else:
                rows = self._conn.execute("SELECT * FROM ip_blocklist").fetchall()
        return [dict(r) for r in rows]

    def get_quarantined_assets(self, incident_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return quarantined assets, optionally filtered by incident."""
        with self._lock:
            if incident_id:
                rows = self._conn.execute(
                    "SELECT * FROM quarantined_assets WHERE incident_id=?", (incident_id,)
                ).fetchall()
            else:
                rows = self._conn.execute("SELECT * FROM quarantined_assets").fetchall()
        return [dict(r) for r in rows]

    def get_iocs(self, incident_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return logged IOCs, optionally filtered by incident."""
        with self._lock:
            if incident_id:
                rows = self._conn.execute(
                    "SELECT * FROM iocs WHERE incident_id=?", (incident_id,)
                ).fetchall()
            else:
                rows = self._conn.execute("SELECT * FROM iocs").fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_runner: Optional[IRPlaybookRunner] = None
_runner_lock = threading.Lock()


def get_playbook_runner(db_path: Optional[str] = None) -> IRPlaybookRunner:
    """Return module-level singleton IRPlaybookRunner."""
    global _runner
    with _runner_lock:
        if _runner is None:
            _runner = IRPlaybookRunner(db_path=db_path)
    return _runner
