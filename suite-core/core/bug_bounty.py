"""Vulnerability Disclosure Program (VDP) / Bug Bounty Management Engine.

Provides end-to-end bug bounty program management: program configuration,
submission intake, triage workflow, reward processing, researcher tracking,
ALDECI finding integration, and program metrics.

Usage:
    from core.bug_bounty import BugBountyEngine, get_bug_bounty_engine
    engine = get_bug_bounty_engine()
    program = engine.create_program(program_config)
    submission = engine.submit_vulnerability(submission_req)
    engine.triage_submission(submission.id, TriageDecision.ACCEPTED, cvss=8.5)
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

_DEFAULT_DB = os.getenv("FIXOPS_BUG_BOUNTY_DB", ".fixops_data/bug_bounty.db")

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:
    _get_tg_bus = None  # type: ignore[assignment]


def _tg_emit(event_type: str, payload: dict) -> None:
    try:
        if _get_tg_bus is None:
            return
        bus = _get_tg_bus()
        if bus is not None:
            bus.emit(event_type, payload)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ProgramStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    CLOSED = "closed"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class SubmissionStatus(str, Enum):
    NEW = "new"
    TRIAGING = "triaging"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    INFORMATIONAL = "informational"
    FIXED = "fixed"


class RewardStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    PAID = "paid"
    DISPUTED = "disputed"
    WAIVED = "waived"


class OWASPCategory(str, Enum):
    A01_BROKEN_ACCESS_CONTROL = "A01:2021-Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021-Cryptographic Failures"
    A03_INJECTION = "A03:2021-Injection"
    A04_INSECURE_DESIGN = "A04:2021-Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021-Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021-Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021-Identification and Authentication Failures"
    A08_DATA_INTEGRITY_FAILURES = "A08:2021-Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021-Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021-Server-Side Request Forgery"
    OTHER = "Other"


# Default reward tiers by severity (USD)
_DEFAULT_REWARDS: Dict[Severity, int] = {
    Severity.CRITICAL: 5000,
    Severity.HIGH: 2000,
    Severity.MEDIUM: 500,
    Severity.LOW: 100,
    Severity.INFORMATIONAL: 0,
}

# SLA hours for acknowledgement by severity
_SLA_HOURS: Dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 24,
    Severity.MEDIUM: 72,
    Severity.LOW: 168,
    Severity.INFORMATIONAL: 336,
}


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class RewardTier(BaseModel):
    severity: Severity
    min_reward: int = Field(ge=0, description="Minimum reward amount (USD)")
    max_reward: int = Field(ge=0, description="Maximum reward amount (USD)")
    bonus_eligible: bool = False


class ProgramScope(BaseModel):
    in_scope: List[str] = Field(default_factory=list, description="In-scope assets (domains, IPs, repos)")
    out_of_scope: List[str] = Field(default_factory=list, description="Explicitly out-of-scope assets")
    vulnerability_types: List[OWASPCategory] = Field(
        default_factory=lambda: list(OWASPCategory),
        description="Accepted vulnerability categories",
    )


class BountyProgram(BaseModel):
    id: str = Field(default_factory=lambda: f"prog-{uuid.uuid4().hex[:12]}")
    name: str
    description: str = ""
    status: ProgramStatus = ProgramStatus.ACTIVE
    scope: ProgramScope = Field(default_factory=ProgramScope)
    reward_tiers: Dict[str, RewardTier] = Field(default_factory=dict)
    safe_harbor: str = Field(
        default="Researchers acting in good faith will not face legal action.",
        description="Safe harbor policy text",
    )
    legal_terms: str = Field(default="", description="Full legal terms and conditions")
    monthly_budget: float = Field(default=0.0, ge=0, description="Monthly budget cap (USD)")
    org_id: str = "default"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_rewards_paid: float = 0.0
    submission_count: int = 0


class VulnerabilitySubmission(BaseModel):
    id: str = Field(default_factory=lambda: f"sub-{uuid.uuid4().hex[:12]}")
    program_id: str
    reporter_id: str
    reporter_email: str
    reporter_name: str = ""
    affected_asset: str = Field(..., description="Asset URL, domain, or identifier")
    vuln_type: OWASPCategory = OWASPCategory.OTHER
    title: str
    description: str
    poc_steps: str = Field(default="", description="Proof-of-concept reproduction steps")
    impact_assessment: str = Field(default="", description="Reporter's impact assessment")
    attachments: List[str] = Field(default_factory=list, description="Attachment URLs or filenames")
    status: SubmissionStatus = SubmissionStatus.NEW
    severity: Optional[Severity] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    duplicate_of: Optional[str] = Field(None, description="ID of original submission if duplicate")
    aldeci_finding_id: Optional[str] = Field(None, description="Linked ALDECI finding ID")
    reward_id: Optional[str] = None
    submitted_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    acknowledged_at: Optional[str] = None
    triaged_at: Optional[str] = None
    resolved_at: Optional[str] = None
    sla_deadline: Optional[str] = None
    triage_notes: str = ""
    org_id: str = "default"


class RewardRecord(BaseModel):
    id: str = Field(default_factory=lambda: f"rwd-{uuid.uuid4().hex[:12]}")
    submission_id: str
    reporter_id: str
    program_id: str
    amount: float = Field(ge=0)
    bonus_amount: float = Field(default=0.0, ge=0)
    status: RewardStatus = RewardStatus.PENDING
    currency: str = "USD"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    approved_at: Optional[str] = None
    paid_at: Optional[str] = None
    notes: str = ""
    org_id: str = "default"


class ResearcherProfile(BaseModel):
    id: str = Field(default_factory=lambda: f"rsr-{uuid.uuid4().hex[:12]}")
    email: str
    name: str = ""
    handle: str = ""
    preferred_contact: str = "email"
    reputation_score: float = Field(default=0.0, ge=0.0, le=100.0)
    total_earnings: float = 0.0
    total_submissions: int = 0
    accepted_submissions: int = 0
    duplicate_submissions: int = 0
    avg_response_time_hours: float = 0.0
    hall_of_fame: bool = False
    joined_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_active: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    org_id: str = "default"

    @property
    def acceptance_rate(self) -> float:
        if self.total_submissions == 0:
            return 0.0
        return round(self.accepted_submissions / self.total_submissions * 100, 1)


class ProgramMetrics(BaseModel):
    program_id: str
    total_submissions: int = 0
    submissions_by_status: Dict[str, int] = Field(default_factory=dict)
    submissions_by_severity: Dict[str, int] = Field(default_factory=dict)
    acceptance_rate: float = 0.0
    avg_triage_hours: float = 0.0
    avg_fix_hours: float = 0.0
    total_rewards_paid: float = 0.0
    monthly_spend: float = 0.0
    top_reporters: List[Dict[str, Any]] = Field(default_factory=list)
    submissions_this_month: int = 0
    roi_estimate: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# SQLite persistence layer
# ---------------------------------------------------------------------------


class _BugBountyDB:
    """SQLite persistence for bug bounty programs, submissions, rewards, and researchers."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        dir_part = os.path.dirname(db_path)
        if dir_part:
            os.makedirs(dir_part, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS bounty_programs (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'active',
                    scope_json TEXT NOT NULL DEFAULT '{}',
                    reward_tiers_json TEXT NOT NULL DEFAULT '{}',
                    safe_harbor TEXT NOT NULL DEFAULT '',
                    legal_terms TEXT NOT NULL DEFAULT '',
                    monthly_budget REAL NOT NULL DEFAULT 0.0,
                    org_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    total_rewards_paid REAL NOT NULL DEFAULT 0.0,
                    submission_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_prog_org ON bounty_programs(org_id);
                CREATE INDEX IF NOT EXISTS idx_prog_status ON bounty_programs(status);

                CREATE TABLE IF NOT EXISTS vulnerability_submissions (
                    id TEXT PRIMARY KEY,
                    program_id TEXT NOT NULL,
                    reporter_id TEXT NOT NULL,
                    reporter_email TEXT NOT NULL,
                    reporter_name TEXT NOT NULL DEFAULT '',
                    affected_asset TEXT NOT NULL,
                    vuln_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    poc_steps TEXT NOT NULL DEFAULT '',
                    impact_assessment TEXT NOT NULL DEFAULT '',
                    attachments_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL DEFAULT 'new',
                    severity TEXT,
                    cvss_score REAL,
                    duplicate_of TEXT,
                    aldeci_finding_id TEXT,
                    reward_id TEXT,
                    submitted_at TEXT NOT NULL,
                    acknowledged_at TEXT,
                    triaged_at TEXT,
                    resolved_at TEXT,
                    sla_deadline TEXT,
                    triage_notes TEXT NOT NULL DEFAULT '',
                    org_id TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_sub_program ON vulnerability_submissions(program_id);
                CREATE INDEX IF NOT EXISTS idx_sub_reporter ON vulnerability_submissions(reporter_id);
                CREATE INDEX IF NOT EXISTS idx_sub_status ON vulnerability_submissions(status);
                CREATE INDEX IF NOT EXISTS idx_sub_org ON vulnerability_submissions(org_id);
                CREATE INDEX IF NOT EXISTS idx_sub_asset ON vulnerability_submissions(affected_asset);

                CREATE TABLE IF NOT EXISTS reward_records (
                    id TEXT PRIMARY KEY,
                    submission_id TEXT NOT NULL,
                    reporter_id TEXT NOT NULL,
                    program_id TEXT NOT NULL,
                    amount REAL NOT NULL DEFAULT 0.0,
                    bonus_amount REAL NOT NULL DEFAULT 0.0,
                    status TEXT NOT NULL DEFAULT 'pending',
                    currency TEXT NOT NULL DEFAULT 'USD',
                    created_at TEXT NOT NULL,
                    approved_at TEXT,
                    paid_at TEXT,
                    notes TEXT NOT NULL DEFAULT '',
                    org_id TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_rwd_submission ON reward_records(submission_id);
                CREATE INDEX IF NOT EXISTS idx_rwd_reporter ON reward_records(reporter_id);
                CREATE INDEX IF NOT EXISTS idx_rwd_status ON reward_records(status);
                CREATE INDEX IF NOT EXISTS idx_rwd_org ON reward_records(org_id);

                CREATE TABLE IF NOT EXISTS researcher_profiles (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    handle TEXT NOT NULL DEFAULT '',
                    preferred_contact TEXT NOT NULL DEFAULT 'email',
                    reputation_score REAL NOT NULL DEFAULT 0.0,
                    total_earnings REAL NOT NULL DEFAULT 0.0,
                    total_submissions INTEGER NOT NULL DEFAULT 0,
                    accepted_submissions INTEGER NOT NULL DEFAULT 0,
                    duplicate_submissions INTEGER NOT NULL DEFAULT 0,
                    avg_response_time_hours REAL NOT NULL DEFAULT 0.0,
                    hall_of_fame INTEGER NOT NULL DEFAULT 0,
                    joined_at TEXT NOT NULL,
                    last_active TEXT NOT NULL,
                    org_id TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_rsr_email_org ON researcher_profiles(email, org_id);
                CREATE INDEX IF NOT EXISTS idx_rsr_org ON researcher_profiles(org_id);
                CREATE INDEX IF NOT EXISTS idx_rsr_reputation ON researcher_profiles(reputation_score);
                CREATE INDEX IF NOT EXISTS idx_rsr_earnings ON researcher_profiles(total_earnings);
            """)
            self._conn.commit()

    # ---- Programs ----

    def upsert_program(self, prog: BountyProgram) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO bounty_programs
                   (id, name, description, status, scope_json, reward_tiers_json,
                    safe_harbor, legal_terms, monthly_budget, org_id,
                    created_at, updated_at, total_rewards_paid, submission_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    prog.id, prog.name, prog.description, prog.status.value,
                    prog.scope.model_dump_json(),
                    json.dumps({k: v.model_dump() for k, v in prog.reward_tiers.items()}),
                    prog.safe_harbor, prog.legal_terms, prog.monthly_budget,
                    prog.org_id, prog.created_at, prog.updated_at,
                    prog.total_rewards_paid, prog.submission_count,
                ),
            )
            self._conn.commit()

    def get_program(self, program_id: str) -> Optional[BountyProgram]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM bounty_programs WHERE id = ?", (program_id,)
            ).fetchone()
        return self._row_to_program(dict(row)) if row else None

    def list_programs(self, org_id: str, status: Optional[str] = None) -> List[BountyProgram]:
        q = "SELECT * FROM bounty_programs WHERE org_id = ?"
        params: List[Any] = [org_id]
        if status:
            q += " AND status = ?"
            params.append(status)
        with self._lock:
            rows = self._conn.execute(q, params).fetchall()
        return [self._row_to_program(dict(r)) for r in rows]

    # ---- Submissions ----

    def upsert_submission(self, sub: VulnerabilitySubmission) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO vulnerability_submissions
                   (id, program_id, reporter_id, reporter_email, reporter_name,
                    affected_asset, vuln_type, title, description, poc_steps,
                    impact_assessment, attachments_json, status, severity, cvss_score,
                    duplicate_of, aldeci_finding_id, reward_id,
                    submitted_at, acknowledged_at, triaged_at, resolved_at,
                    sla_deadline, triage_notes, org_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    sub.id, sub.program_id, sub.reporter_id, sub.reporter_email,
                    sub.reporter_name, sub.affected_asset, sub.vuln_type.value,
                    sub.title, sub.description, sub.poc_steps, sub.impact_assessment,
                    json.dumps(sub.attachments), sub.status.value,
                    sub.severity.value if sub.severity else None,
                    sub.cvss_score, sub.duplicate_of, sub.aldeci_finding_id,
                    sub.reward_id, sub.submitted_at, sub.acknowledged_at,
                    sub.triaged_at, sub.resolved_at, sub.sla_deadline,
                    sub.triage_notes, sub.org_id,
                ),
            )
            self._conn.commit()

    def get_submission(self, submission_id: str) -> Optional[VulnerabilitySubmission]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM vulnerability_submissions WHERE id = ?", (submission_id,)
            ).fetchone()
        return self._row_to_submission(dict(row)) if row else None

    def list_submissions(
        self,
        org_id: str,
        program_id: Optional[str] = None,
        status: Optional[str] = None,
        reporter_id: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[VulnerabilitySubmission]:
        q = "SELECT * FROM vulnerability_submissions WHERE org_id = ?"
        params: List[Any] = [org_id]
        if program_id:
            q += " AND program_id = ?"
            params.append(program_id)
        if status:
            q += " AND status = ?"
            params.append(status)
        if reporter_id:
            q += " AND reporter_id = ?"
            params.append(reporter_id)
        if severity:
            q += " AND severity = ?"
            params.append(severity)
        q += " ORDER BY submitted_at DESC"
        with self._lock:
            rows = self._conn.execute(q, params).fetchall()
        return [self._row_to_submission(dict(r)) for r in rows]

    def find_duplicate(self, program_id: str, affected_asset: str, vuln_type: str) -> Optional[str]:
        """Return ID of existing accepted/triaging submission for same asset+type, if any."""
        with self._lock:
            row = self._conn.execute(
                """SELECT id FROM vulnerability_submissions
                   WHERE program_id = ? AND affected_asset = ? AND vuln_type = ?
                   AND status IN ('accepted', 'triaging', 'new')
                   ORDER BY submitted_at ASC LIMIT 1""",
                (program_id, affected_asset, vuln_type),
            ).fetchone()
        return dict(row)["id"] if row else None

    # ---- Rewards ----

    def upsert_reward(self, reward: RewardRecord) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO reward_records
                   (id, submission_id, reporter_id, program_id, amount, bonus_amount,
                    status, currency, created_at, approved_at, paid_at, notes, org_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    reward.id, reward.submission_id, reward.reporter_id,
                    reward.program_id, reward.amount, reward.bonus_amount,
                    reward.status.value, reward.currency, reward.created_at,
                    reward.approved_at, reward.paid_at, reward.notes, reward.org_id,
                ),
            )
            self._conn.commit()

    def get_reward(self, reward_id: str) -> Optional[RewardRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM reward_records WHERE id = ?", (reward_id,)
            ).fetchone()
        return self._row_to_reward(dict(row)) if row else None

    def list_rewards(
        self,
        org_id: str,
        program_id: Optional[str] = None,
        reporter_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[RewardRecord]:
        q = "SELECT * FROM reward_records WHERE org_id = ?"
        params: List[Any] = [org_id]
        if program_id:
            q += " AND program_id = ?"
            params.append(program_id)
        if reporter_id:
            q += " AND reporter_id = ?"
            params.append(reporter_id)
        if status:
            q += " AND status = ?"
            params.append(status)
        q += " ORDER BY created_at DESC"
        with self._lock:
            rows = self._conn.execute(q, params).fetchall()
        return [self._row_to_reward(dict(r)) for r in rows]

    def get_monthly_spend(self, program_id: str, org_id: str) -> float:
        """Return total paid rewards for the current calendar month."""
        month_start = datetime.now(timezone.utc).replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        ).isoformat()
        with self._lock:
            row = self._conn.execute(
                """SELECT COALESCE(SUM(amount + bonus_amount), 0)
                   FROM reward_records
                   WHERE program_id = ? AND org_id = ? AND status = 'paid'
                   AND paid_at >= ?""",
                (program_id, org_id, month_start),
            ).fetchone()
        return float(list(row)[0])

    # ---- Researchers ----

    def upsert_researcher(self, researcher: ResearcherProfile) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO researcher_profiles
                   (id, email, name, handle, preferred_contact, reputation_score,
                    total_earnings, total_submissions, accepted_submissions,
                    duplicate_submissions, avg_response_time_hours, hall_of_fame,
                    joined_at, last_active, org_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    researcher.id, researcher.email, researcher.name, researcher.handle,
                    researcher.preferred_contact, researcher.reputation_score,
                    researcher.total_earnings, researcher.total_submissions,
                    researcher.accepted_submissions, researcher.duplicate_submissions,
                    researcher.avg_response_time_hours,
                    1 if researcher.hall_of_fame else 0,
                    researcher.joined_at, researcher.last_active, researcher.org_id,
                ),
            )
            self._conn.commit()

    def get_researcher(self, researcher_id: str) -> Optional[ResearcherProfile]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM researcher_profiles WHERE id = ?", (researcher_id,)
            ).fetchone()
        return self._row_to_researcher(dict(row)) if row else None

    def get_researcher_by_email(self, email: str, org_id: str) -> Optional[ResearcherProfile]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM researcher_profiles WHERE email = ? AND org_id = ?",
                (email, org_id),
            ).fetchone()
        return self._row_to_researcher(dict(row)) if row else None

    def list_researchers(
        self,
        org_id: str,
        hall_of_fame_only: bool = False,
        limit: int = 100,
    ) -> List[ResearcherProfile]:
        q = "SELECT * FROM researcher_profiles WHERE org_id = ?"
        params: List[Any] = [org_id]
        if hall_of_fame_only:
            q += " AND hall_of_fame = 1"
        q += " ORDER BY reputation_score DESC, total_earnings DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(q, params).fetchall()
        return [self._row_to_researcher(dict(r)) for r in rows]

    def get_leaderboard(self, org_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT id, name, handle, reputation_score, total_earnings,
                          accepted_submissions, total_submissions, hall_of_fame
                   FROM researcher_profiles
                   WHERE org_id = ?
                   ORDER BY total_earnings DESC, accepted_submissions DESC
                   LIMIT ?""",
                (org_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    # ---- Aggregates ----

    def get_program_submission_stats(self, program_id: str, org_id: str) -> Dict[str, Any]:
        with self._lock:
            total = self._conn.execute(
                "SELECT COUNT(*) FROM vulnerability_submissions WHERE program_id = ? AND org_id = ?",
                (program_id, org_id),
            ).fetchone()[0]

            by_status = {
                r[0]: r[1]
                for r in self._conn.execute(
                    """SELECT status, COUNT(*) FROM vulnerability_submissions
                       WHERE program_id = ? AND org_id = ? GROUP BY status""",
                    (program_id, org_id),
                ).fetchall()
            }
            by_severity = {
                r[0]: r[1]
                for r in self._conn.execute(
                    """SELECT severity, COUNT(*) FROM vulnerability_submissions
                       WHERE program_id = ? AND org_id = ?
                       AND severity IS NOT NULL GROUP BY severity""",
                    (program_id, org_id),
                ).fetchall()
            }
            # avg triage time (hours) for submissions that have been triaged
            triage_row = self._conn.execute(
                """SELECT AVG((julianday(triaged_at) - julianday(submitted_at)) * 24)
                   FROM vulnerability_submissions
                   WHERE program_id = ? AND org_id = ?
                   AND triaged_at IS NOT NULL""",
                (program_id, org_id),
            ).fetchone()[0]
            # avg fix time
            fix_row = self._conn.execute(
                """SELECT AVG((julianday(resolved_at) - julianday(submitted_at)) * 24)
                   FROM vulnerability_submissions
                   WHERE program_id = ? AND org_id = ?
                   AND resolved_at IS NOT NULL""",
                (program_id, org_id),
            ).fetchone()[0]
            # monthly submissions
            month_start = datetime.now(timezone.utc).replace(
                day=1, hour=0, minute=0, second=0, microsecond=0
            ).isoformat()
            monthly = self._conn.execute(
                """SELECT COUNT(*) FROM vulnerability_submissions
                   WHERE program_id = ? AND org_id = ? AND submitted_at >= ?""",
                (program_id, org_id, month_start),
            ).fetchone()[0]
            # total paid
            paid_row = self._conn.execute(
                """SELECT COALESCE(SUM(amount + bonus_amount), 0)
                   FROM reward_records
                   WHERE program_id = ? AND org_id = ? AND status = 'paid'""",
                (program_id, org_id),
            ).fetchone()[0]

        accepted = by_status.get("accepted", 0)
        acceptance_rate = round(accepted / total * 100, 1) if total > 0 else 0.0

        return {
            "total": total,
            "by_status": by_status,
            "by_severity": by_severity,
            "acceptance_rate": acceptance_rate,
            "avg_triage_hours": round(triage_row or 0.0, 1),
            "avg_fix_hours": round(fix_row or 0.0, 1),
            "submissions_this_month": monthly,
            "total_rewards_paid": float(paid_row),
        }

    # ---- Row converters ----

    @staticmethod
    def _row_to_program(row: Dict[str, Any]) -> BountyProgram:
        scope_data = json.loads(row["scope_json"])
        tiers_data = json.loads(row["reward_tiers_json"])
        reward_tiers = {k: RewardTier(**v) for k, v in tiers_data.items()}
        return BountyProgram(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            status=ProgramStatus(row["status"]),
            scope=ProgramScope(**scope_data),
            reward_tiers=reward_tiers,
            safe_harbor=row["safe_harbor"],
            legal_terms=row["legal_terms"],
            monthly_budget=row["monthly_budget"],
            org_id=row["org_id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            total_rewards_paid=row["total_rewards_paid"],
            submission_count=row["submission_count"],
        )

    @staticmethod
    def _row_to_submission(row: Dict[str, Any]) -> VulnerabilitySubmission:
        return VulnerabilitySubmission(
            id=row["id"],
            program_id=row["program_id"],
            reporter_id=row["reporter_id"],
            reporter_email=row["reporter_email"],
            reporter_name=row["reporter_name"],
            affected_asset=row["affected_asset"],
            vuln_type=OWASPCategory(row["vuln_type"]),
            title=row["title"],
            description=row["description"],
            poc_steps=row["poc_steps"],
            impact_assessment=row["impact_assessment"],
            attachments=json.loads(row["attachments_json"]),
            status=SubmissionStatus(row["status"]),
            severity=Severity(row["severity"]) if row["severity"] else None,
            cvss_score=row["cvss_score"],
            duplicate_of=row["duplicate_of"],
            aldeci_finding_id=row["aldeci_finding_id"],
            reward_id=row["reward_id"],
            submitted_at=row["submitted_at"],
            acknowledged_at=row["acknowledged_at"],
            triaged_at=row["triaged_at"],
            resolved_at=row["resolved_at"],
            sla_deadline=row["sla_deadline"],
            triage_notes=row["triage_notes"],
            org_id=row["org_id"],
        )

    @staticmethod
    def _row_to_reward(row: Dict[str, Any]) -> RewardRecord:
        return RewardRecord(
            id=row["id"],
            submission_id=row["submission_id"],
            reporter_id=row["reporter_id"],
            program_id=row["program_id"],
            amount=row["amount"],
            bonus_amount=row["bonus_amount"],
            status=RewardStatus(row["status"]),
            currency=row["currency"],
            created_at=row["created_at"],
            approved_at=row["approved_at"],
            paid_at=row["paid_at"],
            notes=row["notes"],
            org_id=row["org_id"],
        )

    @staticmethod
    def _row_to_researcher(row: Dict[str, Any]) -> ResearcherProfile:
        return ResearcherProfile(
            id=row["id"],
            email=row["email"],
            name=row["name"],
            handle=row["handle"],
            preferred_contact=row["preferred_contact"],
            reputation_score=row["reputation_score"],
            total_earnings=row["total_earnings"],
            total_submissions=row["total_submissions"],
            accepted_submissions=row["accepted_submissions"],
            duplicate_submissions=row["duplicate_submissions"],
            avg_response_time_hours=row["avg_response_time_hours"],
            hall_of_fame=bool(row["hall_of_fame"]),
            joined_at=row["joined_at"],
            last_active=row["last_active"],
            org_id=row["org_id"],
        )


# ---------------------------------------------------------------------------
# BugBountyEngine — public interface
# ---------------------------------------------------------------------------


class BugBountyEngine:
    """End-to-end bug bounty / VDP management engine."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db = _BugBountyDB(db_path)
        logger.info("BugBountyEngine initialised", db_path=db_path)

    # ---- Program Management ----

    def create_program(
        self,
        name: str,
        description: str = "",
        scope: Optional[ProgramScope] = None,
        monthly_budget: float = 0.0,
        safe_harbor: str = "Researchers acting in good faith will not face legal action.",
        legal_terms: str = "",
        org_id: str = "default",
    ) -> BountyProgram:
        """Create a new bug bounty / VDP program with default reward tiers."""
        reward_tiers = {
            sev.value: RewardTier(
                severity=sev,
                min_reward=_DEFAULT_REWARDS[sev],
                max_reward=_DEFAULT_REWARDS[sev],
                bonus_eligible=(sev in (Severity.CRITICAL, Severity.HIGH)),
            )
            for sev in Severity
        }
        prog = BountyProgram(
            name=name,
            description=description,
            scope=scope or ProgramScope(),
            reward_tiers=reward_tiers,
            monthly_budget=monthly_budget,
            safe_harbor=safe_harbor,
            legal_terms=legal_terms,
            org_id=org_id,
        )
        self._db.upsert_program(prog)
        logger.info("Program created", program_id=prog.id, name=name, org_id=org_id)
        _tg_emit("bug_bounty.create_program", {"program_id": prog.id, "name": name, "org_id": org_id})
        return prog

    def update_program_status(self, program_id: str, status: ProgramStatus) -> BountyProgram:
        """Change a program's status (active / paused / closed)."""
        prog = self._require_program(program_id)
        prog.status = status
        prog.updated_at = datetime.now(timezone.utc).isoformat()
        self._db.upsert_program(prog)
        logger.info("Program status updated", program_id=program_id, status=status)
        return prog

    def update_program_scope(self, program_id: str, scope: ProgramScope) -> BountyProgram:
        """Replace the scope definition for a program."""
        prog = self._require_program(program_id)
        prog.scope = scope
        prog.updated_at = datetime.now(timezone.utc).isoformat()
        self._db.upsert_program(prog)
        logger.info("Program scope updated", program_id=program_id)
        return prog

    def get_program(self, program_id: str) -> Optional[BountyProgram]:
        return self._db.get_program(program_id)

    def list_programs(self, org_id: str, status: Optional[ProgramStatus] = None) -> List[BountyProgram]:
        return self._db.list_programs(org_id, status=status.value if status else None)

    # ---- Submission Portal ----

    def submit_vulnerability(
        self,
        program_id: str,
        reporter_email: str,
        reporter_name: str,
        affected_asset: str,
        vuln_type: OWASPCategory,
        title: str,
        description: str,
        poc_steps: str = "",
        impact_assessment: str = "",
        attachments: Optional[List[str]] = None,
        org_id: str = "default",
    ) -> VulnerabilitySubmission:
        """Accept an incoming vulnerability submission and auto-acknowledge it."""
        prog = self._require_program(program_id)
        if prog.status != ProgramStatus.ACTIVE:
            raise ValueError(f"Program '{program_id}' is not accepting submissions (status={prog.status.value})")

        # Get or create researcher profile
        researcher = self._get_or_create_researcher(reporter_email, reporter_name, org_id)

        # Auto-detect duplicate before creating submission
        existing_id = self._db.find_duplicate(program_id, affected_asset, vuln_type.value)

        now = datetime.now(timezone.utc)
        # Default SLA based on severity placeholder (will be updated at triage)
        sla_deadline = (now + timedelta(hours=_SLA_HOURS[Severity.MEDIUM])).isoformat()

        sub = VulnerabilitySubmission(
            program_id=program_id,
            reporter_id=researcher.id,
            reporter_email=reporter_email,
            reporter_name=reporter_name,
            affected_asset=affected_asset,
            vuln_type=vuln_type,
            title=title,
            description=description,
            poc_steps=poc_steps,
            impact_assessment=impact_assessment,
            attachments=attachments or [],
            acknowledged_at=now.isoformat(),
            sla_deadline=sla_deadline,
            org_id=org_id,
        )

        if existing_id:
            sub.status = SubmissionStatus.DUPLICATE
            sub.duplicate_of = existing_id
            logger.info("Duplicate detected", submission_id=sub.id, original_id=existing_id)

        self._db.upsert_submission(sub)

        # Update researcher activity + submission count
        researcher.total_submissions += 1
        if sub.status == SubmissionStatus.DUPLICATE:
            researcher.duplicate_submissions += 1
        researcher.last_active = now.isoformat()
        self._db.upsert_researcher(researcher)

        # Update program submission count
        prog.submission_count += 1
        prog.updated_at = now.isoformat()
        self._db.upsert_program(prog)

        logger.info(
            "Submission received",
            submission_id=sub.id,
            program_id=program_id,
            reporter_email=reporter_email,
            status=sub.status.value,
        )
        _tg_emit("bug_bounty.submit_vulnerability", {"submission_id": sub.id, "program_id": program_id, "status": sub.status.value})
        return sub

    # ---- Triage Workflow ----

    def triage_submission(
        self,
        submission_id: str,
        decision: SubmissionStatus,
        severity: Optional[Severity] = None,
        cvss_score: Optional[float] = None,
        notes: str = "",
    ) -> VulnerabilitySubmission:
        """Move submission through triage: set decision, severity, and CVSS."""
        valid_decisions = {
            SubmissionStatus.TRIAGING,
            SubmissionStatus.ACCEPTED,
            SubmissionStatus.REJECTED,
            SubmissionStatus.DUPLICATE,
            SubmissionStatus.INFORMATIONAL,
        }
        if decision not in valid_decisions:
            raise ValueError(f"Invalid triage decision: {decision}")

        sub = self._require_submission(submission_id)
        now = datetime.now(timezone.utc)

        sub.status = decision
        sub.triaged_at = now.isoformat()
        if notes:
            sub.triage_notes = notes
        if severity:
            sub.severity = severity
            # Recalculate SLA based on actual severity
            sub.sla_deadline = (now + timedelta(hours=_SLA_HOURS[severity])).isoformat()
        if cvss_score is not None:
            sub.cvss_score = cvss_score
            # Infer severity from CVSS if not explicitly provided
            if not severity:
                sub.severity = _cvss_to_severity(cvss_score)
                sub.sla_deadline = (now + timedelta(hours=_SLA_HOURS[sub.severity])).isoformat()

        self._db.upsert_submission(sub)

        # If accepted, auto-create reward record
        if decision == SubmissionStatus.ACCEPTED and sub.severity:
            self._create_pending_reward(sub)
            self._update_researcher_on_acceptance(sub.reporter_id, sub.org_id)

        logger.info(
            "Submission triaged",
            submission_id=submission_id,
            decision=decision.value,
            severity=sub.severity.value if sub.severity else None,
        )
        return sub

    def mark_submission_triaging(self, submission_id: str) -> VulnerabilitySubmission:
        """Move submission to triaging state."""
        return self.triage_submission(submission_id, SubmissionStatus.TRIAGING)

    def resolve_submission(self, submission_id: str, aldeci_finding_id: Optional[str] = None) -> VulnerabilitySubmission:
        """Mark a submission as fixed and optionally link an ALDECI finding."""
        sub = self._require_submission(submission_id)
        if sub.status != SubmissionStatus.ACCEPTED:
            raise ValueError(f"Only accepted submissions can be resolved. Current status: {sub.status.value}")
        now = datetime.now(timezone.utc)
        sub.status = SubmissionStatus.FIXED
        sub.resolved_at = now.isoformat()
        if aldeci_finding_id:
            sub.aldeci_finding_id = aldeci_finding_id
        self._db.upsert_submission(sub)
        logger.info("Submission resolved", submission_id=submission_id)
        return sub

    # ---- Reward Processing ----

    def update_reward_status(
        self,
        reward_id: str,
        status: RewardStatus,
        bonus_amount: float = 0.0,
        notes: str = "",
    ) -> RewardRecord:
        """Approve, pay, dispute, or waive a reward."""
        reward = self._require_reward(reward_id)
        now = datetime.now(timezone.utc).isoformat()
        reward.status = status
        if bonus_amount > 0:
            reward.bonus_amount = bonus_amount
        if notes:
            reward.notes = notes
        if status == RewardStatus.APPROVED:
            reward.approved_at = now
        elif status == RewardStatus.PAID:
            if not reward.approved_at:
                reward.approved_at = now
            reward.paid_at = now
            # Update program totals and researcher earnings
            self._on_reward_paid(reward)
        self._db.upsert_reward(reward)
        logger.info("Reward updated", reward_id=reward_id, status=status.value)
        return reward

    def get_reward(self, reward_id: str) -> Optional[RewardRecord]:
        return self._db.get_reward(reward_id)

    def list_rewards(
        self,
        org_id: str,
        program_id: Optional[str] = None,
        reporter_id: Optional[str] = None,
        status: Optional[RewardStatus] = None,
    ) -> List[RewardRecord]:
        return self._db.list_rewards(
            org_id,
            program_id=program_id,
            reporter_id=reporter_id,
            status=status.value if status else None,
        )

    # ---- Reporter Management ----

    def get_researcher(self, researcher_id: str) -> Optional[ResearcherProfile]:
        return self._db.get_researcher(researcher_id)

    def get_researcher_by_email(self, email: str, org_id: str) -> Optional[ResearcherProfile]:
        return self._db.get_researcher_by_email(email, org_id)

    def list_researchers(self, org_id: str, hall_of_fame_only: bool = False) -> List[ResearcherProfile]:
        return self._db.list_researchers(org_id, hall_of_fame_only=hall_of_fame_only)

    def update_researcher_profile(
        self,
        researcher_id: str,
        name: Optional[str] = None,
        handle: Optional[str] = None,
        preferred_contact: Optional[str] = None,
    ) -> ResearcherProfile:
        """Update mutable fields on a researcher profile."""
        researcher = self._require_researcher(researcher_id)
        if name is not None:
            researcher.name = name
        if handle is not None:
            researcher.handle = handle
        if preferred_contact is not None:
            researcher.preferred_contact = preferred_contact
        self._db.upsert_researcher(researcher)
        return researcher

    def promote_to_hall_of_fame(self, researcher_id: str) -> ResearcherProfile:
        """Promote a researcher to Hall of Fame status."""
        researcher = self._require_researcher(researcher_id)
        researcher.hall_of_fame = True
        self._db.upsert_researcher(researcher)
        logger.info("Researcher promoted to Hall of Fame", researcher_id=researcher_id)
        return researcher

    def get_leaderboard(self, org_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Return top researchers ranked by earnings and acceptance."""
        return self._db.get_leaderboard(org_id, limit=limit)

    # ---- ALDECI Finding Integration ----

    def link_aldeci_finding(self, submission_id: str, aldeci_finding_id: str) -> VulnerabilitySubmission:
        """Associate a submitted vuln with an existing ALDECI finding."""
        sub = self._require_submission(submission_id)
        sub.aldeci_finding_id = aldeci_finding_id
        self._db.upsert_submission(sub)
        logger.info(
            "Submission linked to ALDECI finding",
            submission_id=submission_id,
            finding_id=aldeci_finding_id,
        )
        return sub

    def create_aldeci_finding_from_submission(self, submission_id: str) -> Dict[str, Any]:
        """Generate an ALDECI-compatible finding dict from an accepted submission."""
        sub = self._require_submission(submission_id)
        if sub.status not in (SubmissionStatus.ACCEPTED, SubmissionStatus.FIXED):
            raise ValueError(f"Submission must be accepted or fixed to generate a finding. Status: {sub.status.value}")

        finding = {
            "id": f"aldeci-{sub.id}",
            "source": "bug_bounty",
            "title": sub.title,
            "description": sub.description,
            "affected_asset": sub.affected_asset,
            "severity": sub.severity.value if sub.severity else "unknown",
            "cvss_score": sub.cvss_score,
            "vuln_type": sub.vuln_type.value,
            "poc": sub.poc_steps,
            "impact": sub.impact_assessment,
            "reporter": sub.reporter_email,
            "submission_id": sub.id,
            "program_id": sub.program_id,
            "status": "open" if sub.status == SubmissionStatus.ACCEPTED else "fixed",
            "reported_at": sub.submitted_at,
            "resolved_at": sub.resolved_at,
        }
        logger.info("ALDECI finding generated", submission_id=submission_id, finding_id=finding["id"])
        return finding

    # ---- Metrics ----

    def get_program_metrics(self, program_id: str, org_id: str = "default") -> ProgramMetrics:
        """Compute full program metrics including ROI estimate."""
        self._require_program(program_id)
        stats = self._db.get_program_submission_stats(program_id, org_id)
        monthly_spend = self._db.get_monthly_spend(program_id, org_id)
        top_reporters = self._db.get_leaderboard(org_id, limit=5)

        # ROI estimate: avg breach cost $4.45M (IBM 2023) vs bounty paid
        total_paid = stats["total_rewards_paid"]
        roi = {
            "total_rewards_paid": total_paid,
            "estimated_breach_cost_avoided": stats.get("by_status", {}).get("accepted", 0) * 50000,
            "roi_ratio": round(
                (stats.get("by_status", {}).get("accepted", 0) * 50000) / max(total_paid, 1), 2
            ),
            "note": "Assumes avg $50K cost avoided per accepted critical/high finding",
        }

        return ProgramMetrics(
            program_id=program_id,
            total_submissions=stats["total"],
            submissions_by_status=stats["by_status"],
            submissions_by_severity=stats["by_severity"],
            acceptance_rate=stats["acceptance_rate"],
            avg_triage_hours=stats["avg_triage_hours"],
            avg_fix_hours=stats["avg_fix_hours"],
            total_rewards_paid=stats["total_rewards_paid"],
            monthly_spend=monthly_spend,
            top_reporters=top_reporters,
            submissions_this_month=stats["submissions_this_month"],
            roi_estimate=roi,
        )

    def get_submission(self, submission_id: str) -> Optional[VulnerabilitySubmission]:
        return self._db.get_submission(submission_id)

    def list_submissions(
        self,
        org_id: str,
        program_id: Optional[str] = None,
        status: Optional[SubmissionStatus] = None,
        reporter_id: Optional[str] = None,
        severity: Optional[Severity] = None,
    ) -> List[VulnerabilitySubmission]:
        return self._db.list_submissions(
            org_id,
            program_id=program_id,
            status=status.value if status else None,
            reporter_id=reporter_id,
            severity=severity.value if severity else None,
        )

    # ---- Internal helpers ----

    def _require_program(self, program_id: str) -> BountyProgram:
        prog = self._db.get_program(program_id)
        if not prog:
            raise KeyError(f"Program '{program_id}' not found")
        return prog

    def _require_submission(self, submission_id: str) -> VulnerabilitySubmission:
        sub = self._db.get_submission(submission_id)
        if not sub:
            raise KeyError(f"Submission '{submission_id}' not found")
        return sub

    def _require_reward(self, reward_id: str) -> RewardRecord:
        reward = self._db.get_reward(reward_id)
        if not reward:
            raise KeyError(f"Reward '{reward_id}' not found")
        return reward

    def _require_researcher(self, researcher_id: str) -> ResearcherProfile:
        researcher = self._db.get_researcher(researcher_id)
        if not researcher:
            raise KeyError(f"Researcher '{researcher_id}' not found")
        return researcher

    def _get_or_create_researcher(
        self, email: str, name: str, org_id: str
    ) -> ResearcherProfile:
        existing = self._db.get_researcher_by_email(email, org_id)
        if existing:
            return existing
        researcher = ResearcherProfile(email=email, name=name, org_id=org_id)
        self._db.upsert_researcher(researcher)
        logger.info("Researcher profile created", email=email, org_id=org_id)
        return researcher

    def _create_pending_reward(self, sub: VulnerabilitySubmission) -> RewardRecord:
        """Create a pending reward for an accepted submission."""
        prog = self._db.get_program(sub.program_id)
        base_amount = 0.0
        if prog and sub.severity:
            tier = prog.reward_tiers.get(sub.severity.value)
            base_amount = float(tier.min_reward) if tier else _DEFAULT_REWARDS.get(sub.severity, 0)

        reward = RewardRecord(
            submission_id=sub.id,
            reporter_id=sub.reporter_id,
            program_id=sub.program_id,
            amount=base_amount,
            org_id=sub.org_id,
        )
        self._db.upsert_reward(reward)

        # Link reward back to submission
        sub.reward_id = reward.id
        self._db.upsert_submission(sub)
        return reward

    def _update_researcher_on_acceptance(self, reporter_id: str, org_id: str) -> None:
        researcher = self._db.get_researcher(reporter_id)
        if not researcher:
            return
        researcher.accepted_submissions += 1
        # Reputation: weighted by acceptance rate (0-100)
        rate = researcher.accepted_submissions / max(researcher.total_submissions, 1)
        researcher.reputation_score = min(round(rate * 100, 1), 100.0)
        self._db.upsert_researcher(researcher)

    def _on_reward_paid(self, reward: RewardRecord) -> None:
        total = reward.amount + reward.bonus_amount
        # Update researcher earnings
        researcher = self._db.get_researcher(reward.reporter_id)
        if researcher:
            researcher.total_earnings += total
            # Hall of fame threshold: $10K lifetime earnings
            if researcher.total_earnings >= 10_000:
                researcher.hall_of_fame = True
            self._db.upsert_researcher(researcher)
        # Update program totals
        prog = self._db.get_program(reward.program_id)
        if prog:
            prog.total_rewards_paid += total
            prog.updated_at = datetime.now(timezone.utc).isoformat()
            self._db.upsert_program(prog)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cvss_to_severity(score: float) -> Severity:
    """Map CVSS v3 numeric score to Severity enum."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFORMATIONAL


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_engine_instance: Optional[BugBountyEngine] = None
_engine_lock = threading.Lock()


def get_bug_bounty_engine(db_path: str = _DEFAULT_DB) -> BugBountyEngine:
    """Return the process-level singleton BugBountyEngine."""
    global _engine_instance
    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = BugBountyEngine(db_path=db_path)
    return _engine_instance
