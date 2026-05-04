"""Customer onboarding wizard for ALDECI/Fixops.

Tracks guided setup progress per organisation across 9 steps:
WELCOME → CONFIGURE_AUTH → CONNECT_SCANNERS → CONNECT_TICKETING →
SELECT_FRAMEWORKS → DEFINE_ROLES → RUN_FIRST_SCAN → REVIEW_RESULTS → COMPLETE

Storage: SQLite (one DB at data/onboarding.db).

Also preserves the legacy OnboardingGuide overlay helper.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_FRAMEWORKS = frozenset(
    {"SOC2", "PCI-DSS", "HIPAA", "ISO27001", "NIST-CSF", "CIS", "GDPR"}
)
VALID_ROLES = frozenset(
    {"admin", "security_analyst", "developer", "compliance_officer", "viewer", "sre"}
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class OnboardingStep(str, Enum):
    WELCOME = "WELCOME"
    CONFIGURE_AUTH = "CONFIGURE_AUTH"
    CONNECT_SCANNERS = "CONNECT_SCANNERS"
    CONNECT_TICKETING = "CONNECT_TICKETING"
    SELECT_FRAMEWORKS = "SELECT_FRAMEWORKS"
    DEFINE_ROLES = "DEFINE_ROLES"
    RUN_FIRST_SCAN = "RUN_FIRST_SCAN"
    REVIEW_RESULTS = "REVIEW_RESULTS"
    COMPLETE = "COMPLETE"


# Canonical ordering used for percentage calculation and next-step resolution
STEP_ORDER: List[OnboardingStep] = [
    OnboardingStep.WELCOME,
    OnboardingStep.CONFIGURE_AUTH,
    OnboardingStep.CONNECT_SCANNERS,
    OnboardingStep.CONNECT_TICKETING,
    OnboardingStep.SELECT_FRAMEWORKS,
    OnboardingStep.DEFINE_ROLES,
    OnboardingStep.RUN_FIRST_SCAN,
    OnboardingStep.REVIEW_RESULTS,
    OnboardingStep.COMPLETE,
]


class StepStatus(str, Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"


# ---------------------------------------------------------------------------
# Pydantic model
# ---------------------------------------------------------------------------


class OnboardingProgress(BaseModel):
    org_id: str
    current_step: OnboardingStep
    steps: Dict[str, StepStatus]
    started_at: datetime
    completed_at: Optional[datetime] = None
    completion_percentage: float = Field(ge=0.0, le=100.0)

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# Step validation
# ---------------------------------------------------------------------------


def _validate_step(step: OnboardingStep, config_data: Dict[str, Any]) -> None:
    """Raise ValueError when config_data does not satisfy step requirements."""

    if step == OnboardingStep.CONFIGURE_AUTH:
        has_api_key = bool(config_data.get("api_key") or config_data.get("api_keys"))
        has_sso = bool(
            config_data.get("sso_provider") or config_data.get("sso_enabled")
        )
        if not has_api_key and not has_sso:
            raise ValueError(
                "CONFIGURE_AUTH requires at least one of: api_key, api_keys, sso_provider, sso_enabled"
            )

    elif step == OnboardingStep.CONNECT_SCANNERS:
        scanners = config_data.get("scanners", [])
        if not scanners:
            raise ValueError(
                "CONNECT_SCANNERS requires at least 1 scanner in config_data['scanners']"
            )

    elif step == OnboardingStep.CONNECT_TICKETING:
        # Ticketing is optional — if called without connectors we allow it but warn
        connectors = config_data.get("connectors", [])
        if not connectors:
            raise ValueError(
                "CONNECT_TICKETING requires at least 1 ticketing connector in config_data['connectors']. "
                "Use skip_step() to skip this step."
            )

    elif step == OnboardingStep.SELECT_FRAMEWORKS:
        frameworks = config_data.get("frameworks", [])
        if not frameworks:
            raise ValueError(
                "SELECT_FRAMEWORKS requires at least 1 framework in config_data['frameworks']"
            )
        invalid = set(frameworks) - VALID_FRAMEWORKS
        if invalid:
            raise ValueError(
                f"Unknown compliance frameworks: {invalid}. Valid options: {sorted(VALID_FRAMEWORKS)}"
            )

    elif step == OnboardingStep.DEFINE_ROLES:
        users = config_data.get("users", [])
        admins = [u for u in users if isinstance(u, dict) and u.get("role") == "admin"]
        if not users:
            raise ValueError(
                "DEFINE_ROLES requires at least 1 user in config_data['users']"
            )
        if not admins:
            raise ValueError(
                "DEFINE_ROLES requires at least 1 user with role='admin'"
            )

    elif step == OnboardingStep.RUN_FIRST_SCAN:
        if not config_data.get("scan_triggered"):
            raise ValueError(
                "RUN_FIRST_SCAN requires config_data['scan_triggered'] = true"
            )

    elif step == OnboardingStep.REVIEW_RESULTS:
        if not config_data.get("first_scan_completed"):
            raise ValueError(
                "REVIEW_RESULTS requires config_data['first_scan_completed'] = true"
            )


# ---------------------------------------------------------------------------
# OnboardingManager
# ---------------------------------------------------------------------------

_DEFAULT_DB_PATH = (
    Path(__file__).resolve().parent.parent.parent / "data" / "onboarding.db"
)


class OnboardingManager:
    """SQLite-backed manager for the customer onboarding wizard."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self._lock = threading.Lock()
        # Thread-local connection cache — reuse within the same OS thread to
        # avoid repeated open/close overhead (hotfix #1).
        self._tls = threading.local()
        self._init_db()

    # ------------------------------------------------------------------
    # DB bootstrap
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            # Enable WAL mode for concurrent reads and reduced fsync latency
            # (hotfix #2).
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA cache_size=-4096")  # 4 MB page cache
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS onboardings (
                    org_id       TEXT PRIMARY KEY,
                    current_step TEXT NOT NULL,
                    steps        TEXT NOT NULL,
                    started_at   TEXT NOT NULL,
                    completed_at TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS step_configs (
                    org_id TEXT NOT NULL,
                    step   TEXT NOT NULL,
                    config TEXT NOT NULL,
                    PRIMARY KEY (org_id, step)
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        """Return a per-thread cached connection (hotfix #1)."""
        conn = getattr(self._tls, "conn", None)
        if conn is None:
            conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self._tls.conn = conn
        return conn

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _default_steps(self) -> Dict[str, str]:
        return {s.value: StepStatus.PENDING.value for s in STEP_ORDER}

    def _calc_percentage(self, steps: Dict[str, str]) -> float:
        done_statuses = {StepStatus.COMPLETED.value, StepStatus.SKIPPED.value}
        done = sum(1 for s in STEP_ORDER if steps.get(s.value) in done_statuses)
        return round(done / len(STEP_ORDER) * 100, 1)

    def _next_pending_step(self, steps: Dict[str, str]) -> OnboardingStep:
        for s in STEP_ORDER:
            if steps.get(s.value) == StepStatus.PENDING.value:
                return s
        return OnboardingStep.COMPLETE

    def _all_terminal(self, steps: Dict[str, str]) -> bool:
        terminal = {StepStatus.COMPLETED.value, StepStatus.SKIPPED.value}
        return all(
            steps.get(s.value) in terminal
            for s in STEP_ORDER
            if s != OnboardingStep.COMPLETE
        )

    def _row_to_progress(self, row: sqlite3.Row) -> OnboardingProgress:
        steps: Dict[str, str] = json.loads(row["steps"])
        return OnboardingProgress(
            org_id=row["org_id"],
            current_step=OnboardingStep(row["current_step"]),
            steps={k: StepStatus(v) for k, v in steps.items()},
            started_at=datetime.fromisoformat(row["started_at"]),
            completed_at=(
                datetime.fromisoformat(row["completed_at"])
                if row["completed_at"]
                else None
            ),
            completion_percentage=self._calc_percentage(steps),
        )

    def _get_row(
        self, org_id: str, conn: Optional[sqlite3.Connection] = None
    ) -> Optional[sqlite3.Row]:
        """Fetch the onboarding row.  Accepts an existing *conn* to avoid an
        extra connection open when the caller already holds one (hotfix #3)."""
        c = conn if conn is not None else self._connect()
        return c.execute(
            "SELECT * FROM onboardings WHERE org_id = ?", (org_id,)
        ).fetchone()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start_onboarding(self, org_id: str) -> OnboardingProgress:
        """Create a new onboarding session for org_id (idempotent — returns existing)."""
        with self._lock:
            conn = self._connect()
            existing = self._get_row(org_id, conn)
            if existing:
                return self._row_to_progress(existing)

            steps = self._default_steps()
            now = datetime.now(timezone.utc).isoformat()
            with conn:
                conn.execute(
                    """
                    INSERT INTO onboardings (org_id, current_step, steps, started_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (org_id, OnboardingStep.WELCOME.value, json.dumps(steps), now),
                )

            logger.info("Started onboarding for org=%s", org_id)
            return OnboardingProgress(
                org_id=org_id,
                current_step=OnboardingStep.WELCOME,
                steps={k: StepStatus(v) for k, v in steps.items()},
                started_at=datetime.fromisoformat(now),
                completion_percentage=0.0,
            )

    def get_progress(self, org_id: str) -> OnboardingProgress:
        """Return current onboarding progress for org_id."""
        row = self._get_row(org_id)
        if not row:
            raise KeyError(f"No onboarding found for org_id={org_id!r}")
        return self._row_to_progress(row)

    def complete_step(
        self,
        org_id: str,
        step: OnboardingStep,
        config_data: Dict[str, Any],
    ) -> OnboardingProgress:
        """Mark *step* as COMPLETED after validation; persist config_data."""
        _validate_step(step, config_data)

        with self._lock:
            # Reuse the same cached connection for read + write (hotfix #3).
            conn = self._connect()
            row = self._get_row(org_id, conn)
            if not row:
                raise KeyError(f"No onboarding found for org_id={org_id!r}")

            steps: Dict[str, str] = json.loads(row["steps"])
            steps[step.value] = StepStatus.COMPLETED.value

            completed_at: Optional[str] = None
            if self._all_terminal(steps):
                steps[OnboardingStep.COMPLETE.value] = StepStatus.COMPLETED.value
                completed_at = datetime.now(timezone.utc).isoformat()
                next_step = OnboardingStep.COMPLETE
            else:
                next_step = self._next_pending_step(steps)

            with conn:
                conn.execute(
                    """
                    UPDATE onboardings
                       SET current_step = ?, steps = ?, completed_at = ?
                     WHERE org_id = ?
                    """,
                    (next_step.value, json.dumps(steps), completed_at, org_id),
                )
                conn.execute(
                    """
                    INSERT OR REPLACE INTO step_configs (org_id, step, config)
                    VALUES (?, ?, ?)
                    """,
                    (org_id, step.value, json.dumps(config_data)),
                )

            logger.info("Completed step=%s for org=%s", step.value, org_id)
            return OnboardingProgress(
                org_id=org_id,
                current_step=next_step,
                steps={k: StepStatus(v) for k, v in steps.items()},
                started_at=datetime.fromisoformat(row["started_at"]),
                completed_at=(
                    datetime.fromisoformat(completed_at) if completed_at else None
                ),
                completion_percentage=self._calc_percentage(steps),
            )

    def skip_step(self, org_id: str, step: OnboardingStep) -> OnboardingProgress:
        """Mark *step* as SKIPPED (no config stored)."""
        with self._lock:
            # Reuse the same cached connection for read + write (hotfix #3).
            conn = self._connect()
            row = self._get_row(org_id, conn)
            if not row:
                raise KeyError(f"No onboarding found for org_id={org_id!r}")

            steps: Dict[str, str] = json.loads(row["steps"])
            steps[step.value] = StepStatus.SKIPPED.value

            completed_at: Optional[str] = None
            if self._all_terminal(steps):
                steps[OnboardingStep.COMPLETE.value] = StepStatus.COMPLETED.value
                completed_at = datetime.now(timezone.utc).isoformat()
                next_step = OnboardingStep.COMPLETE
            else:
                next_step = self._next_pending_step(steps)

            with conn:
                conn.execute(
                    """
                    UPDATE onboardings
                       SET current_step = ?, steps = ?, completed_at = ?
                     WHERE org_id = ?
                    """,
                    (next_step.value, json.dumps(steps), completed_at, org_id),
                )

            logger.info("Skipped step=%s for org=%s", step.value, org_id)
            return OnboardingProgress(
                org_id=org_id,
                current_step=next_step,
                steps={k: StepStatus(v) for k, v in steps.items()},
                started_at=datetime.fromisoformat(row["started_at"]),
                completed_at=(
                    datetime.fromisoformat(completed_at) if completed_at else None
                ),
                completion_percentage=self._calc_percentage(steps),
            )

    def get_step_config(self, org_id: str, step: OnboardingStep) -> Dict[str, Any]:
        """Return stored config for a completed step (empty dict if not found)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT config FROM step_configs WHERE org_id = ? AND step = ?",
                (org_id, step.value),
            ).fetchone()
        return json.loads(row["config"]) if row else {}

    def reset_onboarding(self, org_id: str) -> OnboardingProgress:
        """Delete all state for org_id and start a fresh onboarding."""
        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM onboardings WHERE org_id = ?", (org_id,))
                conn.execute("DELETE FROM step_configs WHERE org_id = ?", (org_id,))
        logger.info("Reset onboarding for org=%s", org_id)
        return self.start_onboarding(org_id)

    def list_onboardings(
        self, status_filter: Optional[str] = None
    ) -> List[OnboardingProgress]:
        """Admin view of all org onboardings.

        status_filter: 'completed' | 'in_progress' | 'not_started' | None (all)
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM onboardings ORDER BY started_at DESC"
            ).fetchall()

        results: List[OnboardingProgress] = []
        for row in rows:
            progress = self._row_to_progress(row)
            if status_filter == "completed" and progress.completed_at is None:
                continue
            if status_filter == "in_progress" and (
                progress.completed_at is not None
                or progress.completion_percentage == 0.0
            ):
                continue
            if status_filter == "not_started" and progress.completion_percentage > 0.0:
                continue
            results.append(progress)
        return results

    def get_checklist(self, org_id: str) -> Dict[str, Any]:
        """Pre-flight checklist: which steps are ready vs missing.

        Batches the step_configs fetch into a single query (hotfix #4 — was
        N+1 connections, one per step).
        """
        try:
            progress = self.get_progress(org_id)
        except KeyError:
            return {"org_id": org_id, "onboarding_started": False, "items": []}

        # Single query for all step configs instead of one per step.
        conn = self._connect()
        rows = conn.execute(
            "SELECT step, config FROM step_configs WHERE org_id = ?", (org_id,)
        ).fetchall()
        configs: Dict[str, Dict[str, Any]] = {
            r["step"]: json.loads(r["config"]) for r in rows
        }

        items = []
        for step in STEP_ORDER:
            raw_status = progress.steps.get(step.value, StepStatus.PENDING)
            status_val = (
                raw_status.value
                if isinstance(raw_status, StepStatus)
                else raw_status
            )
            config = configs.get(step.value, {})
            items.append(
                {
                    "step": step.value,
                    "status": status_val,
                    "has_config": bool(config),
                    "config_keys": list(config.keys()),
                }
            )

        return {
            "org_id": org_id,
            "onboarding_started": True,
            "current_step": progress.current_step,
            "completion_percentage": progress.completion_percentage,
            "items": items,
        }


# ---------------------------------------------------------------------------
# Legacy overlay helper (preserved for backward compatibility)
# ---------------------------------------------------------------------------


class OnboardingGuide:
    """Produce onboarding steps tailored to the active overlay mode."""

    def __init__(self, overlay: Any) -> None:
        self.overlay = overlay
        self.settings = overlay.onboarding_settings

    def _iter_steps(self) -> Iterable[Mapping[str, Any]]:
        for step in self.settings.get("checklist", []):
            if isinstance(step, Mapping):
                modes = step.get("modes")
                if modes and self.overlay.mode not in modes:
                    continue
                yield step

    def build(self, required_inputs: Sequence[str]) -> Dict[str, Any]:
        steps = []
        for step in self._iter_steps():
            steps.append({"label": step.get("step"), "modes": step.get("modes", [])})
        steps.extend(
            {"label": f"Provide {item.upper()} artefact", "modes": [self.overlay.mode]}
            for item in required_inputs
        )
        integrations = {
            "jira": self.overlay.jira,
            "confluence": self.overlay.confluence,
            "git": self.overlay.git,
            "ci": self.overlay.ci,
        }
        return {
            "mode": self.overlay.mode,
            "time_to_value_minutes": self.settings.get("time_to_value_minutes", 30),
            "steps": steps,
            "integrations": integrations,
        }


__all__ = [
    "OnboardingStep",
    "StepStatus",
    "OnboardingProgress",
    "OnboardingManager",
    "STEP_ORDER",
    "VALID_FRAMEWORKS",
    "VALID_ROLES",
    "OnboardingGuide",
]
