"""
Security Awareness Training Tracker for ALDECI.

Tracks employee security awareness training completion, compliance evidence,
overdue training, and pass rates across organizations and compliance frameworks.

Supports 10 built-in training modules across 5 categories:
  phishing, passwords, data_handling, incident_reporting, social_engineering
"""
from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class TrainingCategory(str, Enum):
    PHISHING = "phishing"
    PASSWORDS = "passwords"
    DATA_HANDLING = "data_handling"
    INCIDENT_REPORTING = "incident_reporting"
    SOCIAL_ENGINEERING = "social_engineering"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class TrainingModule(BaseModel):
    """A security awareness training module."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    category: TrainingCategory
    duration_minutes: int = Field(ge=1)
    passing_score: int = Field(ge=0, le=100)
    content_url: str


class TrainingCompletion(BaseModel):
    """Record of a user completing (or attempting) a training module."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_email: str
    module_id: str
    score: int = Field(ge=0, le=100)
    passed: bool
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    org_id: str = Field(default="default")


# ---------------------------------------------------------------------------
# Built-in modules seed data
# ---------------------------------------------------------------------------

_BUILTIN_MODULES: List[Dict[str, Any]] = [
    {
        "id": "builtin-phishing-01",
        "title": "Phishing Awareness Fundamentals",
        "description": "Identify and avoid phishing emails, spear-phishing, and whaling attacks.",
        "category": "phishing",
        "duration_minutes": 20,
        "passing_score": 80,
        "content_url": "https://training.aldeci.internal/phishing-fundamentals",
    },
    {
        "id": "builtin-phishing-02",
        "title": "Advanced Phishing Simulation",
        "description": "Hands-on phishing simulation with real-world attack scenarios.",
        "category": "phishing",
        "duration_minutes": 30,
        "passing_score": 85,
        "content_url": "https://training.aldeci.internal/phishing-simulation",
    },
    {
        "id": "builtin-passwords-01",
        "title": "Password Hygiene and MFA",
        "description": "Strong passwords, password managers, and multi-factor authentication best practices.",
        "category": "passwords",
        "duration_minutes": 15,
        "passing_score": 80,
        "content_url": "https://training.aldeci.internal/password-hygiene",
    },
    {
        "id": "builtin-passwords-02",
        "title": "Credential Security and Secrets Management",
        "description": "Protecting credentials, avoiding hardcoded secrets, and using vaults.",
        "category": "passwords",
        "duration_minutes": 20,
        "passing_score": 80,
        "content_url": "https://training.aldeci.internal/credential-security",
    },
    {
        "id": "builtin-data-01",
        "title": "Data Classification and Handling",
        "description": "Classify data by sensitivity and apply appropriate handling procedures.",
        "category": "data_handling",
        "duration_minutes": 25,
        "passing_score": 75,
        "content_url": "https://training.aldeci.internal/data-classification",
    },
    {
        "id": "builtin-data-02",
        "title": "GDPR and Privacy Compliance",
        "description": "Data privacy obligations, GDPR rights, and breach notification procedures.",
        "category": "data_handling",
        "duration_minutes": 35,
        "passing_score": 80,
        "content_url": "https://training.aldeci.internal/gdpr-privacy",
    },
    {
        "id": "builtin-incident-01",
        "title": "Incident Reporting Procedures",
        "description": "How to identify, escalate, and report security incidents promptly.",
        "category": "incident_reporting",
        "duration_minutes": 20,
        "passing_score": 80,
        "content_url": "https://training.aldeci.internal/incident-reporting",
    },
    {
        "id": "builtin-incident-02",
        "title": "Ransomware Response Playbook",
        "description": "Immediate actions to take when ransomware is detected on your system.",
        "category": "incident_reporting",
        "duration_minutes": 25,
        "passing_score": 85,
        "content_url": "https://training.aldeci.internal/ransomware-response",
    },
    {
        "id": "builtin-social-01",
        "title": "Social Engineering Defense",
        "description": "Recognize vishing, pretexting, baiting, and tailgating attacks.",
        "category": "social_engineering",
        "duration_minutes": 20,
        "passing_score": 80,
        "content_url": "https://training.aldeci.internal/social-engineering",
    },
    {
        "id": "builtin-social-02",
        "title": "Safe Remote Work Practices",
        "description": "Securing home networks, avoiding shoulder surfing, and safe video conferencing.",
        "category": "social_engineering",
        "duration_minutes": 15,
        "passing_score": 75,
        "content_url": "https://training.aldeci.internal/remote-work-security",
    },
]

# Compliance framework → required module IDs mapping
_FRAMEWORK_MODULES: Dict[str, List[str]] = {
    "SOC2": [
        "builtin-phishing-01",
        "builtin-passwords-01",
        "builtin-incident-01",
        "builtin-data-01",
    ],
    "HIPAA": [
        "builtin-phishing-01",
        "builtin-passwords-01",
        "builtin-data-01",
        "builtin-data-02",
        "builtin-incident-01",
    ],
    "PCI-DSS": [
        "builtin-phishing-01",
        "builtin-phishing-02",
        "builtin-passwords-01",
        "builtin-passwords-02",
        "builtin-incident-01",
    ],
    "ISO27001": [
        "builtin-phishing-01",
        "builtin-passwords-01",
        "builtin-data-01",
        "builtin-incident-01",
        "builtin-social-01",
    ],
    "GDPR": [
        "builtin-data-01",
        "builtin-data-02",
        "builtin-incident-01",
    ],
    "NIST": [
        "builtin-phishing-01",
        "builtin-phishing-02",
        "builtin-passwords-01",
        "builtin-incident-01",
        "builtin-social-01",
    ],
}


# ---------------------------------------------------------------------------
# TrainingTracker — SQLite-backed
# ---------------------------------------------------------------------------

class TrainingTracker:
    """SQLite-backed security awareness training tracker."""

    def __init__(self, db_path: str = "data/training.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()
        self._seed_builtin_modules()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        conn = self._get_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS training_modules (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    category TEXT NOT NULL,
                    duration_minutes INTEGER NOT NULL,
                    passing_score INTEGER NOT NULL,
                    content_url TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS training_completions (
                    id TEXT PRIMARY KEY,
                    user_email TEXT NOT NULL,
                    module_id TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    passed INTEGER NOT NULL,
                    completed_at TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    FOREIGN KEY (module_id) REFERENCES training_modules(id)
                );

                CREATE INDEX IF NOT EXISTS idx_completions_user ON training_completions(user_email);
                CREATE INDEX IF NOT EXISTS idx_completions_org ON training_completions(org_id);
                CREATE INDEX IF NOT EXISTS idx_completions_module ON training_completions(module_id);
                CREATE INDEX IF NOT EXISTS idx_completions_org_user ON training_completions(org_id, user_email);
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _seed_builtin_modules(self) -> None:
        """Insert built-in modules if they don't already exist."""
        conn = self._get_connection()
        try:
            for m in _BUILTIN_MODULES:
                existing = conn.execute(
                    "SELECT id FROM training_modules WHERE id = ?", (m["id"],)
                ).fetchone()
                if not existing:
                    conn.execute(
                        "INSERT INTO training_modules VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            m["id"],
                            m["title"],
                            m["description"],
                            m["category"],
                            m["duration_minutes"],
                            m["passing_score"],
                            m["content_url"],
                        ),
                    )
            conn.commit()
        finally:
            conn.close()

    def _row_to_module(self, row: sqlite3.Row) -> TrainingModule:
        return TrainingModule(
            id=row["id"],
            title=row["title"],
            description=row["description"],
            category=TrainingCategory(row["category"]),
            duration_minutes=row["duration_minutes"],
            passing_score=row["passing_score"],
            content_url=row["content_url"],
        )

    def _row_to_completion(self, row: sqlite3.Row) -> TrainingCompletion:
        return TrainingCompletion(
            id=row["id"],
            user_email=row["user_email"],
            module_id=row["module_id"],
            score=row["score"],
            passed=bool(row["passed"]),
            completed_at=datetime.fromisoformat(row["completed_at"]),
            org_id=row["org_id"],
        )

    # ------------------------------------------------------------------
    # Module management
    # ------------------------------------------------------------------

    def add_module(self, module: TrainingModule) -> TrainingModule:
        """Create a new training module."""
        conn = self._get_connection()
        try:
            conn.execute(
                "INSERT INTO training_modules VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    module.id,
                    module.title,
                    module.description,
                    module.category.value,
                    module.duration_minutes,
                    module.passing_score,
                    module.content_url,
                ),
            )
            conn.commit()
            return module
        finally:
            conn.close()

    def list_modules(
        self,
        category: Optional[TrainingCategory] = None,
    ) -> List[TrainingModule]:
        """List available training modules, optionally filtered by category."""
        conn = self._get_connection()
        try:
            if category:
                rows = conn.execute(
                    "SELECT * FROM training_modules WHERE category = ? ORDER BY title",
                    (category.value,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM training_modules ORDER BY category, title"
                ).fetchall()
            return [self._row_to_module(r) for r in rows]
        finally:
            conn.close()

    def get_module(self, module_id: str) -> Optional[TrainingModule]:
        """Get a single training module by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM training_modules WHERE id = ?", (module_id,)
            ).fetchone()
            return self._row_to_module(row) if row else None
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Completion recording
    # ------------------------------------------------------------------

    def record_completion(self, completion: TrainingCompletion) -> TrainingCompletion:
        """Log a user's training result."""
        conn = self._get_connection()
        try:
            conn.execute(
                "INSERT INTO training_completions VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    completion.id,
                    completion.user_email,
                    completion.module_id,
                    completion.score,
                    int(completion.passed),
                    completion.completed_at.isoformat(),
                    completion.org_id,
                ),
            )
            conn.commit()
            return completion
        finally:
            conn.close()

    def get_user_training(
        self,
        email: str,
        org_id: Optional[str] = None,
    ) -> List[TrainingCompletion]:
        """Get a user's full training history."""
        conn = self._get_connection()
        try:
            if org_id:
                rows = conn.execute(
                    "SELECT * FROM training_completions WHERE user_email = ? AND org_id = ? ORDER BY completed_at DESC",
                    (email, org_id),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM training_completions WHERE user_email = ? ORDER BY completed_at DESC",
                    (email,),
                ).fetchall()
            return [self._row_to_completion(r) for r in rows]
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Org-level analytics
    # ------------------------------------------------------------------

    def get_completion_rate(self, org_id: str) -> Dict[str, Any]:
        """Percentage of users who completed each required (passing) module."""
        conn = self._get_connection()
        try:
            # Distinct users in org
            users = conn.execute(
                "SELECT DISTINCT user_email FROM training_completions WHERE org_id = ?",
                (org_id,),
            ).fetchall()
            total_users = len(users)

            # Modules available
            modules = conn.execute(
                "SELECT id, title FROM training_modules"
            ).fetchall()

            if total_users == 0:
                return {
                    "org_id": org_id,
                    "total_users": 0,
                    "overall_completion_rate": 0.0,
                    "by_module": {},
                }

            by_module: Dict[str, Any] = {}
            total_completed = 0
            total_possible = 0

            for mod in modules:
                passed_count = conn.execute(
                    "SELECT COUNT(DISTINCT user_email) FROM training_completions "
                    "WHERE org_id = ? AND module_id = ? AND passed = 1",
                    (org_id, mod["id"]),
                ).fetchone()[0]
                rate = round(passed_count / total_users * 100, 1)
                by_module[mod["id"]] = {
                    "title": mod["title"],
                    "users_passed": passed_count,
                    "completion_rate": rate,
                }
                total_completed += passed_count
                total_possible += total_users

            overall = round(total_completed / total_possible * 100, 1) if total_possible > 0 else 0.0

            return {
                "org_id": org_id,
                "total_users": total_users,
                "overall_completion_rate": overall,
                "by_module": by_module,
            }
        finally:
            conn.close()

    def get_overdue_training(
        self,
        org_id: str,
        required_module_ids: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Return users who haven't passed all required modules."""
        conn = self._get_connection()
        try:
            # Default to all built-in modules as required
            if required_module_ids is None:
                required_module_ids = [m["id"] for m in _BUILTIN_MODULES]

            users = conn.execute(
                "SELECT DISTINCT user_email FROM training_completions WHERE org_id = ?",
                (org_id,),
            ).fetchall()

            overdue: List[Dict[str, Any]] = []
            for user_row in users:
                email = user_row["user_email"]
                passed_modules = set(
                    row["module_id"]
                    for row in conn.execute(
                        "SELECT DISTINCT module_id FROM training_completions "
                        "WHERE user_email = ? AND org_id = ? AND passed = 1",
                        (email, org_id),
                    ).fetchall()
                )
                missing = [mid for mid in required_module_ids if mid not in passed_modules]
                if missing:
                    # Fetch titles for missing modules
                    missing_details = []
                    for mid in missing:
                        mod_row = conn.execute(
                            "SELECT id, title FROM training_modules WHERE id = ?", (mid,)
                        ).fetchone()
                        if mod_row:
                            missing_details.append({"id": mod_row["id"], "title": mod_row["title"]})
                        else:
                            missing_details.append({"id": mid, "title": "Unknown"})
                    overdue.append({
                        "user_email": email,
                        "missing_modules": missing_details,
                        "missing_count": len(missing),
                    })

            return overdue
        finally:
            conn.close()

    def get_training_stats(self, org_id: str) -> Dict[str, Any]:
        """Comprehensive stats: by module, by user, pass rates."""
        conn = self._get_connection()
        try:
            # By module stats
            modules = conn.execute(
                "SELECT id, title, category FROM training_modules"
            ).fetchall()

            by_module: List[Dict[str, Any]] = []
            for mod in modules:
                attempts = conn.execute(
                    "SELECT COUNT(*) FROM training_completions WHERE org_id = ? AND module_id = ?",
                    (org_id, mod["id"]),
                ).fetchone()[0]
                passed = conn.execute(
                    "SELECT COUNT(*) FROM training_completions WHERE org_id = ? AND module_id = ? AND passed = 1",
                    (org_id, mod["id"]),
                ).fetchone()[0]
                avg_score_row = conn.execute(
                    "SELECT AVG(score) FROM training_completions WHERE org_id = ? AND module_id = ?",
                    (org_id, mod["id"]),
                ).fetchone()[0]
                avg_score = round(avg_score_row, 1) if avg_score_row is not None else None
                by_module.append({
                    "module_id": mod["id"],
                    "title": mod["title"],
                    "category": mod["category"],
                    "total_attempts": attempts,
                    "total_passed": passed,
                    "pass_rate": round(passed / attempts * 100, 1) if attempts > 0 else 0.0,
                    "average_score": avg_score,
                })

            # By user stats
            users = conn.execute(
                "SELECT DISTINCT user_email FROM training_completions WHERE org_id = ?",
                (org_id,),
            ).fetchall()

            by_user: List[Dict[str, Any]] = []
            for user_row in users:
                email = user_row["user_email"]
                user_attempts = conn.execute(
                    "SELECT COUNT(*) FROM training_completions WHERE org_id = ? AND user_email = ?",
                    (org_id, email),
                ).fetchone()[0]
                user_passed = conn.execute(
                    "SELECT COUNT(*) FROM training_completions WHERE org_id = ? AND user_email = ? AND passed = 1",
                    (org_id, email),
                ).fetchone()[0]
                user_avg_row = conn.execute(
                    "SELECT AVG(score) FROM training_completions WHERE org_id = ? AND user_email = ?",
                    (org_id, email),
                ).fetchone()[0]
                by_user.append({
                    "user_email": email,
                    "total_attempts": user_attempts,
                    "modules_passed": user_passed,
                    "average_score": round(user_avg_row, 1) if user_avg_row is not None else None,
                })

            # Overall org stats
            total_attempts = conn.execute(
                "SELECT COUNT(*) FROM training_completions WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            total_passed = conn.execute(
                "SELECT COUNT(*) FROM training_completions WHERE org_id = ? AND passed = 1", (org_id,)
            ).fetchone()[0]

            return {
                "org_id": org_id,
                "total_attempts": total_attempts,
                "total_passed": total_passed,
                "overall_pass_rate": round(total_passed / total_attempts * 100, 1) if total_attempts > 0 else 0.0,
                "total_users": len(users),
                "by_module": by_module,
                "by_user": by_user,
            }
        finally:
            conn.close()

    def get_compliance_training_status(
        self,
        org_id: str,
        framework: str,
    ) -> Dict[str, Any]:
        """Training evidence for a compliance framework (SOC2, HIPAA, PCI-DSS, ISO27001, GDPR, NIST)."""
        framework_upper = framework.upper()
        required_ids = _FRAMEWORK_MODULES.get(framework_upper, [])

        conn = self._get_connection()
        try:
            users = conn.execute(
                "SELECT DISTINCT user_email FROM training_completions WHERE org_id = ?",
                (org_id,),
            ).fetchall()
            total_users = len(users)

            # Gather module details for required modules
            required_modules: List[Dict[str, Any]] = []
            for mid in required_ids:
                mod_row = conn.execute(
                    "SELECT id, title, category FROM training_modules WHERE id = ?", (mid,)
                ).fetchone()
                if not mod_row:
                    continue
                users_passed = conn.execute(
                    "SELECT COUNT(DISTINCT user_email) FROM training_completions "
                    "WHERE org_id = ? AND module_id = ? AND passed = 1",
                    (org_id, mid),
                ).fetchone()[0]
                required_modules.append({
                    "module_id": mid,
                    "title": mod_row["title"],
                    "category": mod_row["category"],
                    "users_completed": users_passed,
                    "completion_rate": round(users_passed / total_users * 100, 1) if total_users > 0 else 0.0,
                })

            # Fully compliant users (passed all required modules)
            compliant_users = 0
            non_compliant_users: List[str] = []
            for user_row in users:
                email = user_row["user_email"]
                passed_set = set(
                    r["module_id"]
                    for r in conn.execute(
                        "SELECT DISTINCT module_id FROM training_completions "
                        "WHERE user_email = ? AND org_id = ? AND passed = 1",
                        (email, org_id),
                    ).fetchall()
                )
                if all(mid in passed_set for mid in required_ids):
                    compliant_users += 1
                else:
                    non_compliant_users.append(email)

            compliance_rate = round(compliant_users / total_users * 100, 1) if total_users > 0 else 0.0

            return {
                "org_id": org_id,
                "framework": framework_upper,
                "required_module_count": len(required_ids),
                "total_users": total_users,
                "compliant_users": compliant_users,
                "non_compliant_users": non_compliant_users,
                "compliance_rate": compliance_rate,
                "required_modules": required_modules,
                "evidence_generated_at": datetime.now(timezone.utc).isoformat(),
            }
        finally:
            conn.close()
