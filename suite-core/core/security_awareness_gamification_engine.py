"""Security Awareness Gamification Engine — ALDECI.

Manages challenges, completions, leaderboards, badges, and user points
for security awareness training gamification.

Multi-tenant via org_id. Thread-safe via RLock. SQLite WAL mode.
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

_VALID_CHALLENGE_TYPES = {"quiz", "phishing_sim", "ctf", "training", "policy_review"}
_VALID_DIFFICULTIES = {"easy", "medium", "hard", "expert"}
_VALID_BADGE_TYPES = {"achievement", "milestone", "streak", "special"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecurityAwarenessGamificationEngine:
    """SQLite WAL-backed Security Awareness Gamification engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Tables: sag_challenges, sag_completions, sag_badges, sag_user_points.
    """

    def __init__(self, db_dir: str = _DEFAULT_DB_DIR) -> None:
        self._db_dir = db_dir
        self._db_path = str(Path(db_dir) / "security_awareness_gamification.db")
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
                CREATE TABLE IF NOT EXISTS sag_challenges (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    title           TEXT NOT NULL DEFAULT '',
                    challenge_type  TEXT NOT NULL DEFAULT 'quiz',
                    points          INTEGER NOT NULL DEFAULT 10,
                    difficulty      TEXT NOT NULL DEFAULT 'medium',
                    department      TEXT NOT NULL DEFAULT '',
                    active          INTEGER NOT NULL DEFAULT 1,
                    created_at      DATETIME
                );

                CREATE TABLE IF NOT EXISTS sag_completions (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    user_id             TEXT NOT NULL,
                    challenge_id        TEXT NOT NULL,
                    score               REAL NOT NULL DEFAULT 0.0,
                    time_spent_seconds  INTEGER NOT NULL DEFAULT 0,
                    passed              INTEGER NOT NULL DEFAULT 0,
                    completed_at        DATETIME
                );

                CREATE TABLE IF NOT EXISTS sag_badges (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    user_id     TEXT NOT NULL,
                    badge_name  TEXT NOT NULL DEFAULT '',
                    badge_type  TEXT NOT NULL DEFAULT 'achievement',
                    description TEXT NOT NULL DEFAULT '',
                    awarded_at  DATETIME
                );

                CREATE TABLE IF NOT EXISTS sag_user_points (
                    org_id          TEXT NOT NULL,
                    user_id         TEXT NOT NULL,
                    total_points    INTEGER NOT NULL DEFAULT 0,
                    last_updated    DATETIME,
                    PRIMARY KEY (org_id, user_id)
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Challenges
    # ------------------------------------------------------------------

    def create_challenge(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new challenge. Validates title required, challenge_type and difficulty."""
        title = data.get("title", "").strip()
        if not title:
            raise ValueError("title is required")

        challenge_type = data.get("challenge_type", "quiz")
        if challenge_type not in _VALID_CHALLENGE_TYPES:
            raise ValueError(
                f"Invalid challenge_type '{challenge_type}'. "
                f"Must be one of: {sorted(_VALID_CHALLENGE_TYPES)}"
            )

        difficulty = data.get("difficulty", "medium")
        if difficulty not in _VALID_DIFFICULTIES:
            raise ValueError(
                f"Invalid difficulty '{difficulty}'. "
                f"Must be one of: {sorted(_VALID_DIFFICULTIES)}"
            )

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "title": title,
            "challenge_type": challenge_type,
            "points": int(data.get("points", 10)),
            "difficulty": difficulty,
            "department": data.get("department", ""),
            "active": 1,
            "created_at": _now_iso(),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO sag_challenges
                       (id, org_id, title, challenge_type, points, difficulty,
                        department, active, created_at)
                       VALUES (:id, :org_id, :title, :challenge_type, :points,
                               :difficulty, :department, :active, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_awareness_gamification", "org_id": org_id, "source_engine": "security_awareness_gamification"})
            except Exception:
                pass

        return record

    def list_challenges(
        self,
        org_id: str,
        challenge_type: Optional[str] = None,
        difficulty: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List challenges with optional filters."""
        query = "SELECT * FROM sag_challenges WHERE org_id = ?"
        params: List[Any] = [org_id]
        if challenge_type:
            query += " AND challenge_type = ?"
            params.append(challenge_type)
        if difficulty:
            query += " AND difficulty = ?"
            params.append(difficulty)
        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Completions
    # ------------------------------------------------------------------

    def record_completion(
        self,
        org_id: str,
        user_id: str,
        challenge_id: str,
        completion_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Record a challenge completion. If passed=True, add points to user_points."""
        passed = bool(completion_data.get("passed", False))
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "user_id": user_id,
            "challenge_id": challenge_id,
            "score": float(completion_data.get("score", 0.0)),
            "time_spent_seconds": int(completion_data.get("time_spent_seconds", 0)),
            "passed": 1 if passed else 0,
            "completed_at": _now_iso(),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO sag_completions
                       (id, org_id, user_id, challenge_id, score,
                        time_spent_seconds, passed, completed_at)
                       VALUES (:id, :org_id, :user_id, :challenge_id, :score,
                               :time_spent_seconds, :passed, :completed_at)""",
                    record,
                )

                if passed:
                    # Look up challenge points
                    ch_row = conn.execute(
                        "SELECT points FROM sag_challenges WHERE id = ? AND org_id = ?",
                        (challenge_id, org_id),
                    ).fetchone()
                    points_to_add = ch_row["points"] if ch_row else 10

                    # Upsert user points
                    conn.execute(
                        """INSERT INTO sag_user_points (org_id, user_id, total_points, last_updated)
                           VALUES (?, ?, ?, ?)
                           ON CONFLICT(org_id, user_id) DO UPDATE SET
                               total_points = total_points + excluded.total_points,
                               last_updated = excluded.last_updated""",
                        (org_id, user_id, points_to_add, _now_iso()),
                    )
        return record

    # ------------------------------------------------------------------
    # Leaderboard
    # ------------------------------------------------------------------

    def get_leaderboard(
        self,
        org_id: str,
        department: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Return leaderboard ordered by total_points DESC with ranks."""
        if department:
            query = """
                SELECT up.user_id, up.total_points,
                       COUNT(c.id) AS completions_count
                FROM sag_user_points up
                LEFT JOIN sag_completions c
                    ON c.org_id = up.org_id AND c.user_id = up.user_id
                LEFT JOIN sag_challenges ch
                    ON ch.id = c.challenge_id AND ch.org_id = up.org_id
                WHERE up.org_id = ? AND ch.department = ?
                GROUP BY up.user_id, up.total_points
                ORDER BY up.total_points DESC
                LIMIT ?
            """
            params: List[Any] = [org_id, department, limit]
        else:
            query = """
                SELECT up.user_id, up.total_points,
                       COUNT(c.id) AS completions_count
                FROM sag_user_points up
                LEFT JOIN sag_completions c
                    ON c.org_id = up.org_id AND c.user_id = up.user_id
                WHERE up.org_id = ?
                GROUP BY up.user_id, up.total_points
                ORDER BY up.total_points DESC
                LIMIT ?
            """
            params = [org_id, limit]

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()

        result = []
        for rank, row in enumerate(rows, start=1):
            result.append({
                "user_id": row["user_id"],
                "total_points": row["total_points"],
                "rank": rank,
            })
        return result

    # ------------------------------------------------------------------
    # User Profile
    # ------------------------------------------------------------------

    def get_user_profile(self, org_id: str, user_id: str) -> Dict[str, Any]:
        """Return user profile with points, completions, badges, challenges_passed."""
        with self._lock:
            with self._conn() as conn:
                points_row = conn.execute(
                    "SELECT total_points FROM sag_user_points WHERE org_id = ? AND user_id = ?",
                    (org_id, user_id),
                ).fetchone()

                completions_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM sag_completions WHERE org_id = ? AND user_id = ?",
                    (org_id, user_id),
                ).fetchone()

                passed_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM sag_completions "
                    "WHERE org_id = ? AND user_id = ? AND passed = 1",
                    (org_id, user_id),
                ).fetchone()

                badge_rows = conn.execute(
                    "SELECT * FROM sag_badges WHERE org_id = ? AND user_id = ? ORDER BY awarded_at DESC",
                    (org_id, user_id),
                ).fetchall()

        return {
            "user_id": user_id,
            "total_points": points_row["total_points"] if points_row else 0,
            "completions_count": completions_row["cnt"] if completions_row else 0,
            "challenges_passed": passed_row["cnt"] if passed_row else 0,
            "badges": [dict(b) for b in badge_rows],
        }

    # ------------------------------------------------------------------
    # Badges
    # ------------------------------------------------------------------

    def award_badge(
        self,
        org_id: str,
        user_id: str,
        badge_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Award a badge to a user. Validates badge_type."""
        badge_type = badge_data.get("badge_type", "achievement")
        if badge_type not in _VALID_BADGE_TYPES:
            raise ValueError(
                f"Invalid badge_type '{badge_type}'. "
                f"Must be one of: {sorted(_VALID_BADGE_TYPES)}"
            )

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "user_id": user_id,
            "badge_name": badge_data.get("badge_name", ""),
            "badge_type": badge_type,
            "description": badge_data.get("description", ""),
            "awarded_at": _now_iso(),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO sag_badges
                       (id, org_id, user_id, badge_name, badge_type, description, awarded_at)
                       VALUES (:id, :org_id, :user_id, :badge_name, :badge_type,
                               :description, :awarded_at)""",
                    record,
                )
        return record

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_gamification_stats(self, org_id: str) -> Dict[str, Any]:
        """Return org-wide gamification stats."""
        with self._lock:
            with self._conn() as conn:
                total_challenges = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM sag_challenges WHERE org_id = ?",
                    (org_id,),
                ).fetchone()["cnt"]

                total_completions = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM sag_completions WHERE org_id = ?",
                    (org_id,),
                ).fetchone()["cnt"]

                active_users_row = conn.execute(
                    "SELECT COUNT(DISTINCT user_id) AS cnt FROM sag_completions WHERE org_id = ?",
                    (org_id,),
                ).fetchone()

                avg_score_row = conn.execute(
                    "SELECT AVG(score) AS avg FROM sag_completions WHERE org_id = ?",
                    (org_id,),
                ).fetchone()

                # Top department by completions
                top_dept_row = conn.execute(
                    """SELECT ch.department, COUNT(c.id) AS cnt
                       FROM sag_completions c
                       JOIN sag_challenges ch ON ch.id = c.challenge_id AND ch.org_id = c.org_id
                       WHERE c.org_id = ?
                       GROUP BY ch.department
                       ORDER BY cnt DESC
                       LIMIT 1""",
                    (org_id,),
                ).fetchone()

        return {
            "total_challenges": total_challenges,
            "total_completions": total_completions,
            "active_users": active_users_row["cnt"] if active_users_row else 0,
            "avg_score": round(float(avg_score_row["avg"] or 0.0), 2) if avg_score_row else 0.0,
            "top_department": top_dept_row["department"] if top_dept_row else None,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine_instance: Optional[SecurityAwarenessGamificationEngine] = None
_engine_lock = threading.Lock()


def get_engine() -> SecurityAwarenessGamificationEngine:
    global _engine_instance
    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = SecurityAwarenessGamificationEngine()
        return _engine_instance
