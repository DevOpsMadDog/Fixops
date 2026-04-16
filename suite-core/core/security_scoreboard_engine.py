"""Security Scoreboard Engine — ALDECI.

Gamified security team scoreboard with challenge tracking and leaderboard.

Capabilities:
  - Team registry: create, list, get with org isolation
  - Challenge lifecycle: create, score submission, completion
  - Leaderboard: teams ranked by score DESC
  - Stats: top team, avg score, active challenges

Compliance: NIST SP 800-50 (Security Awareness), ISO/IEC 27001 A.7.2.2
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

_VALID_TEAM_TYPES = {"blue", "red", "purple", "devsecops", "compliance"}
_VALID_CHALLENGE_TYPES = {
    "ctf", "tabletop", "red_vs_blue", "compliance_audit", "incident_drill"
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecurityScoreboardEngine:
    """SQLite WAL-backed Security Scoreboard engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_scoreboard.db (shared, org-scoped by column)
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "security_scoreboard.db")
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
                CREATE TABLE IF NOT EXISTS teams (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    name        TEXT NOT NULL,
                    team_type   TEXT NOT NULL DEFAULT 'blue',
                    department  TEXT NOT NULL DEFAULT '',
                    score       INTEGER NOT NULL DEFAULT 0,
                    wins        INTEGER NOT NULL DEFAULT 0,
                    losses      INTEGER NOT NULL DEFAULT 0,
                    status      TEXT NOT NULL DEFAULT 'active',
                    created_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_teams_org
                    ON teams (org_id, team_type, score DESC);

                CREATE TABLE IF NOT EXISTS challenges (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    challenge_type  TEXT NOT NULL,
                    max_points      INTEGER NOT NULL DEFAULT 100,
                    participants    TEXT NOT NULL DEFAULT '[]',
                    status          TEXT NOT NULL DEFAULT 'active',
                    started_at      TEXT NOT NULL,
                    completed_at    TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_challenges_org
                    ON challenges (org_id, status, started_at DESC);

                CREATE TABLE IF NOT EXISTS score_entries (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    challenge_id    TEXT NOT NULL,
                    team_id         TEXT NOT NULL,
                    points_earned   INTEGER NOT NULL DEFAULT 0,
                    notes           TEXT NOT NULL DEFAULT '',
                    submitted_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_score_entries_challenge
                    ON score_entries (org_id, challenge_id, submitted_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _deserialize_challenge(row: Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(row.get("participants"), str):
            try:
                row["participants"] = json.loads(row["participants"])
            except (json.JSONDecodeError, TypeError):
                row["participants"] = []
        return row

    # ------------------------------------------------------------------
    # Teams
    # ------------------------------------------------------------------

    def create_team(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new security team."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        team_type = data.get("team_type", "blue")
        if team_type not in _VALID_TEAM_TYPES:
            raise ValueError(
                f"Invalid team_type: {team_type!r}. "
                f"Must be one of {sorted(_VALID_TEAM_TYPES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "team_type": team_type,
            "department": data.get("department", ""),
            "score": 0,
            "wins": 0,
            "losses": 0,
            "status": "active",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO teams
                       (id, org_id, name, team_type, department, score, wins, losses,
                        status, created_at)
                       VALUES (:id, :org_id, :name, :team_type, :department, :score,
                               :wins, :losses, :status, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("RISK_ASSESSED", {"entity_type": "security_scoreboard", "org_id": org_id, "source_engine": "security_scoreboard"})
            except Exception:
                pass

        return record

    def list_teams(
        self, org_id: str, team_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List teams with optional type filter."""
        sql = "SELECT * FROM teams WHERE org_id = ?"
        params: list = [org_id]
        if team_type:
            sql += " AND team_type = ?"
            params.append(team_type)
        sql += " ORDER BY score DESC, created_at ASC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_team(self, org_id: str, team_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single team by ID. Returns None if not found."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM teams WHERE org_id = ? AND id = ?",
                (org_id, team_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Challenges
    # ------------------------------------------------------------------

    def record_challenge(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new security challenge."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        challenge_type = data.get("challenge_type", "")
        if challenge_type not in _VALID_CHALLENGE_TYPES:
            raise ValueError(
                f"Invalid challenge_type: {challenge_type!r}. "
                f"Must be one of {sorted(_VALID_CHALLENGE_TYPES)}"
            )

        max_points = int(data.get("max_points", 100))
        participants = data.get("participants", [])
        if not isinstance(participants, list):
            participants = []

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "challenge_type": challenge_type,
            "max_points": max_points,
            "participants": json.dumps(participants),
            "status": "active",
            "started_at": now,
            "completed_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO challenges
                       (id, org_id, name, challenge_type, max_points, participants,
                        status, started_at, completed_at)
                       VALUES (:id, :org_id, :name, :challenge_type, :max_points,
                               :participants, :status, :started_at, :completed_at)""",
                    record,
                )
        result = dict(record)
        result["participants"] = participants
        return result

    def submit_score(
        self,
        org_id: str,
        challenge_id: str,
        team_id: str,
        points_earned: int,
        notes: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Submit a score for a team in a challenge.

        Updates team score += points_earned.
        If points_earned >= max_points/2 → wins += 1, else losses += 1.
        Returns None if challenge or team not found.
        """
        with self._lock:
            with self._conn() as conn:
                challenge_row = conn.execute(
                    "SELECT * FROM challenges WHERE org_id = ? AND id = ?",
                    (org_id, challenge_id),
                ).fetchone()
                if not challenge_row:
                    return None

                team_row = conn.execute(
                    "SELECT * FROM teams WHERE org_id = ? AND id = ?",
                    (org_id, team_id),
                ).fetchone()
                if not team_row:
                    return None

                max_points = challenge_row["max_points"]
                threshold = max_points / 2

                # Determine win or loss
                if points_earned >= threshold:
                    conn.execute(
                        "UPDATE teams SET score = score + ?, wins = wins + 1 "
                        "WHERE org_id = ? AND id = ?",
                        (points_earned, org_id, team_id),
                    )
                else:
                    conn.execute(
                        "UPDATE teams SET score = score + ?, losses = losses + 1 "
                        "WHERE org_id = ? AND id = ?",
                        (points_earned, org_id, team_id),
                    )

                # Log score entry
                entry = {
                    "id": str(uuid.uuid4()),
                    "org_id": org_id,
                    "challenge_id": challenge_id,
                    "team_id": team_id,
                    "points_earned": points_earned,
                    "notes": notes,
                    "submitted_at": _now_iso(),
                }
                conn.execute(
                    """INSERT INTO score_entries
                       (id, org_id, challenge_id, team_id, points_earned, notes, submitted_at)
                       VALUES (:id, :org_id, :challenge_id, :team_id, :points_earned,
                               :notes, :submitted_at)""",
                    entry,
                )

                updated_team = conn.execute(
                    "SELECT * FROM teams WHERE org_id = ? AND id = ?",
                    (org_id, team_id),
                ).fetchone()
        return self._row(updated_team) if updated_team else None

    def list_challenges(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List challenges with optional status filter."""
        sql = "SELECT * FROM challenges WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY started_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._deserialize_challenge(self._row(r)) for r in rows]

    # ------------------------------------------------------------------
    # Leaderboard
    # ------------------------------------------------------------------

    def get_leaderboard(self, org_id: str) -> List[Dict[str, Any]]:
        """Return teams ordered by score DESC with rank field added."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM teams WHERE org_id = ? ORDER BY score DESC, created_at ASC",
                (org_id,),
            ).fetchall()
        result = []
        for rank, row in enumerate(rows, start=1):
            team = self._row(row)
            team["rank"] = rank
            result.append(team)
        return result

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_scoreboard_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated scoreboard stats for an org."""
        with self._conn() as conn:
            total_teams = conn.execute(
                "SELECT COUNT(*) FROM teams WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT team_type, COUNT(*) as cnt FROM teams "
                "WHERE org_id = ? GROUP BY team_type",
                (org_id,),
            ).fetchall()
            by_type = {r["team_type"]: r["cnt"] for r in type_rows}

            total_challenges = conn.execute(
                "SELECT COUNT(*) FROM challenges WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_challenges = conn.execute(
                "SELECT COUNT(*) FROM challenges WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            # Top team by score
            top_row = conn.execute(
                "SELECT name, score FROM teams WHERE org_id = ? ORDER BY score DESC LIMIT 1",
                (org_id,),
            ).fetchone()
            top_team = {"name": top_row["name"], "score": top_row["score"]} if top_row else None

            # Avg team score
            avg_row = conn.execute(
                "SELECT AVG(score) FROM teams WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            avg_team_score = round(avg_row, 2) if avg_row is not None else 0.0

        return {
            "total_teams": total_teams,
            "by_type": by_type,
            "total_challenges": total_challenges,
            "active_challenges": active_challenges,
            "top_team": top_team,
            "avg_team_score": avg_team_score,
        }
