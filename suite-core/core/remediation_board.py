"""
RemediationBoard — Kanban-style security fix tracking.

Provides:
- BoardColumn enum: BACKLOG, TODO, IN_PROGRESS, IN_REVIEW, TESTING, DONE
- RemediationCard Pydantic model with full metadata
- RemediationBoard class (thread-safe, SQLite-backed):
  - create_card / move_card / assign_card / add_comment
  - get_board (Kanban view) / get_card / get_overdue
  - get_assignee_workload / get_board_metrics (cycle time, throughput, WIP)
  - auto_create_from_findings (bulk import)

Compliance: SOC2 CC7.2, NIST CSF RS.MI-1
"""

from __future__ import annotations

import json
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


class BoardColumn(str, Enum):
    """Kanban columns for security remediation workflow."""

    BACKLOG = "backlog"
    TODO = "todo"
    IN_PROGRESS = "in_progress"
    IN_REVIEW = "in_review"
    TESTING = "testing"
    DONE = "done"


class CardPriority(str, Enum):
    """Priority levels for remediation cards."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CardComment(BaseModel):
    """A single comment on a remediation card."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    author: str
    text: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RemediationCard(BaseModel):
    """A single Kanban card tracking a security finding remediation."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str
    title: str
    description: str = ""
    assignee: Optional[str] = None
    column: BoardColumn = BoardColumn.BACKLOG
    priority: CardPriority = CardPriority.MEDIUM
    due_date: Optional[datetime] = None
    labels: List[str] = Field(default_factory=list)
    comments: List[CardComment] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    moved_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    org_id: str = "default"

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# SQLite schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS remediation_cards (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    finding_id  TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    assignee    TEXT,
    column_name TEXT NOT NULL DEFAULT 'backlog',
    priority    TEXT NOT NULL DEFAULT 'medium',
    due_date    TEXT,
    labels      TEXT NOT NULL DEFAULT '[]',
    created_at  TEXT NOT NULL,
    moved_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rc_org    ON remediation_cards (org_id, column_name);
CREATE INDEX IF NOT EXISTS idx_rc_finding ON remediation_cards (finding_id);
CREATE INDEX IF NOT EXISTS idx_rc_assign ON remediation_cards (org_id, assignee);
CREATE INDEX IF NOT EXISTS idx_rc_due    ON remediation_cards (org_id, due_date);

CREATE TABLE IF NOT EXISTS card_comments (
    id         TEXT PRIMARY KEY,
    card_id    TEXT NOT NULL,
    author     TEXT NOT NULL,
    text       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (card_id) REFERENCES remediation_cards(id)
);
CREATE INDEX IF NOT EXISTS idx_cc_card ON card_comments (card_id, created_at);
"""

# Column order for cycle-time calculations
_COLUMN_ORDER: Dict[str, int] = {
    BoardColumn.BACKLOG: 0,
    BoardColumn.TODO: 1,
    BoardColumn.IN_PROGRESS: 2,
    BoardColumn.IN_REVIEW: 3,
    BoardColumn.TESTING: 4,
    BoardColumn.DONE: 5,
}

# Priority → CVSS-like numeric weight for auto-create
_SEVERITY_TO_PRIORITY: Dict[str, CardPriority] = {
    "critical": CardPriority.CRITICAL,
    "high": CardPriority.HIGH,
    "medium": CardPriority.MEDIUM,
    "low": CardPriority.LOW,
    "info": CardPriority.INFORMATIONAL,
    "informational": CardPriority.INFORMATIONAL,
}


# ---------------------------------------------------------------------------
# RemediationBoard
# ---------------------------------------------------------------------------


class RemediationBoard:
    """Thread-safe, SQLite-backed Kanban board for security remediation.

    Usage::

        board = RemediationBoard()
        card = board.create_card(
            finding_id="CVE-2024-1234",
            title="Patch OpenSSL",
            assignee="alice@example.com",
            priority="high",
            org_id="acme",
        )
        board.move_card(card.id, BoardColumn.IN_PROGRESS)
        view = board.get_board("acme")
    """

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._db_path = Path(str(db_path))
        self._lock = threading.RLock()
        self._mem_conn: Optional[sqlite3.Connection] = None
        self._init_db()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        if str(self._db_path) == ":memory:":
            if self._mem_conn is None:
                self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
                self._mem_conn.row_factory = sqlite3.Row
            return self._mem_conn
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            conn.executescript(_SCHEMA)
            conn.commit()

    @staticmethod
    def _row_to_card(row: sqlite3.Row, comments: List[CardComment]) -> RemediationCard:
        d = dict(row)
        d["column"] = d.pop("column_name")
        d["labels"] = json.loads(d.get("labels") or "[]")
        d["comments"] = comments
        if d.get("due_date"):
            d["due_date"] = datetime.fromisoformat(d["due_date"])
        return RemediationCard(**d)

    def _load_comments(self, conn: sqlite3.Connection, card_id: str) -> List[CardComment]:
        rows = conn.execute(
            "SELECT * FROM card_comments WHERE card_id = ? ORDER BY created_at",
            (card_id,),
        ).fetchall()
        return [CardComment(**dict(r)) for r in rows]

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def create_card(
        self,
        *,
        finding_id: str,
        title: str,
        assignee: Optional[str] = None,
        priority: str = "medium",
        org_id: str = "default",
        description: str = "",
        labels: Optional[List[str]] = None,
        due_date: Optional[datetime] = None,
    ) -> RemediationCard:
        """Create a new card in BACKLOG and return it."""
        now = datetime.now(timezone.utc)
        card = RemediationCard(
            finding_id=finding_id,
            title=title,
            description=description,
            assignee=assignee,
            column=BoardColumn.BACKLOG,
            priority=_SEVERITY_TO_PRIORITY.get(priority.lower(), CardPriority.MEDIUM),
            due_date=due_date,
            labels=labels or [],
            created_at=now,
            moved_at=now,
            org_id=org_id,
        )
        with self._lock:
            conn = self._connect()
            conn.execute(
                """
                INSERT INTO remediation_cards
                    (id, org_id, finding_id, title, description, assignee,
                     column_name, priority, due_date, labels, created_at, moved_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    card.id,
                    card.org_id,
                    card.finding_id,
                    card.title,
                    card.description,
                    card.assignee,
                    card.column,
                    card.priority,
                    card.due_date.isoformat() if card.due_date else None,
                    json.dumps(card.labels),
                    card.created_at.isoformat(),
                    card.moved_at.isoformat(),
                ),
            )
            conn.commit()
        _logger.debug("remediation_board: created card %s (%s)", card.id, card.finding_id)
        return card

    def move_card(self, card_id: str, to_column: BoardColumn | str) -> RemediationCard:
        """Move a card to a different column. Returns updated card."""
        col = BoardColumn(to_column) if isinstance(to_column, str) else to_column
        now = datetime.now(timezone.utc)
        with self._lock:
            conn = self._connect()
            result = conn.execute(
                "SELECT id FROM remediation_cards WHERE id = ?", (card_id,)
            ).fetchone()
            if result is None:
                raise KeyError(f"Card not found: {card_id}")
            conn.execute(
                "UPDATE remediation_cards SET column_name = ?, moved_at = ? WHERE id = ?",
                (col.value, now.isoformat(), card_id),
            )
            conn.commit()
        return self.get_card(card_id)  # type: ignore[return-value]

    def assign_card(self, card_id: str, assignee: str) -> RemediationCard:
        """Change the assignee of a card. Returns updated card."""
        with self._lock:
            conn = self._connect()
            result = conn.execute(
                "SELECT id FROM remediation_cards WHERE id = ?", (card_id,)
            ).fetchone()
            if result is None:
                raise KeyError(f"Card not found: {card_id}")
            conn.execute(
                "UPDATE remediation_cards SET assignee = ? WHERE id = ?",
                (assignee, card_id),
            )
            conn.commit()
        return self.get_card(card_id)  # type: ignore[return-value]

    def add_comment(self, card_id: str, author: str, text: str) -> CardComment:
        """Add a comment to a card. Returns the new comment."""
        with self._lock:
            conn = self._connect()
            result = conn.execute(
                "SELECT id FROM remediation_cards WHERE id = ?", (card_id,)
            ).fetchone()
            if result is None:
                raise KeyError(f"Card not found: {card_id}")
            comment = CardComment(author=author, text=text)
            conn.execute(
                "INSERT INTO card_comments (id, card_id, author, text, created_at) VALUES (?, ?, ?, ?, ?)",
                (comment.id, card_id, comment.author, comment.text, comment.created_at.isoformat()),
            )
            conn.commit()
        _logger.debug("remediation_board: comment added to card %s by %s", card_id, author)
        return comment

    def auto_create_from_findings(
        self, findings: List[Dict[str, Any]], org_id: str = "default"
    ) -> List[RemediationCard]:
        """Bulk-create cards from a list of finding dicts.

        Each finding dict should have at least: id/finding_id, title.
        Optional: description, severity/priority, assignee, labels.
        Already-existing finding_ids are skipped.
        """
        with self._lock:
            conn = self._connect()
            existing_ids = {
                row[0]
                for row in conn.execute(
                    "SELECT finding_id FROM remediation_cards WHERE org_id = ?", (org_id,)
                ).fetchall()
            }

        created: List[RemediationCard] = []
        for f in findings:
            fid = f.get("finding_id") or f.get("id") or str(uuid.uuid4())
            if fid in existing_ids:
                continue
            card = self.create_card(
                finding_id=fid,
                title=f.get("title", f"Finding {fid}"),
                description=f.get("description", ""),
                assignee=f.get("assignee"),
                priority=f.get("severity") or f.get("priority") or "medium",
                org_id=org_id,
                labels=f.get("labels") or [],
            )
            created.append(card)
        _logger.info("remediation_board: auto_create_from_findings created %d cards", len(created))
        return created

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get_card(self, card_id: str) -> Optional[RemediationCard]:
        """Return full card details with comments, or None if not found."""
        with self._lock:
            conn = self._connect()
            row = conn.execute(
                "SELECT * FROM remediation_cards WHERE id = ?", (card_id,)
            ).fetchone()
            if row is None:
                return None
            comments = self._load_comments(conn, card_id)
        return self._row_to_card(row, comments)

    def get_board(self, org_id: str) -> Dict[str, List[RemediationCard]]:
        """Return all cards for an org grouped by column (Kanban view)."""
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM remediation_cards WHERE org_id = ? ORDER BY column_name, moved_at DESC",
                (org_id,),
            ).fetchall()
            card_ids = [r["id"] for r in rows]
            comments_by_card: Dict[str, List[CardComment]] = {}
            for cid in card_ids:
                comments_by_card[cid] = self._load_comments(conn, cid)

        board: Dict[str, List[RemediationCard]] = {col.value: [] for col in BoardColumn}
        for row in rows:
            card = self._row_to_card(row, comments_by_card.get(row["id"], []))
            board[card.column].append(card)
        return board

    def get_assignee_workload(self, org_id: str) -> Dict[str, int]:
        """Return card count per assignee (excluding DONE) for an org."""
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                """
                SELECT assignee, COUNT(*) as cnt
                FROM remediation_cards
                WHERE org_id = ? AND assignee IS NOT NULL AND column_name != 'done'
                GROUP BY assignee
                ORDER BY cnt DESC
                """,
                (org_id,),
            ).fetchall()
        return {row["assignee"]: row["cnt"] for row in rows}

    def get_board_metrics(self, org_id: str) -> Dict[str, Any]:
        """Return board metrics: cycle_time_hours, throughput_per_day, wip_by_column, total_cards."""
        with self._lock:
            conn = self._connect()

            # WIP per column
            wip_rows = conn.execute(
                """
                SELECT column_name, COUNT(*) as cnt
                FROM remediation_cards
                WHERE org_id = ?
                GROUP BY column_name
                """,
                (org_id,),
            ).fetchall()
            wip: Dict[str, int] = {row["column_name"]: row["cnt"] for row in wip_rows}

            # Total cards and done cards
            total = sum(wip.values())
            done_count = wip.get(BoardColumn.DONE, 0)

            # Cycle time: average hours from created_at to moved_at for DONE cards
            done_cards = conn.execute(
                """
                SELECT created_at, moved_at FROM remediation_cards
                WHERE org_id = ? AND column_name = 'done'
                """,
                (org_id,),
            ).fetchall()

        cycle_time_hours: Optional[float] = None
        if done_cards:
            durations = []
            for dc in done_cards:
                try:
                    created = datetime.fromisoformat(dc["created_at"])
                    moved = datetime.fromisoformat(dc["moved_at"])
                    durations.append((moved - created).total_seconds() / 3600)
                except Exception:
                    pass
            if durations:
                cycle_time_hours = round(sum(durations) / len(durations), 2)

        # Throughput: done cards / distinct days spanned
        throughput_per_day: Optional[float] = None
        if done_cards:
            try:
                dates = [
                    datetime.fromisoformat(dc["moved_at"]).date() for dc in done_cards
                ]
                date_range = (max(dates) - min(dates)).days + 1
                throughput_per_day = round(done_count / date_range, 2)
            except Exception:
                throughput_per_day = float(done_count)

        return {
            "total_cards": total,
            "done_count": done_count,
            "wip_by_column": wip,
            "cycle_time_hours": cycle_time_hours,
            "throughput_per_day": throughput_per_day,
            "active_wip": sum(
                cnt
                for col, cnt in wip.items()
                if col in (BoardColumn.IN_PROGRESS, BoardColumn.IN_REVIEW, BoardColumn.TESTING)
            ),
        }

    def get_overdue(self, org_id: str) -> List[RemediationCard]:
        """Return cards past their due_date that are not yet DONE."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                """
                SELECT * FROM remediation_cards
                WHERE org_id = ? AND due_date IS NOT NULL AND due_date < ? AND column_name != 'done'
                ORDER BY due_date ASC
                """,
                (org_id, now),
            ).fetchall()
            result = []
            for row in rows:
                comments = self._load_comments(conn, row["id"])
                result.append(self._row_to_card(row, comments))
        return result
