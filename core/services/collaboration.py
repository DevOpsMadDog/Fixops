"""Team Collaboration Service - Comments, watchers, and activity feeds."""

import json
import sqlite3
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class EntityType(str, Enum):
    """Types of entities that can have collaboration features."""

    CLUSTER = "cluster"
    TASK = "task"
    FINDING = "finding"


class ActivityType(str, Enum):
    """Types of activities for the activity feed."""

    COMMENT_ADDED = "comment_added"
    STATUS_CHANGED = "status_changed"
    ASSIGNED = "assigned"
    TICKET_LINKED = "ticket_linked"
    EVIDENCE_SUBMITTED = "evidence_submitted"
    WATCHER_ADDED = "watcher_added"
    WATCHER_REMOVED = "watcher_removed"
    MENTION = "mention"


class CollaborationService:
    """Service for team collaboration features."""

    def __init__(self, db_path: Path):
        """Initialize collaboration service."""
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Comments (append-only for audit trail)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS comments (
                comment_id TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                org_id TEXT NOT NULL,
                author TEXT NOT NULL,
                author_email TEXT,
                content TEXT NOT NULL,
                is_internal INTEGER DEFAULT 1,
                is_evidence INTEGER DEFAULT 0,
                parent_comment_id TEXT,
                created_at TEXT NOT NULL,
                edited_at TEXT,
                metadata TEXT
            )
        """
        )

        # Watchers
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS watchers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                user_email TEXT,
                added_at TEXT NOT NULL,
                added_by TEXT,
                UNIQUE(entity_type, entity_id, user_id)
            )
        """
        )

        # Activity feed (append-only event log)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS activities (
                activity_id TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                org_id TEXT NOT NULL,
                activity_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                actor_email TEXT,
                summary TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL
            )
        """
        )

        # Mentions
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS mentions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                comment_id TEXT NOT NULL,
                mentioned_user TEXT NOT NULL,
                mentioned_email TEXT,
                acknowledged INTEGER DEFAULT 0,
                acknowledged_at TEXT,
                FOREIGN KEY (comment_id) REFERENCES comments(comment_id)
            )
        """
        )

        # Indexes
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_comments_entity ON comments(entity_type, entity_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_watchers_entity ON watchers(entity_type, entity_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_watchers_user ON watchers(user_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_activities_entity ON activities(entity_type, entity_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_activities_org ON activities(org_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mentions_user ON mentions(mentioned_user)"
        )

        conn.commit()
        conn.close()

    def add_comment(
        self,
        entity_type: str,
        entity_id: str,
        org_id: str,
        author: str,
        content: str,
        author_email: Optional[str] = None,
        is_internal: bool = True,
        parent_comment_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Add a comment to an entity."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        comment_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()

        cursor.execute(
            """
            INSERT INTO comments (
                comment_id, entity_type, entity_id, org_id, author, author_email,
                content, is_internal, parent_comment_id, created_at, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                comment_id,
                entity_type,
                entity_id,
                org_id,
                author,
                author_email,
                content,
                1 if is_internal else 0,
                parent_comment_id,
                now,
                json.dumps(metadata or {}),
            ),
        )

        # Extract and store mentions (@username)
        mentions = self._extract_mentions(content)
        for mentioned_user in mentions:
            cursor.execute(
                """
                INSERT INTO mentions (comment_id, mentioned_user)
                VALUES (?, ?)
            """,
                (comment_id, mentioned_user),
            )

        # Record activity
        activity_id = str(uuid.uuid4())
        cursor.execute(
            """
            INSERT INTO activities (
                activity_id, entity_type, entity_id, org_id, activity_type,
                actor, actor_email, summary, details, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                activity_id,
                entity_type,
                entity_id,
                org_id,
                ActivityType.COMMENT_ADDED.value,
                author,
                author_email,
                f"{author} added a comment",
                json.dumps({"comment_id": comment_id, "preview": content[:100]}),
                now,
            ),
        )

        conn.commit()
        conn.close()

        return {
            "comment_id": comment_id,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "author": author,
            "created_at": now,
            "mentions": mentions,
        }

    def get_comments(
        self,
        entity_type: str,
        entity_id: str,
        include_internal: bool = True,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Get comments for an entity."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM comments WHERE entity_type = ? AND entity_id = ?"
        params: List[Any] = [entity_type, entity_id]

        if not include_internal:
            query += " AND is_internal = 0"

        query += " ORDER BY created_at ASC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    def promote_to_evidence(self, comment_id: str, promoted_by: str) -> bool:
        """Promote a comment to evidence for compliance."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE comments SET is_evidence = 1 WHERE comment_id = ?",
            (comment_id,),
        )

        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated

    def add_watcher(
        self,
        entity_type: str,
        entity_id: str,
        user_id: str,
        user_email: Optional[str] = None,
        added_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add a watcher to an entity."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        now = datetime.utcnow().isoformat()

        try:
            cursor.execute(
                """
                INSERT INTO watchers (entity_type, entity_id, user_id, user_email, added_at, added_by)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (entity_type, entity_id, user_id, user_email, now, added_by),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return {"status": "already_watching", "user_id": user_id}

        conn.close()

        return {
            "status": "added",
            "entity_type": entity_type,
            "entity_id": entity_id,
            "user_id": user_id,
            "added_at": now,
        }

    def remove_watcher(self, entity_type: str, entity_id: str, user_id: str) -> bool:
        """Remove a watcher from an entity."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM watchers
            WHERE entity_type = ? AND entity_id = ? AND user_id = ?
        """,
            (entity_type, entity_id, user_id),
        )

        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted

    def get_watchers(self, entity_type: str, entity_id: str) -> List[Dict[str, Any]]:
        """Get watchers for an entity."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT user_id, user_email, added_at, added_by
            FROM watchers WHERE entity_type = ? AND entity_id = ?
        """,
            (entity_type, entity_id),
        )

        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    def get_watched_entities(
        self, user_id: str, entity_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get entities watched by a user."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = (
            "SELECT entity_type, entity_id, added_at FROM watchers WHERE user_id = ?"
        )
        params: List[Any] = [user_id]

        if entity_type:
            query += " AND entity_type = ?"
            params.append(entity_type)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    def record_activity(
        self,
        entity_type: str,
        entity_id: str,
        org_id: str,
        activity_type: str,
        actor: str,
        summary: str,
        actor_email: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Record an activity in the feed."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        activity_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()

        cursor.execute(
            """
            INSERT INTO activities (
                activity_id, entity_type, entity_id, org_id, activity_type,
                actor, actor_email, summary, details, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                activity_id,
                entity_type,
                entity_id,
                org_id,
                activity_type,
                actor,
                actor_email,
                summary,
                json.dumps(details or {}),
                now,
            ),
        )

        conn.commit()
        conn.close()

        return activity_id

    def get_activity_feed(
        self,
        org_id: str,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        activity_types: Optional[List[str]] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Get activity feed with optional filters."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM activities WHERE org_id = ?"
        params: List[Any] = [org_id]

        if entity_type:
            query += " AND entity_type = ?"
            params.append(entity_type)
        if entity_id:
            query += " AND entity_id = ?"
            params.append(entity_id)
        if activity_types:
            placeholders = ",".join("?" * len(activity_types))
            query += f" AND activity_type IN ({placeholders})"
            params.extend(activity_types)

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    def get_user_mentions(
        self, user_id: str, unacknowledged_only: bool = False
    ) -> List[Dict[str, Any]]:
        """Get mentions for a user."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = """
            SELECT m.*, c.entity_type, c.entity_id, c.author, c.content, c.created_at
            FROM mentions m
            JOIN comments c ON m.comment_id = c.comment_id
            WHERE m.mentioned_user = ?
        """
        params: List[Any] = [user_id]

        if unacknowledged_only:
            query += " AND m.acknowledged = 0"

        query += " ORDER BY c.created_at DESC"

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    def acknowledge_mention(self, mention_id: int) -> bool:
        """Acknowledge a mention."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        now = datetime.utcnow().isoformat()
        cursor.execute(
            "UPDATE mentions SET acknowledged = 1, acknowledged_at = ? WHERE id = ?",
            (now, mention_id),
        )

        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return updated

    def _extract_mentions(self, content: str) -> List[str]:
        """Extract @mentions from content."""
        import re

        pattern = r"@(\w+)"
        matches = re.findall(pattern, content)
        return list(set(matches))
