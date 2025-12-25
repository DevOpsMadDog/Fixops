"""Team Collaboration Service - Comments, watchers, and activity feeds."""

import json
import re
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

        # Notification queue
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_queue (
                notification_id TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                notification_type TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                priority TEXT DEFAULT 'normal',
                recipients TEXT NOT NULL,
                metadata TEXT,
                status TEXT DEFAULT 'pending',
                created_at TEXT NOT NULL,
                sent_at TEXT,
                error TEXT
            )
        """
        )

        # Notification preferences
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_preferences (
                user_id TEXT PRIMARY KEY,
                email_enabled INTEGER DEFAULT 1,
                slack_enabled INTEGER DEFAULT 1,
                in_app_enabled INTEGER DEFAULT 1,
                digest_frequency TEXT DEFAULT 'immediate',
                quiet_hours_start TEXT,
                quiet_hours_end TEXT,
                notification_types TEXT,
                updated_at TEXT
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
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_notifications_status ON notification_queue(status)"
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
        try:
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

            mentions = self._extract_mentions(content)
            for mentioned_user in mentions:
                cursor.execute(
                    """
                    INSERT INTO mentions (comment_id, mentioned_user)
                    VALUES (?, ?)
                """,
                    (comment_id, mentioned_user),
                )

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

            return {
                "comment_id": comment_id,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "author": author,
                "created_at": now,
                "mentions": mentions,
            }
        finally:
            conn.close()

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
        try:
            cursor = conn.cursor()

            query = "SELECT * FROM comments WHERE entity_type = ? AND entity_id = ?"
            params: List[Any] = [entity_type, entity_id]

            if not include_internal:
                query += " AND is_internal = 0"

            query += " ORDER BY created_at ASC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def promote_to_evidence(self, comment_id: str, promoted_by: str) -> bool:
        """Promote a comment to evidence for compliance."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE comments SET is_evidence = 1 WHERE comment_id = ?",
                (comment_id,),
            )
            updated = cursor.rowcount > 0
            conn.commit()
            return updated
        finally:
            conn.close()

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
        try:
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
                return {"status": "already_watching", "user_id": user_id}

            return {
                "status": "added",
                "entity_type": entity_type,
                "entity_id": entity_id,
                "user_id": user_id,
                "added_at": now,
            }
        finally:
            conn.close()

    def remove_watcher(self, entity_type: str, entity_id: str, user_id: str) -> bool:
        """Remove a watcher from an entity."""
        conn = sqlite3.connect(self.db_path)
        try:
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
            return deleted
        finally:
            conn.close()

    def get_watchers(self, entity_type: str, entity_id: str) -> List[Dict[str, Any]]:
        """Get watchers for an entity."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT user_id, user_email, added_at, added_by
                FROM watchers WHERE entity_type = ? AND entity_id = ?
            """,
                (entity_type, entity_id),
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def get_watched_entities(
        self, user_id: str, entity_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get entities watched by a user."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            query = "SELECT entity_type, entity_id, added_at FROM watchers WHERE user_id = ?"
            params: List[Any] = [user_id]

            if entity_type:
                query += " AND entity_type = ?"
                params.append(entity_type)

            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

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
        try:
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
            return activity_id
        finally:
            conn.close()

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
        try:
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
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def get_user_mentions(
        self, user_id: str, unacknowledged_only: bool = False
    ) -> List[Dict[str, Any]]:
        """Get mentions for a user."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
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
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def acknowledge_mention(self, mention_id: int) -> bool:
        """Acknowledge a mention."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat()
            cursor.execute(
                "UPDATE mentions SET acknowledged = 1, acknowledged_at = ? WHERE id = ?",
                (now, mention_id),
            )
            updated = cursor.rowcount > 0
            conn.commit()
            return updated
        finally:
            conn.close()

    def _extract_mentions(self, content: str) -> List[str]:
        """Extract @mentions from content."""
        pattern = r"@(\w+)"
        matches = re.findall(pattern, content)
        return list(set(matches))

    def queue_notification(
        self,
        entity_type: str,
        entity_id: str,
        notification_type: str,
        title: str,
        message: str,
        recipients: List[str],
        priority: str = "normal",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Queue a notification for delivery to watchers.

        Notification types:
        - new_critical_finding: New critical/high severity finding
        - status_change: Finding/task status changed
        - comment_mention: User was mentioned in a comment
        - sla_breach: SLA deadline approaching or breached
        - assignment: Task/finding assigned to user

        Priority levels: low, normal, high, urgent
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS notification_queue (
                    notification_id TEXT PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    notification_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    priority TEXT DEFAULT 'normal',
                    recipients TEXT NOT NULL,
                    metadata TEXT,
                    status TEXT DEFAULT 'pending',
                    created_at TEXT NOT NULL,
                    sent_at TEXT,
                    error TEXT
                )
            """
            )

            notification_id = str(uuid.uuid4())
            now = datetime.utcnow().isoformat()

            cursor.execute(
                """
                INSERT INTO notification_queue (
                    notification_id, entity_type, entity_id, notification_type,
                    title, message, priority, recipients, metadata, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    notification_id,
                    entity_type,
                    entity_id,
                    notification_type,
                    title,
                    message,
                    priority,
                    json.dumps(recipients),
                    json.dumps(metadata) if metadata else None,
                    now,
                ),
            )

            conn.commit()
            return notification_id
        finally:
            conn.close()

    def get_pending_notifications(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get pending notifications for delivery."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM notification_queue
                WHERE status = 'pending'
                ORDER BY
                    CASE priority
                        WHEN 'urgent' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'normal' THEN 3
                        WHEN 'low' THEN 4
                    END,
                    created_at ASC
                LIMIT ?
            """,
                (limit,),
            )
            rows = cursor.fetchall()
            notifications = []
            for row in rows:
                notification = dict(row)
                notification["recipients"] = json.loads(notification["recipients"])
                if notification["metadata"]:
                    notification["metadata"] = json.loads(notification["metadata"])
                notifications.append(notification)
            return notifications
        finally:
            conn.close()

    def mark_notification_sent(
        self, notification_id: str, error: Optional[str] = None
    ) -> bool:
        """Mark a notification as sent or failed."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat()

            if error:
                cursor.execute(
                    """
                    UPDATE notification_queue
                    SET status = 'failed', error = ?
                    WHERE notification_id = ?
                """,
                    (error, notification_id),
                )
            else:
                cursor.execute(
                    """
                    UPDATE notification_queue
                    SET status = 'sent', sent_at = ?
                    WHERE notification_id = ?
                """,
                    (now, notification_id),
                )

            updated = cursor.rowcount > 0
            conn.commit()
            return updated
        finally:
            conn.close()

    def notify_watchers(
        self,
        entity_type: str,
        entity_id: str,
        notification_type: str,
        title: str,
        message: str,
        priority: str = "normal",
        metadata: Optional[Dict[str, Any]] = None,
        exclude_users: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Notify all watchers of an entity.

        This is a convenience method that:
        1. Gets all watchers for the entity
        2. Queues notifications for each watcher
        3. Returns summary of notifications queued
        """
        watchers = self.get_watchers(entity_type, entity_id)
        recipients = [w["user_id"] for w in watchers]

        if exclude_users:
            recipients = [r for r in recipients if r not in exclude_users]

        if not recipients:
            return {
                "notification_id": None,
                "recipients_count": 0,
                "message": "No watchers to notify",
            }

        notification_id = self.queue_notification(
            entity_type=entity_type,
            entity_id=entity_id,
            notification_type=notification_type,
            title=title,
            message=message,
            recipients=recipients,
            priority=priority,
            metadata=metadata,
        )

        return {
            "notification_id": notification_id,
            "recipients_count": len(recipients),
            "recipients": recipients,
        }

    def get_user_notification_preferences(self, user_id: str) -> Dict[str, Any]:
        """Get notification preferences for a user."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS notification_preferences (
                    user_id TEXT PRIMARY KEY,
                    email_enabled INTEGER DEFAULT 1,
                    slack_enabled INTEGER DEFAULT 1,
                    in_app_enabled INTEGER DEFAULT 1,
                    digest_frequency TEXT DEFAULT 'immediate',
                    quiet_hours_start TEXT,
                    quiet_hours_end TEXT,
                    notification_types TEXT,
                    updated_at TEXT
                )
            """
            )

            cursor.execute(
                "SELECT * FROM notification_preferences WHERE user_id = ?",
                (user_id,),
            )
            row = cursor.fetchone()

            if row:
                prefs = dict(row)
                if prefs.get("notification_types"):
                    prefs["notification_types"] = json.loads(
                        prefs["notification_types"]
                    )
                return prefs

            return {
                "user_id": user_id,
                "email_enabled": True,
                "slack_enabled": True,
                "in_app_enabled": True,
                "digest_frequency": "immediate",
                "quiet_hours_start": None,
                "quiet_hours_end": None,
                "notification_types": None,
            }
        finally:
            conn.close()

    def update_notification_preferences(
        self,
        user_id: str,
        email_enabled: Optional[bool] = None,
        slack_enabled: Optional[bool] = None,
        in_app_enabled: Optional[bool] = None,
        digest_frequency: Optional[str] = None,
        quiet_hours_start: Optional[str] = None,
        quiet_hours_end: Optional[str] = None,
        notification_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Update notification preferences for a user."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS notification_preferences (
                    user_id TEXT PRIMARY KEY,
                    email_enabled INTEGER DEFAULT 1,
                    slack_enabled INTEGER DEFAULT 1,
                    in_app_enabled INTEGER DEFAULT 1,
                    digest_frequency TEXT DEFAULT 'immediate',
                    quiet_hours_start TEXT,
                    quiet_hours_end TEXT,
                    notification_types TEXT,
                    updated_at TEXT
                )
            """
            )

            current = self.get_user_notification_preferences(user_id)
            now = datetime.utcnow().isoformat()

            new_prefs = {
                "email_enabled": email_enabled
                if email_enabled is not None
                else current["email_enabled"],
                "slack_enabled": slack_enabled
                if slack_enabled is not None
                else current["slack_enabled"],
                "in_app_enabled": in_app_enabled
                if in_app_enabled is not None
                else current["in_app_enabled"],
                "digest_frequency": digest_frequency or current["digest_frequency"],
                "quiet_hours_start": quiet_hours_start
                if quiet_hours_start is not None
                else current["quiet_hours_start"],
                "quiet_hours_end": quiet_hours_end
                if quiet_hours_end is not None
                else current["quiet_hours_end"],
                "notification_types": json.dumps(notification_types)
                if notification_types
                else (
                    json.dumps(current["notification_types"])
                    if current["notification_types"]
                    else None
                ),
            }

            cursor.execute(
                """
                INSERT INTO notification_preferences (
                    user_id, email_enabled, slack_enabled, in_app_enabled,
                    digest_frequency, quiet_hours_start, quiet_hours_end,
                    notification_types, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    email_enabled = excluded.email_enabled,
                    slack_enabled = excluded.slack_enabled,
                    in_app_enabled = excluded.in_app_enabled,
                    digest_frequency = excluded.digest_frequency,
                    quiet_hours_start = excluded.quiet_hours_start,
                    quiet_hours_end = excluded.quiet_hours_end,
                    notification_types = excluded.notification_types,
                    updated_at = excluded.updated_at
            """,
                (
                    user_id,
                    1 if new_prefs["email_enabled"] else 0,
                    1 if new_prefs["slack_enabled"] else 0,
                    1 if new_prefs["in_app_enabled"] else 0,
                    new_prefs["digest_frequency"],
                    new_prefs["quiet_hours_start"],
                    new_prefs["quiet_hours_end"],
                    new_prefs["notification_types"],
                    now,
                ),
            )

            conn.commit()
            return self.get_user_notification_preferences(user_id)
        finally:
            conn.close()

    def deliver_notification(
        self,
        notification_id: str,
        slack_webhook: Optional[str] = None,
        email_config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Deliver a notification via configured channels (Slack/email).

        This method:
        1. Fetches the notification from the queue
        2. Gets recipient preferences
        3. Delivers via enabled channels (Slack, email)
        4. Marks notification as sent or failed
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT * FROM notification_queue WHERE notification_id = ?",
                (notification_id,),
            )
            row = cursor.fetchone()
            if not row:
                return {
                    "error": "Notification not found",
                    "notification_id": notification_id,
                }

            notification = dict(row)
            if notification["status"] != "pending":
                return {
                    "notification_id": notification_id,
                    "status": notification["status"],
                    "message": "Notification already processed",
                }

            recipients = json.loads(notification["recipients"])
            delivery_results: Dict[str, Any] = {
                "notification_id": notification_id,
                "slack_sent": [],
                "slack_failed": [],
                "email_sent": [],
                "email_failed": [],
            }

            for recipient in recipients:
                prefs = self.get_user_notification_preferences(recipient)

                if prefs.get("slack_enabled") and slack_webhook:
                    slack_result = self._deliver_slack(
                        webhook_url=slack_webhook,
                        title=notification["title"],
                        message=notification["message"],
                        recipient=recipient,
                        priority=notification["priority"],
                    )
                    if slack_result.get("success"):
                        delivery_results["slack_sent"].append(recipient)
                    else:
                        delivery_results["slack_failed"].append(
                            {
                                "recipient": recipient,
                                "error": slack_result.get("error"),
                            }
                        )

                if prefs.get("email_enabled") and email_config:
                    email_result = self._deliver_email(
                        config=email_config,
                        title=notification["title"],
                        message=notification["message"],
                        recipient=recipient,
                        priority=notification["priority"],
                    )
                    if email_result.get("success"):
                        delivery_results["email_sent"].append(recipient)
                    else:
                        delivery_results["email_failed"].append(
                            {
                                "recipient": recipient,
                                "error": email_result.get("error"),
                            }
                        )

            total_sent = len(delivery_results["slack_sent"]) + len(
                delivery_results["email_sent"]
            )
            total_failed = len(delivery_results["slack_failed"]) + len(
                delivery_results["email_failed"]
            )

            if total_sent > 0:
                self.mark_notification_sent(notification_id, error=None)
                delivery_results["status"] = "sent"
            elif total_failed > 0:
                error_msg = f"Failed to deliver to {total_failed} recipients"
                self.mark_notification_sent(notification_id, error=error_msg)
                delivery_results["status"] = "failed"
                delivery_results["error"] = error_msg
            else:
                delivery_results["status"] = "no_channels"
                delivery_results[
                    "message"
                ] = "No delivery channels configured or enabled"

            return delivery_results
        finally:
            conn.close()

    def _deliver_slack(
        self,
        webhook_url: str,
        title: str,
        message: str,
        recipient: str,
        priority: str = "normal",
    ) -> Dict[str, Any]:
        """Deliver notification via Slack webhook."""
        try:
            import requests

            priority_emoji = {
                "critical": ":rotating_light:",
                "high": ":warning:",
                "normal": ":bell:",
                "low": ":information_source:",
            }
            emoji = priority_emoji.get(priority, ":bell:")

            payload = {
                "text": f"{emoji} *{title}*\n{message}\n_Recipient: {recipient}_",
                "unfurl_links": False,
                "unfurl_media": False,
            }

            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()

            return {"success": True, "recipient": recipient}
        except Exception as e:
            return {"success": False, "recipient": recipient, "error": str(e)}

    def _deliver_email(
        self,
        config: Dict[str, Any],
        title: str,
        message: str,
        recipient: str,
        priority: str = "normal",
    ) -> Dict[str, Any]:
        """Deliver notification via email (SMTP).

        Config should contain:
        - smtp_host: SMTP server hostname
        - smtp_port: SMTP server port (default 587)
        - smtp_user: SMTP username
        - smtp_password: SMTP password
        - from_email: Sender email address
        """
        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText

            smtp_host = config.get("smtp_host")
            smtp_port = config.get("smtp_port", 587)
            smtp_user = config.get("smtp_user")
            smtp_password = config.get("smtp_password")
            from_email = config.get("from_email")

            if not all([smtp_host, smtp_user, smtp_password, from_email]):
                return {
                    "success": False,
                    "recipient": recipient,
                    "error": "Email configuration incomplete",
                }

            msg = MIMEMultipart()
            msg["From"] = from_email
            msg["To"] = recipient
            msg["Subject"] = f"[FixOps {priority.upper()}] {title}"

            body = f"{message}\n\n---\nThis is an automated notification from FixOps."
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.send_message(msg)

            return {"success": True, "recipient": recipient}
        except Exception as e:
            return {"success": False, "recipient": recipient, "error": str(e)}

    def process_pending_notifications(
        self,
        slack_webhook: Optional[str] = None,
        email_config: Optional[Dict[str, Any]] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Process all pending notifications in the queue.

        This is the main worker method that should be called periodically
        to deliver queued notifications.
        """
        pending = self.get_pending_notifications(limit=limit)
        results = {
            "processed": 0,
            "sent": 0,
            "failed": 0,
            "no_channels": 0,
            "details": [],
        }

        for notification in pending:
            result = self.deliver_notification(
                notification_id=notification["notification_id"],
                slack_webhook=slack_webhook,
                email_config=email_config,
            )
            results["processed"] += 1

            if result.get("status") == "sent":
                results["sent"] += 1
            elif result.get("status") == "failed":
                results["failed"] += 1
            else:
                results["no_channels"] += 1

            results["details"].append(result)

        return results
