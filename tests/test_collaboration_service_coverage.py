"""Tests for CollaborationService — entity/activity types and DB init."""

from core.services.collaboration import (
    EntityType,
    ActivityType,
    CollaborationService,
)


class TestEntityType:
    def test_cluster(self):
        assert EntityType.CLUSTER.value == "cluster"

    def test_task(self):
        assert EntityType.TASK.value == "task"

    def test_finding(self):
        assert EntityType.FINDING.value == "finding"

    def test_count(self):
        assert len(EntityType) == 3

    def test_string_enum(self):
        assert isinstance(EntityType.CLUSTER, str)


class TestActivityType:
    def test_comment_added(self):
        assert ActivityType.COMMENT_ADDED.value == "comment_added"

    def test_status_changed(self):
        assert ActivityType.STATUS_CHANGED.value == "status_changed"

    def test_assigned(self):
        assert ActivityType.ASSIGNED.value == "assigned"

    def test_ticket_linked(self):
        assert ActivityType.TICKET_LINKED.value == "ticket_linked"

    def test_evidence_submitted(self):
        assert ActivityType.EVIDENCE_SUBMITTED.value == "evidence_submitted"

    def test_watcher_added(self):
        assert ActivityType.WATCHER_ADDED.value == "watcher_added"

    def test_watcher_removed(self):
        assert ActivityType.WATCHER_REMOVED.value == "watcher_removed"

    def test_mention(self):
        assert ActivityType.MENTION.value == "mention"

    def test_count(self):
        assert len(ActivityType) == 8


class TestCollaborationService:
    def test_init(self, tmp_path):
        db_path = tmp_path / "collab.db"
        CollaborationService(db_path)
        assert db_path.exists()

    def test_init_creates_parent_dirs(self, tmp_path):
        db_path = tmp_path / "deep" / "nested" / "collab.db"
        CollaborationService(db_path)
        assert db_path.exists()

    def test_add_comment(self, tmp_path):
        svc = CollaborationService(tmp_path / "collab.db")
        result = svc.add_comment(
            entity_type="finding",
            entity_id="f-001",
            org_id="org-1",
            author="alice",
            content="This needs attention",
        )
        assert result is not None

    def test_get_comments(self, tmp_path):
        svc = CollaborationService(tmp_path / "collab.db")
        svc.add_comment(
            entity_type="finding",
            entity_id="f-001",
            org_id="org-1",
            author="alice",
            content="Test comment",
        )
        comments = svc.get_comments(entity_type="finding", entity_id="f-001")
        assert isinstance(comments, list)
        assert len(comments) >= 1

    def test_add_watcher(self, tmp_path):
        svc = CollaborationService(tmp_path / "collab.db")
        result = svc.add_watcher(
            entity_type="task",
            entity_id="t-001",
            user_id="user-1",
        )
        assert result is not None
