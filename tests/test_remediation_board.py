"""
Tests for RemediationBoard — Kanban-style security fix tracking.

Covers:
- BoardColumn enum values
- RemediationCard Pydantic model validation
- RemediationBoard CRUD: create, move, assign, comment
- get_board: Kanban view grouped by column
- get_card: full details with comments
- get_assignee_workload: cards per person
- get_board_metrics: cycle time, throughput, WIP
- get_overdue: cards past due date
- auto_create_from_findings: bulk import, dedup
- Router endpoints via FastAPI TestClient (10 endpoints)
- Edge cases: missing card, invalid column, empty org

Run with: python -m pytest tests/test_remediation_board.py -v --timeout=15
"""

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.remediation_board import (
    BoardColumn,
    CardComment,
    CardPriority,
    RemediationBoard,
    RemediationCard,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def board(tmp_path):
    return RemediationBoard(tmp_path / "board.db")


@pytest.fixture
def org():
    return "org_test"


@pytest.fixture
def sample_card(board, org):
    return board.create_card(
        finding_id="CVE-2024-0001",
        title="Patch OpenSSL",
        assignee="alice@example.com",
        priority="high",
        org_id=org,
        description="Upgrade OpenSSL to 3.2",
        labels=["patch", "critical-infra"],
    )


# ============================================================================
# BoardColumn enum
# ============================================================================


class TestBoardColumnEnum:
    def test_all_columns_defined(self):
        expected = {"backlog", "todo", "in_progress", "in_review", "testing", "done"}
        assert {c.value for c in BoardColumn} == expected

    def test_column_is_string_enum(self):
        assert isinstance(BoardColumn.BACKLOG, str)
        assert BoardColumn.DONE == "done"

    def test_column_from_string(self):
        assert BoardColumn("in_progress") == BoardColumn.IN_PROGRESS


# ============================================================================
# RemediationCard model
# ============================================================================


class TestRemediationCardModel:
    def test_defaults(self):
        card = RemediationCard(finding_id="F1", title="Test")
        assert card.column == BoardColumn.BACKLOG
        assert card.priority == CardPriority.MEDIUM
        assert card.labels == []
        assert card.comments == []
        assert card.org_id == "default"
        assert card.assignee is None
        assert card.due_date is None

    def test_id_is_uuid(self):
        card = RemediationCard(finding_id="F1", title="Test")
        uuid.UUID(card.id)  # raises if invalid

    def test_created_at_is_utc(self):
        card = RemediationCard(finding_id="F1", title="Test")
        assert card.created_at.tzinfo is not None

    def test_card_comment_model(self):
        c = CardComment(author="bob@example.com", text="Looks good")
        assert c.author == "bob@example.com"
        assert c.text == "Looks good"
        assert c.created_at.tzinfo is not None


# ============================================================================
# create_card
# ============================================================================


class TestCreateCard:
    def test_creates_in_backlog(self, board, org):
        card = board.create_card(finding_id="F1", title="Fix X", org_id=org)
        assert card.column == BoardColumn.BACKLOG

    def test_finding_id_stored(self, board, org):
        card = board.create_card(finding_id="CVE-2024-9999", title="X", org_id=org)
        assert card.finding_id == "CVE-2024-9999"

    def test_priority_mapping_high(self, board, org):
        card = board.create_card(finding_id="F1", title="X", priority="high", org_id=org)
        assert card.priority == CardPriority.HIGH

    def test_priority_mapping_critical(self, board, org):
        card = board.create_card(finding_id="F1", title="X", priority="critical", org_id=org)
        assert card.priority == CardPriority.CRITICAL

    def test_priority_mapping_unknown_defaults_medium(self, board, org):
        card = board.create_card(finding_id="F1", title="X", priority="unknown", org_id=org)
        assert card.priority == CardPriority.MEDIUM

    def test_labels_stored(self, board, org):
        card = board.create_card(finding_id="F1", title="X", labels=["a", "b"], org_id=org)
        assert card.labels == ["a", "b"]

    def test_assignee_stored(self, board, org):
        card = board.create_card(finding_id="F1", title="X", assignee="eve@example.com", org_id=org)
        assert card.assignee == "eve@example.com"

    def test_description_stored(self, board, org):
        card = board.create_card(finding_id="F1", title="X", description="Do something", org_id=org)
        assert card.description == "Do something"

    def test_due_date_stored(self, board, org):
        due = datetime.now(timezone.utc) + timedelta(days=7)
        card = board.create_card(finding_id="F1", title="X", due_date=due, org_id=org)
        assert card.due_date is not None


# ============================================================================
# move_card
# ============================================================================


class TestMoveCard:
    def test_move_to_in_progress(self, board, sample_card, org):
        updated = board.move_card(sample_card.id, BoardColumn.IN_PROGRESS)
        assert updated.column == BoardColumn.IN_PROGRESS

    def test_move_updates_moved_at(self, board, sample_card, org):
        original_moved_at = sample_card.moved_at
        updated = board.move_card(sample_card.id, BoardColumn.TODO)
        assert updated.moved_at >= original_moved_at

    def test_move_to_done(self, board, sample_card, org):
        updated = board.move_card(sample_card.id, BoardColumn.DONE)
        assert updated.column == BoardColumn.DONE

    def test_move_nonexistent_card_raises(self, board):
        with pytest.raises(KeyError):
            board.move_card("nonexistent-id", BoardColumn.TODO)

    def test_move_accepts_string_column(self, board, sample_card):
        updated = board.move_card(sample_card.id, "testing")
        assert updated.column == BoardColumn.TESTING


# ============================================================================
# assign_card
# ============================================================================


class TestAssignCard:
    def test_assign_changes_assignee(self, board, sample_card, org):
        updated = board.assign_card(sample_card.id, "bob@example.com")
        assert updated.assignee == "bob@example.com"

    def test_assign_nonexistent_card_raises(self, board):
        with pytest.raises(KeyError):
            board.assign_card("bad-id", "someone@example.com")

    def test_assign_preserves_other_fields(self, board, sample_card, org):
        updated = board.assign_card(sample_card.id, "new@example.com")
        assert updated.finding_id == sample_card.finding_id
        assert updated.title == sample_card.title


# ============================================================================
# add_comment
# ============================================================================


class TestAddComment:
    def test_comment_stored(self, board, sample_card, org):
        comment = board.add_comment(sample_card.id, "alice@example.com", "Investigating now")
        assert comment.author == "alice@example.com"
        assert comment.text == "Investigating now"

    def test_comment_has_id(self, board, sample_card, org):
        comment = board.add_comment(sample_card.id, "a@b.com", "txt")
        uuid.UUID(comment.id)

    def test_multiple_comments(self, board, sample_card, org):
        board.add_comment(sample_card.id, "a@b.com", "first")
        board.add_comment(sample_card.id, "b@b.com", "second")
        full = board.get_card(sample_card.id)
        assert len(full.comments) == 2

    def test_comment_on_missing_card_raises(self, board):
        with pytest.raises(KeyError):
            board.add_comment("bad-id", "a@b.com", "nope")


# ============================================================================
# get_card
# ============================================================================


class TestGetCard:
    def test_get_card_returns_full_model(self, board, sample_card, org):
        card = board.get_card(sample_card.id)
        assert card is not None
        assert card.id == sample_card.id
        assert card.title == sample_card.title

    def test_get_card_includes_comments(self, board, sample_card, org):
        board.add_comment(sample_card.id, "x@x.com", "hello")
        card = board.get_card(sample_card.id)
        assert len(card.comments) == 1
        assert card.comments[0].text == "hello"

    def test_get_card_missing_returns_none(self, board):
        assert board.get_card("no-such-id") is None


# ============================================================================
# get_board
# ============================================================================


class TestGetBoard:
    def test_get_board_has_all_columns(self, board, org):
        board_view = board.get_board(org)
        assert set(board_view.keys()) == {c.value for c in BoardColumn}

    def test_new_card_in_backlog_column(self, board, sample_card, org):
        board_view = board.get_board(org)
        assert any(c.id == sample_card.id for c in board_view["backlog"])

    def test_moved_card_in_correct_column(self, board, sample_card, org):
        board.move_card(sample_card.id, BoardColumn.IN_REVIEW)
        board_view = board.get_board(org)
        assert any(c.id == sample_card.id for c in board_view["in_review"])
        assert not any(c.id == sample_card.id for c in board_view["backlog"])

    def test_empty_org_has_empty_columns(self, board):
        board_view = board.get_board("org_empty")
        for col in BoardColumn:
            assert board_view[col.value] == []


# ============================================================================
# get_assignee_workload
# ============================================================================


class TestGetAssigneeWorkload:
    def test_counts_active_cards(self, board, org):
        board.create_card(finding_id="F1", title="T1", assignee="alice@example.com", org_id=org)
        board.create_card(finding_id="F2", title="T2", assignee="alice@example.com", org_id=org)
        board.create_card(finding_id="F3", title="T3", assignee="bob@example.com", org_id=org)
        workload = board.get_assignee_workload(org)
        assert workload["alice@example.com"] == 2
        assert workload["bob@example.com"] == 1

    def test_excludes_done_cards(self, board, org):
        card = board.create_card(finding_id="F1", title="T1", assignee="alice@example.com", org_id=org)
        board.move_card(card.id, BoardColumn.DONE)
        workload = board.get_assignee_workload(org)
        assert "alice@example.com" not in workload

    def test_excludes_unassigned(self, board, org):
        board.create_card(finding_id="F1", title="T1", org_id=org)
        workload = board.get_assignee_workload(org)
        assert None not in workload


# ============================================================================
# get_board_metrics
# ============================================================================


class TestGetBoardMetrics:
    def test_returns_expected_keys(self, board, org):
        metrics = board.get_board_metrics(org)
        assert "total_cards" in metrics
        assert "done_count" in metrics
        assert "wip_by_column" in metrics
        assert "cycle_time_hours" in metrics
        assert "throughput_per_day" in metrics
        assert "active_wip" in metrics

    def test_total_cards_count(self, board, org):
        board.create_card(finding_id="F1", title="T1", org_id=org)
        board.create_card(finding_id="F2", title="T2", org_id=org)
        metrics = board.get_board_metrics(org)
        assert metrics["total_cards"] == 2

    def test_done_count(self, board, org):
        card = board.create_card(finding_id="F1", title="T1", org_id=org)
        board.move_card(card.id, BoardColumn.DONE)
        metrics = board.get_board_metrics(org)
        assert metrics["done_count"] == 1

    def test_cycle_time_none_when_no_done(self, board, org):
        board.create_card(finding_id="F1", title="T1", org_id=org)
        metrics = board.get_board_metrics(org)
        assert metrics["cycle_time_hours"] is None

    def test_active_wip_counts_in_progress(self, board, org):
        card = board.create_card(finding_id="F1", title="T1", org_id=org)
        board.move_card(card.id, BoardColumn.IN_PROGRESS)
        metrics = board.get_board_metrics(org)
        assert metrics["active_wip"] >= 1

    def test_empty_board_metrics(self, board):
        metrics = board.get_board_metrics("org_new")
        assert metrics["total_cards"] == 0
        assert metrics["done_count"] == 0


# ============================================================================
# get_overdue
# ============================================================================


class TestGetOverdue:
    def test_returns_overdue_cards(self, board, org):
        past = datetime.now(timezone.utc) - timedelta(days=1)
        board.create_card(finding_id="F1", title="Old", due_date=past, org_id=org)
        overdue = board.get_overdue(org)
        assert len(overdue) == 1

    def test_excludes_future_due_date(self, board, org):
        future = datetime.now(timezone.utc) + timedelta(days=10)
        board.create_card(finding_id="F1", title="Future", due_date=future, org_id=org)
        overdue = board.get_overdue(org)
        assert len(overdue) == 0

    def test_excludes_done_cards(self, board, org):
        past = datetime.now(timezone.utc) - timedelta(days=1)
        card = board.create_card(finding_id="F1", title="Old Done", due_date=past, org_id=org)
        board.move_card(card.id, BoardColumn.DONE)
        overdue = board.get_overdue(org)
        assert len(overdue) == 0

    def test_excludes_cards_without_due_date(self, board, org):
        board.create_card(finding_id="F1", title="NoDue", org_id=org)
        overdue = board.get_overdue(org)
        assert len(overdue) == 0


# ============================================================================
# auto_create_from_findings
# ============================================================================


class TestAutoCreateFromFindings:
    def test_creates_cards_from_findings(self, board, org):
        findings = [
            {"finding_id": "CVE-001", "title": "Fix A", "severity": "high"},
            {"finding_id": "CVE-002", "title": "Fix B", "severity": "critical"},
        ]
        cards = board.auto_create_from_findings(findings, org_id=org)
        assert len(cards) == 2

    def test_dedup_skips_existing(self, board, org):
        board.create_card(finding_id="CVE-001", title="Already exists", org_id=org)
        findings = [
            {"finding_id": "CVE-001", "title": "Fix A"},
            {"finding_id": "CVE-002", "title": "Fix B"},
        ]
        cards = board.auto_create_from_findings(findings, org_id=org)
        assert len(cards) == 1
        assert cards[0].finding_id == "CVE-002"

    def test_uses_id_field_as_finding_id(self, board, org):
        findings = [{"id": "FINDING-999", "title": "Via id field"}]
        cards = board.auto_create_from_findings(findings, org_id=org)
        assert cards[0].finding_id == "FINDING-999"

    def test_maps_severity_to_priority(self, board, org):
        findings = [{"finding_id": "F1", "title": "X", "severity": "critical"}]
        cards = board.auto_create_from_findings(findings, org_id=org)
        assert cards[0].priority == CardPriority.CRITICAL

    def test_empty_findings_returns_empty(self, board, org):
        cards = board.auto_create_from_findings([], org_id=org)
        assert cards == []

    def test_all_cards_start_in_backlog(self, board, org):
        findings = [{"finding_id": f"F{i}", "title": f"Finding {i}"} for i in range(5)]
        cards = board.auto_create_from_findings(findings, org_id=org)
        assert all(c.column == BoardColumn.BACKLOG for c in cards)


# ============================================================================
# Router endpoint tests (FastAPI TestClient)
# ============================================================================


@pytest.fixture
def client(tmp_path):
    """Create an isolated FastAPI TestClient for the remediation board router."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Patch the board instance to use a temp db
    import apps.api.remediation_board_router as rbr
    rbr._board = RemediationBoard(tmp_path / "router_board.db")

    app = FastAPI()
    from apps.api.remediation_board_router import router
    app.include_router(router)

    # Override auth dependency so tests don't need real credentials
    try:
        from apps.api.auth_deps import api_key_auth
        app.dependency_overrides[api_key_auth] = lambda: None
    except ImportError:
        pass

    return TestClient(app)


class TestRouterCreateCard:
    def test_create_card_201(self, client):
        resp = client.post("/api/v1/remediation-board/cards", json={
            "finding_id": "CVE-2024-1111",
            "title": "Fix Something",
            "org_id": "org1",
            "priority": "high",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["finding_id"] == "CVE-2024-1111"
        assert data["column"] == "backlog"

    def test_create_card_with_due_date(self, client):
        resp = client.post("/api/v1/remediation-board/cards", json={
            "finding_id": "CVE-2024-2222",
            "title": "Fix With Due",
            "org_id": "org1",
            "due_date": "2026-12-31T00:00:00Z",
        })
        assert resp.status_code == 201
        assert resp.json()["due_date"] is not None


class TestRouterGetBoard:
    def test_get_board_returns_all_columns(self, client):
        resp = client.get("/api/v1/remediation-board/board?org_id=org1")
        assert resp.status_code == 200
        data = resp.json()
        assert set(data.keys()) == {c.value for c in BoardColumn}

    def test_created_card_appears_in_board(self, client):
        client.post("/api/v1/remediation-board/cards", json={
            "finding_id": "CVE-99", "title": "Board Test", "org_id": "org2",
        })
        resp = client.get("/api/v1/remediation-board/board?org_id=org2")
        assert resp.status_code == 200
        assert len(resp.json()["backlog"]) == 1


class TestRouterGetCard:
    def test_get_existing_card(self, client):
        create_resp = client.post("/api/v1/remediation-board/cards", json={
            "finding_id": "F1", "title": "My Card", "org_id": "org1",
        })
        card_id = create_resp.json()["id"]
        resp = client.get(f"/api/v1/remediation-board/cards/{card_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == card_id

    def test_get_missing_card_404(self, client):
        resp = client.get("/api/v1/remediation-board/cards/no-such-id")
        assert resp.status_code == 404


class TestRouterMoveCard:
    def test_move_card(self, client):
        create_resp = client.post("/api/v1/remediation-board/cards", json={
            "finding_id": "F1", "title": "Move Me", "org_id": "org1",
        })
        card_id = create_resp.json()["id"]
        resp = client.patch(f"/api/v1/remediation-board/cards/{card_id}/move",
                            json={"to_column": "in_progress"})
        assert resp.status_code == 200
        assert resp.json()["column"] == "in_progress"

    def test_move_invalid_column_422(self, client):
        create_resp = client.post("/api/v1/remediation-board/cards", json={
            "finding_id": "F2", "title": "T", "org_id": "org1",
        })
        card_id = create_resp.json()["id"]
        resp = client.patch(f"/api/v1/remediation-board/cards/{card_id}/move",
                            json={"to_column": "not_a_column"})
        assert resp.status_code == 422

    def test_move_missing_card_404(self, client):
        resp = client.patch("/api/v1/remediation-board/cards/bad-id/move",
                            json={"to_column": "todo"})
        assert resp.status_code == 404


class TestRouterAssignCard:
    def test_assign_card(self, client):
        create_resp = client.post("/api/v1/remediation-board/cards", json={
            "finding_id": "F1", "title": "Assign Me", "org_id": "org1",
        })
        card_id = create_resp.json()["id"]
        resp = client.patch(f"/api/v1/remediation-board/cards/{card_id}/assign",
                            json={"assignee": "charlie@example.com"})
        assert resp.status_code == 200
        assert resp.json()["assignee"] == "charlie@example.com"

    def test_assign_missing_card_404(self, client):
        resp = client.patch("/api/v1/remediation-board/cards/bad-id/assign",
                            json={"assignee": "x@x.com"})
        assert resp.status_code == 404


class TestRouterAddComment:
    def test_add_comment(self, client):
        create_resp = client.post("/api/v1/remediation-board/cards", json={
            "finding_id": "F1", "title": "Comment Test", "org_id": "org1",
        })
        card_id = create_resp.json()["id"]
        resp = client.post(f"/api/v1/remediation-board/cards/{card_id}/comments",
                           json={"author": "alice@example.com", "text": "On it"})
        assert resp.status_code == 201
        data = resp.json()
        assert data["author"] == "alice@example.com"
        assert data["text"] == "On it"

    def test_comment_missing_card_404(self, client):
        resp = client.post("/api/v1/remediation-board/cards/bad-id/comments",
                           json={"author": "a@b.com", "text": "nope"})
        assert resp.status_code == 404


class TestRouterWorkload:
    def test_workload_endpoint(self, client):
        resp = client.get("/api/v1/remediation-board/workload?org_id=org1")
        assert resp.status_code == 200
        assert isinstance(resp.json(), dict)


class TestRouterMetrics:
    def test_metrics_endpoint(self, client):
        resp = client.get("/api/v1/remediation-board/metrics?org_id=org1")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_cards" in data
        assert "wip_by_column" in data


class TestRouterOverdue:
    def test_overdue_endpoint_empty(self, client):
        resp = client.get("/api/v1/remediation-board/overdue?org_id=org1")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


class TestRouterBulkCreate:
    def test_bulk_create(self, client):
        resp = client.post("/api/v1/remediation-board/cards/bulk", json={
            "findings": [
                {"finding_id": "CVE-A", "title": "Fix A", "severity": "high"},
                {"finding_id": "CVE-B", "title": "Fix B", "severity": "critical"},
            ],
            "org_id": "org_bulk",
        })
        assert resp.status_code == 201
        assert len(resp.json()) == 2

    def test_bulk_empty(self, client):
        resp = client.post("/api/v1/remediation-board/cards/bulk", json={
            "findings": [],
            "org_id": "org_bulk",
        })
        assert resp.status_code == 201
        assert resp.json() == []
