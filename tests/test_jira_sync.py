"""Tests for Jira Bidirectional Sync Engine.

Covers:
- JiraSyncConfig: construction, validation, serialisation
- JiraSyncStore: SQLite persistence of links, history, config
- JiraSyncEngine: sync_finding, sync_from_jira, sync_status, sync_all,
                  handle_webhook, field mapping, conflict resolution
- get_jira_sync_engine: module singleton
- Router models: Pydantic request/response shapes

All HTTP calls to Jira are mocked — no real network required.

Usage:
    pytest tests/test_jira_sync.py -v --timeout=10
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core is on the path
suite_core = str(Path(__file__).parent.parent / "suite-core")
if suite_core not in sys.path:
    sys.path.insert(0, suite_core)

from core.jira_sync import (
    ConflictResolution,
    FieldMapping,
    JiraSyncConfig,
    JiraSyncEngine,
    JiraSyncStore,
    SyncDirection,
    SyncRecord,
    SyncResult,
    SyncStatus,
    _DEFAULT_JIRA_TO_FINDING_STATUS,
    _DEFAULT_SEVERITY_TO_PRIORITY,
    _now_iso,
    get_jira_sync_engine,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def tmp_db(tmp_path):
    return str(tmp_path / "jira_sync_test.db")


@pytest.fixture
def store(tmp_db):
    return JiraSyncStore(db_path=tmp_db)


@pytest.fixture
def basic_config():
    return JiraSyncConfig(
        jira_url="https://example.atlassian.net",
        user_email="bot@example.com",
        api_token="tok-123",
        project_key="SEC",
    )


@pytest.fixture
def engine(tmp_db, basic_config):
    eng = JiraSyncEngine(db_path=tmp_db)
    eng.configure(basic_config)
    return eng


@pytest.fixture
def sample_finding():
    return {
        "finding_id": "F-001",
        "title": "Critical RCE in login handler",
        "severity": "critical",
        "description": "Unauthenticated remote code execution.",
        "cve_id": "CVE-2025-1234",
        "source": "semgrep",
        "updated_at": _now_iso(),
    }


def _mock_client(engine: JiraSyncEngine) -> MagicMock:
    """Patch the engine's _JiraClient with a mock and return it."""
    mock = MagicMock()
    engine._client = mock
    return mock


# ============================================================================
# JiraSyncConfig
# ============================================================================


class TestJiraSyncConfig:
    def test_configured_true_when_all_fields_set(self, basic_config):
        assert basic_config.configured is True

    def test_configured_false_when_missing_url(self):
        cfg = JiraSyncConfig(user_email="a@b.com", api_token="t", project_key="P")
        assert cfg.configured is False

    def test_configured_false_when_missing_token(self, basic_config):
        basic_config.api_token = ""
        assert basic_config.configured is False

    def test_configured_false_when_missing_project(self, basic_config):
        basic_config.project_key = ""
        assert basic_config.configured is False

    def test_to_dict_masks_token(self, basic_config):
        d = basic_config.to_dict()
        assert d["api_token"] == "***"
        assert d["project_key"] == "SEC"

    def test_default_sync_direction(self, basic_config):
        assert basic_config.sync_direction == SyncDirection.BIDIRECTIONAL

    def test_default_conflict_resolution(self, basic_config):
        assert basic_config.conflict_resolution == ConflictResolution.NEWEST_WINS

    def test_default_labels(self, basic_config):
        assert "aldeci" in basic_config.labels
        assert "security" in basic_config.labels

    def test_severity_to_priority_defaults(self, basic_config):
        assert basic_config.severity_to_priority["critical"] == "Highest"
        assert basic_config.severity_to_priority["low"] == "Low"

    def test_jira_to_finding_status_defaults(self, basic_config):
        assert basic_config.jira_to_finding_status["Done"] == "resolved"
        assert basic_config.jira_to_finding_status["In Progress"] == "in_progress"


# ============================================================================
# JiraSyncStore
# ============================================================================


class TestJiraSyncStore:
    def test_upsert_and_get_link(self, store):
        store.upsert_link("F-001", "SEC-42")
        link = store.get_link("F-001")
        assert link is not None
        assert link["jira_issue_key"] == "SEC-42"

    def test_get_link_returns_none_for_unknown(self, store):
        assert store.get_link("DOES-NOT-EXIST") is None

    def test_upsert_link_updates_existing(self, store):
        store.upsert_link("F-001", "SEC-10")
        store.upsert_link("F-001", "SEC-99")
        link = store.get_link("F-001")
        assert link["jira_issue_key"] == "SEC-99"

    def test_delete_link_existing(self, store):
        store.upsert_link("F-002", "SEC-5")
        deleted = store.delete_link("F-002")
        assert deleted is True
        assert store.get_link("F-002") is None

    def test_delete_link_nonexistent(self, store):
        assert store.delete_link("NO-SUCH") is False

    def test_list_links_returns_all(self, store):
        store.upsert_link("F-A", "SEC-1")
        store.upsert_link("F-B", "SEC-2")
        links = store.list_links()
        finding_ids = {l["finding_id"] for l in links}
        assert {"F-A", "F-B"}.issubset(finding_ids)

    def test_append_and_get_history(self, store):
        rec = SyncRecord(
            record_id=str(uuid.uuid4()),
            finding_id="F-001",
            jira_issue_key="SEC-1",
            direction=SyncDirection.FINDING_TO_JIRA,
            status=SyncStatus.SUCCESS,
            detail={"op": "created"},
            synced_at=_now_iso(),
        )
        store.append_history(rec)
        history = store.get_history(finding_id="F-001")
        assert len(history) == 1
        assert history[0]["status"] == "success"

    def test_get_history_all_without_filter(self, store):
        for i in range(3):
            store.append_history(
                SyncRecord(
                    record_id=str(uuid.uuid4()),
                    finding_id=f"F-{i}",
                    jira_issue_key=None,
                    direction=SyncDirection.FINDING_TO_JIRA,
                    status=SyncStatus.SKIPPED,
                    detail={},
                    synced_at=_now_iso(),
                )
            )
        assert len(store.get_history()) == 3

    def test_get_stats_empty(self, store):
        stats = store.get_stats()
        assert stats["total_links"] == 0
        assert stats["total_sync_events"] == 0

    def test_get_stats_after_operations(self, store):
        store.upsert_link("F-1", "SEC-1")
        store.append_history(
            SyncRecord(
                record_id=str(uuid.uuid4()),
                finding_id="F-1",
                jira_issue_key="SEC-1",
                direction=SyncDirection.FINDING_TO_JIRA,
                status=SyncStatus.SUCCESS,
                detail={},
                synced_at=_now_iso(),
            )
        )
        stats = store.get_stats()
        assert stats["total_links"] == 1
        assert stats["total_sync_events"] == 1
        assert stats["by_status"]["success"] == 1

    def test_save_and_load_config(self, store, basic_config):
        store.save_config(basic_config)
        loaded = store.load_config()
        assert loaded is not None
        assert loaded.jira_url == basic_config.jira_url
        assert loaded.project_key == basic_config.project_key
        assert loaded.sync_direction == basic_config.sync_direction

    def test_load_config_returns_none_when_absent(self, store):
        assert store.load_config() is None

    def test_history_detail_is_deserialised(self, store):
        store.append_history(
            SyncRecord(
                record_id=str(uuid.uuid4()),
                finding_id="F-X",
                jira_issue_key="SEC-7",
                direction=SyncDirection.JIRA_TO_FINDING,
                status=SyncStatus.SUCCESS,
                detail={"jira_status": "Done", "new_finding_status": "resolved"},
                synced_at=_now_iso(),
            )
        )
        history = store.get_history(finding_id="F-X")
        assert isinstance(history[0]["detail"], dict)
        assert history[0]["detail"]["jira_status"] == "Done"


# ============================================================================
# JiraSyncEngine — sync_finding
# ============================================================================


class TestSyncFinding:
    def test_sync_finding_creates_issue(self, engine, sample_finding):
        mock = _mock_client(engine)
        mock.create_issue.return_value = {"key": "SEC-10", "id": "10001"}

        result = engine.sync_finding("F-001", sample_finding)

        assert result.status == SyncStatus.SUCCESS
        assert result.jira_issue_key == "SEC-10"
        assert result.direction == SyncDirection.FINDING_TO_JIRA
        assert result.detail["operation"] == "created"
        mock.create_issue.assert_called_once()

    def test_sync_finding_updates_existing_issue(self, engine, sample_finding):
        engine._store.upsert_link("F-001", "SEC-5")
        mock = _mock_client(engine)

        result = engine.sync_finding("F-001", sample_finding)

        assert result.status == SyncStatus.SUCCESS
        assert result.jira_issue_key == "SEC-5"
        assert result.detail["operation"] == "updated"
        mock.update_issue.assert_called_once()
        mock.create_issue.assert_not_called()

    def test_sync_finding_skips_when_not_configured(self, tmp_db, sample_finding):
        eng = JiraSyncEngine(db_path=tmp_db)
        result = eng.sync_finding("F-001", sample_finding)
        assert result.status == SyncStatus.SKIPPED

    def test_sync_finding_records_history(self, engine, sample_finding):
        mock = _mock_client(engine)
        mock.create_issue.return_value = {"key": "SEC-11"}

        engine.sync_finding("F-001", sample_finding)
        history = engine.get_history(finding_id="F-001")
        assert len(history) >= 1
        assert history[0]["status"] == "success"

    def test_sync_finding_handles_http_error(self, engine, sample_finding):
        from requests import RequestException
        mock = _mock_client(engine)
        mock.create_issue.side_effect = RequestException("timeout")

        result = engine.sync_finding("F-001", sample_finding)
        assert result.status == SyncStatus.FAILED
        assert "error" in result.detail

    def test_sync_finding_skips_when_direction_jira_only(self, tmp_db, basic_config, sample_finding):
        basic_config.sync_direction = SyncDirection.JIRA_TO_FINDING
        eng = JiraSyncEngine(db_path=tmp_db)
        eng.configure(basic_config)
        result = eng.sync_finding("F-001", sample_finding)
        assert result.status == SyncStatus.SKIPPED

    def test_sync_finding_jira_wins_conflict(self, tmp_db, basic_config, sample_finding):
        basic_config.conflict_resolution = ConflictResolution.JIRA_WINS
        eng = JiraSyncEngine(db_path=tmp_db)
        eng.configure(basic_config)
        eng._store.upsert_link("F-001", "SEC-1")
        mock = _mock_client(eng)

        result = eng.sync_finding("F-001", sample_finding)
        assert result.status == SyncStatus.SKIPPED
        mock.update_issue.assert_not_called()


# ============================================================================
# JiraSyncEngine — sync_from_jira
# ============================================================================


class TestSyncFromJira:
    def test_sync_from_jira_with_provided_data(self, engine):
        engine._store.upsert_link("F-001", "SEC-5")
        jira_data = {
            "key": "SEC-5",
            "fields": {
                "status": {"name": "Done"},
                "updated": _now_iso(),
            },
        }
        result = engine.sync_from_jira("SEC-5", jira_data=jira_data)
        assert result.status == SyncStatus.SUCCESS
        assert result.detail["new_finding_status"] == "resolved"
        assert result.detail["jira_status"] == "Done"

    def test_sync_from_jira_fetches_issue_when_no_data(self, engine):
        engine._store.upsert_link("F-002", "SEC-7")
        mock = _mock_client(engine)
        mock.get_issue.return_value = {
            "key": "SEC-7",
            "fields": {"status": {"name": "In Progress"}, "updated": _now_iso()},
        }
        result = engine.sync_from_jira("SEC-7")
        assert result.status == SyncStatus.SUCCESS
        assert result.detail["new_finding_status"] == "in_progress"

    def test_sync_from_jira_skips_when_not_configured(self, tmp_db):
        eng = JiraSyncEngine(db_path=tmp_db)
        result = eng.sync_from_jira("SEC-1")
        assert result.status == SyncStatus.SKIPPED

    def test_sync_from_jira_handles_unknown_status(self, engine):
        engine._store.upsert_link("F-003", "SEC-8")
        jira_data = {"key": "SEC-8", "fields": {"status": {"name": "Weird State"}, "updated": _now_iso()}}
        result = engine.sync_from_jira("SEC-8", jira_data=jira_data)
        assert result.status == SyncStatus.SUCCESS
        assert result.detail["new_finding_status"] == "unknown"

    def test_sync_from_jira_handles_http_error(self, engine):
        from requests import RequestException
        mock = _mock_client(engine)
        mock.get_issue.side_effect = RequestException("conn refused")
        result = engine.sync_from_jira("SEC-99")
        assert result.status == SyncStatus.FAILED


# ============================================================================
# JiraSyncEngine — sync_status
# ============================================================================


class TestSyncStatus:
    def test_sync_status_transitions_jira_issue(self, engine):
        engine._store.upsert_link("F-001", "SEC-10")
        mock = _mock_client(engine)
        mock.get_transitions.return_value = [
            {"id": "31", "name": "Done"},
            {"id": "11", "name": "In Progress"},
        ]

        result = engine.sync_status("F-001", "resolved")
        assert result.status == SyncStatus.SUCCESS
        assert result.detail["transition"] == "Done"
        mock.transition_issue.assert_called_once_with("SEC-10", "31")

    def test_sync_status_skips_when_no_link(self, engine):
        result = engine.sync_status("NO-LINK", "resolved")
        assert result.status == SyncStatus.SKIPPED

    def test_sync_status_skips_when_no_mapping(self, engine):
        engine._store.upsert_link("F-X", "SEC-2")
        _mock_client(engine)
        result = engine.sync_status("F-X", "some_unknown_status")
        assert result.status == SyncStatus.SKIPPED

    def test_sync_status_fails_when_transition_not_available(self, engine):
        engine._store.upsert_link("F-Y", "SEC-3")
        mock = _mock_client(engine)
        mock.get_transitions.return_value = []  # no transitions available
        result = engine.sync_status("F-Y", "resolved")
        assert result.status == SyncStatus.FAILED

    def test_sync_status_skips_when_not_configured(self, tmp_db):
        eng = JiraSyncEngine(db_path=tmp_db)
        result = eng.sync_status("F-Z", "resolved")
        assert result.status == SyncStatus.SKIPPED


# ============================================================================
# JiraSyncEngine — sync_all
# ============================================================================


class TestSyncAll:
    def test_sync_all_returns_results_for_each_finding(self, engine):
        mock = _mock_client(engine)
        mock.create_issue.return_value = {"key": "SEC-99"}

        findings = [
            {"finding_id": f"F-{i}", "title": f"Finding {i}", "severity": "high"}
            for i in range(5)
        ]
        results = engine.sync_all(findings)
        assert len(results) == 5

    def test_sync_all_uses_id_field_as_fallback(self, engine):
        mock = _mock_client(engine)
        mock.create_issue.return_value = {"key": "SEC-1"}

        findings = [{"id": "ALT-001", "title": "Test", "severity": "medium"}]
        results = engine.sync_all(findings)
        assert len(results) == 1

    def test_sync_all_continues_after_failure(self, engine):
        from requests import RequestException
        mock = _mock_client(engine)
        # First call fails, second succeeds
        mock.create_issue.side_effect = [
            RequestException("err"),
            {"key": "SEC-2"},
        ]
        findings = [
            {"finding_id": "F-bad", "title": "Bad", "severity": "low"},
            {"finding_id": "F-good", "title": "Good", "severity": "low"},
        ]
        results = engine.sync_all(findings)
        assert len(results) == 2
        statuses = {r.finding_id: r.status for r in results}
        assert statuses["F-bad"] == SyncStatus.FAILED
        assert statuses["F-good"] == SyncStatus.SUCCESS


# ============================================================================
# JiraSyncEngine — handle_webhook
# ============================================================================


class TestHandleWebhook:
    def test_webhook_issue_updated(self, engine):
        engine._store.upsert_link("F-001", "SEC-5")
        payload = {
            "webhookEvent": "jira:issue_updated",
            "issue": {
                "key": "SEC-5",
                "fields": {"status": {"name": "Done"}, "updated": _now_iso()},
            },
        }
        result = engine.handle_webhook(payload)
        assert result.status == SyncStatus.SUCCESS
        assert result.jira_issue_key == "SEC-5"

    def test_webhook_unknown_event_skipped(self, engine):
        payload = {
            "webhookEvent": "jira:worklog_created",
            "issue": {"key": "SEC-5", "fields": {}},
        }
        result = engine.handle_webhook(payload)
        assert result.status == SyncStatus.SKIPPED

    def test_webhook_missing_issue_key_skipped(self, engine):
        payload = {"webhookEvent": "jira:issue_updated", "issue": {}}
        result = engine.handle_webhook(payload)
        assert result.status == SyncStatus.SKIPPED

    def test_webhook_issue_created_event(self, engine):
        payload = {
            "webhookEvent": "jira:issue_created",
            "issue": {
                "key": "SEC-20",
                "fields": {"status": {"name": "To Do"}, "updated": _now_iso()},
            },
        }
        result = engine.handle_webhook(payload)
        assert result.jira_issue_key == "SEC-20"


# ============================================================================
# JiraSyncEngine — field mapping
# ============================================================================


class TestFieldMapping:
    def test_get_field_mapping_empty_by_default(self, engine):
        assert engine.get_field_mapping() == []

    def test_set_and_get_field_mapping(self, engine):
        engine.set_field_mapping([
            {"finding_field": "asset_id", "jira_field": "customfield_10001"},
            {"finding_field": "app_id", "jira_field": "customfield_10002", "transform": None},
        ])
        mappings = engine.get_field_mapping()
        assert len(mappings) == 2
        assert mappings[0]["finding_field"] == "asset_id"

    def test_set_field_mapping_raises_when_not_configured(self, tmp_db):
        eng = JiraSyncEngine(db_path=tmp_db)
        with pytest.raises(RuntimeError):
            eng.set_field_mapping([{"finding_field": "x", "jira_field": "y"}])

    def test_field_mappings_applied_in_create_issue(self, engine):
        engine.set_field_mapping([
            {"finding_field": "asset_id", "jira_field": "customfield_99999"},
        ])
        mock = _mock_client(engine)
        mock.create_issue.return_value = {"key": "SEC-50"}

        finding = {
            "finding_id": "F-custom",
            "title": "Test",
            "severity": "high",
            "asset_id": "ASSET-42",
        }
        engine.sync_finding("F-custom", finding)

        call_kwargs = mock.create_issue.call_args[0][0]
        assert call_kwargs["fields"].get("customfield_99999") == "ASSET-42"


# ============================================================================
# JiraSyncEngine — history and stats
# ============================================================================


class TestHistoryAndStats:
    def test_get_history_returns_events(self, engine):
        mock = _mock_client(engine)
        mock.create_issue.return_value = {"key": "SEC-1"}
        engine.sync_finding("F-hist", {"finding_id": "F-hist", "title": "T", "severity": "low"})
        history = engine.get_history(finding_id="F-hist")
        assert len(history) >= 1

    def test_get_history_pagination(self, engine):
        mock = _mock_client(engine)
        mock.create_issue.return_value = {"key": "SEC-1"}
        for i in range(5):
            engine.sync_finding(f"F-{i}", {"finding_id": f"F-{i}", "title": "T", "severity": "low"})
            mock.create_issue.return_value = {"key": f"SEC-{i+2}"}
        all_h = engine.get_history(limit=3, offset=0)
        assert len(all_h) <= 3

    def test_get_stats_reflects_operations(self, engine):
        mock = _mock_client(engine)
        mock.create_issue.return_value = {"key": "SEC-3"}
        engine.sync_finding("F-stat", {"finding_id": "F-stat", "title": "T", "severity": "medium"})
        stats = engine.get_stats()
        assert stats["total_sync_events"] >= 1


# ============================================================================
# Module singleton
# ============================================================================


class TestModuleSingleton:
    def test_get_engine_returns_instance(self, tmp_path):
        import core.jira_sync as mod
        original = mod._engine
        mod._engine = None
        try:
            eng = get_jira_sync_engine(db_path=str(tmp_path / "singleton.db"))
            assert isinstance(eng, JiraSyncEngine)
        finally:
            mod._engine = original

    def test_get_engine_returns_same_instance(self, tmp_path):
        import core.jira_sync as mod
        original = mod._engine
        mod._engine = None
        try:
            db = str(tmp_path / "singleton2.db")
            eng1 = get_jira_sync_engine(db_path=db)
            eng2 = get_jira_sync_engine(db_path=db)
            assert eng1 is eng2
        finally:
            mod._engine = original


# ============================================================================
# SyncResult serialisation
# ============================================================================


class TestSyncResult:
    def test_to_dict_contains_required_keys(self):
        result = SyncResult(
            finding_id="F-001",
            jira_issue_key="SEC-1",
            status=SyncStatus.SUCCESS,
            direction=SyncDirection.FINDING_TO_JIRA,
            detail={"operation": "created"},
            synced_at=_now_iso(),
        )
        d = result.to_dict()
        for key in ("finding_id", "jira_issue_key", "status", "direction", "detail", "synced_at"):
            assert key in d

    def test_to_dict_status_is_string(self):
        result = SyncResult(
            finding_id="F-X",
            jira_issue_key=None,
            status=SyncStatus.FAILED,
            direction=SyncDirection.JIRA_TO_FINDING,
            detail={},
            synced_at=_now_iso(),
        )
        assert result.to_dict()["status"] == "failed"


# ============================================================================
# Router Pydantic models (import-level smoke test)
# ============================================================================


class TestRouterModels:
    def test_configure_request_valid(self):
        from apps.api.jira_sync_router import ConfigureRequest
        req = ConfigureRequest(
            jira_url="https://x.atlassian.net",
            user_email="a@b.com",
            api_token="tok",
            project_key="P",
        )
        assert req.project_key == "P"
        assert req.sync_direction == "bidirectional"

    def test_sync_finding_request(self):
        from apps.api.jira_sync_router import SyncFindingRequest
        req = SyncFindingRequest(
            finding_id="F-1",
            finding_data={"title": "test", "severity": "high"},
        )
        assert req.finding_id == "F-1"

    def test_sync_status_request(self):
        from apps.api.jira_sync_router import SyncStatusRequest
        req = SyncStatusRequest(finding_id="F-2", new_status="resolved")
        assert req.new_status == "resolved"

    def test_field_mapping_update_request(self):
        from apps.api.jira_sync_router import FieldMappingItem, FieldMappingUpdateRequest
        req = FieldMappingUpdateRequest(
            mappings=[FieldMappingItem(finding_field="cve_id", jira_field="customfield_10050")]
        )
        assert req.mappings[0].finding_field == "cve_id"
