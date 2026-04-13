"""Tests for ServiceNow Bidirectional Sync Engine.

Covers:
- ServiceNowSyncConfig: construction, validation, serialisation
- ServiceNowSyncStore: SQLite persistence of links, history, config
- ServiceNowSyncEngine: sync_finding, sync_from_servicenow, sync_status,
                        sync_all, handle_webhook, field mapping,
                        conflict resolution, mock-safe (no credentials)
- get_servicenow_sync_engine: module singleton
- Router models: Pydantic request/response shapes

All HTTP calls to ServiceNow are mocked — no real network required.

Usage:
    pytest tests/test_servicenow_sync.py -v --timeout=10
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

from core.servicenow_sync import (
    ConflictResolution,
    FieldMapping,
    ServiceNowSyncConfig,
    ServiceNowSyncEngine,
    ServiceNowSyncStore,
    SyncDirection,
    SyncRecord,
    SyncResult,
    SyncStatus,
    _DEFAULT_FINDING_TO_SN_STATE,
    _DEFAULT_SEVERITY_TO_IMPACT,
    _DEFAULT_SEVERITY_TO_URGENCY,
    _DEFAULT_SN_STATE_TO_FINDING_STATUS,
    _now_iso,
    get_servicenow_sync_engine,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def tmp_db(tmp_path):
    return str(tmp_path / "sn_sync_test.db")


@pytest.fixture
def store(tmp_db):
    return ServiceNowSyncStore(db_path=tmp_db)


@pytest.fixture
def basic_config():
    return ServiceNowSyncConfig(
        instance_url="https://mycompany.service-now.com",
        username="sync_user",
        password="s3cr3t",
        assignment_group="Security Operations",
    )


@pytest.fixture
def engine(tmp_db, basic_config):
    eng = ServiceNowSyncEngine(db_path=tmp_db)
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


def _mock_client(engine: ServiceNowSyncEngine) -> MagicMock:
    """Patch the engine's _ServiceNowClient with a mock and return it."""
    mock = MagicMock()
    engine._client = mock
    return mock


# ============================================================================
# ServiceNowSyncConfig
# ============================================================================


class TestServiceNowSyncConfig:
    def test_configured_true_when_all_fields_set(self, basic_config):
        assert basic_config.configured is True

    def test_configured_false_when_missing_url(self):
        cfg = ServiceNowSyncConfig(username="u", password="p")
        assert cfg.configured is False

    def test_configured_false_when_missing_username(self, basic_config):
        basic_config.username = ""
        assert basic_config.configured is False

    def test_configured_false_when_missing_password(self, basic_config):
        basic_config.password = ""
        assert basic_config.configured is False

    def test_to_dict_masks_password(self, basic_config):
        d = basic_config.to_dict()
        assert d["password"] == "***"
        assert d["instance_url"] == "https://mycompany.service-now.com"

    def test_default_sync_direction(self, basic_config):
        assert basic_config.sync_direction == SyncDirection.BIDIRECTIONAL

    def test_default_conflict_resolution(self, basic_config):
        assert basic_config.conflict_resolution == ConflictResolution.NEWEST_WINS

    def test_default_tags(self, basic_config):
        assert "aldeci" in basic_config.tags
        assert "security" in basic_config.tags

    def test_severity_to_urgency_defaults(self, basic_config):
        assert basic_config.severity_to_urgency["critical"] == "1"
        assert basic_config.severity_to_urgency["low"] == "3"

    def test_severity_to_impact_defaults(self, basic_config):
        assert basic_config.severity_to_impact["critical"] == "1"
        assert basic_config.severity_to_impact["medium"] == "2"

    def test_sn_state_to_finding_status_defaults(self, basic_config):
        assert basic_config.sn_state_to_finding_status["1"] == "open"
        assert basic_config.sn_state_to_finding_status["6"] == "resolved"
        assert basic_config.sn_state_to_finding_status["7"] == "closed"

    def test_finding_to_sn_state_defaults(self, basic_config):
        assert basic_config.finding_to_sn_state["open"] == "1"
        assert basic_config.finding_to_sn_state["resolved"] == "6"

    def test_to_dict_has_configured_key(self, basic_config):
        d = basic_config.to_dict()
        assert d["configured"] is True


# ============================================================================
# ServiceNowSyncStore
# ============================================================================


class TestServiceNowSyncStore:
    def test_upsert_and_get_link(self, store):
        store.upsert_link("F-001", "sys-abc123", "INC0010001")
        link = store.get_link("F-001")
        assert link is not None
        assert link["sn_sys_id"] == "sys-abc123"
        assert link["sn_incident_number"] == "INC0010001"

    def test_get_link_returns_none_for_unknown(self, store):
        assert store.get_link("DOES-NOT-EXIST") is None

    def test_get_link_by_sys_id(self, store):
        store.upsert_link("F-002", "sys-xyz", "INC0010002")
        link = store.get_link_by_sys_id("sys-xyz")
        assert link is not None
        assert link["finding_id"] == "F-002"

    def test_get_link_by_sys_id_returns_none_for_unknown(self, store):
        assert store.get_link_by_sys_id("nonexistent-sys-id") is None

    def test_upsert_link_updates_existing(self, store):
        store.upsert_link("F-001", "sys-old", "INC0000001")
        store.upsert_link("F-001", "sys-new", "INC0000099")
        link = store.get_link("F-001")
        assert link["sn_sys_id"] == "sys-new"
        assert link["sn_incident_number"] == "INC0000099"

    def test_delete_link_existing(self, store):
        store.upsert_link("F-002", "sys-del", "INC0000002")
        deleted = store.delete_link("F-002")
        assert deleted is True
        assert store.get_link("F-002") is None

    def test_delete_link_nonexistent(self, store):
        assert store.delete_link("NO-SUCH") is False

    def test_list_links_returns_all(self, store):
        store.upsert_link("F-A", "sys-a", "INC0000010")
        store.upsert_link("F-B", "sys-b", "INC0000011")
        links = store.list_links()
        finding_ids = {lnk["finding_id"] for lnk in links}
        assert {"F-A", "F-B"}.issubset(finding_ids)

    def test_append_and_get_history(self, store):
        rec = SyncRecord(
            record_id=str(uuid.uuid4()),
            finding_id="F-001",
            sn_incident_number="INC0010001",
            sn_sys_id="sys-abc",
            direction=SyncDirection.FINDING_TO_SN,
            status=SyncStatus.SUCCESS,
            detail={"op": "created"},
            synced_at=_now_iso(),
        )
        store.append_history(rec)
        history = store.get_history(finding_id="F-001")
        assert len(history) == 1
        assert history[0]["status"] == "success"
        assert history[0]["detail"]["op"] == "created"

    def test_get_history_all_without_filter(self, store):
        for i in range(3):
            store.append_history(
                SyncRecord(
                    record_id=str(uuid.uuid4()),
                    finding_id=f"F-{i}",
                    sn_incident_number=f"INC00{i}",
                    sn_sys_id=f"sys-{i}",
                    direction=SyncDirection.FINDING_TO_SN,
                    status=SyncStatus.SUCCESS,
                    detail={},
                    synced_at=_now_iso(),
                )
            )
        history = store.get_history()
        assert len(history) == 3

    def test_get_stats_empty(self, store):
        stats = store.get_stats()
        assert stats["total_links"] == 0
        assert stats["total_sync_events"] == 0

    def test_get_stats_after_activity(self, store):
        store.upsert_link("F-1", "sys-1", "INC0000001")
        store.append_history(
            SyncRecord(
                record_id=str(uuid.uuid4()),
                finding_id="F-1",
                sn_incident_number="INC0000001",
                sn_sys_id="sys-1",
                direction=SyncDirection.FINDING_TO_SN,
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
        assert loaded.instance_url == basic_config.instance_url
        assert loaded.username == basic_config.username
        assert loaded.assignment_group == basic_config.assignment_group

    def test_load_config_returns_none_when_not_saved(self, store):
        assert store.load_config() is None


# ============================================================================
# ServiceNowSyncEngine — configuration
# ============================================================================


class TestServiceNowSyncEngineConfig:
    def test_configure_sets_config(self, engine, basic_config):
        assert engine.get_config() is not None
        assert engine.get_config().instance_url == basic_config.instance_url

    def test_configure_persists_to_store(self, tmp_db, basic_config):
        eng = ServiceNowSyncEngine(db_path=tmp_db)
        eng.configure(basic_config)
        # Fresh engine loads from DB
        eng2 = ServiceNowSyncEngine(db_path=tmp_db)
        assert eng2.get_config() is not None
        assert eng2.get_config().instance_url == basic_config.instance_url

    def test_unconfigured_engine_returns_none_config(self, tmp_db):
        eng = ServiceNowSyncEngine(db_path=tmp_db)
        assert eng.get_config() is None


# ============================================================================
# ServiceNowSyncEngine — sync_finding
# ============================================================================


class TestSyncFinding:
    def test_sync_finding_creates_incident(self, engine, sample_finding):
        mock = _mock_client(engine)
        mock.create_incident.return_value = {
            "sys_id": "sys-abc123",
            "number": "INC0010001",
        }
        result = engine.sync_finding("F-001", sample_finding)

        assert result.status == SyncStatus.SUCCESS
        assert result.sn_sys_id == "sys-abc123"
        assert result.sn_incident_number == "INC0010001"
        assert result.detail["operation"] == "created"
        mock.create_incident.assert_called_once()

    def test_sync_finding_updates_existing_incident(self, engine, sample_finding):
        mock = _mock_client(engine)
        engine._store.upsert_link("F-001", "sys-existing", "INC0009999")
        mock.update_incident.return_value = {}

        result = engine.sync_finding("F-001", sample_finding)

        assert result.status == SyncStatus.SUCCESS
        assert result.detail["operation"] == "updated"
        assert result.sn_sys_id == "sys-existing"
        mock.update_incident.assert_called_once()
        mock.create_incident.assert_not_called()

    def test_sync_finding_skipped_when_not_configured(self, tmp_db, sample_finding):
        eng = ServiceNowSyncEngine(db_path=tmp_db)
        result = eng.sync_finding("F-001", sample_finding)
        assert result.status == SyncStatus.SKIPPED
        assert "not configured" in result.detail["reason"]

    def test_sync_finding_skipped_when_direction_is_sn_to_finding(
        self, tmp_db, basic_config, sample_finding
    ):
        basic_config.sync_direction = SyncDirection.SN_TO_FINDING
        eng = ServiceNowSyncEngine(db_path=tmp_db)
        eng.configure(basic_config)
        result = eng.sync_finding("F-001", sample_finding)
        assert result.status == SyncStatus.SKIPPED

    def test_sync_finding_conflict_resolution_sn_wins(
        self, tmp_db, basic_config, sample_finding
    ):
        basic_config.conflict_resolution = ConflictResolution.SN_WINS
        eng = ServiceNowSyncEngine(db_path=tmp_db)
        eng.configure(basic_config)
        eng._store.upsert_link("F-001", "sys-existing", "INC0009999")
        mock = _mock_client(eng)

        result = eng.sync_finding("F-001", sample_finding)
        assert result.status == SyncStatus.SKIPPED
        assert "servicenow_wins" in result.detail["reason"]
        mock.update_incident.assert_not_called()

    def test_sync_finding_failed_on_request_error(self, engine, sample_finding):
        from requests import RequestException
        mock = _mock_client(engine)
        mock.create_incident.side_effect = RequestException("connection refused")

        result = engine.sync_finding("F-001", sample_finding)
        assert result.status == SyncStatus.FAILED
        assert "error" in result.detail

    def test_sync_finding_field_mapping_urgency(self, engine, sample_finding):
        """Critical severity maps to urgency=1."""
        mock = _mock_client(engine)
        mock.create_incident.return_value = {"sys_id": "s1", "number": "INC0001"}
        engine.sync_finding("F-001", sample_finding)
        call_args = mock.create_incident.call_args[0][0]
        assert call_args["urgency"] == "1"
        assert call_args["impact"] == "1"

    def test_sync_finding_medium_severity_maps_to_urgency_2(
        self, engine, sample_finding
    ):
        mock = _mock_client(engine)
        mock.create_incident.return_value = {"sys_id": "s2", "number": "INC0002"}
        sample_finding["severity"] = "medium"
        engine.sync_finding("F-001", sample_finding)
        call_args = mock.create_incident.call_args[0][0]
        assert call_args["urgency"] == "2"


# ============================================================================
# ServiceNowSyncEngine — sync_from_servicenow
# ============================================================================


class TestSyncFromServiceNow:
    def test_sync_from_sn_translates_state_to_finding_status(self, engine):
        mock = _mock_client(engine)
        mock.get_incident.return_value = {
            "sys_id": "sys-abc",
            "number": "INC0010001",
            "state": "6",
            "sys_updated_on": _now_iso(),
        }
        engine._store.upsert_link("F-001", "sys-abc", "INC0010001")

        result = engine.sync_from_servicenow("sys-abc")
        assert result.status == SyncStatus.SUCCESS
        assert result.detail["new_finding_status"] == "resolved"

    def test_sync_from_sn_with_inline_data(self, engine):
        engine._store.upsert_link("F-002", "sys-xyz", "INC0010002")
        sn_data = {
            "sys_id": "sys-xyz",
            "number": "INC0010002",
            "state": "1",
            "sys_updated_on": _now_iso(),
        }
        result = engine.sync_from_servicenow("sys-xyz", sn_data=sn_data)
        assert result.status == SyncStatus.SUCCESS
        assert result.detail["new_finding_status"] == "open"

    def test_sync_from_sn_skipped_when_not_configured(self, tmp_db):
        eng = ServiceNowSyncEngine(db_path=tmp_db)
        result = eng.sync_from_servicenow("sys-xxx")
        assert result.status == SyncStatus.SKIPPED

    def test_sync_from_sn_skipped_when_direction_is_finding_to_sn(
        self, tmp_db, basic_config
    ):
        basic_config.sync_direction = SyncDirection.FINDING_TO_SN
        eng = ServiceNowSyncEngine(db_path=tmp_db)
        eng.configure(basic_config)
        _mock_client(eng)
        result = eng.sync_from_servicenow("sys-xxx")
        assert result.status == SyncStatus.SKIPPED

    def test_sync_from_sn_handles_dict_state(self, engine):
        """ServiceNow sometimes returns state as a dict with value/display_value."""
        engine._store.upsert_link("F-003", "sys-dict", "INC0010003")
        sn_data = {
            "sys_id": "sys-dict",
            "number": "INC0010003",
            "state": {"value": "2", "display_value": "In Progress"},
            "sys_updated_on": _now_iso(),
        }
        result = engine.sync_from_servicenow("sys-dict", sn_data=sn_data)
        assert result.status == SyncStatus.SUCCESS
        assert result.detail["new_finding_status"] == "in_progress"

    def test_sync_from_sn_failed_on_request_error(self, engine):
        from requests import RequestException
        mock = _mock_client(engine)
        mock.get_incident.side_effect = RequestException("timeout")
        result = engine.sync_from_servicenow("sys-bad")
        assert result.status == SyncStatus.FAILED


# ============================================================================
# ServiceNowSyncEngine — sync_status
# ============================================================================


class TestSyncStatus:
    def test_sync_status_updates_sn_state(self, engine):
        mock = _mock_client(engine)
        engine._store.upsert_link("F-001", "sys-abc", "INC0010001")
        mock.update_incident.return_value = {}

        result = engine.sync_status("F-001", "resolved")
        assert result.status == SyncStatus.SUCCESS
        assert result.detail["new_state"] == "6"
        mock.update_incident.assert_called_once_with("sys-abc", {"state": "6"})

    def test_sync_status_skipped_when_no_link(self, engine):
        result = engine.sync_status("F-UNKNOWN", "resolved")
        assert result.status == SyncStatus.SKIPPED
        assert "no servicenow link" in result.detail["reason"]

    def test_sync_status_skipped_when_no_state_mapping(self, engine):
        engine._store.upsert_link("F-001", "sys-abc", "INC0010001")
        result = engine.sync_status("F-001", "unknown_status_xyz")
        assert result.status == SyncStatus.SKIPPED
        assert "no state mapping" in result.detail["reason"]

    def test_sync_status_failed_on_request_error(self, engine):
        from requests import RequestException
        engine._store.upsert_link("F-001", "sys-abc", "INC0010001")
        mock = _mock_client(engine)
        mock.update_incident.side_effect = RequestException("network error")

        result = engine.sync_status("F-001", "resolved")
        assert result.status == SyncStatus.FAILED

    def test_sync_status_skipped_when_not_configured(self, tmp_db):
        eng = ServiceNowSyncEngine(db_path=tmp_db)
        result = eng.sync_status("F-001", "resolved")
        assert result.status == SyncStatus.SKIPPED


# ============================================================================
# ServiceNowSyncEngine — sync_all
# ============================================================================


class TestSyncAll:
    def test_sync_all_returns_one_result_per_finding(self, engine, sample_finding):
        mock = _mock_client(engine)
        mock.create_incident.return_value = {"sys_id": "s1", "number": "INC0001"}

        findings = [
            {**sample_finding, "finding_id": f"F-{i}", "title": f"Finding {i}"}
            for i in range(5)
        ]
        results = engine.sync_all(findings)
        assert len(results) == 5

    def test_sync_all_uses_id_field_as_fallback(self, engine):
        mock = _mock_client(engine)
        mock.create_incident.return_value = {"sys_id": "s1", "number": "INC0001"}

        findings = [{"id": "ALT-001", "title": "Alt finding", "severity": "low"}]
        results = engine.sync_all(findings)
        assert results[0].finding_id == "ALT-001"

    def test_sync_all_continues_after_failure(self, engine, sample_finding):
        from requests import RequestException
        mock = _mock_client(engine)
        mock.create_incident.side_effect = [
            RequestException("fail"),
            {"sys_id": "s2", "number": "INC0002"},
        ]
        findings = [
            {**sample_finding, "finding_id": "F-FAIL"},
            {**sample_finding, "finding_id": "F-OK"},
        ]
        results = engine.sync_all(findings)
        assert results[0].status == SyncStatus.FAILED
        assert results[1].status == SyncStatus.SUCCESS


# ============================================================================
# ServiceNowSyncEngine — field mapping
# ============================================================================


class TestFieldMapping:
    def test_get_field_mapping_empty_by_default(self, engine):
        assert engine.get_field_mapping() == []

    def test_set_and_get_field_mapping(self, engine):
        engine.set_field_mapping(
            [{"finding_field": "cve_id", "sn_field": "u_cve_id", "transform": None}]
        )
        mappings = engine.get_field_mapping()
        assert len(mappings) == 1
        assert mappings[0]["finding_field"] == "cve_id"
        assert mappings[0]["sn_field"] == "u_cve_id"

    def test_set_field_mapping_persists(self, tmp_db, basic_config):
        eng = ServiceNowSyncEngine(db_path=tmp_db)
        eng.configure(basic_config)
        eng.set_field_mapping(
            [{"finding_field": "source", "sn_field": "u_source", "transform": None}]
        )
        eng2 = ServiceNowSyncEngine(db_path=tmp_db)
        mappings = eng2.get_field_mapping()
        assert len(mappings) == 1
        assert mappings[0]["sn_field"] == "u_source"

    def test_set_field_mapping_raises_when_not_configured(self, tmp_db):
        eng = ServiceNowSyncEngine(db_path=tmp_db)
        with pytest.raises(RuntimeError, match="not configured"):
            eng.set_field_mapping(
                [{"finding_field": "x", "sn_field": "y", "transform": None}]
            )

    def test_custom_field_mapping_applied_during_sync(self, engine, sample_finding):
        engine.set_field_mapping(
            [{"finding_field": "cve_id", "sn_field": "u_cve_id", "transform": None}]
        )
        mock = _mock_client(engine)
        mock.create_incident.return_value = {"sys_id": "s1", "number": "INC0001"}
        engine.sync_finding("F-001", sample_finding)
        call_args = mock.create_incident.call_args[0][0]
        assert call_args.get("u_cve_id") == "CVE-2025-1234"

    def test_severity_to_urgency_transform_in_field_mapping(
        self, engine, sample_finding
    ):
        engine.set_field_mapping(
            [
                {
                    "finding_field": "severity",
                    "sn_field": "u_urgency_override",
                    "transform": "severity_to_urgency",
                }
            ]
        )
        mock = _mock_client(engine)
        mock.create_incident.return_value = {"sys_id": "s1", "number": "INC0001"}
        engine.sync_finding("F-001", sample_finding)
        call_args = mock.create_incident.call_args[0][0]
        assert call_args.get("u_urgency_override") == "1"  # critical → "1"


# ============================================================================
# ServiceNowSyncEngine — handle_webhook
# ============================================================================


class TestHandleWebhook:
    def test_webhook_skipped_when_no_sys_id(self, engine):
        result = engine.handle_webhook({"action": "update", "table_name": "incident"})
        assert result.status == SyncStatus.SKIPPED
        assert "no sys_id" in result.detail["reason"]

    def test_webhook_skipped_for_non_incident_table(self, engine):
        result = engine.handle_webhook(
            {
                "sys_id": "sys-abc",
                "number": "CHG0001",
                "table_name": "change_request",
                "action": "update",
            }
        )
        assert result.status == SyncStatus.SKIPPED
        assert "unsupported table" in result.detail["reason"]

    def test_webhook_insert_triggers_sync(self, engine):
        engine._store.upsert_link("F-001", "sys-new", "INC0010001")
        result = engine.handle_webhook(
            {
                "sys_id": "sys-new",
                "number": "INC0010001",
                "table_name": "incident",
                "action": "insert",
                "state": "1",
                "sys_updated_on": _now_iso(),
            }
        )
        assert result.status == SyncStatus.SUCCESS
        assert result.detail["new_finding_status"] == "open"

    def test_webhook_update_resolved_state(self, engine):
        engine._store.upsert_link("F-002", "sys-upd", "INC0010002")
        result = engine.handle_webhook(
            {
                "sys_id": "sys-upd",
                "number": "INC0010002",
                "table_name": "incident",
                "action": "update",
                "state": "6",
                "sys_updated_on": _now_iso(),
            }
        )
        assert result.status == SyncStatus.SUCCESS
        assert result.detail["new_finding_status"] == "resolved"

    def test_webhook_skipped_for_unknown_action(self, engine):
        result = engine.handle_webhook(
            {
                "sys_id": "sys-act",
                "number": "INC0010003",
                "table_name": "incident",
                "action": "some_unknown_action",
                "state": "1",
                "sys_updated_on": _now_iso(),
            }
        )
        # action="" is handled but "some_unknown_action" is not in insert/update/delete/""
        # The engine should skip it
        assert result.status == SyncStatus.SKIPPED


# ============================================================================
# ServiceNowSyncEngine — sync history
# ============================================================================


class TestSyncHistory:
    def test_history_recorded_after_sync(self, engine, sample_finding):
        mock = _mock_client(engine)
        mock.create_incident.return_value = {"sys_id": "s1", "number": "INC0001"}
        engine.sync_finding("F-001", sample_finding)

        history = engine.get_history(finding_id="F-001")
        assert len(history) >= 1
        assert history[0]["finding_id"] == "F-001"

    def test_history_recorded_after_skipped_sync(self, tmp_db, sample_finding):
        eng = ServiceNowSyncEngine(db_path=tmp_db)
        eng.sync_finding("F-001", sample_finding)  # not configured → skipped
        history = eng.get_history(finding_id="F-001")
        assert len(history) == 1
        assert history[0]["status"] == "skipped"

    def test_history_pagination(self, engine, sample_finding):
        mock = _mock_client(engine)
        mock.create_incident.side_effect = [
            {"sys_id": f"s{i}", "number": f"INC000{i}"} for i in range(5)
        ]
        for i in range(5):
            engine.sync_finding(f"F-{i}", {**sample_finding, "finding_id": f"F-{i}"})

        page1 = engine.get_history(limit=2, offset=0)
        page2 = engine.get_history(limit=2, offset=2)
        assert len(page1) == 2
        assert len(page2) == 2
        assert page1[0]["synced_at"] >= page2[0]["synced_at"]


# ============================================================================
# ServiceNowSyncEngine — stats
# ============================================================================


class TestStats:
    def test_stats_empty_initially(self, engine):
        stats = engine.get_stats()
        assert stats["total_links"] == 0
        assert stats["total_sync_events"] == 0

    def test_stats_after_sync(self, engine, sample_finding):
        mock = _mock_client(engine)
        mock.create_incident.return_value = {"sys_id": "s1", "number": "INC0001"}
        engine.sync_finding("F-001", sample_finding)

        stats = engine.get_stats()
        assert stats["total_links"] == 1
        assert stats["total_sync_events"] >= 1
        assert "success" in stats["by_status"]


# ============================================================================
# Module-level singleton
# ============================================================================


class TestSingleton:
    def test_get_engine_returns_same_instance(self, tmp_path):
        import core.servicenow_sync as sn_mod
        original = sn_mod._engine
        try:
            sn_mod._engine = None
            db = str(tmp_path / "singleton.db")
            e1 = get_servicenow_sync_engine(db_path=db)
            e2 = get_servicenow_sync_engine(db_path=db)
            assert e1 is e2
        finally:
            sn_mod._engine = original

    def test_get_engine_is_servicenow_sync_engine_instance(self, tmp_path):
        import core.servicenow_sync as sn_mod
        original = sn_mod._engine
        try:
            sn_mod._engine = None
            db = str(tmp_path / "singleton2.db")
            eng = get_servicenow_sync_engine(db_path=db)
            assert isinstance(eng, ServiceNowSyncEngine)
        finally:
            sn_mod._engine = original


# ============================================================================
# Default constant coverage
# ============================================================================


class TestDefaultConstants:
    def test_default_sn_state_covers_common_states(self):
        assert "1" in _DEFAULT_SN_STATE_TO_FINDING_STATUS
        assert "6" in _DEFAULT_SN_STATE_TO_FINDING_STATUS
        assert "7" in _DEFAULT_SN_STATE_TO_FINDING_STATUS

    def test_default_severity_urgency_covers_all_levels(self):
        for sev in ("critical", "high", "medium", "low", "info", "informational"):
            assert sev in _DEFAULT_SEVERITY_TO_URGENCY

    def test_default_severity_impact_covers_all_levels(self):
        for sev in ("critical", "high", "medium", "low", "info", "informational"):
            assert sev in _DEFAULT_SEVERITY_TO_IMPACT

    def test_default_finding_to_sn_state_covers_common_statuses(self):
        for status in ("open", "in_progress", "resolved", "closed", "wont_fix"):
            assert status in _DEFAULT_FINDING_TO_SN_STATE

    def test_now_iso_returns_utc_string(self):
        ts = _now_iso()
        assert "T" in ts
        assert "+" in ts or "Z" in ts or ts.endswith("+00:00")
