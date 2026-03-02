"""
Comprehensive unit tests for suite-integrations/api/webhooks_router.py

Covers:
- Status mapping functions: _map_jira_status_to_fixops, _map_servicenow_state_to_fixops,
  _map_gitlab_state_to_fixops, _map_azure_state_to_fixops, _map_gitlab_labels_to_status
- Signature verification: _verify_jira_signature
- Secret getters: _get_jira_webhook_secret, _get_servicenow_webhook_secret,
  _get_azure_devops_webhook_secret, _get_gitlab_webhook_secret
- Drift detection: _detect_drift
- Database: _init_db, _get_db_path — table creation + schema verification
- Pydantic models: JiraWebhookPayload, ServiceNowWebhookPayload,
  CreateMappingRequest, DriftResolutionRequest
- Additional models: OutboxRequest, GitLabWebhookPayload, AzureDevOpsWebhookPayload,
  CreateWorkItemRequest
- Exponential backoff: _calculate_next_retry
- Connector settings: _get_connector_settings

Strategy: set _db_path module variable to a temp path AFTER import to redirect
all SQLite calls away from production data/integrations/webhooks.db.
"""

import hashlib
import hmac
import os
import sqlite3
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Path setup — must happen before any project imports
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-integrations"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

# Set required env vars before importing anything that triggers _init_db
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

# ---------------------------------------------------------------------------
# Import the module under test — _init_db() fires at import (line 139)
# We redirect _db_path after import via the fixture below.
# ---------------------------------------------------------------------------
import api.webhooks_router as webhooks_router
from api.webhooks_router import (
    AzureDevOpsWebhookPayload,
    CreateMappingRequest,
    CreateWorkItemRequest,
    DriftResolutionRequest,
    GitLabWebhookPayload,
    JiraWebhookPayload,
    OutboxRequest,
    ServiceNowWebhookPayload,
    _calculate_next_retry,
    _detect_drift,
    _get_azure_devops_webhook_secret,
    _get_connector_settings,
    _get_db_path,
    _get_gitlab_webhook_secret,
    _get_jira_webhook_secret,
    _get_servicenow_webhook_secret,
    _init_db,
    _map_azure_state_to_fixops,
    _map_gitlab_labels_to_status,
    _map_gitlab_state_to_fixops,
    _map_jira_status_to_fixops,
    _map_servicenow_state_to_fixops,
    _verify_jira_signature,
)


# ===========================================================================
# Shared fixture: isolated temp database
# ===========================================================================


@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    """
    Redirect the module-level _db_path to a per-test temp directory,
    then call _init_db() so the new temp DB has all four tables.
    Restores the original _db_path after each test.
    """
    db_file = tmp_path / "test_webhooks.db"
    original = webhooks_router._db_path

    webhooks_router._db_path = db_file
    _init_db()

    yield db_file

    webhooks_router._db_path = original


def _get_conn(db_path):
    """Helper: open an SQLite connection to the test database."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def _insert_mapping(db_path, *, cluster_id, integration_type, external_id,
                    fixops_status="open", external_status=None):
    """Helper: insert a row into integration_mappings and return mapping_id."""
    mapping_id = str(uuid.uuid4())
    now = "2024-01-01T00:00:00+00:00"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        INSERT INTO integration_mappings (
            mapping_id, cluster_id, integration_type, external_id,
            external_status, fixops_status, last_synced, created_at
        ) VALUES (?,?,?,?,?,?,?,?)
        """,
        (mapping_id, cluster_id, integration_type, external_id,
         external_status, fixops_status, now, now),
    )
    conn.commit()
    conn.close()
    return mapping_id


# ===========================================================================
# 1. _map_jira_status_to_fixops — all branches
# ===========================================================================


class TestMapJiraStatusToFixops:
    def test_to_do_maps_to_open(self):
        assert _map_jira_status_to_fixops("To Do") == "open"

    def test_open_maps_to_open(self):
        assert _map_jira_status_to_fixops("Open") == "open"

    def test_in_progress_maps_to_in_progress(self):
        assert _map_jira_status_to_fixops("In Progress") == "in_progress"

    def test_in_review_maps_to_in_progress(self):
        assert _map_jira_status_to_fixops("In Review") == "in_progress"

    def test_done_maps_to_resolved(self):
        assert _map_jira_status_to_fixops("Done") == "resolved"

    def test_closed_maps_to_resolved(self):
        assert _map_jira_status_to_fixops("Closed") == "resolved"

    def test_wont_fix_maps_to_accepted_risk(self):
        assert _map_jira_status_to_fixops("Won't Fix") == "accepted_risk"

    def test_wont_do_maps_to_accepted_risk(self):
        assert _map_jira_status_to_fixops("Won't Do") == "accepted_risk"

    def test_duplicate_maps_to_false_positive(self):
        assert _map_jira_status_to_fixops("Duplicate") == "false_positive"

    def test_unknown_status_defaults_to_open(self):
        assert _map_jira_status_to_fixops("SomeWeirdStatus") == "open"

    def test_empty_string_defaults_to_open(self):
        assert _map_jira_status_to_fixops("") == "open"

    def test_case_sensitive_miss_defaults_to_open(self):
        # The map is case-sensitive — "done" != "Done"
        assert _map_jira_status_to_fixops("done") == "open"

    def test_returns_string(self):
        result = _map_jira_status_to_fixops("Done")
        assert isinstance(result, str)


# ===========================================================================
# 2. _map_servicenow_state_to_fixops — all branches
# ===========================================================================


class TestMapServiceNowStateToFixops:
    def test_state_1_maps_to_open(self):
        assert _map_servicenow_state_to_fixops("1") == "open"

    def test_state_2_maps_to_in_progress(self):
        assert _map_servicenow_state_to_fixops("2") == "in_progress"

    def test_state_3_maps_to_in_progress(self):
        assert _map_servicenow_state_to_fixops("3") == "in_progress"

    def test_state_4_maps_to_in_progress(self):
        assert _map_servicenow_state_to_fixops("4") == "in_progress"

    def test_state_5_maps_to_in_progress(self):
        assert _map_servicenow_state_to_fixops("5") == "in_progress"

    def test_state_6_maps_to_resolved(self):
        assert _map_servicenow_state_to_fixops("6") == "resolved"

    def test_state_7_maps_to_resolved(self):
        assert _map_servicenow_state_to_fixops("7") == "resolved"

    def test_state_8_maps_to_accepted_risk(self):
        assert _map_servicenow_state_to_fixops("8") == "accepted_risk"

    def test_unknown_state_defaults_to_open(self):
        assert _map_servicenow_state_to_fixops("99") == "open"

    def test_empty_state_defaults_to_open(self):
        assert _map_servicenow_state_to_fixops("") == "open"

    def test_integer_like_input_not_matched(self):
        # Only string keys are in the map; integer would not match
        assert _map_servicenow_state_to_fixops("0") == "open"


# ===========================================================================
# 3. _map_gitlab_state_to_fixops
# ===========================================================================


class TestMapGitlabStateToFixops:
    def test_opened_maps_to_open(self):
        assert _map_gitlab_state_to_fixops("opened") == "open"

    def test_closed_maps_to_resolved(self):
        assert _map_gitlab_state_to_fixops("closed") == "resolved"

    def test_reopened_maps_to_open(self):
        assert _map_gitlab_state_to_fixops("reopened") == "open"

    def test_merged_maps_to_resolved(self):
        assert _map_gitlab_state_to_fixops("merged") == "resolved"

    def test_uppercase_opened_maps_to_open(self):
        # The function uses .lower() before lookup
        assert _map_gitlab_state_to_fixops("OPENED") == "open"

    def test_mixed_case_closed_maps_to_resolved(self):
        assert _map_gitlab_state_to_fixops("Closed") == "resolved"

    def test_unknown_state_defaults_to_open(self):
        assert _map_gitlab_state_to_fixops("unknown_state") == "open"


# ===========================================================================
# 4. _map_azure_state_to_fixops
# ===========================================================================


class TestMapAzureStateToFixops:
    def test_new_maps_to_open(self):
        assert _map_azure_state_to_fixops("new") == "open"

    def test_active_maps_to_in_progress(self):
        assert _map_azure_state_to_fixops("active") == "in_progress"

    def test_resolved_maps_to_resolved(self):
        assert _map_azure_state_to_fixops("resolved") == "resolved"

    def test_closed_maps_to_resolved(self):
        assert _map_azure_state_to_fixops("closed") == "resolved"

    def test_removed_maps_to_false_positive(self):
        assert _map_azure_state_to_fixops("removed") == "false_positive"

    def test_done_maps_to_resolved(self):
        assert _map_azure_state_to_fixops("done") == "resolved"

    def test_to_do_maps_to_open(self):
        assert _map_azure_state_to_fixops("to do") == "open"

    def test_doing_maps_to_in_progress(self):
        assert _map_azure_state_to_fixops("doing") == "in_progress"

    def test_uppercase_handled_via_lower(self):
        assert _map_azure_state_to_fixops("ACTIVE") == "in_progress"

    def test_unknown_state_defaults_to_open(self):
        assert _map_azure_state_to_fixops("bogus") == "open"


# ===========================================================================
# 5. _map_gitlab_labels_to_status
# ===========================================================================


class TestMapGitlabLabelsToStatus:
    def test_in_progress_label(self):
        labels = [{"title": "in progress"}]
        assert _map_gitlab_labels_to_status(labels) == "in_progress"

    def test_in_progress_hyphenated(self):
        labels = [{"title": "in-progress"}]
        assert _map_gitlab_labels_to_status(labels) == "in_progress"

    def test_wip_label(self):
        labels = [{"title": "wip"}]
        assert _map_gitlab_labels_to_status(labels) == "in_progress"

    def test_wont_fix_label(self):
        labels = [{"title": "won't fix"}]
        assert _map_gitlab_labels_to_status(labels) == "accepted_risk"

    def test_wontfix_label(self):
        labels = [{"title": "wontfix"}]
        assert _map_gitlab_labels_to_status(labels) == "accepted_risk"

    def test_false_positive_label(self):
        labels = [{"title": "false positive"}]
        assert _map_gitlab_labels_to_status(labels) == "false_positive"

    def test_duplicate_label(self):
        labels = [{"title": "duplicate"}]
        assert _map_gitlab_labels_to_status(labels) == "false_positive"

    def test_case_insensitive_label_match(self):
        labels = [{"title": "WIP"}]
        assert _map_gitlab_labels_to_status(labels) == "in_progress"

    def test_unknown_label_returns_none(self):
        labels = [{"title": "priority::high"}]
        assert _map_gitlab_labels_to_status(labels) is None

    def test_empty_labels_returns_none(self):
        assert _map_gitlab_labels_to_status([]) is None

    def test_first_matching_label_wins(self):
        labels = [{"title": "wip"}, {"title": "duplicate"}]
        # "wip" is first and matches
        assert _map_gitlab_labels_to_status(labels) == "in_progress"

    def test_label_without_title_key_skipped(self):
        labels = [{"name": "wip"}, {"title": "duplicate"}]
        # First label has no 'title' key — empty string, no match
        assert _map_gitlab_labels_to_status(labels) == "false_positive"


# ===========================================================================
# 6. _verify_jira_signature — HMAC-SHA256
# ===========================================================================


class TestVerifyJiraSignature:
    def _make_signature(self, payload: bytes, secret: str) -> str:
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        return f"sha256={expected}"

    def test_valid_signature_returns_true(self):
        payload = b'{"webhookEvent":"jira:issue_updated"}'
        secret = "my-secret-key"
        sig = self._make_signature(payload, secret)
        assert _verify_jira_signature(payload, sig, secret) is True

    def test_wrong_secret_returns_false(self):
        payload = b'{"webhookEvent":"jira:issue_updated"}'
        sig = self._make_signature(payload, "correct-secret")
        assert _verify_jira_signature(payload, sig, "wrong-secret") is False

    def test_tampered_payload_returns_false(self):
        payload = b'{"webhookEvent":"jira:issue_updated"}'
        sig = self._make_signature(payload, "secret")
        tampered = b'{"webhookEvent":"jira:issue_deleted"}'
        assert _verify_jira_signature(tampered, sig, "secret") is False

    def test_missing_sha256_prefix_returns_false(self):
        payload = b"hello"
        secret = "secret"
        raw_hex = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        # No "sha256=" prefix — compare_digest will not match
        assert _verify_jira_signature(payload, raw_hex, secret) is False

    def test_empty_payload_with_correct_sig(self):
        payload = b""
        secret = "s3cr3t"
        sig = self._make_signature(payload, secret)
        assert _verify_jira_signature(payload, sig, secret) is True

    def test_returns_bool(self):
        result = _verify_jira_signature(b"test", "sha256=bad", "secret")
        assert isinstance(result, bool)


# ===========================================================================
# 7. Secret getter functions — env var based
# ===========================================================================


class TestSecretGetters:
    def test_jira_secret_returns_none_when_env_not_set(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FIXOPS_JIRA_WEBHOOK_SECRET", None)
            assert _get_jira_webhook_secret() is None

    def test_jira_secret_returns_value_from_env(self):
        with patch.dict(os.environ, {"FIXOPS_JIRA_WEBHOOK_SECRET": "jira-secret-xyz"}):
            assert _get_jira_webhook_secret() == "jira-secret-xyz"

    def test_servicenow_secret_returns_none_when_env_not_set(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FIXOPS_SERVICENOW_WEBHOOK_SECRET", None)
            assert _get_servicenow_webhook_secret() is None

    def test_servicenow_secret_returns_value_from_env(self):
        with patch.dict(os.environ, {"FIXOPS_SERVICENOW_WEBHOOK_SECRET": "snow-secret"}):
            assert _get_servicenow_webhook_secret() == "snow-secret"

    def test_azure_devops_secret_returns_none_when_env_not_set(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FIXOPS_AZURE_DEVOPS_WEBHOOK_SECRET", None)
            assert _get_azure_devops_webhook_secret() is None

    def test_azure_devops_secret_returns_value_from_env(self):
        with patch.dict(
            os.environ, {"FIXOPS_AZURE_DEVOPS_WEBHOOK_SECRET": "azure-secret"}
        ):
            assert _get_azure_devops_webhook_secret() == "azure-secret"

    def test_gitlab_secret_returns_none_when_env_not_set(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FIXOPS_GITLAB_WEBHOOK_SECRET", None)
            assert _get_gitlab_webhook_secret() is None

    def test_gitlab_secret_returns_value_from_env(self):
        with patch.dict(os.environ, {"FIXOPS_GITLAB_WEBHOOK_SECRET": "gl-token"}):
            assert _get_gitlab_webhook_secret() == "gl-token"


# ===========================================================================
# 8. _init_db — tables and schema verification
# ===========================================================================


class TestInitDb:
    def test_all_four_tables_exist(self, isolated_db):
        conn = sqlite3.connect(str(isolated_db))
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()

        assert "integration_mappings" in tables
        assert "webhook_events" in tables
        assert "sync_drift" in tables
        assert "outbox" in tables

    def test_integration_mappings_columns(self, isolated_db):
        conn = sqlite3.connect(str(isolated_db))
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(integration_mappings)")
        cols = {row[1] for row in cursor.fetchall()}
        conn.close()

        expected = {
            "mapping_id", "cluster_id", "integration_type", "external_id",
            "external_url", "external_status", "fixops_status",
            "last_synced", "sync_direction", "created_at",
        }
        assert expected.issubset(cols)

    def test_webhook_events_columns(self, isolated_db):
        conn = sqlite3.connect(str(isolated_db))
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(webhook_events)")
        cols = {row[1] for row in cursor.fetchall()}
        conn.close()

        expected = {
            "event_id", "integration_type", "event_type", "external_id",
            "payload", "processed", "processed_at", "error", "created_at",
        }
        assert expected.issubset(cols)

    def test_sync_drift_columns(self, isolated_db):
        conn = sqlite3.connect(str(isolated_db))
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(sync_drift)")
        cols = {row[1] for row in cursor.fetchall()}
        conn.close()

        expected = {
            "drift_id", "mapping_id", "fixops_status", "external_status",
            "detected_at", "resolved", "resolved_at", "resolution",
        }
        assert expected.issubset(cols)

    def test_outbox_columns(self, isolated_db):
        conn = sqlite3.connect(str(isolated_db))
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(outbox)")
        cols = {row[1] for row in cursor.fetchall()}
        conn.close()

        expected = {
            "outbox_id", "integration_type", "operation", "cluster_id",
            "external_id", "payload", "status", "retry_count", "max_retries",
            "next_retry_at", "last_error", "created_at", "processed_at",
        }
        assert expected.issubset(cols)

    def test_indexes_created(self, isolated_db):
        conn = sqlite3.connect(str(isolated_db))
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='index' ORDER BY name"
        )
        indexes = {row[0] for row in cursor.fetchall()}
        conn.close()

        assert "idx_mappings_cluster" in indexes
        assert "idx_mappings_external" in indexes
        assert "idx_events_processed" in indexes
        assert "idx_outbox_status" in indexes

    def test_idempotent_reinit_does_not_raise(self, isolated_db):
        # Calling _init_db() twice on same path should not raise
        _init_db()
        _init_db()


# ===========================================================================
# 9. _get_db_path — path resolution
# ===========================================================================


class TestGetDbPath:
    def test_returns_currently_set_db_path(self, isolated_db):
        # isolated_db fixture sets webhooks_router._db_path to isolated_db
        result = _get_db_path()
        assert result == isolated_db

    def test_returns_path_object(self, isolated_db):
        result = _get_db_path()
        assert isinstance(result, Path)


# ===========================================================================
# 10. _detect_drift — core logic
# ===========================================================================


class TestDetectDrift:
    def test_drift_detected_when_statuses_differ(self, isolated_db):
        mapping_id = _insert_mapping(
            isolated_db,
            cluster_id="cluster-1",
            integration_type="jira",
            external_id="PROJ-1",
            fixops_status="open",
            external_status="resolved",
        )
        drift_id = _detect_drift(mapping_id, "open", "resolved")

        assert drift_id is not None
        assert isinstance(drift_id, str)
        # Must be a UUID4
        uuid.UUID(drift_id, version=4)

    def test_no_drift_when_statuses_same(self, isolated_db):
        mapping_id = _insert_mapping(
            isolated_db,
            cluster_id="cluster-2",
            integration_type="jira",
            external_id="PROJ-2",
            fixops_status="resolved",
        )
        drift_id = _detect_drift(mapping_id, "resolved", "resolved")
        assert drift_id is None

    def test_drift_row_written_to_db(self, isolated_db):
        mapping_id = _insert_mapping(
            isolated_db,
            cluster_id="cluster-3",
            integration_type="jira",
            external_id="PROJ-3",
        )
        drift_id = _detect_drift(mapping_id, "open", "in_progress")

        conn = sqlite3.connect(str(isolated_db))
        row = conn.execute(
            "SELECT * FROM sync_drift WHERE drift_id = ?", (drift_id,)
        ).fetchone()
        conn.close()

        assert row is not None
        assert row[1] == mapping_id     # mapping_id column
        assert row[2] == "open"          # fixops_status column
        assert row[3] == "in_progress"   # external_status column

    def test_drift_resolved_defaults_to_false(self, isolated_db):
        mapping_id = _insert_mapping(
            isolated_db,
            cluster_id="cluster-4",
            integration_type="servicenow",
            external_id="INC001",
        )
        drift_id = _detect_drift(mapping_id, "open", "resolved")

        conn = sqlite3.connect(str(isolated_db))
        row = conn.execute(
            "SELECT resolved FROM sync_drift WHERE drift_id = ?", (drift_id,)
        ).fetchone()
        conn.close()

        assert row[0] == 0  # False in SQLite

    def test_multiple_drifts_for_same_mapping(self, isolated_db):
        mapping_id = _insert_mapping(
            isolated_db,
            cluster_id="cluster-5",
            integration_type="jira",
            external_id="PROJ-5",
        )
        id1 = _detect_drift(mapping_id, "open", "resolved")
        id2 = _detect_drift(mapping_id, "in_progress", "resolved")

        assert id1 != id2
        assert id1 is not None
        assert id2 is not None


# ===========================================================================
# 11. Pydantic model validation
# ===========================================================================


class TestJiraWebhookPayload:
    def test_valid_minimal_payload(self):
        p = JiraWebhookPayload(webhookEvent="jira:issue_created")
        assert p.webhookEvent == "jira:issue_created"
        assert p.issue is None
        assert p.changelog is None
        assert p.user is None

    def test_payload_with_issue(self):
        p = JiraWebhookPayload(
            webhookEvent="jira:issue_updated",
            issue={"key": "PROJ-42", "fields": {"status": {"name": "Done"}}},
        )
        assert p.issue["key"] == "PROJ-42"

    def test_payload_with_changelog(self):
        p = JiraWebhookPayload(
            webhookEvent="jira:issue_updated",
            changelog={"items": [{"field": "status"}]},
        )
        assert p.changelog["items"][0]["field"] == "status"

    def test_missing_webhook_event_raises(self):
        with pytest.raises(Exception):
            JiraWebhookPayload()

    def test_model_dump_round_trip(self):
        p = JiraWebhookPayload(
            webhookEvent="jira:issue_created",
            issue={"key": "X-1"},
        )
        d = p.model_dump()
        assert d["webhookEvent"] == "jira:issue_created"
        assert d["issue"]["key"] == "X-1"


class TestServiceNowWebhookPayload:
    def test_valid_minimal_payload(self):
        p = ServiceNowWebhookPayload(event_type="create", sys_id="abc123")
        assert p.event_type == "create"
        assert p.sys_id == "abc123"

    def test_all_fields(self):
        p = ServiceNowWebhookPayload(
            event_type="update",
            sys_id="def456",
            number="INC0001234",
            state="2",
            assignment_group="IT Security",
            assigned_to="jdoe",
            short_description="CVE detected",
            additional_info={"priority": "1"},
        )
        assert p.number == "INC0001234"
        assert p.state == "2"
        assert p.additional_info["priority"] == "1"

    def test_missing_required_fields_raises(self):
        with pytest.raises(Exception):
            ServiceNowWebhookPayload(event_type="create")  # missing sys_id

    def test_missing_event_type_raises(self):
        with pytest.raises(Exception):
            ServiceNowWebhookPayload(sys_id="abc")  # missing event_type


class TestCreateMappingRequest:
    def test_valid_minimal(self):
        r = CreateMappingRequest(
            cluster_id="clu-1",
            integration_type="jira",
            external_id="PROJ-1",
        )
        assert r.cluster_id == "clu-1"
        assert r.external_url is None
        assert r.external_status is None

    def test_full_fields(self):
        r = CreateMappingRequest(
            cluster_id="clu-2",
            integration_type="servicenow",
            external_id="INC002",
            external_url="https://example.service-now.com/INC002",
            external_status="open",
        )
        assert r.external_url == "https://example.service-now.com/INC002"
        assert r.external_status == "open"

    def test_missing_required_fields_raises(self):
        with pytest.raises(Exception):
            CreateMappingRequest(cluster_id="x")  # missing integration_type, external_id


class TestDriftResolutionRequest:
    def test_valid_minimal(self):
        r = DriftResolutionRequest(resolution="manual_review")
        assert r.resolution == "manual_review"
        assert r.apply_fixops_status is False
        assert r.apply_external_status is False

    def test_apply_fixops_status_true(self):
        r = DriftResolutionRequest(
            resolution="accept_fixops", apply_fixops_status=True
        )
        assert r.apply_fixops_status is True
        assert r.apply_external_status is False

    def test_apply_external_status_true(self):
        r = DriftResolutionRequest(
            resolution="accept_external", apply_external_status=True
        )
        assert r.apply_external_status is True

    def test_missing_resolution_raises(self):
        with pytest.raises(Exception):
            DriftResolutionRequest()


class TestOutboxRequest:
    def test_valid_minimal(self):
        r = OutboxRequest(
            integration_type="jira",
            operation="create_issue",
            payload={"title": "Bug"},
        )
        assert r.integration_type == "jira"
        assert r.max_retries == 3

    def test_custom_max_retries(self):
        r = OutboxRequest(
            integration_type="gitlab",
            operation="update_issue",
            payload={},
            max_retries=5,
        )
        assert r.max_retries == 5

    def test_optional_cluster_and_external_id(self):
        r = OutboxRequest(
            integration_type="servicenow",
            operation="close_ticket",
            cluster_id="c1",
            external_id="INC-99",
            payload={"state": "6"},
        )
        assert r.cluster_id == "c1"
        assert r.external_id == "INC-99"


class TestGitLabWebhookPayload:
    def test_valid_issue_event(self):
        p = GitLabWebhookPayload(object_kind="issue")
        assert p.object_kind == "issue"
        assert p.labels is None

    def test_full_payload(self):
        p = GitLabWebhookPayload(
            object_kind="issue",
            event_type="update",
            object_attributes={"iid": 5, "state": "closed"},
            project={"id": 100, "name": "MyProject"},
            user={"id": 1, "name": "Alice"},
            labels=[{"title": "bug"}, {"title": "wip"}],
        )
        assert p.object_attributes["iid"] == 5
        assert len(p.labels) == 2

    def test_missing_object_kind_raises(self):
        with pytest.raises(Exception):
            GitLabWebhookPayload()


class TestAzureDevOpsWebhookPayload:
    def test_valid_minimal(self):
        p = AzureDevOpsWebhookPayload(eventType="workitem.updated")
        assert p.eventType == "workitem.updated"
        assert p.resource is None

    def test_full_payload(self):
        p = AzureDevOpsWebhookPayload(
            subscriptionId="sub-abc",
            notificationId=42,
            eventType="workitem.created",
            resource={
                "id": 123,
                "fields": {
                    "System.State": "Active",
                    "System.TeamProject": "MyProject",
                },
            },
            resourceVersion="1.0",
        )
        assert p.resource["id"] == 123
        assert p.notificationId == 42

    def test_missing_event_type_raises(self):
        with pytest.raises(Exception):
            AzureDevOpsWebhookPayload(subscriptionId="x")


class TestCreateWorkItemRequest:
    def test_defaults(self):
        r = CreateWorkItemRequest()
        assert r.cluster_id == "default-cluster"
        assert r.integration_type == "jira"
        assert r.title == "Untitled Work Item"

    def test_custom_values(self):
        r = CreateWorkItemRequest(
            cluster_id="c-99",
            integration_type="gitlab",
            title="SQL Injection CVE",
            description="Critical vulnerability",
            severity="critical",
            labels=["security"],
            assignee="alice",
            project_id="proj-1",
        )
        assert r.title == "SQL Injection CVE"
        assert r.severity == "critical"
        assert r.labels == ["security"]

    def test_invalid_integration_type_raises(self):
        with pytest.raises(Exception):
            CreateWorkItemRequest(integration_type="slack")  # not in Literal


# ===========================================================================
# 12. _calculate_next_retry — exponential backoff
# ===========================================================================


class TestCalculateNextRetry:
    def test_first_retry_delay(self):
        from datetime import datetime, timezone

        result = _calculate_next_retry(0)
        # retry_count=0 -> delay = 60 * (2^0) = 60 seconds
        now = datetime.now(timezone.utc)
        # The result should be a parseable ISO string approx 60s from now
        result_dt = datetime.fromisoformat(result)
        delta = result_dt - now
        assert 55 <= delta.total_seconds() <= 65

    def test_second_retry_delay(self):
        from datetime import datetime, timezone

        result = _calculate_next_retry(1)
        # retry_count=1 -> delay = 60 * (2^1) = 120 seconds
        now = datetime.now(timezone.utc)
        result_dt = datetime.fromisoformat(result)
        delta = result_dt - now
        assert 115 <= delta.total_seconds() <= 125

    def test_max_delay_capped_at_3600(self):
        from datetime import datetime, timezone

        # retry_count=10 -> 60*(2^10) = 61440 -> capped at 3600
        result = _calculate_next_retry(10)
        now = datetime.now(timezone.utc)
        result_dt = datetime.fromisoformat(result)
        delta = result_dt - now
        assert 3595 <= delta.total_seconds() <= 3605

    def test_returns_iso_format_string(self):
        result = _calculate_next_retry(0)
        assert isinstance(result, str)
        # Must be parseable as ISO datetime
        from datetime import datetime
        datetime.fromisoformat(result)


# ===========================================================================
# 13. _get_connector_settings — env var driven
# ===========================================================================


class TestGetConnectorSettings:
    def test_empty_settings_when_no_env_vars(self):
        env_keys = [
            "FIXOPS_JIRA_URL", "FIXOPS_SERVICENOW_URL", "FIXOPS_GITLAB_URL",
            "FIXOPS_GITHUB_OWNER", "FIXOPS_AZURE_DEVOPS_ORG",
            "FIXOPS_SLACK_WEBHOOK_URL", "FIXOPS_CONFLUENCE_URL",
        ]
        clean_env = {k: v for k, v in os.environ.items() if k not in env_keys}
        with patch.dict(os.environ, clean_env, clear=True):
            result = _get_connector_settings()
        assert result == {}

    def test_jira_settings_populated(self):
        with patch.dict(os.environ, {
            "FIXOPS_JIRA_URL": "https://jira.example.com",
            "FIXOPS_JIRA_USER": "admin",
            "FIXOPS_JIRA_PROJECT_KEY": "SEC",
        }):
            result = _get_connector_settings()
        assert "jira" in result
        assert result["jira"]["url"] == "https://jira.example.com"
        assert result["jira"]["project_key"] == "SEC"

    def test_servicenow_settings_populated(self):
        with patch.dict(os.environ, {
            "FIXOPS_SERVICENOW_URL": "https://snow.example.com",
            "FIXOPS_SERVICENOW_USER": "svcuser",
        }):
            result = _get_connector_settings()
        assert "servicenow" in result
        assert result["servicenow"]["instance_url"] == "https://snow.example.com"

    def test_gitlab_settings_populated(self):
        with patch.dict(os.environ, {
            "FIXOPS_GITLAB_URL": "https://gitlab.example.com",
            "FIXOPS_GITLAB_PROJECT_ID": "42",
        }):
            result = _get_connector_settings()
        assert "gitlab" in result
        assert result["gitlab"]["project_id"] == "42"

    def test_github_settings_populated(self):
        with patch.dict(os.environ, {
            "FIXOPS_GITHUB_OWNER": "myorg",
            "FIXOPS_GITHUB_REPO": "myrepo",
        }):
            result = _get_connector_settings()
        assert "github" in result
        assert result["github"]["owner"] == "myorg"
        assert result["github"]["repo"] == "myrepo"

    def test_azure_devops_settings_populated(self):
        with patch.dict(os.environ, {
            "FIXOPS_AZURE_DEVOPS_ORG": "myorg",
            "FIXOPS_AZURE_DEVOPS_PROJECT": "MyProject",
        }):
            result = _get_connector_settings()
        assert "azure_devops" in result
        assert result["azure_devops"]["organization"] == "myorg"

    def test_slack_settings_populated(self):
        with patch.dict(os.environ, {
            "FIXOPS_SLACK_WEBHOOK_URL": "https://hooks.slack.com/T01/xxx",
        }):
            result = _get_connector_settings()
        assert "policy_automation" in result
        assert result["policy_automation"]["webhook_url"].startswith("https://")

    def test_confluence_settings_populated(self):
        with patch.dict(os.environ, {
            "FIXOPS_CONFLUENCE_URL": "https://confluence.example.com",
            "FIXOPS_CONFLUENCE_USER": "user",
            "FIXOPS_CONFLUENCE_SPACE_KEY": "ENG",
        }):
            result = _get_connector_settings()
        assert "confluence" in result
        assert result["confluence"]["space_key"] == "ENG"

    def test_multiple_integrations_together(self):
        with patch.dict(os.environ, {
            "FIXOPS_JIRA_URL": "https://jira.example.com",
            "FIXOPS_GITLAB_URL": "https://gitlab.example.com",
            "FIXOPS_GITLAB_PROJECT_ID": "1",
        }):
            result = _get_connector_settings()
        assert "jira" in result
        assert "gitlab" in result


# ===========================================================================
# 14. Integration: database CRUD — create mapping, then detect drift
# ===========================================================================


class TestDatabaseIntegration:
    def test_mapping_unique_constraint(self, isolated_db):
        """Same cluster_id + integration_type must be rejected on second insert."""
        mapping_id = _insert_mapping(
            isolated_db,
            cluster_id="unique-cluster",
            integration_type="jira",
            external_id="PROJ-99",
        )
        assert mapping_id

        with pytest.raises(sqlite3.IntegrityError):
            _insert_mapping(
                isolated_db,
                cluster_id="unique-cluster",
                integration_type="jira",
                external_id="PROJ-100",  # same cluster+type, different external_id
            )

    def test_drift_detection_full_cycle(self, isolated_db):
        """Insert mapping, detect drift, verify DB state."""
        mapping_id = _insert_mapping(
            isolated_db,
            cluster_id="cycle-cluster",
            integration_type="servicenow",
            external_id="INC-CYCLE",
            fixops_status="open",
        )

        drift_id = _detect_drift(mapping_id, "open", "in_progress")
        assert drift_id is not None

        conn = sqlite3.connect(str(isolated_db))
        row = conn.execute(
            "SELECT mapping_id, fixops_status, external_status, resolved "
            "FROM sync_drift WHERE drift_id = ?",
            (drift_id,),
        ).fetchone()
        conn.close()

        assert row[0] == mapping_id
        assert row[1] == "open"
        assert row[2] == "in_progress"
        assert row[3] == 0  # not resolved

    def test_no_drift_for_equal_statuses_leaves_table_empty(self, isolated_db):
        mapping_id = _insert_mapping(
            isolated_db,
            cluster_id="nodrift-cluster",
            integration_type="jira",
            external_id="PROJ-NODRIFT",
            fixops_status="resolved",
        )

        result = _detect_drift(mapping_id, "resolved", "resolved")
        assert result is None

        conn = sqlite3.connect(str(isolated_db))
        count = conn.execute("SELECT COUNT(*) FROM sync_drift").fetchone()[0]
        conn.close()

        assert count == 0

    def test_webhook_events_table_accepts_insert(self, isolated_db):
        event_id = str(uuid.uuid4())
        now = "2024-06-01T12:00:00+00:00"
        conn = sqlite3.connect(str(isolated_db))
        conn.execute(
            """
            INSERT INTO webhook_events (
                event_id, integration_type, event_type, payload, created_at
            ) VALUES (?,?,?,?,?)
            """,
            (event_id, "jira", "jira:issue_created", '{"test": 1}', now),
        )
        conn.commit()
        row = conn.execute(
            "SELECT event_id, processed FROM webhook_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        conn.close()

        assert row[0] == event_id
        assert row[1] == 0  # processed defaults to FALSE

    def test_outbox_table_accepts_insert(self, isolated_db):
        outbox_id = str(uuid.uuid4())
        now = "2024-06-01T12:00:00+00:00"
        conn = sqlite3.connect(str(isolated_db))
        conn.execute(
            """
            INSERT INTO outbox (
                outbox_id, integration_type, operation, payload, status, created_at
            ) VALUES (?,?,?,?,?,?)
            """,
            (outbox_id, "jira", "create_issue", '{}', "pending", now),
        )
        conn.commit()
        row = conn.execute(
            "SELECT outbox_id, retry_count, max_retries FROM outbox WHERE outbox_id = ?",
            (outbox_id,),
        ).fetchone()
        conn.close()

        assert row[0] == outbox_id
        assert row[1] == 0    # retry_count default
        assert row[2] == 3    # max_retries default
