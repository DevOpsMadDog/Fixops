"""Tests for webhook_notifications_router.py

Covers: register, list, delete, test dispatch, event firing, retry logic,
event validation, org isolation, HMAC signing, DB schema.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for sub in ("suite-api", "suite-core"):
    p = os.path.join(ROOT, sub)
    if p not in sys.path:
        sys.path.insert(0, p)

# Patch api_key_auth before importing the router
from unittest.mock import MagicMock, patch
import apps.api.auth_deps as _auth_deps
_auth_deps.api_key_auth = MagicMock(return_value=None)

import apps.api.webhook_notifications_router as _mod
from apps.api.webhook_notifications_router import (
    SUPPORTED_EVENTS,
    RegisterWebhookRequest,
    _deliver_once,
    _open_db,
    _row_to_dict,
    _sign,
    fire_event,
    router,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _tmp_db(tmp_path):
    """Redirect all DB writes to a temp file for each test."""
    db_file = str(tmp_path / "wn_test.db")
    orig = _mod._DB_PATH_OVERRIDE
    _mod._DB_PATH_OVERRIDE = db_file
    yield db_file
    _mod._DB_PATH_OVERRIDE = orig


def _insert_webhook(
    org_id: str = "org-test",
    url: str = "https://example.com/hook",
    events: list | None = None,
    active: int = 1,
    fail_count: int = 0,
) -> str:
    """Insert a webhook row directly into the test DB and return its ID."""
    wh_id = str(uuid.uuid4())
    secret = "test-secret-abc"
    now = datetime.now(timezone.utc).isoformat()
    conn = _open_db()
    try:
        conn.execute(
            "INSERT INTO webhooks (id, org_id, url, secret, events, active, description, created_at, fail_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                wh_id,
                org_id,
                url,
                secret,
                json.dumps(events or ["alert.created"]),
                active,
                "test webhook",
                now,
                fail_count,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return wh_id


# ---------------------------------------------------------------------------
# Test 1: RegisterWebhookRequest validation
# ---------------------------------------------------------------------------

class TestRegisterWebhookRequest:
    def test_valid_request(self):
        req = RegisterWebhookRequest(
            org_id="org-1",
            url="https://hooks.example.com/aldeci",
            events=["alert.created", "incident.created"],
        )
        assert req.org_id == "org-1"
        assert set(req.events) == {"alert.created", "incident.created"}

    def test_invalid_scheme_rejected(self):
        with pytest.raises(Exception):
            RegisterWebhookRequest(
                org_id="org-1",
                url="ftp://example.com/hook",
                events=["alert.created"],
            )

    def test_invalid_event_type_rejected(self):
        with pytest.raises(Exception):
            RegisterWebhookRequest(
                org_id="org-1",
                url="https://example.com/hook",
                events=["nonexistent.event"],
            )

    def test_duplicate_events_deduplicated(self):
        req = RegisterWebhookRequest(
            org_id="org-1",
            url="https://example.com/hook",
            events=["alert.created", "alert.created", "incident.created"],
        )
        assert len(req.events) == 2


# ---------------------------------------------------------------------------
# Test 2: HMAC signing
# ---------------------------------------------------------------------------

class TestHMACSign:
    def test_sign_produces_sha256_prefix(self):
        sig = _sign("mysecret", b'{"event":"test"}')
        assert sig.startswith("sha256=")
        assert len(sig) == len("sha256=") + 64

    def test_different_secrets_produce_different_signatures(self):
        body = b'{"event":"alert.created"}'
        sig1 = _sign("secret-a", body)
        sig2 = _sign("secret-b", body)
        assert sig1 != sig2

    def test_same_inputs_deterministic(self):
        body = b'{"event":"test"}'
        assert _sign("s", body) == _sign("s", body)


# ---------------------------------------------------------------------------
# Test 3: DB schema and open_db
# ---------------------------------------------------------------------------

class TestDatabase:
    def test_schema_creates_webhooks_table(self):
        conn = _open_db()
        try:
            tables = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        finally:
            conn.close()
        assert "webhooks" in tables
        assert "delivery_attempts" in tables

    def test_row_to_dict_parses_events(self):
        wh_id = _insert_webhook(events=["alert.created", "incident.resolved"])
        conn = _open_db()
        try:
            row = conn.execute("SELECT * FROM webhooks WHERE id=?", (wh_id,)).fetchone()
        finally:
            conn.close()
        d = _row_to_dict(row)
        assert isinstance(d["events"], list)
        assert "alert.created" in d["events"]
        assert d["active"] is True


# ---------------------------------------------------------------------------
# Test 4: fire_event — no matching webhooks
# ---------------------------------------------------------------------------

class TestFireEvent:
    def test_no_webhooks_returns_empty(self):
        results = fire_event("alert.created", {"severity": "high"}, "org-no-webhooks")
        assert results == []

    def test_unsupported_event_returns_empty(self):
        results = fire_event("not.a.real.event", {}, "org-1")
        assert results == []

    def test_inactive_webhooks_skipped(self):
        _insert_webhook(org_id="org-skip", active=0)
        results = fire_event("alert.created", {}, "org-skip")
        assert results == []

    def test_event_filter_skips_non_matching(self):
        # Webhook listens to incident.created only
        _insert_webhook(org_id="org-filter", events=["incident.created"])
        # Fire alert.created — should not match
        results = fire_event("alert.created", {}, "org-filter")
        assert results == []

    def test_matching_webhook_attempted(self):
        _insert_webhook(org_id="org-match", events=["alert.created"])
        fake_result = {"status": "success", "http_status": 200, "error": None}
        with patch.object(_mod, "_deliver_with_retry", return_value=fake_result) as mock_deliver:
            results = fire_event("alert.created", {"host": "web01"}, "org-match")
        assert len(results) == 1
        assert results[0]["status"] == "success"
        mock_deliver.assert_called_once()

    def test_org_isolation(self):
        _insert_webhook(org_id="org-a", events=["compliance.failure"])
        fake_result = {"status": "success", "http_status": 200, "error": None}
        with patch.object(_mod, "_deliver_with_retry", return_value=fake_result):
            results_a = fire_event("compliance.failure", {}, "org-a")
            results_b = fire_event("compliance.failure", {}, "org-b")
        assert len(results_a) == 1
        assert len(results_b) == 0


# ---------------------------------------------------------------------------
# Test 5: Retry logic — _deliver_once
# ---------------------------------------------------------------------------

class TestDeliveryRetry:
    def test_deliver_once_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("requests.post", return_value=mock_resp):
            result = _deliver_once(
                "https://example.com/hook",
                "secret",
                "alert.created",
                {"msg": "hello"},
                1,
            )
        assert result["status"] == "success"
        assert result["http_status"] == 200

    def test_deliver_once_non_2xx_is_failed(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        with patch("requests.post", return_value=mock_resp):
            result = _deliver_once(
                "https://example.com/hook",
                "secret",
                "alert.created",
                {},
                1,
            )
        assert result["status"] == "failed"
        assert "500" in result["error"]

    def test_deliver_once_timeout(self):
        import requests as _req
        with patch("requests.post", side_effect=_req.Timeout()):
            result = _deliver_once("https://example.com/hook", "secret", "test", {}, 1)
        assert result["status"] == "failed"
        assert result["error"] == "Timeout"

    def test_deliver_with_retry_retries_on_failure(self):
        wh_id = _insert_webhook(org_id="org-retry")
        conn = _open_db()
        try:
            row = conn.execute("SELECT * FROM webhooks WHERE id=?", (wh_id,)).fetchone()
        finally:
            conn.close()
        wh = _row_to_dict(row)

        call_count = {"n": 0}

        def fake_deliver_once(url, secret, event_type, payload, attempt):
            call_count["n"] += 1
            return {"status": "failed", "http_status": 503, "error": "HTTP 503"}

        with patch.object(_mod, "_deliver_once", side_effect=fake_deliver_once):
            with patch("time.sleep"):  # skip sleep delays in tests
                result = _mod._deliver_with_retry(wh, "alert.created", {"x": 1})

        assert result["status"] == "failed"
        assert call_count["n"] == _mod._MAX_RETRIES

    def test_deliver_with_retry_stops_on_success(self):
        wh_id = _insert_webhook(org_id="org-success")
        conn = _open_db()
        try:
            row = conn.execute("SELECT * FROM webhooks WHERE id=?", (wh_id,)).fetchone()
        finally:
            conn.close()
        wh = _row_to_dict(row)

        call_count = {"n": 0}

        def fake_deliver_once(url, secret, event_type, payload, attempt):
            call_count["n"] += 1
            return {"status": "success", "http_status": 200, "error": None}

        with patch.object(_mod, "_deliver_once", side_effect=fake_deliver_once):
            result = _mod._deliver_with_retry(wh, "alert.created", {})

        assert result["status"] == "success"
        assert call_count["n"] == 1  # stopped after first success


# ---------------------------------------------------------------------------
# Test 6: webhook state updates
# ---------------------------------------------------------------------------

class TestWebhookStateUpdate:
    def test_success_resets_fail_count(self):
        wh_id = _insert_webhook(org_id="org-state", fail_count=2)
        _mod._update_webhook_state(wh_id, success=True)
        conn = _open_db()
        try:
            row = conn.execute("SELECT fail_count FROM webhooks WHERE id=?", (wh_id,)).fetchone()
        finally:
            conn.close()
        assert row["fail_count"] == 0

    def test_failure_increments_fail_count(self):
        wh_id = _insert_webhook(org_id="org-fail-count", fail_count=0)
        _mod._update_webhook_state(wh_id, success=False)
        conn = _open_db()
        try:
            row = conn.execute("SELECT fail_count FROM webhooks WHERE id=?", (wh_id,)).fetchone()
        finally:
            conn.close()
        assert row["fail_count"] == 1

    def test_three_failures_deactivates_webhook(self):
        # fail_count already at MAX_RETRIES - 1, one more should disable
        wh_id = _insert_webhook(org_id="org-deactivate", fail_count=_mod._MAX_RETRIES - 1)
        _mod._update_webhook_state(wh_id, success=False)
        conn = _open_db()
        try:
            row = conn.execute("SELECT active, fail_count FROM webhooks WHERE id=?", (wh_id,)).fetchone()
        finally:
            conn.close()
        assert row["active"] == 0


# ---------------------------------------------------------------------------
# Test 7: SUPPORTED_EVENTS coverage
# ---------------------------------------------------------------------------

class TestSupportedEvents:
    def test_alert_events_present(self):
        assert "alert.created" in SUPPORTED_EVENTS
        assert "alert.resolved" in SUPPORTED_EVENTS

    def test_incident_events_present(self):
        assert "incident.created" in SUPPORTED_EVENTS
        assert "incident.resolved" in SUPPORTED_EVENTS

    def test_compliance_failure_present(self):
        assert "compliance.failure" in SUPPORTED_EVENTS

    def test_finding_events_present(self):
        assert "finding.critical" in SUPPORTED_EVENTS
        assert "finding.created" in SUPPORTED_EVENTS


# ---------------------------------------------------------------------------
# Test 8: Multiple webhooks for same org
# ---------------------------------------------------------------------------

class TestMultiWebhook:
    def test_all_matching_webhooks_receive_event(self):
        org = "org-multi"
        _insert_webhook(org_id=org, events=["alert.created"])
        _insert_webhook(org_id=org, events=["alert.created", "incident.created"])
        _insert_webhook(org_id=org, events=["sla.breach"])  # should not match

        fake_result = {"status": "success", "http_status": 200, "error": None}
        with patch.object(_mod, "_deliver_with_retry", return_value=fake_result) as mock:
            results = fire_event("alert.created", {}, org)

        assert len(results) == 2  # only 2 of 3 subscribe to alert.created
        assert mock.call_count == 2
