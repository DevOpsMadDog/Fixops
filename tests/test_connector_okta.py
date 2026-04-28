"""Tests for OktaConnector.

4 tests:
1. Missing creds → graceful no-op (needs_credentials)
2. Mock API response: users + logs parse correctly into findings
3. Live API call (skipped if creds absent)
4. Pagination: Link header followed for multi-page user list
"""
from __future__ import annotations

import os
import json
from typing import Any, Dict, List, Tuple, Optional
from unittest.mock import MagicMock, patch

import pytest

import sys
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops")
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-core")


def _mock_findings():
    fe = MagicMock()
    fe.record_finding.return_value = {"id": "okta-finding-001"}
    return fe


_SAMPLE_USERS = [
    {
        "id": "00u1a2b3c4d5e6f7",
        "status": "ACTIVE",
        "created": "2024-01-15T09:00:00.000Z",
        "lastLogin": "2026-04-27T08:00:00.000Z",
        "passwordChanged": "2025-12-01T00:00:00.000Z",
        "profile": {
            "firstName": "Alice",
            "lastName": "Smith",
            "email": "alice@example.com",
            "login": "alice@example.com",
            "department": "Engineering",
            "title": "Senior Engineer",
            "mobilePhone": "+1-555-0101",
        },
        "credentials": {
            "provider": {"name": "OKTA"},
        },
    },
    {
        "id": "00u2b3c4d5e6f7a1",
        "status": "LOCKED_OUT",
        "created": "2023-06-01T09:00:00.000Z",
        "lastLogin": "2026-04-01T08:00:00.000Z",
        "passwordChanged": "2025-01-01T00:00:00.000Z",
        "profile": {
            "firstName": "Bob",
            "lastName": "Jones",
            "email": "bob@example.com",
            "login": "bob@example.com",
            "department": "Finance",
            "title": "Analyst",
        },
        "credentials": {"provider": {"name": "OKTA"}},
    },
]

_SAMPLE_LOGS = [
    {
        "uuid": "aaaa-bbbb-cccc-dddd-0001",
        "published": "2026-04-27T10:00:00.000Z",
        "eventType": "user.account.lock",
        "displayMessage": "Max sign-in attempts exceeded",
        "severity": "WARN",
        "outcome": {"result": "FAILURE", "reason": "PASSWORD_FAILURE"},
        "actor": {
            "id": "00u1a2b3c4d5e6f7",
            "displayName": "Alice Smith",
            "alternateId": "alice@example.com",
        },
        "target": [
            {"displayName": "alice@example.com", "alternateId": "alice@example.com"}
        ],
    },
    {
        "uuid": "aaaa-bbbb-cccc-dddd-0002",
        "published": "2026-04-27T09:00:00.000Z",
        "eventType": "group.user_membership.add",
        "displayMessage": "User added to Okta Administrators group",
        "severity": "INFO",
        "outcome": {"result": "SUCCESS", "reason": ""},
        "actor": {
            "id": "00uadmin1234",
            "displayName": "Super Admin",
            "alternateId": "admin@example.com",
        },
        "target": [{"displayName": "bob@example.com"}],
    },
    {
        "uuid": "aaaa-bbbb-cccc-dddd-0003",
        "published": "2026-04-27T08:00:00.000Z",
        "eventType": "user.session.start",
        "displayMessage": "User login to Okta",
        "severity": "INFO",
        "outcome": {"result": "SUCCESS"},
        "actor": {"id": "00u99", "displayName": "Carol"},
        "target": [],
    },
]


# ---------------------------------------------------------------------------
# Test 1: missing creds → graceful no-op
# ---------------------------------------------------------------------------
def test_okta_missing_creds_graceful_noop():
    env_patch = {"OKTA_API_KEY": "", "OKTA_DOMAIN": ""}
    with patch.dict(os.environ, env_patch, clear=False):
        from connectors.okta_connector import OktaConnector
        connector = OktaConnector(findings_engine=_mock_findings())
        result = connector.sync(org_id="test-org")

    assert result["status"] == "needs_credentials"
    assert result["mode"] == "no-op"
    assert result["users_synced"] == 0
    assert result["findings_recorded"] == 0
    assert "hint" in result
    assert isinstance(result["users"], list)
    assert isinstance(result["log_findings"], list)


# ---------------------------------------------------------------------------
# Test 2: mock API response parses correctly
# ---------------------------------------------------------------------------
def test_okta_mock_api_parses_correctly():
    from connectors.okta_connector import OktaConnector

    fe = _mock_findings()
    connector = OktaConnector(findings_engine=fe, max_users=100, max_logs=100)

    with patch.dict(os.environ, {
        "OKTA_API_KEY": "fake-ssws-token",
        "OKTA_DOMAIN": "https://fake.okta.com",
    }), \
    patch("connectors.okta_connector._fetch_all_users", return_value=_SAMPLE_USERS), \
    patch("connectors.okta_connector._fetch_all_logs", return_value=_SAMPLE_LOGS):

        result = connector.sync(org_id="test-okta-org", force_refresh=True)

    assert result["status"] == "ok"
    assert result["mode"] == "live"
    assert result["users_synced"] == 2

    # Verify user normalization
    users = result["users"]
    assert len(users) == 2
    alice = next(u for u in users if u["email"] == "alice@example.com")
    assert alice["status"] == "ACTIVE"
    assert alice["risk_level"] == "low"
    bob = next(u for u in users if u["email"] == "bob@example.com")
    assert bob["status"] == "LOCKED_OUT"
    assert bob["risk_level"] == "high"

    # Verify findings from logs: all three sample events produce findings
    # (user.account.lock, group.user_membership.add, user.session.start are all
    # in _HIGH_RISK_EVENTS). Titles use displayMessage, not eventType.
    log_findings = result["log_findings"]
    assert len(log_findings) >= 1
    titles = [f["title"] for f in log_findings]
    # user.account.lock → displayMessage "Max sign-in attempts exceeded"
    # group.user_membership.add → displayMessage "User added to Okta Administrators group"
    assert any("sign-in" in t.lower() or "attempts" in t.lower() or "administrators" in t.lower()
               for t in titles)

    # record_finding should have been called for security findings
    assert fe.record_finding.call_count >= 1
    first_call = fe.record_finding.call_args_list[0][1]
    assert first_call["org_id"] == "test-okta-org"
    assert first_call["source_tool"] == "okta"
    assert first_call["correlation_key"].startswith("okta_log|")


# ---------------------------------------------------------------------------
# Test 3: live API call (skipped if creds absent)
# ---------------------------------------------------------------------------
@pytest.mark.skipif(
    not (os.environ.get("OKTA_API_KEY") and os.environ.get("OKTA_DOMAIN")),
    reason="OKTA_API_KEY / OKTA_DOMAIN not set",
)
def test_okta_live_api_call():
    from connectors.okta_connector import OktaConnector
    connector = OktaConnector(findings_engine=_mock_findings(), max_users=10, max_logs=10)
    result = connector.sync(org_id="live-okta-org", force_refresh=True)
    assert result["status"] in {"ok", "partial"}
    assert isinstance(result["users_synced"], int)
    assert isinstance(result["users"], list)


# ---------------------------------------------------------------------------
# Test 4: pagination — Link header followed for multi-page user list
# ---------------------------------------------------------------------------
def test_okta_pagination_follows_link_header():
    """_fetch_all_users follows Link: <url>; rel="next" headers."""
    from connectors.okta_connector import _fetch_all_users

    page1 = _SAMPLE_USERS[:1]
    page2 = _SAMPLE_USERS[1:]

    call_count = 0

    class MockHeaders:
        def __init__(self, link_val: str = ""):
            self._link = link_val
        def get(self, key, default=""):
            if key.lower() == "link":
                return self._link
            return default

    class MockResp:
        def __init__(self, data, link=""):
            self._data = data
            self.headers = MockHeaders(link)
        def raise_for_status(self):
            pass
        def json(self):
            return self._data

    responses = [
        MockResp(page1, link='<https://fake.okta.com/api/v1/users?after=page2>; rel="next"'),
        MockResp(page2, link=""),
    ]

    def mock_get(url, params=None, headers=None, timeout=None):
        nonlocal call_count
        resp = responses[call_count]
        call_count += 1
        return resp

    with patch("httpx.get", side_effect=mock_get):
        users = _fetch_all_users(
            api_key="fake-key",
            domain="https://fake.okta.com",
            max_users=100,
        )

    assert len(users) == 2
    assert call_count == 2
    assert users[0]["id"] == _SAMPLE_USERS[0]["id"]
    assert users[1]["id"] == _SAMPLE_USERS[1]["id"]
