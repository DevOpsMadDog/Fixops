"""Tests for connector registration DX improvements.

Verifies that:
1. The canonical typed-key form still works (regression guard).
2. The generic 'config' alias form now works (option a fix).
3. Missing config returns a 422 whose detail names the expected key
   and lists required fields (option b fallback message).
4. A malformed 'config' value returns a 422 with per-field errors.
5. All three connector types (github, jira, slack) are covered.
"""

from __future__ import annotations

import json
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    import sys
    # Ensure suite paths are on sys.path (mirrors PYTHONPATH in CI command)
    for p in ("suite-api", "suite-core", "suite-feeds", "suite-integrations",
              "suite-evidence-risk", "archive/legacy", "archive/enterprise_legacy"):
        if p not in sys.path:
            sys.path.insert(0, p)

    from apps.api.connectors_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# GitHub — canonical typed key
# ---------------------------------------------------------------------------

def test_github_canonical_typed_key(client):
    """Canonical form: 'github': {...} must succeed."""
    r = client.post("/api/v1/connectors/register", json={
        "name": "gh-canonical",
        "type": "github",
        "github": {"token": "ghp_abc123", "owner": "acme", "repo": "core"},
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "registered"
    assert body["type"] == "github"
    assert body["configured"] is True


# ---------------------------------------------------------------------------
# GitHub — generic config alias (the fix)
# ---------------------------------------------------------------------------

def test_github_generic_config_alias(client):
    """Generic alias: 'config': {...} must be remapped and succeed (option a)."""
    r = client.post("/api/v1/connectors/register", json={
        "name": "gh-alias",
        "type": "github",
        "config": {"token": "ghp_abc123", "owner": "acme", "repo": "core"},
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "registered"
    assert body["type"] == "github"
    assert body["configured"] is True


def test_github_typed_key_wins_over_config(client):
    """When both typed key and config are present, the typed key wins."""
    r = client.post("/api/v1/connectors/register", json={
        "name": "gh-both",
        "type": "github",
        "github": {"token": "ghp_typed", "owner": "acme", "repo": "typed-repo"},
        "config": {"token": "ghp_generic", "owner": "acme", "repo": "generic-repo"},
    })
    assert r.status_code == 200, r.text


# ---------------------------------------------------------------------------
# GitHub — missing config: error must name the expected key
# ---------------------------------------------------------------------------

def test_github_missing_config_names_expected_key(client):
    """Missing sub-config returns 422 whose detail names 'github' as expected key."""
    r = client.post("/api/v1/connectors/register", json={
        "name": "gh-missing",
        "type": "github",
    })
    assert r.status_code == 422, r.text
    detail_str = json.dumps(r.json())
    # Must name the expected key
    assert "'github'" in detail_str or '"github"' in detail_str, (
        f"Error detail does not mention 'github' key: {detail_str}"
    )
    # Must list required fields
    assert "token" in detail_str, f"Error detail does not mention required field 'token': {detail_str}"
    assert "owner" in detail_str, f"Error detail does not mention required field 'owner': {detail_str}"
    assert "repo" in detail_str, f"Error detail does not mention required field 'repo': {detail_str}"


# ---------------------------------------------------------------------------
# GitHub — malformed config: Pydantic per-field error
# ---------------------------------------------------------------------------

def test_github_malformed_config_reports_field_error(client):
    """Malformed 'config' value must return 422 (not 500), with field error detail."""
    r = client.post("/api/v1/connectors/register", json={
        "name": "gh-bad",
        "type": "github",
        "config": {"token": "ghp_ok", "owner": "acme"},  # missing 'repo'
    })
    assert r.status_code == 422, r.text
    # Should mention the missing field somewhere
    detail_str = json.dumps(r.json())
    assert "repo" in detail_str, f"Error detail does not mention missing 'repo': {detail_str}"


# ---------------------------------------------------------------------------
# Jira — generic config alias
# ---------------------------------------------------------------------------

def test_jira_generic_config_alias(client):
    r = client.post("/api/v1/connectors/register", json={
        "name": "jira-alias",
        "type": "jira",
        "config": {
            "base_url": "https://acme.atlassian.net",
            "email": "dev@acme.com",
            "api_token": "tok123",
            "project_key": "OPS",
        },
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["type"] == "jira"
    assert body["configured"] is True


def test_jira_missing_config_names_expected_key(client):
    r = client.post("/api/v1/connectors/register", json={
        "name": "jira-missing",
        "type": "jira",
    })
    assert r.status_code == 422, r.text
    detail_str = json.dumps(r.json())
    assert "'jira'" in detail_str or '"jira"' in detail_str, (
        f"Error detail does not mention 'jira' key: {detail_str}"
    )


# ---------------------------------------------------------------------------
# Slack — generic config alias
# ---------------------------------------------------------------------------

def test_slack_generic_config_alias(client):
    r = client.post("/api/v1/connectors/register", json={
        "name": "slack-alias",
        "type": "slack",
        "config": {"webhook_url": "https://hooks.slack.com/services/T000/B000/xxx"},
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["type"] == "slack"
    assert body["configured"] is True


def test_slack_missing_config_names_expected_key(client):
    r = client.post("/api/v1/connectors/register", json={
        "name": "slack-missing",
        "type": "slack",
    })
    assert r.status_code == 422, r.text
    detail_str = json.dumps(r.json())
    assert "'slack'" in detail_str or '"slack"' in detail_str, (
        f"Error detail does not mention 'slack' key: {detail_str}"
    )


# ---------------------------------------------------------------------------
# Ensure 'config' field is not leaked in success response
# ---------------------------------------------------------------------------

def test_config_field_not_in_response(client):
    """The generic 'config' field must be excluded from the success response."""
    r = client.post("/api/v1/connectors/register", json={
        "name": "gh-no-leak",
        "type": "github",
        "config": {"token": "ghp_abc123", "owner": "acme", "repo": "core"},
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert "config" not in body, f"'config' key leaked into response: {body}"


# ---------------------------------------------------------------------------
# Validation still rejects genuinely invalid input
# ---------------------------------------------------------------------------

def test_invalid_connector_type_rejected(client):
    r = client.post("/api/v1/connectors/register", json={
        "name": "bad-type",
        "type": "postgres",
        "config": {"host": "localhost"},
    })
    assert r.status_code == 422, r.text


def test_invalid_name_rejected(client):
    """Names with uppercase or special chars must still be rejected."""
    r = client.post("/api/v1/connectors/register", json={
        "name": "INVALID NAME!",
        "type": "github",
        "github": {"token": "ghp_x", "owner": "acme", "repo": "core"},
    })
    assert r.status_code == 422, r.text


def test_slack_invalid_webhook_url_rejected(client):
    """Slack webhook URL validation must still fire even when using 'config' alias."""
    r = client.post("/api/v1/connectors/register", json={
        "name": "slack-bad-url",
        "type": "slack",
        "config": {"webhook_url": "https://evil.com/steal"},
    })
    assert r.status_code == 422, r.text
    detail_str = json.dumps(r.json())
    assert "hooks.slack.com" in detail_str, (
        f"Error should mention the required webhook URL domain: {detail_str}"
    )
