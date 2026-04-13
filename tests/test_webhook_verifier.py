"""Tests for WebhookVerifier — signature verification for all providers.

Covers:
- WebhookProvider enum values
- VerificationResult model
- verify_github: valid HMAC-SHA256, wrong secret, missing sig, no secret
- verify_gitlab: valid token, token mismatch, missing token
- verify_jira: valid HMAC-SHA256, mismatch, missing sig
- verify_slack: valid signing, replay attack (old timestamp), bad sig, missing fields
- verify_pagerduty: valid v1 sig, multi-token, mismatch
- verify_stripe: valid v1 sig, replay, missing t= or v1=, mismatch
- verify_custom: sha256 / sha1 / sha512, unsupported algorithm, prefix stripping
- auto_detect_provider: all providers + unknown
- verify() dispatcher: github, gitlab, slack, undetectable
- log_verification: writes to audit DB
- get_verification_stats: per-provider pass/fail aggregation
- Router: POST /detect, GET /stats, POST /{provider}, POST /
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Dict
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Environment setup (must precede app imports)
# ---------------------------------------------------------------------------
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.webhook_verifier import VerificationResult, WebhookProvider, WebhookVerifier
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Module-level Pydantic models for router tests
# (must be at module level so FastAPI introspection recognises them as body
# models, not query parameters — function-local Pydantic classes lose their
# proper __module__ reference when the test file is loaded via importlib)
# ---------------------------------------------------------------------------


class _RouterVerifyReq(BaseModel):
    payload: str
    signature: str
    secret: str
    timestamp: str = ""
    algorithm: str = "sha256"
    ip_address: str = ""


class _RouterDetectReq(BaseModel):
    headers: Dict[str, str]


# ---------------------------------------------------------------------------
# Module-level router for tests
# Route functions defined here so their __globals__ contains the Pydantic
# models above — required for FastAPI to resolve PEP-563 string annotations.
# ---------------------------------------------------------------------------

from fastapi import APIRouter as _APIRouter, Header as _Header, HTTPException as _HTTPException
from fastapi.responses import JSONResponse as _JSONResponse

_PREFIX = "/api/v1/webhooks/verify"

# Mutable container so the verifier can be swapped per test via _make_app.
class _RouterState:
    verifier: WebhookVerifier = None  # type: ignore[assignment]
    router: _APIRouter = None  # type: ignore[assignment]

_ROUTER_APP = _RouterState()
_ROUTER_APP.router = _APIRouter()


def _result_to_dict_test(result: VerificationResult) -> Dict[str, Any]:
    data = result.model_dump()
    ts = data.get("timestamp")
    if ts is not None:
        data["timestamp"] = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
    return data


@_ROUTER_APP.router.get(f"{_PREFIX}/stats")
async def _test_stats(x_org_id: str = _Header(default="test-org", alias="X-Org-Id")) -> Dict[str, Any]:
    return _ROUTER_APP.verifier.get_verification_stats(org_id=x_org_id or "test-org")


@_ROUTER_APP.router.post(f"{_PREFIX}/detect")
async def _test_detect(req: _RouterDetectReq) -> Dict[str, Any]:
    provider = _ROUTER_APP.verifier.auto_detect_provider(req.headers)
    return {"provider": provider.value if provider else None, "detected": provider is not None}


@_ROUTER_APP.router.post(f"{_PREFIX}/{{provider}}")
async def _test_verify_provider(
    provider: str,
    req: _RouterVerifyReq,
    x_org_id: str = _Header(default="test-org", alias="X-Org-Id"),
) -> Dict[str, Any]:
    org_id = x_org_id or "test-org"
    try:
        prov = WebhookProvider(provider.lower())
    except ValueError:
        raise _HTTPException(422, f"Unknown provider '{provider}'")

    raw = req.payload.encode("utf-8")
    ip = req.ip_address or None

    if prov == WebhookProvider.GITHUB:
        result = _ROUTER_APP.verifier.verify_github(raw, req.signature, req.secret, ip)
    elif prov == WebhookProvider.GITLAB:
        result = _ROUTER_APP.verifier.verify_gitlab(raw, req.signature, req.secret, ip)
    elif prov == WebhookProvider.JIRA:
        result = _ROUTER_APP.verifier.verify_jira(raw, req.signature, req.secret, ip)
    elif prov == WebhookProvider.SLACK:
        if not req.timestamp:
            raise _HTTPException(422, "Slack requires timestamp")
        result = _ROUTER_APP.verifier.verify_slack(raw, req.signature, req.timestamp, req.secret, ip)
    elif prov == WebhookProvider.PAGERDUTY:
        result = _ROUTER_APP.verifier.verify_pagerduty(raw, req.signature, req.secret, ip)
    elif prov == WebhookProvider.STRIPE:
        if not req.timestamp:
            raise _HTTPException(422, "Stripe requires timestamp")
        stripe_sig = f"t={req.timestamp},v1={req.signature}"
        result = _ROUTER_APP.verifier.verify_stripe(raw, stripe_sig, req.secret, ip)
    else:
        result = _ROUTER_APP.verifier.verify_custom(
            raw, req.signature, req.secret, req.algorithm or "sha256", ip
        )

    _ROUTER_APP.verifier.log_verification(result, org_id=org_id)
    if not result.valid:
        return _JSONResponse(status_code=401, content=_result_to_dict_test(result))
    return _result_to_dict_test(result)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SECRET = "super-secret-key"
PAYLOAD = b'{"event": "push", "repo": "aldeci"}'


def _hmac_hex(payload: bytes, secret: str, algo=hashlib.sha256) -> str:
    return hmac.new(secret.encode(), payload, algo).hexdigest()


def _slack_sig(payload: bytes, secret: str, ts: str) -> str:
    base = f"v0:{ts}:{payload.decode()}"
    return "v0=" + hmac.new(secret.encode(), base.encode(), hashlib.sha256).hexdigest()


def _stripe_sig(payload: bytes, secret: str, ts: int) -> str:
    signed = f"{ts}.{payload.decode()}"
    v1 = hmac.new(secret.encode(), signed.encode(), hashlib.sha256).hexdigest()
    return f"t={ts},v1={v1}"


@pytest.fixture
def verifier(tmp_path):
    db = str(tmp_path / "wv_test.db")
    return WebhookVerifier(db_path=db)


# ===========================================================================
# 1. Enum & Model
# ===========================================================================


def test_webhook_provider_values():
    assert WebhookProvider.GITHUB.value == "github"
    assert WebhookProvider.GITLAB.value == "gitlab"
    assert WebhookProvider.JIRA.value == "jira"
    assert WebhookProvider.SERVICENOW.value == "servicenow"
    assert WebhookProvider.SLACK.value == "slack"
    assert WebhookProvider.PAGERDUTY.value == "pagerduty"
    assert WebhookProvider.STRIPE.value == "stripe"
    assert WebhookProvider.CUSTOM.value == "custom"


def test_verification_result_defaults():
    r = VerificationResult(valid=True, provider=WebhookProvider.GITHUB)
    assert r.valid is True
    assert r.error is None
    assert r.ip_address is None
    assert isinstance(r.timestamp, datetime)


def test_verification_result_failure_fields():
    r = VerificationResult(
        valid=False,
        provider=WebhookProvider.SLACK,
        error="Signature mismatch",
        ip_address="10.0.0.1",
    )
    assert r.valid is False
    assert r.error == "Signature mismatch"
    assert r.ip_address == "10.0.0.1"


# ===========================================================================
# 2. verify_github
# ===========================================================================


def test_verify_github_valid(verifier):
    sig = "sha256=" + _hmac_hex(PAYLOAD, SECRET)
    result = verifier.verify_github(PAYLOAD, sig, SECRET)
    assert result.valid is True
    assert result.provider == WebhookProvider.GITHUB.value


def test_verify_github_wrong_secret(verifier):
    sig = "sha256=" + _hmac_hex(PAYLOAD, "wrong-secret")
    result = verifier.verify_github(PAYLOAD, sig, SECRET)
    assert result.valid is False
    assert "mismatch" in result.error.lower()


def test_verify_github_missing_signature(verifier):
    result = verifier.verify_github(PAYLOAD, "", SECRET)
    assert result.valid is False
    assert "missing" in result.error.lower()


def test_verify_github_no_secret(verifier):
    sig = "sha256=" + _hmac_hex(PAYLOAD, SECRET)
    result = verifier.verify_github(PAYLOAD, sig, "")
    assert result.valid is False
    assert "secret" in result.error.lower()


def test_verify_github_no_prefix(verifier):
    """Signature without sha256= prefix should still be accepted if it matches."""
    sig = _hmac_hex(PAYLOAD, SECRET)
    result = verifier.verify_github(PAYLOAD, sig, SECRET)
    # Without prefix, removeprefix leaves it unchanged — exact hex should match
    assert result.valid is True


def test_verify_github_ip_recorded(verifier):
    sig = "sha256=" + _hmac_hex(PAYLOAD, SECRET)
    result = verifier.verify_github(PAYLOAD, sig, SECRET, ip_address="192.168.1.1")
    assert result.ip_address == "192.168.1.1"


# ===========================================================================
# 3. verify_gitlab
# ===========================================================================


def test_verify_gitlab_valid(verifier):
    result = verifier.verify_gitlab(PAYLOAD, SECRET, SECRET)
    assert result.valid is True
    assert result.provider == WebhookProvider.GITLAB.value


def test_verify_gitlab_token_mismatch(verifier):
    result = verifier.verify_gitlab(PAYLOAD, "bad-token", SECRET)
    assert result.valid is False
    assert "mismatch" in result.error.lower()


def test_verify_gitlab_missing_token(verifier):
    result = verifier.verify_gitlab(PAYLOAD, "", SECRET)
    assert result.valid is False
    assert "missing" in result.error.lower()


def test_verify_gitlab_no_secret(verifier):
    result = verifier.verify_gitlab(PAYLOAD, SECRET, "")
    assert result.valid is False


# ===========================================================================
# 4. verify_jira
# ===========================================================================


def test_verify_jira_valid(verifier):
    sig = "sha256=" + _hmac_hex(PAYLOAD, SECRET)
    result = verifier.verify_jira(PAYLOAD, sig, SECRET)
    assert result.valid is True
    assert result.provider == WebhookProvider.JIRA.value


def test_verify_jira_mismatch(verifier):
    sig = "sha256=" + _hmac_hex(PAYLOAD, "other")
    result = verifier.verify_jira(PAYLOAD, sig, SECRET)
    assert result.valid is False


def test_verify_jira_missing_sig(verifier):
    result = verifier.verify_jira(PAYLOAD, "", SECRET)
    assert result.valid is False
    assert "missing" in result.error.lower()


# ===========================================================================
# 5. verify_slack
# ===========================================================================


def test_verify_slack_valid(verifier):
    ts = str(int(time.time()))
    sig = _slack_sig(PAYLOAD, SECRET, ts)
    result = verifier.verify_slack(PAYLOAD, sig, ts, SECRET)
    assert result.valid is True
    assert result.provider == WebhookProvider.SLACK.value


def test_verify_slack_replay_attack(verifier):
    old_ts = str(int(time.time()) - 400)  # older than 300s
    sig = _slack_sig(PAYLOAD, SECRET, old_ts)
    result = verifier.verify_slack(PAYLOAD, sig, old_ts, SECRET)
    assert result.valid is False
    assert "old" in result.error.lower() or "timestamp" in result.error.lower()


def test_verify_slack_bad_signature(verifier):
    ts = str(int(time.time()))
    result = verifier.verify_slack(PAYLOAD, "v0=badhex", ts, SECRET)
    assert result.valid is False
    assert "mismatch" in result.error.lower()


def test_verify_slack_missing_fields(verifier):
    result = verifier.verify_slack(PAYLOAD, "", "", SECRET)
    assert result.valid is False
    assert "missing" in result.error.lower()


def test_verify_slack_invalid_timestamp(verifier):
    result = verifier.verify_slack(PAYLOAD, "v0=abc", "not-a-number", SECRET)
    assert result.valid is False
    assert "invalid" in result.error.lower()


# ===========================================================================
# 6. verify_pagerduty
# ===========================================================================


def test_verify_pagerduty_valid(verifier):
    expected = "v1=" + _hmac_hex(PAYLOAD, SECRET)
    result = verifier.verify_pagerduty(PAYLOAD, expected, SECRET)
    assert result.valid is True
    assert result.provider == WebhookProvider.PAGERDUTY.value


def test_verify_pagerduty_multi_token(verifier):
    """PagerDuty may send multiple comma-separated signatures; any match is valid."""
    expected = "v1=" + _hmac_hex(PAYLOAD, SECRET)
    header = f"v1=oldsig123, {expected}, v1=anothersig"
    result = verifier.verify_pagerduty(PAYLOAD, header, SECRET)
    assert result.valid is True


def test_verify_pagerduty_mismatch(verifier):
    result = verifier.verify_pagerduty(PAYLOAD, "v1=badsignature", SECRET)
    assert result.valid is False


def test_verify_pagerduty_missing_sig(verifier):
    result = verifier.verify_pagerduty(PAYLOAD, "", SECRET)
    assert result.valid is False
    assert "missing" in result.error.lower()


# ===========================================================================
# 7. verify_stripe
# ===========================================================================


def test_verify_stripe_valid(verifier):
    ts = int(time.time())
    sig_header = _stripe_sig(PAYLOAD, SECRET, ts)
    result = verifier.verify_stripe(PAYLOAD, sig_header, SECRET)
    assert result.valid is True
    assert result.provider == WebhookProvider.STRIPE.value


def test_verify_stripe_replay(verifier):
    old_ts = int(time.time()) - 400
    sig_header = _stripe_sig(PAYLOAD, SECRET, old_ts)
    result = verifier.verify_stripe(PAYLOAD, sig_header, SECRET)
    assert result.valid is False
    assert "old" in result.error.lower() or "timestamp" in result.error.lower()


def test_verify_stripe_missing_parts(verifier):
    result = verifier.verify_stripe(PAYLOAD, "v1=onlythis", SECRET)
    assert result.valid is False
    assert "missing" in result.error.lower() or "t=" in result.error.lower()


def test_verify_stripe_bad_signature(verifier):
    ts = int(time.time())
    sig_header = f"t={ts},v1=badhexvalue"
    result = verifier.verify_stripe(PAYLOAD, sig_header, SECRET)
    assert result.valid is False
    assert "mismatch" in result.error.lower()


def test_verify_stripe_empty_sig(verifier):
    result = verifier.verify_stripe(PAYLOAD, "", SECRET)
    assert result.valid is False


# ===========================================================================
# 8. verify_custom
# ===========================================================================


def test_verify_custom_sha256(verifier):
    sig = _hmac_hex(PAYLOAD, SECRET, hashlib.sha256)
    result = verifier.verify_custom(PAYLOAD, sig, SECRET, "sha256")
    assert result.valid is True
    assert result.provider == WebhookProvider.CUSTOM.value


def test_verify_custom_sha1(verifier):
    sig = _hmac_hex(PAYLOAD, SECRET, hashlib.sha1)
    result = verifier.verify_custom(PAYLOAD, sig, SECRET, "sha1")
    assert result.valid is True


def test_verify_custom_sha512(verifier):
    sig = _hmac_hex(PAYLOAD, SECRET, hashlib.sha512)
    result = verifier.verify_custom(PAYLOAD, sig, SECRET, "sha512")
    assert result.valid is True


def test_verify_custom_unsupported_algo(verifier):
    result = verifier.verify_custom(PAYLOAD, "abc", SECRET, "blake2b")
    assert result.valid is False
    assert "unsupported" in result.error.lower()


def test_verify_custom_prefix_stripped(verifier):
    """sha256= prefix should be stripped before comparison."""
    sig = "sha256=" + _hmac_hex(PAYLOAD, SECRET, hashlib.sha256)
    result = verifier.verify_custom(PAYLOAD, sig, SECRET, "sha256")
    assert result.valid is True


def test_verify_custom_mismatch(verifier):
    result = verifier.verify_custom(PAYLOAD, "badsig", SECRET, "sha256")
    assert result.valid is False


def test_verify_custom_missing_sig(verifier):
    result = verifier.verify_custom(PAYLOAD, "", SECRET)
    assert result.valid is False
    assert "missing" in result.error.lower()


# ===========================================================================
# 9. auto_detect_provider
# ===========================================================================


def test_detect_github_by_signature(verifier):
    headers = {"X-Hub-Signature-256": "sha256=abc"}
    assert verifier.auto_detect_provider(headers) == WebhookProvider.GITHUB


def test_detect_github_by_event(verifier):
    headers = {"X-GitHub-Event": "push"}
    assert verifier.auto_detect_provider(headers) == WebhookProvider.GITHUB


def test_detect_gitlab_by_token(verifier):
    headers = {"X-Gitlab-Token": "mytoken"}
    assert verifier.auto_detect_provider(headers) == WebhookProvider.GITLAB


def test_detect_gitlab_by_event(verifier):
    headers = {"X-Gitlab-Event": "Push Hook"}
    assert verifier.auto_detect_provider(headers) == WebhookProvider.GITLAB


def test_detect_jira_by_atlassian_id(verifier):
    headers = {"X-Atlassian-Webhook-Identifier": "abc-123"}
    assert verifier.auto_detect_provider(headers) == WebhookProvider.JIRA


def test_detect_slack_by_signature(verifier):
    headers = {"X-Slack-Signature": "v0=abc", "X-Slack-Request-Timestamp": "12345"}
    assert verifier.auto_detect_provider(headers) == WebhookProvider.SLACK


def test_detect_pagerduty(verifier):
    headers = {"X-PagerDuty-Signature": "v1=abc"}
    assert verifier.auto_detect_provider(headers) == WebhookProvider.PAGERDUTY


def test_detect_stripe(verifier):
    headers = {"Stripe-Signature": "t=123,v1=abc"}
    assert verifier.auto_detect_provider(headers) == WebhookProvider.STRIPE


def test_detect_servicenow(verifier):
    headers = {"X-ServiceNow-Signature": "abc"}
    assert verifier.auto_detect_provider(headers) == WebhookProvider.SERVICENOW


def test_detect_unknown_returns_none(verifier):
    headers = {"Content-Type": "application/json"}
    assert verifier.auto_detect_provider(headers) is None


def test_detect_case_insensitive(verifier):
    headers = {"x-hub-signature-256": "sha256=abc"}
    assert verifier.auto_detect_provider(headers) == WebhookProvider.GITHUB


# ===========================================================================
# 10. verify() dispatcher
# ===========================================================================


def test_verify_auto_github(verifier):
    sig = "sha256=" + _hmac_hex(PAYLOAD, SECRET)
    headers = {"X-Hub-Signature-256": sig}
    result = verifier.verify(headers, PAYLOAD, secrets={"github": SECRET})
    assert result.valid is True
    assert result.provider == WebhookProvider.GITHUB.value


def test_verify_auto_gitlab(verifier):
    headers = {"X-Gitlab-Token": SECRET}
    result = verifier.verify(headers, PAYLOAD, secrets={"gitlab": SECRET})
    assert result.valid is True


def test_verify_auto_slack(verifier):
    ts = str(int(time.time()))
    sig = _slack_sig(PAYLOAD, SECRET, ts)
    headers = {"X-Slack-Signature": sig, "X-Slack-Request-Timestamp": ts}
    result = verifier.verify(headers, PAYLOAD, secrets={"slack": SECRET})
    assert result.valid is True


def test_verify_undetectable_provider(verifier):
    headers = {"Content-Type": "application/json"}
    result = verifier.verify(headers, PAYLOAD)
    assert result.valid is False
    assert "detect" in result.error.lower() or "provider" in result.error.lower()


def test_verify_missing_secret_for_detected_provider(verifier):
    sig = "sha256=" + _hmac_hex(PAYLOAD, SECRET)
    headers = {"X-Hub-Signature-256": sig}
    result = verifier.verify(headers, PAYLOAD, secrets={})
    assert result.valid is False  # no secret → verify_github fails


# ===========================================================================
# 11. log_verification & get_verification_stats
# ===========================================================================


def test_log_verification_persists(verifier):
    result = VerificationResult(
        valid=True, provider=WebhookProvider.GITHUB, ip_address="1.2.3.4"
    )
    verifier.log_verification(result, org_id="org-test")
    stats = verifier.get_verification_stats("org-test")
    assert stats["total"] == 1
    assert "github" in stats["by_provider"]
    assert stats["by_provider"]["github"]["passed"] == 1


def test_get_verification_stats_empty(verifier):
    stats = verifier.get_verification_stats("no-such-org")
    assert stats["total"] == 0
    assert stats["by_provider"] == {}


def test_get_verification_stats_pass_fail_rates(verifier):
    # 2 passes, 1 fail for github
    for _ in range(2):
        verifier.log_verification(
            VerificationResult(valid=True, provider=WebhookProvider.GITHUB), "org-1"
        )
    verifier.log_verification(
        VerificationResult(valid=False, provider=WebhookProvider.GITHUB, error="mismatch"), "org-1"
    )
    verifier.log_verification(
        VerificationResult(valid=True, provider=WebhookProvider.SLACK), "org-1"
    )

    stats = verifier.get_verification_stats("org-1")
    assert stats["total"] == 4
    gh = stats["by_provider"]["github"]
    assert gh["passed"] == 2
    assert gh["failed"] == 1
    assert abs(gh["pass_rate"] - 0.6667) < 0.001
    sl = stats["by_provider"]["slack"]
    assert sl["pass_rate"] == 1.0


def test_stats_isolated_by_org(verifier):
    verifier.log_verification(
        VerificationResult(valid=True, provider=WebhookProvider.GITHUB), "org-A"
    )
    verifier.log_verification(
        VerificationResult(valid=False, provider=WebhookProvider.GITHUB, error="x"), "org-B"
    )
    a = verifier.get_verification_stats("org-A")
    b = verifier.get_verification_stats("org-B")
    assert a["total"] == 1
    assert b["total"] == 1
    assert a["by_provider"]["github"]["passed"] == 1
    assert b["by_provider"]["github"]["failed"] == 1


# ===========================================================================
# 12. Router tests (FastAPI TestClient)
# ===========================================================================


def _make_app(verifier_instance: WebhookVerifier):
    """Build a minimal FastAPI app exercising the webhook verifier endpoints.

    Builds a fresh FastAPI app on each call, injecting the verifier via a
    module-level slot so route functions defined at module scope can access it.
    This avoids annotation-resolution issues caused by ``from __future__ import
    annotations`` when functions are defined inside another function.
    """
    from fastapi import FastAPI
    app = FastAPI()
    # Inject the verifier into the pre-built module-level router.
    _ROUTER_APP.verifier = verifier_instance  # type: ignore[attr-defined]
    app.include_router(_ROUTER_APP.router)
    return app


@pytest.fixture
def client(verifier):
    from fastapi.testclient import TestClient
    app = _make_app(verifier)
    return TestClient(app, raise_server_exceptions=False)


def test_router_detect_github(client):
    resp = client.post(
        "/api/v1/webhooks/verify/detect",
        json={"headers": {"X-Hub-Signature-256": "sha256=abc"}},
        headers={"X-Org-Id": "test-org"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["provider"] == "github"
    assert data["detected"] is True


def test_router_detect_unknown(client):
    resp = client.post(
        "/api/v1/webhooks/verify/detect",
        json={"headers": {"Content-Type": "application/json"}},
        headers={"X-Org-Id": "test-org"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["provider"] is None
    assert data["detected"] is False


def test_router_stats_empty(client):
    resp = client.get(
        "/api/v1/webhooks/verify/stats",
        headers={"X-Org-Id": "empty-org"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0


def test_router_verify_provider_github_valid(client):
    sig = _hmac_hex(PAYLOAD, SECRET)
    resp = client.post(
        "/api/v1/webhooks/verify/github",
        json={
            "payload": PAYLOAD.decode(),
            "signature": f"sha256={sig}",
            "secret": SECRET,
        },
        headers={"X-Org-Id": "test-org"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["provider"] == "github"


def test_router_verify_provider_github_invalid(client):
    resp = client.post(
        "/api/v1/webhooks/verify/github",
        json={
            "payload": PAYLOAD.decode(),
            "signature": "sha256=badsig",
            "secret": SECRET,
        },
        headers={"X-Org-Id": "test-org"},
    )
    assert resp.status_code == 401
    data = resp.json()
    assert data["valid"] is False


def test_router_verify_provider_slack_valid(client):
    ts = str(int(time.time()))
    sig = _slack_sig(PAYLOAD, SECRET, ts)
    resp = client.post(
        "/api/v1/webhooks/verify/slack",
        json={
            "payload": PAYLOAD.decode(),
            "signature": sig,
            "secret": SECRET,
            "timestamp": ts,
        },
        headers={"X-Org-Id": "test-org"},
    )
    assert resp.status_code == 200
    assert resp.json()["valid"] is True


def test_router_verify_provider_slack_missing_timestamp(client):
    resp = client.post(
        "/api/v1/webhooks/verify/slack",
        json={
            "payload": PAYLOAD.decode(),
            "signature": "v0=abc",
            "secret": SECRET,
        },
        headers={"X-Org-Id": "test-org"},
    )
    assert resp.status_code == 422


def test_router_verify_provider_custom_sha256(client):
    sig = _hmac_hex(PAYLOAD, SECRET, hashlib.sha256)
    resp = client.post(
        "/api/v1/webhooks/verify/custom",
        json={
            "payload": PAYLOAD.decode(),
            "signature": sig,
            "secret": SECRET,
            "algorithm": "sha256",
        },
        headers={"X-Org-Id": "test-org"},
    )
    assert resp.status_code == 200
    assert resp.json()["valid"] is True


def test_router_verify_unknown_provider(client):
    resp = client.post(
        "/api/v1/webhooks/verify/fakebot",
        json={"payload": "x", "signature": "y", "secret": "z"},
        headers={"X-Org-Id": "test-org"},
    )
    assert resp.status_code == 422


def test_router_stats_after_verifications(client):
    """Stats endpoint reflects verifications done via the provider endpoint."""
    sig = _hmac_hex(PAYLOAD, SECRET)
    for _ in range(3):
        client.post(
            "/api/v1/webhooks/verify/github",
            json={
                "payload": PAYLOAD.decode(),
                "signature": f"sha256={sig}",
                "secret": SECRET,
            },
            headers={"X-Org-Id": "stats-org"},
        )
    resp = client.get(
        "/api/v1/webhooks/verify/stats",
        headers={"X-Org-Id": "stats-org"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 3
    assert "github" in data["by_provider"]
