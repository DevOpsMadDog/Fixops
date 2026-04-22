"""Tests for GAP-015 (GitHub App) + GAP-068 (.fixops/hooks.yaml policy).

Covers:
- App registration UNIQUE(org_id, installation_id) idempotency
- HMAC-SHA256 webhook verification (happy path + tampered payload + unknown install)
- hooks.yaml parse (valid YAML, valid JSON, malformed rejection, empty input)
- Hook policy apply idempotency (hash match)
- org_id isolation for installations and policies
- Endpoint smoke (auth + responses)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from core.devsecops_engine import DevSecOpsEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "devsecops_test.db")
    return DevSecOpsEngine(db_path=db)


@pytest.fixture
def app_client(monkeypatch, tmp_path):
    """Full FastAPI app with a fresh engine singleton pointed at tmp DB."""
    db = str(tmp_path / "devsecops_api_test.db")

    # Reset singleton so the fresh DB is used.
    from core import devsecops_engine as dse_mod
    dse_mod._engine_instance = None
    # Patch constructor default so get_devsecops_engine() uses tmp DB.
    orig_init = DevSecOpsEngine.__init__

    def patched_init(self, db_path=db):
        orig_init(self, db_path=db_path)

    monkeypatch.setattr(DevSecOpsEngine, "__init__", patched_init)

    # Patch auth_deps to accept our test token (tokens load at module import time).
    from apps.api import auth_deps as _auth_deps
    monkeypatch.setattr(_auth_deps, "_EXPECTED_TOKENS", ("test-api-key-123",))
    monkeypatch.setattr(_auth_deps, "_HAS_TOKEN_AUTH", True)
    monkeypatch.setattr(_auth_deps, "_DEV_MODE", False)

    from apps.api.app import create_app
    app = create_app()
    with TestClient(app) as client:
        yield client

    dse_mod._engine_instance = None


def _auth_headers():
    return {"X-API-Key": "test-api-key-123", "Authorization": "Bearer test-api-key-123"}


# ---------------------------------------------------------------------------
# 1. App registration idempotency
# ---------------------------------------------------------------------------


def test_register_github_app_happy(engine):
    r = engine.register_github_app("org1", "app-42", "inst-1", "secret-xyz")
    assert r["org_id"] == "org1"
    assert r["installation_id"] == "inst-1"
    # Stored hash should be SHA-256 hex (64 chars)
    assert len(r["webhook_secret_hash"]) == 64
    assert r["webhook_secret_hash"] != "secret-xyz"


def test_register_github_app_unique_dedup(engine):
    r1 = engine.register_github_app("org1", "app-42", "inst-1", "secret-xyz")
    r2 = engine.register_github_app("org1", "app-42", "inst-1", "secret-xyz")
    assert r1["id"] == r2["id"], "registration must be idempotent on (org_id, installation_id)"


def test_register_github_app_refresh_secret(engine):
    r1 = engine.register_github_app("org1", "app-42", "inst-1", "secret-A")
    r2 = engine.register_github_app("org1", "app-42", "inst-1", "secret-B")
    assert r1["id"] == r2["id"]
    assert r1["webhook_secret_hash"] != r2["webhook_secret_hash"]


def test_register_github_app_different_orgs_no_collision(engine):
    r1 = engine.register_github_app("org1", "app-42", "inst-1", "secret-1")
    r2 = engine.register_github_app("org2", "app-42", "inst-1", "secret-1")
    assert r1["id"] != r2["id"]


def test_register_github_app_missing_fields(engine):
    with pytest.raises(ValueError):
        engine.register_github_app("", "app-1", "inst-1", "secret")
    with pytest.raises(ValueError):
        engine.register_github_app("org1", "", "inst-1", "secret")
    with pytest.raises(ValueError):
        engine.register_github_app("org1", "app-1", "", "secret")


def test_register_github_app_accepts_pre_hashed(engine):
    pre_hashed = hashlib.sha256(b"raw-secret").hexdigest()
    r = engine.register_github_app("org1", "app-1", "inst-1", pre_hashed)
    assert r["webhook_secret_hash"] == pre_hashed


# ---------------------------------------------------------------------------
# 2. list_github_app_installations / org_id isolation
# ---------------------------------------------------------------------------


def test_list_installations_org_isolation(engine):
    engine.register_github_app("orgA", "app-1", "inst-A1", "s1")
    engine.register_github_app("orgA", "app-2", "inst-A2", "s2")
    engine.register_github_app("orgB", "app-1", "inst-B1", "s3")
    a = engine.list_github_app_installations("orgA")
    b = engine.list_github_app_installations("orgB")
    assert len(a) == 2
    assert len(b) == 1
    assert all(r["org_id"] == "orgA" for r in a)
    assert all(r["org_id"] == "orgB" for r in b)


def test_list_installations_empty(engine):
    assert engine.list_github_app_installations("nobody") == []


# ---------------------------------------------------------------------------
# 3. HMAC webhook verification
# ---------------------------------------------------------------------------


def test_verify_webhook_happy_path(engine):
    r = engine.register_github_app("org1", "app-1", "inst-1", "super-secret")
    payload = b'{"action":"opened","pull_request":{"id":1}}'
    key = r["webhook_secret_hash"].encode("utf-8")
    sig = hmac.new(key, payload, hashlib.sha256).hexdigest()
    assert engine.verify_webhook(payload, f"sha256={sig}", "inst-1") is True


def test_verify_webhook_without_prefix(engine):
    r = engine.register_github_app("org1", "app-1", "inst-1", "super-secret")
    payload = b"{}"
    key = r["webhook_secret_hash"].encode("utf-8")
    sig = hmac.new(key, payload, hashlib.sha256).hexdigest()
    assert engine.verify_webhook(payload, sig, "inst-1") is True


def test_verify_webhook_tampered_payload(engine):
    r = engine.register_github_app("org1", "app-1", "inst-1", "super-secret")
    payload = b"original"
    key = r["webhook_secret_hash"].encode("utf-8")
    sig = hmac.new(key, payload, hashlib.sha256).hexdigest()
    assert engine.verify_webhook(b"tampered", f"sha256={sig}", "inst-1") is False


def test_verify_webhook_unknown_installation(engine):
    engine.register_github_app("org1", "app-1", "inst-1", "super-secret")
    assert engine.verify_webhook(b"{}", "sha256=deadbeef", "inst-unknown") is False


def test_verify_webhook_missing_inputs(engine):
    engine.register_github_app("org1", "app-1", "inst-1", "super-secret")
    assert engine.verify_webhook(b"", "", "inst-1") is False
    assert engine.verify_webhook(None, "sha256=abc", "inst-1") is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 4. hooks.yaml parsing
# ---------------------------------------------------------------------------


def test_parse_hooks_yaml_valid():
    text = (
        "pre-commit:\n"
        "  block-on: [critical, high]\n"
        "  llm: true\n"
        "pr-gate:\n"
        "  block-on: [critical, secrets]\n"
    )
    out = DevSecOpsEngine.parse_hooks_yaml(text)
    assert out["valid"] is True
    assert out["source"] in {"yaml", "json"}
    assert out["policy"]["pre-commit"]["block-on"] == ["critical", "high"]
    assert out["policy"]["pre-commit"]["llm"] is True
    assert out["policy"]["pr-gate"]["block-on"] == ["critical", "secrets"]


def test_parse_hooks_yaml_valid_json_only_pregate():
    text = json.dumps({"pr-gate": {"block-on": ["critical"]}})
    out = DevSecOpsEngine.parse_hooks_yaml(text)
    assert out["valid"] is True
    assert "pr-gate" in out["policy"]
    assert "pre-commit" not in out["policy"]


def test_parse_hooks_yaml_underscore_aliases():
    text = json.dumps({"pre_commit": {"block_on": ["high"], "llm": False}})
    out = DevSecOpsEngine.parse_hooks_yaml(text)
    assert out["valid"] is True
    assert out["policy"]["pre-commit"]["block-on"] == ["high"]
    assert out["policy"]["pre-commit"]["llm"] is False


def test_parse_hooks_yaml_malformed_block_on_type():
    text = "pre-commit:\n  block-on: not-a-list\n"
    out = DevSecOpsEngine.parse_hooks_yaml(text)
    assert out["valid"] is False
    assert any("must be a list" in e for e in out["errors"])


def test_parse_hooks_yaml_unknown_severity_rejected():
    text = json.dumps({"pre-commit": {"block-on": ["nuclear"]}})
    out = DevSecOpsEngine.parse_hooks_yaml(text)
    assert out["valid"] is False
    assert any("unsupported value" in e for e in out["errors"])


def test_parse_hooks_yaml_unknown_top_level():
    text = json.dumps({"random": {"block-on": ["high"]}})
    out = DevSecOpsEngine.parse_hooks_yaml(text)
    assert out["valid"] is False


def test_parse_hooks_yaml_empty_rejected():
    out = DevSecOpsEngine.parse_hooks_yaml("   ")
    assert out["valid"] is False
    assert "empty document" in out["errors"]


def test_parse_hooks_yaml_non_string_input():
    out = DevSecOpsEngine.parse_hooks_yaml(None)  # type: ignore[arg-type]
    assert out["valid"] is False


def test_parse_hooks_yaml_root_not_mapping():
    out = DevSecOpsEngine.parse_hooks_yaml("[1, 2, 3]")
    assert out["valid"] is False
    assert any("mapping" in e for e in out["errors"])


def test_parse_hooks_yaml_llm_non_bool():
    text = json.dumps({"pre-commit": {"block-on": ["high"], "llm": "yes"}})
    out = DevSecOpsEngine.parse_hooks_yaml(text)
    assert out["valid"] is False
    assert any("llm" in e and "boolean" in e for e in out["errors"])


# ---------------------------------------------------------------------------
# 5. apply_hook_policy idempotency + org_id isolation
# ---------------------------------------------------------------------------


def test_apply_hook_policy_idempotent(engine):
    parsed = engine.parse_hooks_yaml(
        json.dumps({"pre-commit": {"block-on": ["critical"], "llm": True}})
    )
    assert parsed["valid"]
    a = engine.apply_hook_policy("org1", parsed["policy"])
    b = engine.apply_hook_policy("org1", parsed["policy"])
    assert a["hash"] == b["hash"]
    assert b["deduplicated"] is True
    assert a["id"] == b["id"]


def test_apply_hook_policy_org_isolation(engine):
    policy = {"pr-gate": {"block-on": ["critical"]}}
    a = engine.apply_hook_policy("orgA", policy)
    b = engine.apply_hook_policy("orgB", policy)
    assert a["id"] != b["id"]  # different orgs get distinct rows even with same hash
    assert a["hash"] == b["hash"]  # canonical hash is content-based


def test_apply_hook_policy_rejects_empty(engine):
    with pytest.raises(ValueError):
        engine.apply_hook_policy("org1", {})
    with pytest.raises(ValueError):
        engine.apply_hook_policy("", {"pr-gate": {"block-on": ["critical"]}})


def test_get_active_hook_policy_returns_latest(engine):
    p1 = {"pre-commit": {"block-on": ["high"], "llm": False}}
    p2 = {"pre-commit": {"block-on": ["critical"], "llm": True}}
    engine.apply_hook_policy("org1", p1)
    latest = engine.apply_hook_policy("org1", p2)
    active = engine.get_active_hook_policy("org1")
    assert active is not None
    assert active["hash"] == latest["hash"]
    assert active["policy"]["pre-commit"]["block-on"] == ["critical"]


def test_get_active_hook_policy_none_for_unknown_org(engine):
    assert engine.get_active_hook_policy("nobody") is None


# ---------------------------------------------------------------------------
# 6. Endpoint smoke tests
# ---------------------------------------------------------------------------


def test_endpoint_register_and_list(app_client):
    body = {
        "org_id": "demo-org",
        "app_id": "app-1",
        "installation_id": "inst-1",
        "webhook_secret": "shhh-secret-value",
        "app_slug": "aldeci-app",
    }
    r = app_client.post("/api/v1/github-app/register", json=body, headers=_auth_headers())
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["status"] == "ok"
    # Never leak the stored hash
    assert "webhook_secret_hash" not in data["installation"]

    r2 = app_client.get(
        "/api/v1/github-app/installations",
        params={"org_id": "demo-org"},
        headers=_auth_headers(),
    )
    assert r2.status_code == 200
    assert r2.json()["count"] == 1


def test_endpoint_webhook_happy_and_tampered(app_client):
    # Register first
    body = {
        "org_id": "demo-org",
        "app_id": "app-1",
        "installation_id": "inst-1",
        "webhook_secret": "my-webhook-secret",
    }
    reg = app_client.post(
        "/api/v1/github-app/register", json=body, headers=_auth_headers()
    )
    assert reg.status_code == 201

    # Compute expected signature using stored hash as HMAC key
    stored_hash = hashlib.sha256(b"my-webhook-secret").hexdigest()
    payload = b'{"ping":"ok"}'
    sig = hmac.new(stored_hash.encode(), payload, hashlib.sha256).hexdigest()
    headers = {
        **_auth_headers(),
        "X-Hub-Signature-256": f"sha256={sig}",
        "X-Installation-Id": "inst-1",
        "Content-Type": "application/json",
    }
    r = app_client.post("/api/v1/github-app/webhook", content=payload, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["verified"] is True

    # Tamper the signature
    bad_headers = {**headers, "X-Hub-Signature-256": "sha256=deadbeef"}
    r2 = app_client.post(
        "/api/v1/github-app/webhook", content=payload, headers=bad_headers
    )
    assert r2.status_code == 401


def test_endpoint_hooks_parse_and_apply(app_client):
    yaml_text = (
        "pre-commit:\n"
        "  block-on: [critical, secrets]\n"
        "  llm: true\n"
        "pr-gate:\n"
        "  block-on: [critical]\n"
    )

    # Parse
    r = app_client.post(
        "/api/v1/hooks-yaml/parse",
        json={"yaml_text": yaml_text},
        headers=_auth_headers(),
    )
    assert r.status_code == 200, r.text
    assert r.json()["valid"] is True

    # Apply
    r2 = app_client.post(
        "/api/v1/hooks-yaml/apply",
        json={"org_id": "demo-org", "yaml_text": yaml_text},
        headers=_auth_headers(),
    )
    assert r2.status_code == 201, r2.text
    payload = r2.json()
    assert payload["status"] == "ok"
    assert payload["applied"]["policy"]["pre-commit"]["llm"] is True

    # Apply again — dedup
    r3 = app_client.post(
        "/api/v1/hooks-yaml/apply",
        json={"org_id": "demo-org", "yaml_text": yaml_text},
        headers=_auth_headers(),
    )
    assert r3.status_code == 201
    assert r3.json()["applied"]["deduplicated"] is True


def test_endpoint_hooks_apply_invalid_yaml(app_client):
    r = app_client.post(
        "/api/v1/hooks-yaml/apply",
        json={"org_id": "demo-org", "yaml_text": "pre-commit:\n  block-on: 5"},
        headers=_auth_headers(),
    )
    assert r.status_code == 400


def test_endpoint_webhook_missing_headers(app_client):
    body = {
        "org_id": "demo-org",
        "app_id": "app-1",
        "installation_id": "inst-1",
        "webhook_secret": "my-webhook-secret",
    }
    app_client.post("/api/v1/github-app/register", json=body, headers=_auth_headers())
    # Missing both installation_id and signature
    r = app_client.post(
        "/api/v1/github-app/webhook", content=b"{}", headers=_auth_headers()
    )
    assert r.status_code == 400
