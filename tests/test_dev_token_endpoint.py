"""Tests for /api/v1/auth/dev-token — Playwright NO MOCKS unblock.

Validates:
- 403 when FIXOPS_DEV_MODE is unset/false (production-safe)
- 200 with default body when FIXOPS_DEV_MODE=true
- 200 with custom body
- Returned JWT decodes successfully + has correct claims
- Audit row created on every mint
- Audit table has correct columns
- Cross-tenant isolation in audit (org_id_a vs org_id_b distinct rows)
- Smoke: token works against /api/v1/security-findings/findings
"""
from __future__ import annotations

import importlib
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Test JWT secret — must be >= 32 chars to satisfy auth_deps validation
# ---------------------------------------------------------------------------
_TEST_JWT_SECRET = "test-secret-for-dev-token-tests-min-32-chars-long-enough"


def _isolated_audit_db(tmp_path: Path) -> Path:
    return tmp_path / "dev_token_audit.db"


@pytest.fixture(autouse=True)
def _isolate_auth_router_only(monkeypatch):
    """Snapshot env, then on teardown reload auth_deps so its module-level
    JWT_SECRET / API_TOKEN constants reset to whatever the post-test env is.

    Drop auth_router from sys.modules so a future re-import binds against the
    refreshed auth_deps. We use importlib.reload (in-place mutation) instead
    of sys.modules.pop because other tests hold module-level references to
    functions in auth_deps (test_rbac_enforcement imports api_key_auth at top).
    """
    snap = {
        "FIXOPS_JWT_SECRET": os.environ.get("FIXOPS_JWT_SECRET"),
        "FIXOPS_API_TOKEN": os.environ.get("FIXOPS_API_TOKEN"),
        "FIXOPS_DEV_MODE": os.environ.get("FIXOPS_DEV_MODE"),
        "FIXOPS_MODE": os.environ.get("FIXOPS_MODE"),
    }
    yield
    # Restore env to pre-test snapshot.
    for k, v in snap.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    # Drop router modules so future re-imports rebuild against current env.
    for mod in ("apps.api.auth_router", "apps.api.security_findings_router"):
        sys.modules.pop(mod, None)
    # Reload auth_deps in-place so its frozen module-level constants reset.
    auth_deps_mod = sys.modules.get("apps.api.auth_deps")
    if auth_deps_mod is not None:
        try:
            importlib.reload(auth_deps_mod)
        except (ImportError, AttributeError):
            pass


def _build_app(monkeypatch, tmp_path: Path, *, dev_mode: bool):
    """Reload auth_router with the requested env config and mount it on a fresh FastAPI."""
    audit_db = _isolated_audit_db(tmp_path)
    monkeypatch.setenv("FIXOPS_DEV_TOKEN_AUDIT_DB", str(audit_db))
    monkeypatch.setenv("FIXOPS_JWT_SECRET", _TEST_JWT_SECRET)
    if dev_mode:
        monkeypatch.setenv("FIXOPS_DEV_MODE", "true")
    else:
        monkeypatch.delenv("FIXOPS_DEV_MODE", raising=False)

    # Force re-import so module-level constants pick up the new env.
    sys.modules.pop("apps.api.auth_router", None)
    auth_router_mod = importlib.import_module("apps.api.auth_router")

    app = FastAPI()
    app.include_router(auth_router_mod.router)
    return app, auth_router_mod, audit_db


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_403_when_dev_mode_unset(monkeypatch, tmp_path):
    """Production-safety: endpoint must 403 when FIXOPS_DEV_MODE is unset."""
    app, _, _ = _build_app(monkeypatch, tmp_path, dev_mode=False)
    client = TestClient(app)
    r = client.post("/api/v1/auth/dev-token", json={})
    assert r.status_code == 403
    assert r.json()["detail"] == "dev mode disabled"


def test_403_when_dev_mode_explicit_false(monkeypatch, tmp_path):
    """Endpoint must 403 when FIXOPS_DEV_MODE is explicitly 'false'."""
    monkeypatch.setenv("FIXOPS_DEV_MODE", "false")
    app, _, _ = _build_app(monkeypatch, tmp_path, dev_mode=False)
    monkeypatch.setenv("FIXOPS_DEV_MODE", "false")
    client = TestClient(app)
    r = client.post("/api/v1/auth/dev-token", json={})
    assert r.status_code == 403


def test_200_with_default_body(monkeypatch, tmp_path):
    """Default request body returns a valid token bundle."""
    app, _, _ = _build_app(monkeypatch, tmp_path, dev_mode=True)
    client = TestClient(app)
    r = client.post("/api/v1/auth/dev-token", json={})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 3600
    assert body["access_token"]
    assert body["user"]["org_id"] == "default"
    assert body["user"]["role"] == "admin"
    assert body["user"]["email"] == "dev@verify"
    assert "admin:all" in body["user"]["scopes"]


def test_200_with_custom_body(monkeypatch, tmp_path):
    """Custom org_id/role/email round-trip into the response payload."""
    app, _, _ = _build_app(monkeypatch, tmp_path, dev_mode=True)
    client = TestClient(app)
    r = client.post(
        "/api/v1/auth/dev-token",
        json={"org_id": "acme-corp", "role": "analyst", "email": "alice@acme"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user"]["org_id"] == "acme-corp"
    assert body["user"]["role"] == "analyst"
    assert body["user"]["email"] == "alice@acme"
    assert "read:findings" in body["user"]["scopes"]
    assert "admin:all" not in body["user"]["scopes"]


def test_token_decodes_with_correct_claims(monkeypatch, tmp_path):
    """JWT must decode using FIXOPS_JWT_SECRET and contain the expected claims."""
    app, _, _ = _build_app(monkeypatch, tmp_path, dev_mode=True)
    client = TestClient(app)
    r = client.post(
        "/api/v1/auth/dev-token",
        json={"org_id": "tenant-a", "role": "admin", "email": "ops@tenant-a"},
    )
    assert r.status_code == 200
    token = r.json()["access_token"]
    claims = jwt.decode(
        token,
        _TEST_JWT_SECRET,
        algorithms=["HS256"],
        options={"require": ["exp", "iat", "sub"]},
    )
    assert claims["sub"] == "dev-ops@tenant-a"
    assert claims["email"] == "ops@tenant-a"
    assert claims["role"] == "admin"
    assert claims["org_id"] == "tenant-a"
    assert claims["dev_token"] is True
    # TTL should be ~3600s
    assert claims["exp"] - claims["iat"] == 3600


def test_audit_row_created_on_mint(monkeypatch, tmp_path):
    """Every mint must insert an audit row."""
    app, _, audit_db = _build_app(monkeypatch, tmp_path, dev_mode=True)
    client = TestClient(app)
    r = client.post(
        "/api/v1/auth/dev-token",
        json={"org_id": "auditable", "role": "admin", "email": "auditor@x"},
    )
    assert r.status_code == 200
    assert audit_db.exists()
    conn = sqlite3.connect(str(audit_db))
    rows = conn.execute("SELECT org_id, role, email FROM dev_token_audit").fetchall()
    conn.close()
    assert len(rows) == 1
    assert rows[0] == ("auditable", "admin", "auditor@x")


def test_audit_table_has_correct_columns(monkeypatch, tmp_path):
    """Audit table schema must contain id, org_id, role, email, minted_at, ip."""
    app, _, audit_db = _build_app(monkeypatch, tmp_path, dev_mode=True)
    client = TestClient(app)
    client.post("/api/v1/auth/dev-token", json={})
    conn = sqlite3.connect(str(audit_db))
    cols = [r[1] for r in conn.execute("PRAGMA table_info(dev_token_audit)").fetchall()]
    conn.close()
    assert set(cols) == {"id", "org_id", "role", "email", "minted_at", "ip"}


def test_audit_minted_at_is_iso_utc(monkeypatch, tmp_path):
    """minted_at must be parseable ISO 8601 UTC timestamp."""
    app, _, audit_db = _build_app(monkeypatch, tmp_path, dev_mode=True)
    client = TestClient(app)
    client.post("/api/v1/auth/dev-token", json={})
    conn = sqlite3.connect(str(audit_db))
    ts = conn.execute("SELECT minted_at FROM dev_token_audit").fetchone()[0]
    conn.close()
    parsed = datetime.fromisoformat(ts)
    assert parsed.tzinfo is not None
    # Should be very recent
    now = datetime.now(timezone.utc)
    assert abs((now - parsed).total_seconds()) < 60


def test_cross_tenant_isolation_in_audit(monkeypatch, tmp_path):
    """Two mints with different org_ids must produce two distinct audit rows."""
    app, _, audit_db = _build_app(monkeypatch, tmp_path, dev_mode=True)
    client = TestClient(app)
    r1 = client.post("/api/v1/auth/dev-token", json={"org_id": "org-a"})
    r2 = client.post("/api/v1/auth/dev-token", json={"org_id": "org-b"})
    assert r1.status_code == 200 and r2.status_code == 200
    conn = sqlite3.connect(str(audit_db))
    rows_a = conn.execute(
        "SELECT id FROM dev_token_audit WHERE org_id = ?", ("org-a",)
    ).fetchall()
    rows_b = conn.execute(
        "SELECT id FROM dev_token_audit WHERE org_id = ?", ("org-b",)
    ).fetchall()
    conn.close()
    assert len(rows_a) == 1
    assert len(rows_b) == 1
    assert rows_a[0][0] != rows_b[0][0]  # Distinct UUIDs


def test_multiple_mints_create_multiple_audit_rows(monkeypatch, tmp_path):
    """N mints → N audit rows (no dedup)."""
    app, _, audit_db = _build_app(monkeypatch, tmp_path, dev_mode=True)
    client = TestClient(app)
    for _ in range(5):
        r = client.post("/api/v1/auth/dev-token", json={})
        assert r.status_code == 200
    conn = sqlite3.connect(str(audit_db))
    count = conn.execute("SELECT COUNT(*) FROM dev_token_audit").fetchone()[0]
    conn.close()
    assert count == 5


def test_token_works_against_findings_endpoint(monkeypatch, tmp_path):
    """Smoke: minted JWT must authenticate against /api/v1/security-findings/findings.

    Sets env first, then forces a fresh load of auth_deps + auth_router so both
    use the same JWT secret. Teardown fixture reloads auth_deps to restore env.
    """
    audit_db = _isolated_audit_db(tmp_path)
    monkeypatch.setenv("FIXOPS_DEV_TOKEN_AUDIT_DB", str(audit_db))
    monkeypatch.setenv("FIXOPS_JWT_SECRET", _TEST_JWT_SECRET)
    monkeypatch.setenv("FIXOPS_DEV_MODE", "true")
    monkeypatch.delenv("FIXOPS_API_TOKEN", raising=False)

    # Force fresh load of auth_deps so its module-level _JWT_SECRET is OUR secret.
    auth_deps_mod = sys.modules.get("apps.api.auth_deps")
    if auth_deps_mod is not None:
        importlib.reload(auth_deps_mod)
    else:
        importlib.import_module("apps.api.auth_deps")

    sys.modules.pop("apps.api.auth_router", None)
    sys.modules.pop("apps.api.security_findings_router", None)
    auth_router_mod = importlib.import_module("apps.api.auth_router")
    findings_router_mod = importlib.import_module("apps.api.security_findings_router")

    app = FastAPI()
    app.include_router(auth_router_mod.router)
    app.include_router(findings_router_mod.router)
    client = TestClient(app)

    r = client.post(
        "/api/v1/auth/dev-token",
        json={"org_id": "smoke", "role": "admin", "email": "smoke@verify"},
    )
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]

    r2 = client.get(
        "/api/v1/security-findings/findings",
        params={"org_id": "smoke"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r2.status_code not in (401, 403), (
        f"JWT rejected by api_key_auth: HTTP {r2.status_code} body={r2.text}"
    )


def test_dev_token_response_schema_complete(monkeypatch, tmp_path):
    """Response payload must contain all documented fields."""
    app, _, _ = _build_app(monkeypatch, tmp_path, dev_mode=True)
    client = TestClient(app)
    r = client.post("/api/v1/auth/dev-token", json={})
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) >= {"access_token", "token_type", "expires_in", "user"}
    assert set(body["user"].keys()) >= {"sub", "email", "role", "org_id", "scopes"}
