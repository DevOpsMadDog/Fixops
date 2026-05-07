"""
Smoke tests for email verification flow — Multica #4114.

Tests:
  1. POST /api/v1/auth/signup → 201, token generated, email_verified=False
  2. GET  /api/v1/auth/verify-email/{token} → 200, email_verified=True
     (also covers: reuse of consumed token → 400)
"""
from __future__ import annotations

import os
import sys
import tempfile
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Inject suite paths the same way sitecustomize.py does
_ROOT = Path(__file__).resolve().parents[1]
for _suite in ("suite-api", "suite-core", "suite-attack", "suite-feeds",
               "suite-integrations", "suite-evidence-risk"):
    _p = str(_ROOT / _suite)
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-min-32-chars-for-smoke-tests!!")
os.environ["FIXOPS_DEV_MODE"] = "false"

_TMP_DIR = tempfile.mkdtemp()


@pytest.fixture(scope="module")
def client():
    """TestClient with DBs wired to temp files so tests don't pollute real data."""
    # Patch EmailVerificationDB default path before first import
    import core.email_verification_db as _evdb_mod
    _evdb_mod._DEFAULT_DB = os.path.join(_TMP_DIR, "ev_test.db")

    # Patch UserDB to use temp db
    import core.user_db as _udb_mod
    _orig_init = _udb_mod.UserDB.__init__

    def _patched_init(self, db_path=None):
        _orig_init(self, db_path=os.path.join(_TMP_DIR, "users_test.db"))

    _udb_mod.UserDB.__init__ = _patched_init

    import apps.api.auth_router as _ar
    # Reset lazy singletons to pick up patched paths
    _ar._ev_db = None
    _ar._user_db = _udb_mod.UserDB()

    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(_ar.router)
    return TestClient(app, raise_server_exceptions=True)


def _unique_email() -> str:
    return f"smoke_{uuid.uuid4().hex[:8]}@test.example"


# ── test 1: signup creates user and returns email_verified=False ──────────────

def test_signup_creates_user_and_returns_unverified(client):
    payload = {
        "email": _unique_email(),
        "password": "Str0ngP@ssword!",
        "first_name": "Smoke",
        "last_name": "Test",
    }
    resp = client.post("/api/v1/auth/signup", json=payload)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["email"] == payload["email"]
    assert body["email_verified"] is False
    assert body["user_id"]  # non-empty UUID


# ── test 2: verify-email round-trip ──────────────────────────────────────────

def test_verify_email_roundtrip(client):
    email = _unique_email()
    # 2a — signup
    resp = client.post("/api/v1/auth/signup", json={
        "email": email,
        "password": "Str0ngP@ssword!",
        "first_name": "Alice",
        "last_name": "Verify",
    })
    assert resp.status_code == 201, resp.text
    user_id = resp.json()["user_id"]

    # 2b — pull token directly from DB (SMTP not wired in tests)
    import sqlite3
    import apps.api.auth_router as _ar2
    ev_db_path = str(_ar2._get_ev_db()._db)
    conn = sqlite3.connect(ev_db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT token FROM verification_tokens WHERE user_id=? AND used=0 "
        "ORDER BY rowid DESC LIMIT 1",
        (user_id,),
    ).fetchone()
    conn.close()
    assert row is not None, "No token found for newly signed-up user"
    token = row["token"]

    # 2c — verify: 200 + email_verified=true
    resp2 = client.get(f"/api/v1/auth/verify-email/{token}")
    assert resp2.status_code == 200, resp2.text
    body2 = resp2.json()
    assert body2["email_verified"] is True
    assert body2["user_id"] == user_id
    assert body2["email"] == email

    # 2d — reuse consumed token → 400
    resp3 = client.get(f"/api/v1/auth/verify-email/{token}")
    assert resp3.status_code == 400
    detail = resp3.json()["detail"].lower()
    assert "invalid" in detail or "expired" in detail or "used" in detail
