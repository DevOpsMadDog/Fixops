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

import pytest
from fastapi.testclient import TestClient

# Ensure suite paths are available
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Point DBs at temp files so tests don't pollute real data
_TMP_DIR = tempfile.mkdtemp()
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-min-32-chars-for-smoke-tests!!")
os.environ["FIXOPS_DEV_MODE"] = "false"


@pytest.fixture(scope="module")
def client():
    """Return a TestClient with DBs wired to temp files."""
    import importlib

    # Patch EmailVerificationDB path before importing auth_router
    from core import email_verification_db as _evdb_mod
    _evdb_mod._DEFAULT_DB = os.path.join(_TMP_DIR, "ev_test.db")

    # Patch UserDB path
    from core import user_db as _udb_mod
    _orig_init = _udb_mod.UserDB.__init__

    def _patched_init(self, db_path=None):
        _orig_init(self, db_path=os.path.join(_TMP_DIR, "users_test.db"))

    _udb_mod.UserDB.__init__ = _patched_init

    # Reset lazy singleton so it picks up patched path
    import suite_api.apps.api.auth_router as _ar
    _ar._ev_db = None
    _ar._user_db = _udb_mod.UserDB()

    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(_ar.router)
    return TestClient(app, raise_server_exceptions=True)


# ── helpers ──────────────────────────────────────────────────────────────────

def _unique_email() -> str:
    return f"smoke_{uuid.uuid4().hex[:8]}@test.example"


# ── test 1: signup creates user + token ──────────────────────────────────────

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
    assert "user_id" in body
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

    # 2b — extract token directly from DB (SMTP not wired in tests)
    from core.email_verification_db import EmailVerificationDB
    import sqlite3
    ev_db_path = os.path.join(_TMP_DIR, "ev_test.db")
    conn = sqlite3.connect(ev_db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT token FROM verification_tokens WHERE user_id=? AND used=0 ORDER BY rowid DESC LIMIT 1",
        (user_id,),
    ).fetchone()
    conn.close()
    assert row is not None, "No token found for newly signed-up user"
    token = row["token"]

    # 2c — verify
    resp2 = client.get(f"/api/v1/auth/verify-email/{token}")
    assert resp2.status_code == 200, resp2.text
    body2 = resp2.json()
    assert body2["email_verified"] is True
    assert body2["user_id"] == user_id
    assert body2["email"] == email

    # 2d — reuse token → 400
    resp3 = client.get(f"/api/v1/auth/verify-email/{token}")
    assert resp3.status_code == 400
    assert "invalid" in resp3.json()["detail"].lower() or "expired" in resp3.json()["detail"].lower()
