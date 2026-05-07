"""
Smoke tests for forgot-password / reset-password flow — Multica #4127.

Tests:
  1. POST /api/v1/auth/forgot-password → 200 (even for unknown email — no enumeration)
  2. POST /api/v1/auth/forgot-password with known email → token in DB
  3. POST /api/v1/auth/reset-password with valid token → 200, can login with new password
  4. POST /api/v1/auth/reset-password with bad/expired token → 400
  5. Token single-use: second reset with same token → 400
"""
from __future__ import annotations

import os
import sys
import sqlite3
import tempfile
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

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
    """TestClient with all DBs wired to temp files."""
    import core.password_reset_db as _prdb_mod
    _prdb_mod._DEFAULT_DB = os.path.join(_TMP_DIR, "pr_test.db")

    import core.email_verification_db as _evdb_mod
    _evdb_mod._DEFAULT_DB = os.path.join(_TMP_DIR, "ev_test2.db")

    import core.user_db as _udb_mod
    _orig_init = _udb_mod.UserDB.__init__

    def _patched_init(self, db_path=None):
        _orig_init(self, db_path=os.path.join(_TMP_DIR, "users_test2.db"))

    _udb_mod.UserDB.__init__ = _patched_init

    import apps.api.auth_router as _ar
    _ar._ev_db = None
    _ar._pr_db = None
    _ar._user_db = _udb_mod.UserDB()

    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(_ar.router)
    return TestClient(app, raise_server_exceptions=True)


def _unique_email() -> str:
    return f"pr_{uuid.uuid4().hex[:8]}@test.example"


def _create_user(client, email: str, password: str = "Str0ngP@ssword!") -> str:
    """Signup a user and return their user_id."""
    resp = client.post("/api/v1/auth/signup", json={
        "email": email,
        "password": password,
        "first_name": "Smoke",
        "last_name": "Reset",
    })
    assert resp.status_code == 201, resp.text
    return resp.json()["user_id"]


# ── test 1: unknown email returns 200 (no enumeration) ────────────────────────

def test_forgot_password_unknown_email_no_enumeration(client):
    resp = client.post("/api/v1/auth/forgot-password", json={
        "email": "nonexistent_xyzzy_9999@nowhere.invalid"
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "message" in body


# ── test 2: known email → token present in DB ─────────────────────────────────

def test_forgot_password_known_email_creates_token(client):
    email = _unique_email()
    _create_user(client, email)

    resp = client.post("/api/v1/auth/forgot-password", json={"email": email})
    assert resp.status_code == 200, resp.text

    import apps.api.auth_router as _ar
    pr_db_path = str(_ar._get_pr_db()._db)
    conn = sqlite3.connect(pr_db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT token FROM password_reset_tokens WHERE email=? AND used=0 "
        "ORDER BY rowid DESC LIMIT 1",
        (email,),
    ).fetchone()
    conn.close()
    assert row is not None, "No reset token created for known email"


# ── test 3: valid token → password changed, can login with new password ────────

def test_reset_password_valid_token(client):
    email = _unique_email()
    old_password = "Str0ngP@ssword!"
    new_password = "N3wS3cur3P@ss!"

    _create_user(client, email, old_password)

    client.post("/api/v1/auth/forgot-password", json={"email": email})

    import apps.api.auth_router as _ar
    pr_db_path = str(_ar._get_pr_db()._db)
    conn = sqlite3.connect(pr_db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT token FROM password_reset_tokens WHERE email=? AND used=0 "
        "ORDER BY rowid DESC LIMIT 1",
        (email,),
    ).fetchone()
    conn.close()
    assert row is not None
    token = row["token"]

    resp = client.post("/api/v1/auth/reset-password", json={
        "token": token,
        "new_password": new_password,
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body.get("message") or body.get("status")

    # Can now login with new password
    login_resp = client.post("/api/v1/auth/login", json={
        "email": email,
        "password": new_password,
    })
    assert login_resp.status_code == 200, login_resp.text
    assert "access_token" in login_resp.json()

    # Old password rejected
    old_login = client.post("/api/v1/auth/login", json={
        "email": email,
        "password": old_password,
    })
    assert old_login.status_code == 401


# ── test 4: bad token → 400 ───────────────────────────────────────────────────

def test_reset_password_invalid_token(client):
    resp = client.post("/api/v1/auth/reset-password", json={
        "token": str(uuid.uuid4()),
        "new_password": "DoesNotMatter1!",
    })
    assert resp.status_code == 400, resp.text


# ── test 5: token single-use ──────────────────────────────────────────────────

def test_reset_password_token_single_use(client):
    email = _unique_email()
    _create_user(client, email)
    client.post("/api/v1/auth/forgot-password", json={"email": email})

    import apps.api.auth_router as _ar
    pr_db_path = str(_ar._get_pr_db()._db)
    conn = sqlite3.connect(pr_db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT token FROM password_reset_tokens WHERE email=? AND used=0 "
        "ORDER BY rowid DESC LIMIT 1",
        (email,),
    ).fetchone()
    conn.close()
    token = row["token"]

    # First use → success
    r1 = client.post("/api/v1/auth/reset-password", json={
        "token": token, "new_password": "FirstReset1!"
    })
    assert r1.status_code == 200

    # Second use → 400
    r2 = client.post("/api/v1/auth/reset-password", json={
        "token": token, "new_password": "SecondReset1!"
    })
    assert r2.status_code == 400
