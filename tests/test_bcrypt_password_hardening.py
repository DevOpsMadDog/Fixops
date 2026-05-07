"""
Multica #4125 — bcrypt password hardening smoke tests.

Verifies:
1. Signup hashes != plaintext  (bcrypt hash stored, never raw password)
2. Login verifies bcrypt correctly (correct pw → 200, wrong pw → 401)
"""
import pytest
import re
import tempfile
import os


# ---------------------------------------------------------------------------
# Unit-level: UserDB hash / verify contract
# ---------------------------------------------------------------------------

def test_hash_is_not_plaintext():
    """Stored hash must not equal the raw password (bcrypt $2b$ prefix)."""
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[1]))

    from core.user_db import UserDB

    with tempfile.TemporaryDirectory() as tmpdir:
        db = UserDB(db_path=os.path.join(tmpdir, "users.db"))
        raw = "S3cur3P@ssw0rd!"
        hashed = db.hash_password(raw)

        # Must NOT be the plaintext
        assert hashed != raw, "hash must not equal plaintext"
        # Must be a bcrypt hash (starts with $2b$ or $2a$)
        assert re.match(r"^\$2[ab]\$", hashed), f"expected bcrypt hash, got: {hashed[:10]}"
        # Two calls must produce different salts (bcrypt is salted)
        hashed2 = db.hash_password(raw)
        assert hashed != hashed2, "two hashes of the same password must differ (unique salts)"


def test_verify_password_bcrypt():
    """verify_password must accept correct pw and reject wrong pw."""
    from core.user_db import UserDB
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[1]))

    with tempfile.TemporaryDirectory() as tmpdir:
        db = UserDB(db_path=os.path.join(tmpdir, "users.db"))
        raw = "C0rrectHorse#Battery9"
        hashed = db.hash_password(raw)

        assert db.verify_password(raw, hashed) is True, "correct password must verify"
        assert db.verify_password("WrongPassword!", hashed) is False, "wrong password must not verify"
        assert db.verify_password("", hashed) is False, "empty password must not verify"


# ---------------------------------------------------------------------------
# API-level: signup stores bcrypt, login accepts/rejects correctly
# Mount only the auth router on a bare FastAPI() to bypass global auth
# middleware in create_app() — same pattern as test_email_verification.py.
# ---------------------------------------------------------------------------

import os as _os
import sys as _sys
import tempfile as _tempfile
from pathlib import Path as _Path

_ROOT = _Path(__file__).resolve().parents[1]
for _suite in ("suite-api", "suite-core", "suite-attack", "suite-feeds",
               "suite-integrations", "suite-evidence-risk"):
    _p = str(_ROOT / _suite)
    if _p not in _sys.path:
        _sys.path.insert(0, _p)

_os.environ["FIXOPS_JWT_SECRET"] = "test-secret-min-32-chars-for-bcrypt-smoke-tests-4125!!"
_os.environ["FIXOPS_DEV_MODE"] = "false"

_API_TMP = _tempfile.mkdtemp()


@pytest.fixture(scope="module")
def auth_client():
    """Bare FastAPI app with only the auth router — no global auth middleware."""
    import core.user_db as _udb_mod
    import core.email_verification_db as _evdb_mod

    _evdb_mod._DEFAULT_DB = _os.path.join(_API_TMP, "ev_bcrypt_test.db")

    _orig_init = _udb_mod.UserDB.__init__

    def _patched_init(self, db_path=None):
        _orig_init(self, db_path=_os.path.join(_API_TMP, "users_bcrypt_test.db"))

    _udb_mod.UserDB.__init__ = _patched_init

    import apps.api.auth_router as _ar
    _ar._ev_db = None
    _ar._user_db = _udb_mod.UserDB()

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    app = FastAPI()
    app.include_router(_ar.router)
    return TestClient(app, raise_server_exceptions=True)


def test_signup_hash_not_plaintext_via_api(auth_client):
    """POST /api/v1/auth/signup must store a bcrypt hash, not the raw password."""
    import uuid
    email = f"bcrypt-api-{uuid.uuid4().hex[:8]}@aldeci.test"
    raw_pw = "ApiSmoke#Hash99"

    r = auth_client.post("/api/v1/auth/signup", json={
        "email": email,
        "password": raw_pw,
        "first_name": "Hash",
        "last_name": "Smoke",
    })
    assert r.status_code == 201, f"signup failed: {r.status_code} {r.text}"
    body = r.json()
    assert "user_id" in body

    # Retrieve the stored hash directly from UserDB and confirm it is bcrypt
    import core.user_db as _udb_mod
    db = _udb_mod.UserDB()
    stored_user = db.get_user_by_email(email)
    assert stored_user is not None, "user must exist after signup"
    stored_hash = stored_user.password_hash

    assert stored_hash != raw_pw, "stored hash must not equal plaintext password"
    assert re.match(r"^\$2[ab]\$", stored_hash), (
        f"expected bcrypt hash ($2b$...), got: {stored_hash[:12]}"
    )


def test_login_bcrypt_verify_via_api(auth_client):
    """
    Signup then login:
      - correct password → 200 with access_token (JWT, not raw pw)
      - wrong password   → 401
    """
    import uuid
    email = f"bcrypt-login-{uuid.uuid4().hex[:8]}@aldeci.test"
    pw = "Sm0keTest#2025"

    # Signup
    r = auth_client.post("/api/v1/auth/signup", json={
        "email": email,
        "password": pw,
        "first_name": "Bcrypt",
        "last_name": "Login",
    })
    assert r.status_code == 201, f"signup failed: {r.status_code} {r.text}"

    # Login with correct password → 200 + access_token
    r_ok = auth_client.post("/api/v1/auth/login", json={"email": email, "password": pw})
    assert r_ok.status_code == 200, f"login failed: {r_ok.status_code} {r_ok.text}"
    body = r_ok.json()
    assert "access_token" in body, "access_token missing from login response"
    assert body["access_token"] != pw, "access_token must not be the raw password"

    # Login with wrong password → 401
    r_bad = auth_client.post("/api/v1/auth/login", json={"email": email, "password": "WrongPw!"})
    assert r_bad.status_code == 401, (
        f"expected 401 for wrong password, got {r_bad.status_code}"
    )
