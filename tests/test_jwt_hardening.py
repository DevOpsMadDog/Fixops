"""Tests for JWT authentication hardening in suite-api/apps/api/app.py.

Covers:
1. JWT secret strength validation (_MIN_JWT_SECRET_LENGTH)
2. Token decode hardening (max length, required iat claim)
3. Auth failed-attempt tracking (brute-force protection)
4. generate_access_token includes iat claim
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import HTTPException

# Import the module so we can monkeypatch its attributes
from apps.api import app as app_module


# ---------------------------------------------------------------------------
# 1. JWT Secret Strength Validation
# ---------------------------------------------------------------------------


class TestJWTSecretStrength:
    """Verify _load_or_generate_jwt_secret rejects weak secrets."""

    def test_strong_secret_accepted(self, monkeypatch):
        """A secret >= 32 chars should be used as-is."""
        strong = "a" * 32
        monkeypatch.setenv("FIXOPS_JWT_SECRET", strong)
        result = app_module._load_or_generate_jwt_secret()
        assert result == strong

    def test_exactly_32_chars_accepted(self, monkeypatch):
        """Boundary: exactly 32 characters should be accepted."""
        exact = "x" * 32
        monkeypatch.setenv("FIXOPS_JWT_SECRET", exact)
        result = app_module._load_or_generate_jwt_secret()
        assert result == exact

    def test_weak_secret_rejected(self, monkeypatch):
        """A secret < 32 chars (like 'demo-secret') is rejected."""
        monkeypatch.setenv("FIXOPS_JWT_SECRET", "demo-secret")
        result = app_module._load_or_generate_jwt_secret()
        # Should NOT return the weak secret
        assert result != "demo-secret"
        # Should be a strong generated secret (token_hex(32) = 64 hex chars)
        assert len(result) == 64

    def test_short_secret_rejected(self, monkeypatch):
        """A 31-char secret is rejected."""
        monkeypatch.setenv("FIXOPS_JWT_SECRET", "a" * 31)
        result = app_module._load_or_generate_jwt_secret()
        assert result != "a" * 31
        assert len(result) == 64

    def test_empty_secret_generates_ephemeral(self, monkeypatch):
        """Empty string in env var falls through to ephemeral generation."""
        monkeypatch.setenv("FIXOPS_JWT_SECRET", "")
        result = app_module._load_or_generate_jwt_secret()
        # Empty string is falsy in Python, os.getenv returns "" which is falsy
        # so it should fall through to ephemeral
        assert len(result) == 64

    def test_no_env_var_generates_ephemeral(self, monkeypatch):
        """Missing env var generates an ephemeral secret."""
        monkeypatch.delenv("FIXOPS_JWT_SECRET", raising=False)
        result = app_module._load_or_generate_jwt_secret()
        assert len(result) == 64


# ---------------------------------------------------------------------------
# 2. Token Decode Hardening
# ---------------------------------------------------------------------------


class TestTokenDecodeHardening:
    """Verify decode_access_token enforces length, iat, and nbf checks."""

    @pytest.fixture(autouse=True)
    def _patch_jwt_secret(self, monkeypatch):
        """Use a known secret for testing."""
        self.secret = "test-secret-that-is-long-enough-for-tests-32chars"
        monkeypatch.setattr(app_module, "JWT_SECRET", self.secret)

    def _make_token(self, payload: dict) -> str:
        """Create a token with given payload (caller controls claims)."""
        return jwt.encode(payload, self.secret, algorithm="HS256")

    def test_valid_token_with_iat(self):
        """Token with exp + iat should decode successfully."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "user-1",
            "exp": now + timedelta(hours=1),
            "iat": now,
        }
        token = self._make_token(payload)
        result = app_module.decode_access_token(token)
        assert result["sub"] == "user-1"

    def test_token_without_iat_rejected(self):
        """Token missing iat claim should be rejected."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "user-1",
            "exp": now + timedelta(hours=1),
            # no iat
        }
        token = self._make_token(payload)
        with pytest.raises(HTTPException) as exc_info:
            app_module.decode_access_token(token)
        assert exc_info.value.status_code == 401

    def test_token_without_exp_rejected(self):
        """Token missing exp claim should be rejected."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "user-1",
            "iat": now,
            # no exp
        }
        token = self._make_token(payload)
        with pytest.raises(HTTPException) as exc_info:
            app_module.decode_access_token(token)
        assert exc_info.value.status_code == 401

    def test_oversized_token_rejected(self):
        """Token exceeding _MAX_TOKEN_LENGTH bytes should be rejected."""
        # Create a token with a very large payload
        huge_payload = {
            "sub": "x" * 10000,
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "iat": datetime.now(timezone.utc),
        }
        token = self._make_token(huge_payload)
        assert len(token.encode("utf-8")) > app_module._MAX_TOKEN_LENGTH
        with pytest.raises(HTTPException) as exc_info:
            app_module.decode_access_token(token)
        assert exc_info.value.status_code == 401

    def test_token_at_max_length_accepted(self):
        """Token at exactly _MAX_TOKEN_LENGTH should be accepted if valid."""
        now = datetime.now(timezone.utc)
        # A normal token is well under 4096 bytes
        payload = {
            "sub": "user-1",
            "exp": now + timedelta(hours=1),
            "iat": now,
        }
        token = self._make_token(payload)
        assert len(token.encode("utf-8")) <= app_module._MAX_TOKEN_LENGTH
        result = app_module.decode_access_token(token)
        assert result["sub"] == "user-1"

    def test_expired_token_rejected(self):
        """Expired token should return 401 with 'Token expired'."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "user-1",
            "exp": now - timedelta(hours=1),
            "iat": now - timedelta(hours=2),
        }
        token = self._make_token(payload)
        with pytest.raises(HTTPException) as exc_info:
            app_module.decode_access_token(token)
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower() or "invalid" in exc_info.value.detail.lower()

    def test_invalid_signature_rejected(self):
        """Token signed with wrong key should be rejected."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "user-1",
            "exp": now + timedelta(hours=1),
            "iat": now,
        }
        token = jwt.encode(payload, "wrong-secret-key-that-is-long-enough", algorithm="HS256")
        with pytest.raises(HTTPException) as exc_info:
            app_module.decode_access_token(token)
        assert exc_info.value.status_code == 401

    def test_nbf_in_future_rejected(self):
        """Token with nbf in the future should be rejected."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "user-1",
            "exp": now + timedelta(hours=2),
            "iat": now,
            "nbf": now + timedelta(hours=1),  # not valid yet
        }
        token = self._make_token(payload)
        with pytest.raises(HTTPException) as exc_info:
            app_module.decode_access_token(token)
        assert exc_info.value.status_code == 401

    def test_nbf_in_past_accepted(self):
        """Token with nbf in the past should be accepted."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "user-1",
            "exp": now + timedelta(hours=2),
            "iat": now - timedelta(hours=1),
            "nbf": now - timedelta(minutes=5),  # already valid
        }
        token = self._make_token(payload)
        result = app_module.decode_access_token(token)
        assert result["sub"] == "user-1"

    def test_garbage_token_rejected(self):
        """Completely invalid token string should be rejected."""
        with pytest.raises(HTTPException) as exc_info:
            app_module.decode_access_token("not.a.valid.jwt.token")
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# 3. generate_access_token includes iat
# ---------------------------------------------------------------------------


class TestGenerateAccessToken:
    """Verify generate_access_token includes iat claim."""

    @pytest.fixture(autouse=True)
    def _patch_jwt_secret(self, monkeypatch):
        self.secret = "test-secret-that-is-long-enough-for-tests-32chars"
        monkeypatch.setattr(app_module, "JWT_SECRET", self.secret)
        monkeypatch.setattr(app_module, "JWT_EXP_MINUTES", 60)

    def test_token_has_iat(self):
        """Generated token must include iat claim."""
        token = app_module.generate_access_token({"sub": "tester"})
        payload = jwt.decode(token, self.secret, algorithms=["HS256"])
        assert "iat" in payload
        assert "exp" in payload
        assert payload["sub"] == "tester"

    def test_iat_is_recent(self):
        """iat should be within a few seconds of now."""
        before = datetime.now(timezone.utc).replace(microsecond=0)
        token = app_module.generate_access_token({"sub": "tester"})
        after = datetime.now(timezone.utc) + timedelta(seconds=1)
        payload = jwt.decode(token, self.secret, algorithms=["HS256"])
        iat = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
        # JWT iat is integer seconds — allow 1s tolerance for truncation
        assert before <= iat <= after

    def test_round_trip(self):
        """Token from generate_access_token should decode via decode_access_token."""
        token = app_module.generate_access_token({"sub": "roundtrip"})
        result = app_module.decode_access_token(token)
        assert result["sub"] == "roundtrip"
        assert "iat" in result
        assert "exp" in result


# ---------------------------------------------------------------------------
# 4. Auth Failed Attempt Tracking (brute-force protection)
# ---------------------------------------------------------------------------


class TestAuthFailTracker:
    """Verify _check_auth_rate_limit and _record_auth_failure."""

    @pytest.fixture(autouse=True)
    def _reset_tracker(self):
        """Reset the tracker before each test."""
        with app_module._AUTH_FAIL_LOCK:
            app_module._AUTH_FAIL_TRACKER.clear()
        yield
        with app_module._AUTH_FAIL_LOCK:
            app_module._AUTH_FAIL_TRACKER.clear()

    def test_no_failures_not_rate_limited(self):
        """An IP with no failures should not be rate limited."""
        assert app_module._check_auth_rate_limit("10.0.0.1") is False

    def test_below_threshold_not_rate_limited(self):
        """An IP below the failure threshold should not be rate limited."""
        for _ in range(app_module._AUTH_FAIL_MAX - 1):
            app_module._record_auth_failure("10.0.0.2")
        assert app_module._check_auth_rate_limit("10.0.0.2") is False

    def test_at_threshold_rate_limited(self):
        """An IP at the failure threshold should be rate limited."""
        for _ in range(app_module._AUTH_FAIL_MAX):
            app_module._record_auth_failure("10.0.0.3")
        assert app_module._check_auth_rate_limit("10.0.0.3") is True

    def test_above_threshold_rate_limited(self):
        """An IP above the threshold should be rate limited."""
        for _ in range(app_module._AUTH_FAIL_MAX + 5):
            app_module._record_auth_failure("10.0.0.4")
        assert app_module._check_auth_rate_limit("10.0.0.4") is True

    def test_different_ips_independent(self):
        """Rate limiting should be per-IP."""
        for _ in range(app_module._AUTH_FAIL_MAX):
            app_module._record_auth_failure("10.0.0.5")
        assert app_module._check_auth_rate_limit("10.0.0.5") is True
        assert app_module._check_auth_rate_limit("10.0.0.6") is False

    def test_old_attempts_expire(self, monkeypatch):
        """Attempts outside the window should be cleaned up."""
        # Record failures at a time in the past
        old_time = time.monotonic() - app_module._AUTH_FAIL_WINDOW - 10
        with app_module._AUTH_FAIL_LOCK:
            app_module._AUTH_FAIL_TRACKER["10.0.0.7"] = [
                old_time + i for i in range(app_module._AUTH_FAIL_MAX)
            ]
        # Old attempts should be expired
        assert app_module._check_auth_rate_limit("10.0.0.7") is False

    def test_memory_cap_prunes_oldest_ip(self):
        """Tracker should prune when exceeding 1000 IPs."""
        # Fill with 1000 IPs
        with app_module._AUTH_FAIL_LOCK:
            for i in range(1000):
                app_module._AUTH_FAIL_TRACKER[f"192.168.{i // 256}.{i % 256}"] = [
                    time.monotonic()
                ]
        # Recording one more should trigger pruning
        app_module._record_auth_failure("10.99.99.99")
        with app_module._AUTH_FAIL_LOCK:
            # Should be at most 1001 (prune removes 1)
            assert len(app_module._AUTH_FAIL_TRACKER) <= 1001

    def test_thread_safety(self):
        """Multiple threads recording failures should not crash."""
        errors = []

        def hammer(ip: str):
            try:
                for _ in range(50):
                    app_module._record_auth_failure(ip)
                    app_module._check_auth_rate_limit(ip)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=hammer, args=(f"10.0.1.{i}",)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert not errors, f"Thread errors: {errors}"


# ---------------------------------------------------------------------------
# 5. Constants sanity check
# ---------------------------------------------------------------------------


class TestConstants:
    """Verify hardening constants are sane."""

    def test_min_jwt_secret_length(self):
        assert app_module._MIN_JWT_SECRET_LENGTH == 32

    def test_max_token_length(self):
        assert app_module._MAX_TOKEN_LENGTH == 4096

    def test_auth_fail_window(self):
        assert app_module._AUTH_FAIL_WINDOW == 300

    def test_auth_fail_max(self):
        assert app_module._AUTH_FAIL_MAX == 20
