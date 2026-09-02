"""Whatever signs a login token must be what verifies it.

Three resolvers each generated their own key when FIXOPS_JWT_SECRET was unset —
auth_router._get_dev_jwt_secret, app._load_or_generate_jwt_secret, and
auth_deps._load_jwt_secret. Measured end to end against a live server:

    POST /api/v1/auth/signup            -> 201, real org-scoped API key
    POST /api/v1/auth/login             -> 503 "JWT auth not configured"

and after the 503 was fixed but before the keys were unified:

    POST /api/v1/auth/login             -> 200, a 436-char JWT
    GET  /api/v1/findings (that token)  -> 403
    POST /api/v1/scanner-ingest/upload  -> 401

A customer signs up, logs in, and every screen stays empty. Signing with key A
and verifying with key B is the same defect class as writing ``rule_id`` and
reading ``cve_id``.

Under uvicorn the module is executed twice — the ephemeral-key warning was
observed logged TWICE in one server run — so a module-level constant was not
enough. The generated key is published into the process environment, which is
what makes the first generation win for every later reader.
"""

from __future__ import annotations

import importlib
import os

import pytest


def _fresh(monkeypatch):
    """Re-import auth_deps with a clean environment."""
    monkeypatch.delenv("FIXOPS_JWT_SECRET", raising=False)
    import apps.api.auth_deps as auth_deps

    return importlib.reload(auth_deps)


def test_an_unset_secret_yields_a_strong_key_not_none(monkeypatch) -> None:
    """None meant _HAS_JWT_AUTH=False, so no JWT could ever be accepted."""
    module = _fresh(monkeypatch)
    assert module._JWT_SECRET, "no signing key — every login token would be rejected"
    assert len(module._JWT_SECRET) >= 32
    assert module._HAS_JWT_AUTH is True


def test_the_generated_key_is_published_so_a_second_import_reuses_it(monkeypatch) -> None:
    """The uvicorn double-execution case. Without this, two module instances
    mint two keys and sign/verify disagree."""
    module = _fresh(monkeypatch)
    first = module._JWT_SECRET
    assert os.environ.get("FIXOPS_JWT_SECRET") == first

    again = importlib.reload(module)
    assert again._JWT_SECRET == first, "a re-import minted a different key"


def test_a_configured_secret_is_used_verbatim(monkeypatch) -> None:
    monkeypatch.setenv("FIXOPS_JWT_SECRET", "x" * 40)
    import apps.api.auth_deps as auth_deps

    module = importlib.reload(auth_deps)
    assert module._JWT_SECRET == "x" * 40


def test_a_too_short_secret_still_refuses(monkeypatch) -> None:
    """An operator error that would genuinely weaken signing. Silently
    upgrading it to a strong random key would hide the misconfiguration."""
    monkeypatch.setenv("FIXOPS_JWT_SECRET", "short")
    import apps.api.auth_deps as auth_deps

    module = importlib.reload(auth_deps)
    assert module._JWT_SECRET is None
    assert module._HAS_JWT_AUTH is False


def test_login_signs_with_the_key_the_verifier_holds(monkeypatch) -> None:
    """The actual regression: the login path must not resolve its own key."""
    module = _fresh(monkeypatch)
    from apps.api.auth_router import _get_login_jwt_secret

    assert _get_login_jwt_secret() == module._JWT_SECRET


def test_a_token_signed_for_login_verifies_under_the_verifier_key(monkeypatch) -> None:
    """End-to-end at the crypto level, without needing a live server."""
    jwt = pytest.importorskip("jwt")
    module = _fresh(monkeypatch)
    from apps.api.auth_router import _get_login_jwt_secret

    token = jwt.encode(
        {"sub": "u1", "org_id": "acme", "exp": 9999999999, "iat": 1},
        _get_login_jwt_secret(),
        algorithm="HS256",
    )
    claims = jwt.decode(token, module._JWT_SECRET, algorithms=["HS256"])
    assert claims["org_id"] == "acme"
