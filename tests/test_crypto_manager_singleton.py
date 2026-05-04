"""Regression tests for CryptoManager singleton — perf fix from commit 0bb21886.

Asserts that the 2,111ms RSA-4096 keygen bottleneck does not repeat:
  - First call to get_crypto_manager() may pay keygen cost (or loads from disk).
  - Second call must return in < 50ms (singleton / class cache hit).
  - rotate() regenerates keys and updates the singleton.
  - CLI ``crypto rotate-keys`` subcommand is wired and callable.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import time
from pathlib import Path
from typing import Iterator

import pytest

from core.crypto import (
    CryptoManager,
    RSAKeyManager,
    get_crypto_manager,
    reset_crypto_manager,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_singleton_and_cache() -> Iterator[None]:
    """Reset both the module singleton and the class-level RSAKeyManager cache
    before and after each test to prevent cross-test contamination."""
    # Save snapshot
    cache_snapshot = dict(RSAKeyManager._KEY_CACHE)
    RSAKeyManager._KEY_CACHE.clear()
    reset_crypto_manager()
    yield
    # Restore
    RSAKeyManager._KEY_CACHE.clear()
    RSAKeyManager._KEY_CACHE.update(cache_snapshot)
    reset_crypto_manager()


@pytest.fixture
def tmp_key_paths(tmp_path: Path) -> tuple[Path, Path]:
    return tmp_path / "rsa_private.pem", tmp_path / "rsa_public.pem"


# ---------------------------------------------------------------------------
# Core singleton tests
# ---------------------------------------------------------------------------


def test_get_crypto_manager_returns_same_instance(tmp_key_paths) -> None:
    """get_crypto_manager() must return the identical object on every call."""
    priv, pub = tmp_key_paths
    import core.crypto as _m
    _m.RSAKeyManager._DEFAULT_KEY_DIR  # just access to ensure module loaded

    # Redirect key paths via env override
    import os
    os.environ["FIXOPS_RSA_PRIVATE_KEY_PATH"] = str(priv)
    os.environ["FIXOPS_RSA_PUBLIC_KEY_PATH"] = str(pub)
    try:
        mgr1 = get_crypto_manager()
        mgr2 = get_crypto_manager()
        assert mgr1 is mgr2, "Singleton must return the same object on every call"
    finally:
        os.environ.pop("FIXOPS_RSA_PRIVATE_KEY_PATH", None)
        os.environ.pop("FIXOPS_RSA_PUBLIC_KEY_PATH", None)


def test_second_get_crypto_manager_under_50ms(tmp_key_paths) -> None:
    """Second call to get_crypto_manager() must complete in < 50ms.

    This is the primary regression guard for the 2,111ms RSA-4096 keygen
    bottleneck identified in docs/perf/brain_pipeline_profile_2026-04-27.md.
    """
    priv, pub = tmp_key_paths
    import os
    os.environ["FIXOPS_RSA_PRIVATE_KEY_PATH"] = str(priv)
    os.environ["FIXOPS_RSA_PUBLIC_KEY_PATH"] = str(pub)
    try:
        # Cold start — pays keygen cost (2048 for test speed; cache mechanics identical).
        mgr1 = get_crypto_manager()
        # Force key material to be loaded.
        _ = mgr1.fingerprint

        # Warm call — must hit singleton, never keygen.
        start = time.perf_counter()
        mgr2 = get_crypto_manager()
        _ = mgr2.fingerprint
        elapsed_ms = (time.perf_counter() - start) * 1000.0
    finally:
        os.environ.pop("FIXOPS_RSA_PRIVATE_KEY_PATH", None)
        os.environ.pop("FIXOPS_RSA_PUBLIC_KEY_PATH", None)

    assert elapsed_ms < 50.0, (
        f"Second get_crypto_manager() call took {elapsed_ms:.1f} ms — "
        f"singleton regression detected (expected < 50 ms)."
    )


def test_crypto_manager_sign_verify_roundtrip(tmp_key_paths) -> None:
    """CryptoManager.sign() / verify() must produce a valid roundtrip."""
    priv, pub = tmp_key_paths
    import os
    os.environ["FIXOPS_RSA_PRIVATE_KEY_PATH"] = str(priv)
    os.environ["FIXOPS_RSA_PUBLIC_KEY_PATH"] = str(pub)
    try:
        mgr = CryptoManager(
            key_manager=RSAKeyManager(
                private_key_path=str(priv),
                public_key_path=str(pub),
                key_size=2048,
            )
        )
        payload = b"aldeci-perf-fix-test"
        sig, fp = mgr.sign(payload)
        assert isinstance(sig, bytes) and len(sig) > 0
        assert isinstance(fp, str) and len(fp) > 0
        assert mgr.verify(payload, sig) is True
        assert mgr.verify(b"tampered", sig) is False
    finally:
        os.environ.pop("FIXOPS_RSA_PRIVATE_KEY_PATH", None)
        os.environ.pop("FIXOPS_RSA_PUBLIC_KEY_PATH", None)


def test_rotate_updates_singleton_and_changes_fingerprint(tmp_key_paths) -> None:
    """CryptoManager.rotate() must replace the singleton and produce a new fingerprint."""
    priv, pub = tmp_key_paths
    km = RSAKeyManager(
        private_key_path=str(priv),
        public_key_path=str(pub),
        key_size=2048,
    )
    mgr_old = CryptoManager(key_manager=km)

    import core.crypto as _m
    _m._CRYPTO_MANAGER_INSTANCE = mgr_old
    old_fp = mgr_old.fingerprint

    new_mgr = mgr_old.rotate()

    assert new_mgr is not mgr_old, "rotate() must return a new CryptoManager instance"
    assert new_mgr.fingerprint != old_fp, "Rotated key must have a different fingerprint"
    # Singleton must now point to the new manager
    assert _m._CRYPTO_MANAGER_INSTANCE is new_mgr


def test_reset_crypto_manager_clears_singleton() -> None:
    """reset_crypto_manager() must set the singleton back to None."""
    import core.crypto as _m
    import os
    os.environ["FIXOPS_RSA_PRIVATE_KEY_PATH"] = ""
    os.environ["FIXOPS_RSA_PUBLIC_KEY_PATH"] = ""
    try:
        _ = get_crypto_manager()
        assert _m._CRYPTO_MANAGER_INSTANCE is not None
        reset_crypto_manager()
        assert _m._CRYPTO_MANAGER_INSTANCE is None
    finally:
        os.environ.pop("FIXOPS_RSA_PRIVATE_KEY_PATH", None)
        os.environ.pop("FIXOPS_RSA_PUBLIC_KEY_PATH", None)


# ---------------------------------------------------------------------------
# CLI integration test
# ---------------------------------------------------------------------------


def test_cli_crypto_rotate_keys_exits_zero(tmp_key_paths, monkeypatch) -> None:
    """``fixops crypto rotate-keys`` must exit with code 0 and update PEM files."""
    priv, pub = tmp_key_paths
    monkeypatch.setenv("FIXOPS_RSA_PRIVATE_KEY_PATH", str(priv))
    monkeypatch.setenv("FIXOPS_RSA_PUBLIC_KEY_PATH", str(pub))

    from core.cli import main
    import core.crypto as _m
    # Reset singleton so CLI starts fresh
    _m._CRYPTO_MANAGER_INSTANCE = None

    exit_code = main(["crypto", "rotate-keys", "--key-size", "2048"])
    assert exit_code == 0, f"CLI rotate-keys returned exit code {exit_code}"
    assert priv.is_file(), "Private key PEM must be written after rotate-keys"
    assert pub.is_file(), "Public key PEM must be written after rotate-keys"
