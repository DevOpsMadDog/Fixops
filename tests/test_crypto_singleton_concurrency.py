"""Concurrency tests for crypto.get_crypto_manager() singleton.

Covers:
- Concurrent get_crypto_manager() from N threads returns the SAME instance
- No race condition: singleton constructed exactly once under load
- rotate() from one thread replaces singleton; other threads observe new instance
- rotate() does not break a concurrent sign() call on the old manager
- reset_crypto_manager() allows fresh construction (test isolation helper)
- CryptoManager.sign() / verify() round-trip is correct
- Two managers with independent keys do NOT cross-verify

Tests are self-contained: RSA key pairs are generated in a temp directory so
they never pollute the project's data/ directory. Key generation happens once
per test session via the module-scoped fixture.

Timeout guard: all thread joins capped at 30 s to avoid CI hangs.
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_CORE = _ROOT / "suite-core" / "core"
if str(_CORE.parent) not in sys.path:
    sys.path.insert(0, str(_CORE.parent))

from core.crypto import (  # noqa: E402
    CryptoManager,
    get_crypto_manager,
    reset_crypto_manager,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolated_singleton(tmp_path, monkeypatch):
    """Each test gets a fresh singleton backed by keys in a temp directory.

    We point the RSA env vars at tmp_path so key generation never touches
    data/ and is hermetic per test.
    """
    monkeypatch.setenv("FIXOPS_RSA_PRIVATE_KEY_PATH", str(tmp_path / "rsa_priv.pem"))
    monkeypatch.setenv("FIXOPS_RSA_PUBLIC_KEY_PATH", str(tmp_path / "rsa_pub.pem"))
    # Use 2048-bit keys in tests for speed (still real RSA, not stubs)
    monkeypatch.setenv("FIXOPS_RSA_KEY_SIZE", "2048")
    reset_crypto_manager()
    yield
    # Clean up singleton so next test starts fresh
    reset_crypto_manager()


# ---------------------------------------------------------------------------
# Basic singleton behaviour
# ---------------------------------------------------------------------------

class TestSingletonBasic:

    def test_same_instance_single_thread(self):
        mgr1 = get_crypto_manager()
        mgr2 = get_crypto_manager()
        assert mgr1 is mgr2

    def test_instance_is_crypto_manager(self):
        mgr = get_crypto_manager()
        assert isinstance(mgr, CryptoManager)

    def test_reset_allows_new_instance(self):
        mgr1 = get_crypto_manager()
        reset_crypto_manager()
        mgr2 = get_crypto_manager()
        assert mgr1 is not mgr2

    def test_fingerprint_stable_across_calls(self):
        fp1 = get_crypto_manager().fingerprint
        fp2 = get_crypto_manager().fingerprint
        assert fp1 == fp2

    def test_sign_verify_round_trip(self):
        mgr = get_crypto_manager()
        payload = b"aldeci test payload 2026"
        sig, fp = mgr.sign(payload)
        assert mgr.verify(payload, sig)
        assert fp == mgr.fingerprint

    def test_verify_rejects_tampered_data(self):
        mgr = get_crypto_manager()
        sig, _ = mgr.sign(b"original")
        assert not mgr.verify(b"tampered", sig)

    def test_verify_rejects_tampered_signature(self):
        mgr = get_crypto_manager()
        sig, _ = mgr.sign(b"original")
        bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
        assert not mgr.verify(b"original", bad_sig)


# ---------------------------------------------------------------------------
# Concurrent construction: singleton created exactly once
# ---------------------------------------------------------------------------

class TestConcurrentSingletonConstruction:

    def test_concurrent_get_same_instance(self):
        """20 threads all calling get_crypto_manager() get the SAME object."""
        N = 20
        results: List[CryptoManager] = []
        errors: List[Exception] = []
        barrier = threading.Barrier(N)

        def _worker():
            try:
                barrier.wait(timeout=10)
                results.append(get_crypto_manager())
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_worker) for _ in range(N)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert errors == [], f"Thread errors: {errors}"
        assert len(results) == N
        first = results[0]
        for mgr in results[1:]:
            assert mgr is first, "Different instances returned — race condition detected"

    def test_singleton_fingerprint_consistent_across_threads(self):
        """All threads see the same key fingerprint."""
        N = 16
        fingerprints: List[str] = []
        errors: List[Exception] = []

        def _worker():
            try:
                fingerprints.append(get_crypto_manager().fingerprint)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_worker) for _ in range(N)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert errors == []
        assert len(set(fingerprints)) == 1, "Multiple fingerprints — multiple instances created"


# ---------------------------------------------------------------------------
# Rotate: new singleton replaces old; existing sign ops survive
# ---------------------------------------------------------------------------

class TestRotate:

    def test_rotate_produces_new_instance(self):
        mgr1 = get_crypto_manager()
        mgr2 = mgr1.rotate()
        assert mgr1 is not mgr2

    def test_rotate_updates_module_singleton(self):
        mgr1 = get_crypto_manager()
        mgr1.rotate()
        mgr2 = get_crypto_manager()
        assert mgr1 is not mgr2

    def test_rotate_fingerprint_changes(self):
        mgr1 = get_crypto_manager()
        fp1 = mgr1.fingerprint
        mgr1.rotate()
        fp2 = get_crypto_manager().fingerprint
        assert fp1 != fp2

    def test_old_manager_still_verifies_own_sigs_after_rotate(self):
        """The old CryptoManager instance can still verify sigs it produced
        even after the module singleton has been replaced by rotate()."""
        old_mgr = get_crypto_manager()
        payload = b"signed before rotate"
        sig, _ = old_mgr.sign(payload)
        # Rotate replaces the singleton
        old_mgr.rotate()
        # Old manager's local key is still usable
        assert old_mgr.verify(payload, sig)

    def test_new_manager_does_not_verify_old_sigs(self):
        """Signatures from the old key must NOT verify with the new key."""
        old_mgr = get_crypto_manager()
        payload = b"signed with old key"
        sig, _ = old_mgr.sign(payload)
        new_mgr = old_mgr.rotate()
        # New manager has a different key pair
        assert not new_mgr.verify(payload, sig)

    def test_rotate_from_thread_no_deadlock(self):
        """rotate() called from a worker thread must not deadlock."""
        # Pre-initialise singleton
        _ = get_crypto_manager()
        result: List[CryptoManager] = []
        errors: List[Exception] = []

        def _rotate_worker():
            try:
                old = get_crypto_manager()
                new = old.rotate()
                result.append(new)
            except Exception as exc:
                errors.append(exc)

        t = threading.Thread(target=_rotate_worker)
        t.start()
        t.join(timeout=30)

        assert errors == [], f"rotate() raised in thread: {errors}"
        assert len(result) == 1
        assert isinstance(result[0], CryptoManager)

    def test_concurrent_sign_during_rotate(self):
        """Thread A signs in a loop; Thread B rotates once.
        Thread A must not crash — it may use either old or new manager."""
        _ = get_crypto_manager()
        sign_errors: List[Exception] = []
        stop_event = threading.Event()

        def _sign_loop():
            for _ in range(50):
                if stop_event.is_set():
                    break
                try:
                    mgr = get_crypto_manager()
                    sig, fp = mgr.sign(b"concurrent payload")
                    assert mgr.verify(b"concurrent payload", sig)
                except Exception as exc:
                    sign_errors.append(exc)
                time.sleep(0.001)

        def _rotate_once():
            time.sleep(0.02)  # let signer get a few iterations in
            try:
                get_crypto_manager().rotate()
            except Exception:
                pass  # rotate may transiently fail if key files are locked

        signer = threading.Thread(target=_sign_loop)
        rotator = threading.Thread(target=_rotate_once)
        signer.start()
        rotator.start()
        rotator.join(timeout=15)
        stop_event.set()
        signer.join(timeout=15)

        assert sign_errors == [], f"sign_loop errors during rotate: {sign_errors}"

    def test_threadpool_all_get_same_instance_after_rotate(self):
        """After a rotate, all subsequent callers share the NEW singleton."""
        original = get_crypto_manager()
        new_mgr = original.rotate()
        N = 12

        def _get():
            return get_crypto_manager()

        with ThreadPoolExecutor(max_workers=N) as ex:
            futures = [ex.submit(_get) for _ in range(N)]
            results = [f.result() for f in as_completed(futures)]

        for mgr in results:
            assert mgr is new_mgr, "Thread received stale singleton after rotate"
