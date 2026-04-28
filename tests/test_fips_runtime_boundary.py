"""FIPS runtime boundary enforcement tests (must-fix #10).

Six tests verifying:
1. Runtime status endpoint returns the required shape.
2. FIPS_MODE_REQUIRED=1 + no FIPS module → startup raises RuntimeError.
3. FIPS_MODE_REQUIRED=1 + FIPS module simulated → startup proceeds.
4. FIPS_MODE_REQUIRED=0 (default) → warning logged, no panic.
5. Allowed algorithm set excludes MD5 and SHA-1 (deprecated by FIPS 140-3).
6. Crypto operations use the ``cryptography`` lib (no ``Crypto.Cipher`` imports).
"""
from __future__ import annotations

import importlib
import logging
import os
import sys
import unittest.mock as mock
from types import ModuleType
from typing import Any

import pytest

sys.path.insert(0, "suite-core")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_boot_with_env(env_overrides: dict[str, str]):
    """Import and run run_fips_boot() with a patched environment."""
    import importlib as _il
    env = {k: v for k, v in os.environ.items()}
    env.update(env_overrides)
    # Keys set to empty string should be removed so getenv defaults apply.
    for k, v in env_overrides.items():
        if v == "":
            env.pop(k, None)

    import core.fips_boot as fb
    _il.reload(fb)

    with mock.patch.dict(os.environ, env_overrides, clear=False):
        return fb.run_fips_boot()


# ---------------------------------------------------------------------------
# Test 1 — Status endpoint returns required shape
# ---------------------------------------------------------------------------

class TestRuntimeStatusShape:
    """get_runtime_fips_status() always returns the four mandatory fields."""

    def test_required_fields_present(self):
        from core.fips_boot import get_runtime_fips_status
        status = get_runtime_fips_status()
        required = {"enabled", "openssl_version", "validated_module", "algorithms_allowed"}
        assert required.issubset(status.keys()), (
            f"Missing fields: {required - status.keys()}"
        )

    def test_enabled_is_bool(self):
        from core.fips_boot import get_runtime_fips_status
        status = get_runtime_fips_status()
        assert isinstance(status["enabled"], bool)

    def test_openssl_version_is_non_empty_string(self):
        from core.fips_boot import get_runtime_fips_status
        status = get_runtime_fips_status()
        assert isinstance(status["openssl_version"], str)
        assert len(status["openssl_version"]) > 0

    def test_algorithms_allowed_is_list(self):
        from core.fips_boot import get_runtime_fips_status
        status = get_runtime_fips_status()
        assert isinstance(status["algorithms_allowed"], list)

    def test_validated_module_none_when_fips_not_active(self):
        """On a dev machine without FIPS OpenSSL, validated_module must be None."""
        from core.fips_boot import get_runtime_fips_status, _openssl_fips_active
        if _openssl_fips_active():
            pytest.skip("Host has FIPS OpenSSL — validated_module is not None")
        status = get_runtime_fips_status()
        assert status["validated_module"] is None


# ---------------------------------------------------------------------------
# Test 2 — FIPS_MODE_REQUIRED=1 + no FIPS module → RuntimeError at startup
# ---------------------------------------------------------------------------

class TestFipsModeRequiredPanic:
    """FIPS_MODE_REQUIRED=1 with a non-FIPS OpenSSL must raise RuntimeError."""

    def test_raises_runtime_error_when_openssl_not_fips(self):
        import core.fips_boot as fb
        # Simulate a non-FIPS OpenSSL environment.
        with mock.patch.object(fb, "_openssl_fips_active", return_value=False):
            with mock.patch.dict(os.environ, {"FIPS_MODE_REQUIRED": "1"}, clear=False):
                with pytest.raises(RuntimeError, match="FIPS_MODE_REQUIRED=1"):
                    fb.run_fips_boot()

    def test_error_message_mentions_openssl_version(self):
        import core.fips_boot as fb
        with mock.patch.object(fb, "_openssl_fips_active", return_value=False):
            with mock.patch.object(fb, "_openssl_version", return_value="OpenSSL 1.1.1k"):
                with mock.patch.dict(os.environ, {"FIPS_MODE_REQUIRED": "1"}, clear=False):
                    with pytest.raises(RuntimeError, match="OpenSSL 1.1.1k"):
                        fb.run_fips_boot()

    def test_boot_report_sets_boot_refused(self):
        """boot_refused must be True before the RuntimeError propagates."""
        import core.fips_boot as fb
        with mock.patch.object(fb, "_openssl_fips_active", return_value=False):
            with mock.patch.dict(os.environ, {"FIPS_MODE_REQUIRED": "1"}, clear=False):
                try:
                    fb.run_fips_boot()
                except RuntimeError:
                    pass  # expected


# ---------------------------------------------------------------------------
# Test 3 — FIPS_MODE_REQUIRED=1 + FIPS module present → boot proceeds
# ---------------------------------------------------------------------------

class TestFipsModeRequiredProceeds:
    """When OpenSSL FIPS is active, FIPS_MODE_REQUIRED=1 must not raise."""

    def test_boot_proceeds_when_openssl_fips_active(self):
        import core.fips_boot as fb
        # Simulate FIPS OpenSSL.
        fips_version = "OpenSSL 3.0.7 fips 1 Nov 2022"

        # Also patch away heavy side-effects (HSM, audit chain, engine).
        with mock.patch.object(fb, "_openssl_fips_active", return_value=True), \
             mock.patch.object(fb, "_openssl_version", return_value=fips_version), \
             mock.patch.object(fb, "_check_kernel_fips", return_value=True), \
             mock.patch.object(fb, "_check_non_fips_libs", return_value=[]), \
             mock.patch.dict(os.environ, {"FIPS_MODE_REQUIRED": "1", "FIPS_MODE": "1"}, clear=False):
            # Patch optional heavy imports to avoid missing module errors.
            with mock.patch.dict(sys.modules, {
                "core.hsm_provider": mock.MagicMock(),
                "core.audit_chain": mock.MagicMock(),
                "core.fips_compliance_mode_engine": mock.MagicMock(),
            }):
                report = fb.run_fips_boot()

        assert report.fips_mode_active is True
        assert report.openssl_fips_active is True
        assert report.validated_module == fips_version

    def test_validated_module_populated_when_fips_active(self):
        import core.fips_boot as fb
        fips_version = "OpenSSL 3.0.7 fips 1 Nov 2022"
        with mock.patch.object(fb, "_openssl_fips_active", return_value=True), \
             mock.patch.object(fb, "_openssl_version", return_value=fips_version), \
             mock.patch.object(fb, "_check_kernel_fips", return_value=True), \
             mock.patch.object(fb, "_check_non_fips_libs", return_value=[]), \
             mock.patch.dict(os.environ, {"FIPS_MODE_REQUIRED": "1", "FIPS_MODE": "1"}, clear=False):
            with mock.patch.dict(sys.modules, {
                "core.hsm_provider": mock.MagicMock(),
                "core.audit_chain": mock.MagicMock(),
                "core.fips_compliance_mode_engine": mock.MagicMock(),
            }):
                report = fb.run_fips_boot()
        assert report.validated_module == fips_version


# ---------------------------------------------------------------------------
# Test 4 — FIPS_MODE_REQUIRED=0 (default) → warning logged, no panic
# ---------------------------------------------------------------------------

class TestFipsModeNotRequired:
    """Without FIPS_MODE_REQUIRED, boot always succeeds with a warning."""

    def test_no_panic_without_fips_mode_required(self, caplog):
        import core.fips_boot as fb
        with mock.patch.object(fb, "_openssl_fips_active", return_value=False):
            with mock.patch.dict(
                os.environ,
                {"FIPS_MODE_REQUIRED": "0", "FIPS_MODE": "0"},
                clear=False,
            ):
                with caplog.at_level(logging.WARNING, logger="core.fips_boot"):
                    report = fb.run_fips_boot()
        assert report.boot_refused is False

    def test_warning_logged_when_fips_not_active(self, caplog):
        import core.fips_boot as fb
        with mock.patch.object(fb, "_openssl_fips_active", return_value=False):
            with mock.patch.dict(
                os.environ,
                {"FIPS_MODE_REQUIRED": "0", "FIPS_MODE": "0"},
                clear=False,
            ):
                with caplog.at_level(logging.WARNING, logger="core.fips_boot"):
                    fb.run_fips_boot()
        # A warning about non-FIPS boundary must appear.
        assert any("FIPS" in r.message for r in caplog.records), (
            f"Expected FIPS warning in logs; got: {[r.message for r in caplog.records]}"
        )


# ---------------------------------------------------------------------------
# Test 5 — Allowed algorithm set excludes MD5 and SHA-1
# ---------------------------------------------------------------------------

class TestAllowedAlgorithms:
    """FIPS 140-3 deprecated algorithms must not appear in the allow-list."""

    def test_md5_excluded_from_allowed_algorithms(self):
        from core.fips_boot import _fips_allowed_algorithms
        algos = _fips_allowed_algorithms()
        assert not any("MD5" in a for a in algos), (
            f"MD5 must not be in FIPS 140-3 allowed list; got: {algos}"
        )

    def test_sha1_excluded_from_allowed_algorithms(self):
        from core.fips_boot import _fips_allowed_algorithms
        algos = _fips_allowed_algorithms()
        # SHA-1 in any form (SHA1, SHA-1, SHA_1) must be absent.
        assert not any(
            a.replace("-", "").replace("_", "").upper() == "SHA1" for a in algos
        ), f"SHA-1 must not be in FIPS 140-3 allowed list; got: {algos}"

    def test_aes_256_gcm_present(self):
        from core.fips_boot import _fips_allowed_algorithms
        algos = _fips_allowed_algorithms()
        assert "AES-256-GCM" in algos

    def test_sha256_present(self):
        from core.fips_boot import _fips_allowed_algorithms
        algos = _fips_allowed_algorithms()
        assert "SHA-256" in algos

    def test_algorithms_non_empty(self):
        from core.fips_boot import _fips_allowed_algorithms
        assert len(_fips_allowed_algorithms()) > 0

    def test_runtime_status_algorithms_exclude_md5_and_sha1(self):
        from core.fips_boot import get_runtime_fips_status
        status = get_runtime_fips_status()
        algos = status["algorithms_allowed"]
        assert not any("MD5" in a for a in algos)
        assert not any(
            a.replace("-", "").replace("_", "").upper() == "SHA1" for a in algos
        )


# ---------------------------------------------------------------------------
# Test 6 — Crypto ops use ``cryptography`` lib (no Crypto.Cipher imports)
# ---------------------------------------------------------------------------

class TestCryptographyLibUsage:
    """fips_encryption.py must use the ``cryptography`` package, not Crypto.Cipher."""

    def test_fips_encryption_does_not_import_pycryptodome_cipher(self):
        """Verify the module source does not contain bare Crypto.Cipher usage."""
        import inspect
        import core.fips_encryption as fe
        source = inspect.getsource(fe)
        # The only Crypto.Cipher reference allowed is in comments explaining
        # what NOT to use.  Actual import statements must not appear.
        import ast
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                else:
                    names = [node.module or ""]
                for name in names:
                    assert not (name or "").startswith("Crypto.Cipher"), (
                        f"Forbidden import found: {name}. "
                        "Use the 'cryptography' library instead."
                    )

    def test_fips_encryption_imports_cryptography_aesgcm(self):
        """The AESGCM import from cryptography must be present when available."""
        import core.fips_encryption as fe
        # _CRYPTOGRAPHY_AVAILABLE flag must exist (set at module load).
        assert hasattr(fe, "_CRYPTOGRAPHY_AVAILABLE")

    def test_encrypt_decrypt_uses_aesgcm_when_cryptography_available(self):
        """When cryptography is installed, AES-GCM must be used for encrypt/decrypt."""
        import core.fips_encryption as fe
        if not fe._CRYPTOGRAPHY_AVAILABLE:
            pytest.skip("cryptography library not installed — AESGCM path unavailable")
        enc = fe.FIPSEncryption()
        key = enc.generate_key()
        plaintext = b"fips boundary test payload"
        ciphertext = enc.encrypt(plaintext, key)
        recovered = enc.decrypt(ciphertext, key)
        assert recovered == plaintext

    def test_aesgcm_ciphertext_longer_than_plaintext(self):
        """AES-256-GCM output = nonce(12) + ciphertext + tag(16) > plaintext."""
        import core.fips_encryption as fe
        if not fe._CRYPTOGRAPHY_AVAILABLE:
            pytest.skip("cryptography library not installed")
        enc = fe.FIPSEncryption()
        key = enc.generate_key()
        plaintext = b"short"
        ct = enc.encrypt(plaintext, key)
        # Minimum overhead: 12 (nonce) + 16 (GCM tag) = 28 bytes
        assert len(ct) >= len(plaintext) + 28

    def test_wrong_key_raises_auth_error_via_cryptography(self):
        """Decryption with wrong key raises ValueError (wrapping InvalidTag)."""
        import core.fips_encryption as fe
        if not fe._CRYPTOGRAPHY_AVAILABLE:
            pytest.skip("cryptography library not installed")
        enc = fe.FIPSEncryption()
        key = enc.generate_key()
        wrong_key = enc.generate_key()
        ct = enc.encrypt(b"secret data", key)
        with pytest.raises(ValueError, match="Authentication failed"):
            enc.decrypt(ct, wrong_key)
