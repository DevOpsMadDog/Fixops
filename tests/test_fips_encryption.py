"""
Comprehensive tests for FIPS 140-2 encryption + air-gap module.

Tests cover:
- EncryptionMode enum values
- FIPSEncryption: key generation, hash, HMAC sign/verify, encrypt/decrypt,
  wrong key, tampered data, file encryption, different data sizes
- AirGapMode: enable/disable, blocked call recording, export/import round-trip,
  wrong key import fails
- get_encryption_status fields
- Thread safety for concurrent encrypt/decrypt
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
from pathlib import Path

import pytest

sys.path.insert(0, "suite-core")

from core.fips_encryption import (
    AirGapMode,
    EncryptionMode,
    FIPSEncryption,
    EncryptionStatus,
    get_fips_encryption,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def fips():
    """Return a fresh FIPSEncryption instance."""
    return FIPSEncryption()


@pytest.fixture
def key(fips):
    """Return a valid 32-byte key."""
    return fips.generate_key()


@pytest.fixture(autouse=True)
def reset_air_gap():
    """Ensure AirGapMode is disabled and clean before each test."""
    AirGapMode.disable()
    yield
    AirGapMode.disable()


# ============================================================================
# EncryptionMode enum
# ============================================================================


class TestEncryptionModeEnum:
    """Verify EncryptionMode enum values are correct strings."""

    def test_standard_value_is_standard(self):
        assert EncryptionMode.STANDARD.value == "standard"

    def test_fips_140_2_value(self):
        assert EncryptionMode.FIPS_140_2.value == "fips_140_2"

    def test_air_gap_value(self):
        assert EncryptionMode.AIR_GAP.value == "air_gap"

    def test_enum_has_exactly_three_modes(self):
        modes = list(EncryptionMode)
        assert len(modes) == 3

    def test_enum_members_are_str_subclass(self):
        for mode in EncryptionMode:
            assert isinstance(mode, str)


# ============================================================================
# FIPSEncryption — key generation
# ============================================================================


class TestKeyGeneration:
    """Key generation produces 32-byte, cryptographically random values."""

    def test_generate_key_returns_32_bytes(self, fips):
        key = fips.generate_key()
        assert len(key) == 32

    def test_generate_key_returns_bytes(self, fips):
        key = fips.generate_key()
        assert isinstance(key, bytes)

    def test_consecutive_keys_are_unique(self, fips):
        k1 = fips.generate_key()
        k2 = fips.generate_key()
        assert k1 != k2

    def test_key_generation_is_not_zero_filled(self, fips):
        """Sanity check: key is not trivially weak."""
        key = fips.generate_key()
        assert key != b"\x00" * 32


# ============================================================================
# FIPSEncryption — hash
# ============================================================================


class TestHash:
    """SHA-256 hashing produces stable, deterministic hex digests."""

    def test_hash_returns_string(self, fips):
        result = fips.hash(b"hello")
        assert isinstance(result, str)

    def test_hash_is_64_hex_chars(self, fips):
        result = fips.hash(b"hello")
        assert len(result) == 64

    def test_hash_is_deterministic(self, fips):
        assert fips.hash(b"data") == fips.hash(b"data")

    def test_hash_different_inputs_produce_different_digests(self, fips):
        assert fips.hash(b"aaa") != fips.hash(b"bbb")

    def test_hash_empty_bytes(self, fips):
        """SHA-256 of empty bytes has a well-known value."""
        import hashlib
        expected = hashlib.sha256(b"").hexdigest()
        assert fips.hash(b"") == expected

    def test_hash_consistency_across_instances(self):
        """Two separate FIPSEncryption instances hash the same data identically."""
        a = FIPSEncryption()
        b = FIPSEncryption()
        assert a.hash(b"consistent") == b.hash(b"consistent")


# ============================================================================
# FIPSEncryption — HMAC sign / verify
# ============================================================================


class TestHMAC:
    """HMAC-SHA256 sign and verify behave correctly."""

    def test_hmac_sign_returns_bytes(self, fips, key):
        sig = fips.hmac_sign(b"payload", key)
        assert isinstance(sig, bytes)

    def test_hmac_sign_returns_32_bytes(self, fips, key):
        sig = fips.hmac_sign(b"payload", key)
        assert len(sig) == 32

    def test_hmac_verify_valid_signature_returns_true(self, fips, key):
        data = b"important data"
        sig = fips.hmac_sign(data, key)
        assert fips.hmac_verify(data, key, sig) is True

    def test_hmac_verify_wrong_key_returns_false(self, fips, key):
        data = b"important data"
        sig = fips.hmac_sign(data, key)
        wrong_key = fips.generate_key()
        assert fips.hmac_verify(data, wrong_key, sig) is False

    def test_hmac_verify_tampered_data_returns_false(self, fips, key):
        data = b"original"
        sig = fips.hmac_sign(data, key)
        tampered = b"tampered"
        assert fips.hmac_verify(tampered, key, sig) is False

    def test_hmac_sign_is_deterministic_for_same_inputs(self, fips, key):
        sig1 = fips.hmac_sign(b"same", key)
        sig2 = fips.hmac_sign(b"same", key)
        assert sig1 == sig2


# ============================================================================
# FIPSEncryption — encrypt / decrypt round-trip
# ============================================================================


class TestEncryptDecrypt:
    """Core encrypt/decrypt semantics."""

    def test_encrypt_returns_bytes(self, fips, key):
        ct = fips.encrypt(b"hello", key)
        assert isinstance(ct, bytes)

    def test_decrypt_returns_original_plaintext(self, fips, key):
        plaintext = b"hello world"
        ct = fips.encrypt(plaintext, key)
        assert fips.decrypt(ct, key) == plaintext

    def test_encrypt_output_longer_than_plaintext(self, fips, key):
        """Ciphertext includes nonce + tag overhead."""
        plaintext = b"short"
        ct = fips.encrypt(plaintext, key)
        assert len(ct) > len(plaintext)

    def test_encrypt_empty_bytes_round_trip(self, fips, key):
        ct = fips.encrypt(b"", key)
        assert fips.decrypt(ct, key) == b""

    def test_encrypt_large_data_round_trip(self, fips, key):
        """1 MB payload survives encrypt/decrypt."""
        plaintext = os.urandom(1024 * 1024)
        ct = fips.encrypt(plaintext, key)
        assert fips.decrypt(ct, key) == plaintext

    def test_encrypt_small_data_round_trip(self, fips, key):
        """Single byte survives encrypt/decrypt."""
        ct = fips.encrypt(b"\xff", key)
        assert fips.decrypt(ct, key) == b"\xff"

    def test_encrypt_medium_data_round_trip(self, fips, key):
        """Exactly 64 bytes (two SHA-256 block widths) round-trips correctly."""
        plaintext = b"A" * 64
        ct = fips.encrypt(plaintext, key)
        assert fips.decrypt(ct, key) == plaintext

    def test_different_encryptions_of_same_plaintext_differ(self, fips, key):
        """Random nonce means two encryptions of the same plaintext differ."""
        ct1 = fips.encrypt(b"same", key)
        ct2 = fips.encrypt(b"same", key)
        assert ct1 != ct2

    def test_encrypt_with_wrong_key_length_raises(self, fips):
        with pytest.raises(ValueError, match="Key must be"):
            fips.encrypt(b"data", b"short-key")

    def test_decrypt_with_wrong_key_length_raises(self, fips, key):
        ct = fips.encrypt(b"data", key)
        with pytest.raises(ValueError, match="Key must be"):
            fips.decrypt(ct, b"bad")

    def test_decrypt_with_wrong_key_raises_auth_error(self, fips, key):
        ct = fips.encrypt(b"secret", key)
        wrong_key = fips.generate_key()
        with pytest.raises(ValueError, match="Authentication failed"):
            fips.decrypt(ct, wrong_key)

    def test_decrypt_tampered_ciphertext_raises(self, fips, key):
        ct = bytearray(fips.encrypt(b"original data here", key))
        # Flip a byte deep in the ciphertext body (past nonce+tag = 28 bytes)
        ct[30] ^= 0xFF
        with pytest.raises(ValueError, match="Authentication failed"):
            fips.decrypt(bytes(ct), key)

    def test_decrypt_tampered_tag_raises(self, fips, key):
        ct = bytearray(fips.encrypt(b"data", key))
        # Tag starts at byte 12 (after 12-byte nonce)
        ct[12] ^= 0xFF
        with pytest.raises(ValueError, match="Authentication failed"):
            fips.decrypt(bytes(ct), key)

    def test_decrypt_data_too_short_raises(self, fips, key):
        with pytest.raises(ValueError, match="Data too short"):
            fips.decrypt(b"\x00" * 5, key)

    def test_binary_data_round_trip(self, fips, key):
        plaintext = bytes(range(256))
        ct = fips.encrypt(plaintext, key)
        assert fips.decrypt(ct, key) == plaintext


# ============================================================================
# FIPSEncryption — file encrypt / decrypt
# ============================================================================


class TestFileEncryptDecrypt:
    """encrypt_file and decrypt_file produce correct on-disk output."""

    def test_encrypt_file_creates_enc_file(self, fips, key, tmp_path):
        src = tmp_path / "secret.txt"
        src.write_bytes(b"file contents")
        out = fips.encrypt_file(str(src), key)
        assert out == str(src) + ".enc"
        assert Path(out).exists()

    def test_decrypt_file_restores_original_contents(self, fips, key, tmp_path):
        plaintext = b"restore me"
        src = tmp_path / "data.bin"
        src.write_bytes(plaintext)
        enc_path = fips.encrypt_file(str(src), key)
        dec_path = fips.decrypt_file(enc_path, key)
        assert Path(dec_path).read_bytes() == plaintext

    def test_decrypt_file_without_enc_suffix_uses_dec_suffix(self, fips, key, tmp_path):
        """Files without .enc suffix get .dec suffix to avoid overwriting."""
        plaintext = b"no enc suffix"
        # Manually create an encrypted blob with a non-.enc filename
        ct = fips.encrypt(plaintext, key)
        odd_path = tmp_path / "payload.dat"
        odd_path.write_bytes(ct)
        dec_path = fips.decrypt_file(str(odd_path), key)
        assert dec_path.endswith(".dec")
        assert Path(dec_path).read_bytes() == plaintext

    def test_encrypt_file_preserves_binary_fidelity(self, fips, key, tmp_path):
        """Binary file content survives file encrypt/decrypt round-trip."""
        plaintext = os.urandom(4096)
        src = tmp_path / "rand.bin"
        src.write_bytes(plaintext)
        enc_path = fips.encrypt_file(str(src), key)
        dec_path = fips.decrypt_file(enc_path, key)
        assert Path(dec_path).read_bytes() == plaintext


# ============================================================================
# FIPSEncryption — mode & status
# ============================================================================


class TestFIPSMode:
    """verify_fips_mode, set_mode, and get_encryption_status."""

    def test_verify_fips_mode_returns_true(self, fips):
        assert fips.verify_fips_mode() is True

    def test_default_mode_is_standard(self, fips):
        status = fips.get_encryption_status()
        assert status["mode"] == "standard"

    def test_set_mode_changes_reported_mode(self, fips):
        fips.set_mode(EncryptionMode.FIPS_140_2)
        status = fips.get_encryption_status()
        assert status["mode"] == "fips_140_2"

    def test_get_encryption_status_contains_required_keys(self, fips):
        status = fips.get_encryption_status()
        for field in ("mode", "algorithms", "key_length", "fips_verified", "air_gap_enabled"):
            assert field in status

    def test_get_encryption_status_key_length_is_256(self, fips):
        assert fips.get_encryption_status()["key_length"] == 256

    def test_get_encryption_status_algorithms_include_aes_and_hmac(self, fips):
        algos = fips.get_encryption_status()["algorithms"]
        assert any("AES" in a for a in algos)
        assert any("HMAC" in a for a in algos)

    def test_get_encryption_status_fips_verified_is_bool(self, fips):
        assert isinstance(fips.get_encryption_status()["fips_verified"], bool)

    def test_get_encryption_status_air_gap_reflects_air_gap_mode(self, fips):
        AirGapMode.enable()
        assert fips.get_encryption_status()["air_gap_enabled"] is True
        AirGapMode.disable()
        assert fips.get_encryption_status()["air_gap_enabled"] is False

    def test_get_fips_encryption_factory_returns_instance(self):
        enc = get_fips_encryption()
        assert isinstance(enc, FIPSEncryption)


# ============================================================================
# AirGapMode — enable / disable
# ============================================================================


class TestAirGapEnableDisable:
    """AirGapMode state transitions and blocked-call recording."""

    def test_disabled_by_default(self):
        assert AirGapMode.is_enabled() is False

    def test_enable_sets_enabled_true(self):
        AirGapMode.enable()
        assert AirGapMode.is_enabled() is True

    def test_disable_sets_enabled_false(self):
        AirGapMode.enable()
        AirGapMode.disable()
        assert AirGapMode.is_enabled() is False

    def test_disable_clears_blocked_calls(self):
        AirGapMode.enable()
        AirGapMode.record_blocked("https://example.com", "POST")
        AirGapMode.disable()
        assert AirGapMode.get_blocked_calls() == []

    def test_record_blocked_adds_entry(self):
        AirGapMode.enable()
        AirGapMode.record_blocked("https://threat-intel.example.com", "GET")
        calls = AirGapMode.get_blocked_calls()
        assert len(calls) == 1

    def test_record_blocked_stores_url_and_method(self):
        AirGapMode.enable()
        AirGapMode.record_blocked("https://api.example.com/data", "POST")
        entry = AirGapMode.get_blocked_calls()[0]
        assert entry["url"] == "https://api.example.com/data"
        assert entry["method"] == "POST"

    def test_record_blocked_stores_timestamp(self):
        AirGapMode.enable()
        AirGapMode.record_blocked("https://example.com")
        entry = AirGapMode.get_blocked_calls()[0]
        assert "blocked_at" in entry
        assert entry["blocked_at"]  # non-empty string

    def test_multiple_blocked_calls_accumulate(self):
        AirGapMode.enable()
        for i in range(5):
            AirGapMode.record_blocked(f"https://example.com/endpoint/{i}")
        assert len(AirGapMode.get_blocked_calls()) == 5

    def test_get_blocked_calls_returns_copy(self):
        """Mutating the returned list does not affect internal state."""
        AirGapMode.enable()
        AirGapMode.record_blocked("https://example.com")
        calls = AirGapMode.get_blocked_calls()
        calls.clear()
        assert len(AirGapMode.get_blocked_calls()) == 1


# ============================================================================
# AirGapMode — export / import round-trip
# ============================================================================


class TestAirGapTransfer:
    """export_for_transfer and import_from_transfer data integrity."""

    def _key(self):
        return FIPSEncryption().generate_key()

    def test_export_returns_bytes(self):
        key = self._key()
        result = AirGapMode.export_for_transfer({"findings": [1, 2, 3]}, key)
        assert isinstance(result, bytes)

    def test_import_restores_original_dict(self):
        key = self._key()
        data = {"findings": ["CVE-2024-001", "CVE-2024-002"], "severity": "critical"}
        package = AirGapMode.export_for_transfer(data, key)
        restored = AirGapMode.import_from_transfer(package, key)
        assert restored == data

    def test_import_preserves_nested_structures(self):
        key = self._key()
        data = {"level1": {"level2": {"level3": [1, 2, 3]}}}
        package = AirGapMode.export_for_transfer(data, key)
        assert AirGapMode.import_from_transfer(package, key) == data

    def test_import_with_wrong_key_raises(self):
        enc_key = self._key()
        wrong_key = self._key()
        package = AirGapMode.export_for_transfer({"secret": "data"}, enc_key)
        with pytest.raises(ValueError, match="Authentication failed"):
            AirGapMode.import_from_transfer(package, wrong_key)

    def test_export_empty_dict_round_trips(self):
        key = self._key()
        package = AirGapMode.export_for_transfer({}, key)
        assert AirGapMode.import_from_transfer(package, key) == {}

    def test_export_large_payload_round_trips(self):
        key = self._key()
        data = {"entries": list(range(1000)), "label": "bulk transfer"}
        package = AirGapMode.export_for_transfer(data, key)
        assert AirGapMode.import_from_transfer(package, key) == data


# ============================================================================
# Thread safety
# ============================================================================


class TestThreadSafety:
    """Concurrent encrypt/decrypt operations do not corrupt results."""

    def test_concurrent_encrypt_decrypt_produces_correct_results(self):
        fips = FIPSEncryption()
        key = fips.generate_key()
        errors = []
        results = {}

        def worker(thread_id: int):
            try:
                plaintext = f"thread-{thread_id}-payload".encode()
                ct = fips.encrypt(plaintext, key)
                pt = fips.decrypt(ct, key)
                results[thread_id] = pt
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Thread errors: {errors}"
        for thread_id, pt in results.items():
            assert pt == f"thread-{thread_id}-payload".encode()

    def test_concurrent_air_gap_record_blocked_is_safe(self):
        """Concurrent record_blocked calls do not raise or drop entries."""
        AirGapMode.enable()
        errors = []

        def recorder(i: int):
            try:
                AirGapMode.record_blocked(f"https://example.com/{i}", "GET")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=recorder, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(AirGapMode.get_blocked_calls()) == 50
