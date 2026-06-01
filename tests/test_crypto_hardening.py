"""
tests/test_crypto_hardening.py — AC-006b-* acceptance tests
============================================================

Covers:
  AC-006b-01  RSA + ML-DSA private keys: encrypted when FIXOPS_KEY_PASSPHRASE
              is set; plaintext + WARNING when not set; load handles both.
  AC-006b-02  chain_entries + key_audit_log: DELETE/UPDATE raises; INSERT works.
  AC-006b-03  crypto_posture() returns honest flags incl fips_validated=False,
              piv_cac=False, key_at_rest_encrypted reflects env state.
  AC-006b-04  Boot: create_app() starts without error in default config;
              no regressions in crypto/evidence imports.

All tests are self-contained (temp dirs / in-memory DBs) and leave no
side-effects on the real data/keys/ directory.
"""
from __future__ import annotations

import importlib
import os
import sqlite3
import sys
import tempfile
import types
from pathlib import Path
from typing import Generator
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Ensure suite-core is on sys.path (mirrors sitecustomize.py behaviour)
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in [
    str(_REPO_ROOT),
    str(_REPO_ROOT / "suite-core"),
    str(_REPO_ROOT / "suite-api"),
]:
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_rsa_manager(priv_path: Path, pub_path: Path):
    """Return a new RSAKeyManager with class-cache cleared."""
    from core.crypto import RSAKeyManager
    with RSAKeyManager._CACHE_LOCK:
        RSAKeyManager._KEY_CACHE.clear()
    return RSAKeyManager(
        private_key_path=str(priv_path),
        public_key_path=str(pub_path),
        key_size=2048,  # small for test speed
    )


# ===========================================================================
# AC-006b-01 — RSA key encryption at rest
# ===========================================================================

class TestRSAKeyAtRest:
    """REQ-006b-01 / AC-006b-01: RSA private key encrypted when passphrase set."""

    def test_no_passphrase_writes_plaintext_and_warns(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Without passphrase: key file is loadable without password + WARNING logged."""
        import logging
        from cryptography.hazmat.primitives import serialization as _ser
        from cryptography.hazmat.backends import default_backend

        priv = tmp_path / "rsa_private.pem"
        pub = tmp_path / "rsa_public.pem"

        env = {k: v for k, v in os.environ.items() if k != "FIXOPS_KEY_PASSPHRASE"}
        with patch.dict(os.environ, env, clear=True):
            with caplog.at_level(logging.WARNING, logger="core.crypto"):
                km = _fresh_rsa_manager(priv, pub)
                _ = km.private_key  # trigger generation + save

        assert priv.exists(), "Private key file should be written"
        # File must be loadable without password (plaintext)
        pem_bytes = priv.read_bytes()
        loaded = _ser.load_pem_private_key(pem_bytes, password=None, backend=default_backend())
        assert loaded is not None

        # WARNING must appear in logs
        warning_text = " ".join(caplog.messages)
        assert "FIXOPS_KEY_PASSPHRASE" in warning_text, (
            "Expected WARNING about missing FIXOPS_KEY_PASSPHRASE, got: " + warning_text
        )

    def test_with_passphrase_writes_encrypted_key(self, tmp_path: Path) -> None:
        """With passphrase: key file cannot be loaded without the passphrase."""
        from cryptography.hazmat.primitives import serialization as _ser
        from cryptography.hazmat.backends import default_backend
        from cryptography.exceptions import UnsupportedAlgorithm

        priv = tmp_path / "rsa_private.pem"
        pub = tmp_path / "rsa_public.pem"

        env = {k: v for k, v in os.environ.items()}
        env["FIXOPS_KEY_PASSPHRASE"] = "test-passphrase-hardening-1"

        with patch.dict(os.environ, env, clear=True):
            km = _fresh_rsa_manager(priv, pub)
            _ = km.private_key  # trigger generation + save

        assert priv.exists()
        pem_bytes = priv.read_bytes()

        # Loading WITHOUT password must fail
        with pytest.raises(Exception):
            _ser.load_pem_private_key(pem_bytes, password=None, backend=default_backend())

        # Loading WITH correct password must succeed
        loaded = _ser.load_pem_private_key(
            pem_bytes,
            password=b"test-passphrase-hardening-1",
            backend=default_backend(),
        )
        assert loaded is not None

    def test_load_encrypted_key_with_correct_passphrase(self, tmp_path: Path) -> None:
        """Round-trip: generate with passphrase, then load with passphrase."""
        from core.crypto import RSAKeyManager

        priv = tmp_path / "rsa_private.pem"
        pub = tmp_path / "rsa_public.pem"
        passphrase = "round-trip-passphrase-42"

        env = {k: v for k, v in os.environ.items()}
        env["FIXOPS_KEY_PASSPHRASE"] = passphrase

        with patch.dict(os.environ, env, clear=True):
            # Generate
            km1 = _fresh_rsa_manager(priv, pub)
            fp1 = km1.metadata.fingerprint

            # Load fresh instance (cache cleared inside _fresh_rsa_manager)
            km2 = _fresh_rsa_manager(priv, pub)
            fp2 = km2.metadata.fingerprint

        assert fp1 == fp2, "Fingerprints must match after encrypted round-trip"

    def test_load_legacy_plaintext_key_when_passphrase_set_warns(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Legacy plaintext key: loads OK + WARNING when passphrase is now set."""
        import logging
        from cryptography.hazmat.primitives import serialization as _ser
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa

        priv = tmp_path / "rsa_private.pem"
        pub = tmp_path / "rsa_public.pem"

        # Write a legacy plaintext key manually
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        priv.write_bytes(
            private_key.private_bytes(
                encoding=_ser.Encoding.PEM,
                format=_ser.PrivateFormat.PKCS8,
                encryption_algorithm=_ser.NoEncryption(),
            )
        )
        pub.write_bytes(
            private_key.public_key().public_bytes(
                encoding=_ser.Encoding.PEM,
                format=_ser.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        env = {k: v for k, v in os.environ.items()}
        env["FIXOPS_KEY_PASSPHRASE"] = "new-passphrase-for-legacy-key"

        with patch.dict(os.environ, env, clear=True):
            with caplog.at_level(logging.WARNING, logger="core.crypto"):
                from core.crypto import RSAKeyManager
                with RSAKeyManager._CACHE_LOCK:
                    RSAKeyManager._KEY_CACHE.clear()
                km = RSAKeyManager(
                    private_key_path=str(priv),
                    public_key_path=str(pub),
                    key_size=2048,
                )
                _ = km.private_key  # triggers load

        combined = " ".join(caplog.messages)
        assert "UNENCRYPTED" in combined or "legacy" in combined or "plaintext" in combined, (
            "Expected warning about legacy unencrypted key, got: " + combined
        )

    def test_noencryption_not_on_default_write_path(self, tmp_path: Path) -> None:
        """grep-equivalent: NoEncryption() must not be the default write path."""
        import ast

        crypto_path = _REPO_ROOT / "suite-core" / "core" / "crypto.py"
        source = crypto_path.read_text(encoding="utf-8")

        # The _save_private_key for RSA must reference _key_encryption_algorithm()
        # not a hardcoded NoEncryption() call.
        assert "_key_encryption_algorithm()" in source, (
            "_save_private_key should call _key_encryption_algorithm(), not hardcode NoEncryption()"
        )
        # Ensure NoEncryption() is only used in the helper (return path) and the load fallback,
        # not as the direct argument to private_bytes() in _save_private_key.
        # We parse the AST and look for private_bytes calls with NoEncryption() as arg.
        tree = ast.parse(source)
        violations = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_save_private_key":
                for subnode in ast.walk(node):
                    if isinstance(subnode, ast.Call):
                        func = subnode.func
                        if isinstance(func, ast.Attribute) and func.attr == "private_bytes":
                            for kw in subnode.keywords:
                                if kw.arg == "encryption_algorithm":
                                    val = kw.value
                                    if isinstance(val, ast.Call):
                                        if isinstance(val.func, ast.Attribute):
                                            if val.func.attr == "NoEncryption":
                                                violations.append(node.lineno)
        assert not violations, (
            f"_save_private_key directly passes NoEncryption() to private_bytes() at lines {violations}. "
            "It must call _key_encryption_algorithm() instead."
        )


# ===========================================================================
# AC-006b-01 — ML-DSA key encryption at rest
# ===========================================================================

class TestMLDSAKeyAtRest:
    """REQ-006b-01 / AC-006b-01: ML-DSA private key encrypted when passphrase set."""

    @pytest.fixture
    def mldsa_available(self) -> bool:
        try:
            from dilithium_py.ml_dsa import ML_DSA_44  # noqa: F401
            return True
        except ImportError:
            return False

    def test_mldsa_encrypted_round_trip(self, tmp_path: Path, mldsa_available: bool) -> None:
        if not mldsa_available:
            pytest.skip("dilithium_py not installed")

        from core.crypto import MLDSAKeyManager

        priv = tmp_path / "mldsa_private.pem"
        pub = tmp_path / "mldsa_public.pem"
        passphrase = "mldsa-test-passphrase-99"

        env = {k: v for k, v in os.environ.items()}
        env["FIXOPS_KEY_PASSPHRASE"] = passphrase
        env.pop("FIXOPS_MLDSA_PRIVATE_KEY_PATH", None)
        env.pop("FIXOPS_MLDSA_PUBLIC_KEY_PATH", None)

        with patch.dict(os.environ, env, clear=True):
            km1 = MLDSAKeyManager(
                private_key_path=str(priv),
                public_key_path=str(pub),
                level=44,
            )
            fp1 = km1.metadata.fingerprint

            # Reload
            km2 = MLDSAKeyManager(
                private_key_path=str(priv),
                public_key_path=str(pub),
                level=44,
            )
            fp2 = km2.metadata.fingerprint

        assert fp1 == fp2, "ML-DSA fingerprints must match after encrypted round-trip"

    def test_mldsa_encrypted_file_not_loadable_without_passphrase(
        self, tmp_path: Path, mldsa_available: bool
    ) -> None:
        if not mldsa_available:
            pytest.skip("dilithium_py not installed")

        from core.crypto import MLDSAKeyManager, CryptoError

        priv = tmp_path / "mldsa_private.pem"
        pub = tmp_path / "mldsa_public.pem"

        env = {k: v for k, v in os.environ.items()}
        env["FIXOPS_KEY_PASSPHRASE"] = "write-passphrase"
        env.pop("FIXOPS_MLDSA_PRIVATE_KEY_PATH", None)
        env.pop("FIXOPS_MLDSA_PUBLIC_KEY_PATH", None)

        with patch.dict(os.environ, env, clear=True):
            km1 = MLDSAKeyManager(
                private_key_path=str(priv), public_key_path=str(pub), level=44
            )
            _ = km1.metadata  # generate + save

        # Now try to load without passphrase
        env_no_pass = {k: v for k, v in os.environ.items()}
        env_no_pass.pop("FIXOPS_KEY_PASSPHRASE", None)

        with patch.dict(os.environ, env_no_pass, clear=True):
            km2 = MLDSAKeyManager(
                private_key_path=str(priv), public_key_path=str(pub), level=44
            )
            with pytest.raises(CryptoError, match="passphrase"):
                _ = km2.metadata


# ===========================================================================
# AC-006b-02 — Append-only triggers on chain_entries and key_audit_log
# ===========================================================================

class TestAppendOnlyTriggers:
    """REQ-006b-02 / AC-006b-02: DELETE/UPDATE raises; INSERT works."""

    @pytest.fixture
    def evidence_chain(self, tmp_path: Path):
        """Return a fresh EvidenceChain backed by a temp DB."""
        from core.evidence_chain import EvidenceChain
        db = tmp_path / "test_evidence_chain.db"
        chain = EvidenceChain(db_path=str(db))
        return chain

    @pytest.fixture
    def key_manager_db(self, tmp_path: Path):
        """Return a fresh KeyManager backed by a temp DB."""
        from core.key_manager import KeyManager
        db = tmp_path / "test_key_manager.db"
        km = KeyManager(db_path=str(db))
        return km

    # --- chain_entries ---

    def test_chain_entries_insert_works(self, evidence_chain) -> None:
        """INSERT into chain_entries must succeed (append-only allows writes)."""
        entry = evidence_chain.append(
            event_type="test.event",
            data={"key": "value"},
            org_id="org-test",
        )
        assert entry.sequence_number == 0
        assert entry.org_id == "org-test"

    def test_chain_entries_delete_raises(self, evidence_chain) -> None:
        """DELETE on chain_entries must raise (trigger blocks deletion).

        SQLite RAISE(ABORT, ...) in a BEFORE trigger raises IntegrityError
        (not OperationalError) in Python's sqlite3 module.
        """
        evidence_chain.append("test.event", {"x": 1}, "org-del-test")
        conn = evidence_chain._get_conn()
        with pytest.raises(sqlite3.DatabaseError, match="deletion not permitted"):
            conn.execute("DELETE FROM chain_entries WHERE org_id = 'org-del-test'")

    def test_chain_entries_update_raises(self, evidence_chain) -> None:
        """UPDATE on chain_entries must raise (trigger blocks modification).

        SQLite RAISE(ABORT, ...) in a BEFORE trigger raises IntegrityError
        (not OperationalError) in Python's sqlite3 module.
        """
        evidence_chain.append("test.event", {"x": 1}, "org-upd-test")
        conn = evidence_chain._get_conn()
        with pytest.raises(sqlite3.DatabaseError, match="update not permitted"):
            conn.execute(
                "UPDATE chain_entries SET event_type = 'tampered' WHERE org_id = 'org-upd-test'"
            )

    def test_chain_entries_multiple_inserts_work(self, evidence_chain) -> None:
        """Multiple sequential INSERTs must all succeed."""
        for i in range(5):
            entry = evidence_chain.append("test.event", {"i": i}, "org-multi")
            assert entry.sequence_number == i

    def test_chain_verify_after_inserts(self, evidence_chain) -> None:
        """Chain must verify as valid after multiple inserts."""
        for i in range(3):
            evidence_chain.append("event", {"i": i}, "org-verify")
        result = evidence_chain.verify_chain("org-verify")
        assert result["is_valid"] is True
        assert result["chain_length"] == 3

    # --- key_audit_log ---

    def test_key_audit_log_insert_works(self, key_manager_db) -> None:
        """INSERT into key_audit_log must succeed."""
        _, plaintext = key_manager_db.create_key(
            user_id="u-test", name="Test Key", role="viewer"
        )
        assert plaintext.startswith("fixops_")

    def test_key_audit_log_delete_raises(self, key_manager_db) -> None:
        """DELETE on key_audit_log must raise (trigger blocks deletion).

        SQLite RAISE(ABORT, ...) in a BEFORE trigger raises IntegrityError
        (subclass of DatabaseError) in Python's sqlite3 module.
        """
        key_manager_db.create_key(user_id="u-del", name="Del Key", role="viewer")
        conn = key_manager_db._conn()
        with pytest.raises(sqlite3.DatabaseError, match="deletion not permitted"):
            conn.execute("DELETE FROM key_audit_log")

    def test_key_audit_log_update_raises(self, key_manager_db) -> None:
        """UPDATE on key_audit_log must raise (trigger blocks modification).

        SQLite RAISE(ABORT, ...) in a BEFORE trigger raises IntegrityError
        (subclass of DatabaseError) in Python's sqlite3 module.
        """
        key_manager_db.create_key(user_id="u-upd", name="Upd Key", role="viewer")
        conn = key_manager_db._conn()
        with pytest.raises(sqlite3.DatabaseError, match="update not permitted"):
            conn.execute("UPDATE key_audit_log SET action = 'tampered'")

    def test_triggers_present_in_schema(self, evidence_chain, key_manager_db) -> None:
        """Verify trigger names exist in sqlite_master."""
        conn_ec = evidence_chain._get_conn()
        rows = conn_ec.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='chain_entries'"
        ).fetchall()
        trigger_names = {r[0] for r in rows}
        assert "chain_entries_block_delete" in trigger_names
        assert "chain_entries_block_update" in trigger_names

        conn_km = key_manager_db._conn()
        rows_km = conn_km.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='key_audit_log'"
        ).fetchall()
        trigger_names_km = {r[0] for r in rows_km}
        assert "key_audit_log_block_delete" in trigger_names_km
        assert "key_audit_log_block_update" in trigger_names_km


# ===========================================================================
# AC-006b-03 — crypto_posture() honest flags
# ===========================================================================

class TestCryptoPosture:
    """REQ-006b-05 / AC-006b-03: crypto_posture() returns honest flags."""

    def _posture(self, extra_env: dict | None = None):
        """Call crypto_posture() with a clean env override."""
        from core import crypto as _crypto_mod
        # Reload to pick up env changes (the module caches nothing at module
        # level that we need, but _get_key_passphrase() reads os.environ live).
        base = {k: v for k, v in os.environ.items()}
        base.pop("FIXOPS_KEY_PASSPHRASE", None)
        base.pop("FIXOPS_AUDIT_HMAC_KEY", None)
        if extra_env:
            base.update(extra_env)
        with patch.dict(os.environ, base, clear=True):
            return _crypto_mod.crypto_posture()

    def test_fips_validated_always_false(self) -> None:
        posture = self._posture()
        assert posture["fips_validated"] is False, (
            "fips_validated must always be False — pyca/dilithium_py are not CMVP-validated"
        )

    def test_piv_cac_always_false(self) -> None:
        posture = self._posture()
        assert posture["piv_cac"] is False, (
            "piv_cac must always be False — no PKCS#11/PIV-CAC implementation exists"
        )

    def test_key_at_rest_encrypted_false_without_passphrase(self) -> None:
        posture = self._posture()
        assert posture["key_at_rest_encrypted"] is False

    def test_key_at_rest_encrypted_true_with_passphrase(self) -> None:
        posture = self._posture({"FIXOPS_KEY_PASSPHRASE": "some-passphrase"})
        assert posture["key_at_rest_encrypted"] is True

    def test_audit_hmac_key_external_false_without_env(self) -> None:
        posture = self._posture()
        assert posture["audit_hmac_key_external"] is False

    def test_audit_hmac_key_external_true_with_env(self) -> None:
        posture = self._posture({"FIXOPS_AUDIT_HMAC_KEY": "my-secret-hmac-key"})
        assert posture["audit_hmac_key_external"] is True

    def test_audit_immutable_always_true(self) -> None:
        posture = self._posture()
        assert posture["audit_immutable"] is True, (
            "audit_immutable must be True — DELETE/UPDATE triggers installed (REQ-006b-02)"
        )

    def test_posture_has_all_required_keys(self) -> None:
        posture = self._posture()
        required = {
            "key_at_rest_encrypted",
            "audit_hmac_key_external",
            "audit_immutable",
            "db_at_rest_encrypted",
            "fips_validated",
            "piv_cac",
            "notes",
            "assessed_at",
        }
        missing = required - set(posture.keys())
        assert not missing, f"crypto_posture() missing keys: {missing}"

    def test_notes_mention_fips_founder_blocked(self) -> None:
        posture = self._posture()
        notes_text = " ".join(posture["notes"])
        assert "FOUNDER-BLOCKED" in notes_text or "CMVP" in notes_text, (
            "notes must document FIPS-CMVP as founder-blocked"
        )

    def test_notes_mention_piv_founder_blocked(self) -> None:
        posture = self._posture()
        notes_text = " ".join(posture["notes"])
        assert "PIV" in notes_text or "PKCS#11" in notes_text or "CAC" in notes_text, (
            "notes must document PIV-CAC as founder-blocked"
        )

    def test_db_at_rest_encrypted_is_bool(self) -> None:
        posture = self._posture()
        assert isinstance(posture["db_at_rest_encrypted"], bool)


# ===========================================================================
# AC-006b-04 — boot + import sanity
# ===========================================================================

class TestBootAndImports:
    """AC-006b-04: create_app() boots; crypto/evidence imports are clean."""

    def test_crypto_module_imports(self) -> None:
        """core.crypto must import without error."""
        import core.crypto  # noqa: F401

    def test_evidence_chain_imports(self) -> None:
        """core.evidence_chain must import without error."""
        import core.evidence_chain  # noqa: F401

    def test_key_manager_imports(self) -> None:
        """core.key_manager must import without error."""
        import core.key_manager  # noqa: F401

    def test_crypto_posture_importable(self) -> None:
        """crypto_posture() must be importable from core.crypto."""
        from core.crypto import crypto_posture
        assert callable(crypto_posture)

    def test_create_app_boots_default(self) -> None:
        """create_app() must succeed in default (no passphrase) config."""
        try:
            from apps.api.app import create_app
            app = create_app()
            assert app is not None
        except Exception as exc:
            pytest.fail(f"create_app() raised unexpectedly: {exc}")

    def test_create_app_boots_with_passphrase(self, tmp_path: Path) -> None:
        """create_app() must succeed when FIXOPS_KEY_PASSPHRASE is set."""
        env = {k: v for k, v in os.environ.items()}
        env["FIXOPS_KEY_PASSPHRASE"] = "boot-test-passphrase"
        # Point key paths to tmp so we don't encrypt the real dev keys
        env["FIXOPS_RSA_PRIVATE_KEY_PATH"] = str(tmp_path / "rsa_private.pem")
        env["FIXOPS_RSA_PUBLIC_KEY_PATH"] = str(tmp_path / "rsa_public.pem")

        with patch.dict(os.environ, env, clear=True):
            try:
                # We need to clear the RSA cache so it re-generates under the new env.
                from core.crypto import RSAKeyManager
                with RSAKeyManager._CACHE_LOCK:
                    RSAKeyManager._KEY_CACHE.clear()
                from apps.api.app import create_app
                app = create_app()
                assert app is not None
            except Exception as exc:
                pytest.fail(f"create_app() with FIXOPS_KEY_PASSPHRASE raised: {exc}")

    def test_evidence_chain_existing_entries_still_readable_after_triggers(
        self, tmp_path: Path
    ) -> None:
        """Existing entries must still be readable after triggers are installed."""
        from core.evidence_chain import EvidenceChain

        db = tmp_path / "ec_regression.db"
        chain = EvidenceChain(db_path=str(db))

        for i in range(3):
            chain.append("regression.event", {"i": i}, "org-reg")

        entries = chain.get_chain("org-reg")
        assert len(entries) == 3
        assert [e.sequence_number for e in entries] == [0, 1, 2]

    def test_hmac_key_warning_on_no_env(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """evidence_chain module must warn when FIXOPS_AUDIT_HMAC_KEY is unset."""
        import logging
        import importlib

        env = {k: v for k, v in os.environ.items()}
        env.pop("FIXOPS_AUDIT_HMAC_KEY", None)
        env.pop("EVIDENCE_CHAIN_HMAC_KEY", None)

        # Re-run _load_hmac_key() directly (the module-level call already ran).
        with patch.dict(os.environ, env, clear=True):
            with caplog.at_level(logging.WARNING):
                from core.evidence_chain import _load_hmac_key
                key = _load_hmac_key()

        assert key == b"fixops-evidence-chain-key"
        combined = " ".join(caplog.messages)
        assert "FIXOPS_AUDIT_HMAC_KEY" in combined

    def test_hmac_key_no_warning_when_primary_set(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No warning when FIXOPS_AUDIT_HMAC_KEY is properly set."""
        import logging

        env = {k: v for k, v in os.environ.items()}
        env["FIXOPS_AUDIT_HMAC_KEY"] = "production-hmac-secret"
        env.pop("EVIDENCE_CHAIN_HMAC_KEY", None)

        with patch.dict(os.environ, env, clear=True):
            with caplog.at_level(logging.WARNING, logger="core.evidence_chain"):
                from core.evidence_chain import _load_hmac_key
                key = _load_hmac_key()

        assert key == b"production-hmac-secret"
        # No SECURITY WARNING should appear for this case
        warning_msgs = [m for m in caplog.messages if "FIXOPS_AUDIT_HMAC_KEY" in m]
        assert not warning_msgs, f"Unexpected warnings: {warning_msgs}"
