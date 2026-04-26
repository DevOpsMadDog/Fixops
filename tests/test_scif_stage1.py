"""Tests for SCIF Stage 1 hardening artefacts.

Covers:
  * core.audit_chain — chain creation, append, tamper detection
  * core.hsm_provider — software fallback (PKCS#11 backend tested only when
                        SoftHSM is available on the host)
  * core.fips_boot    — boot reports under multiple env permutations
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest

# sitecustomize handles path setup in production, but pytest may run from any cwd
_REPO = Path(__file__).resolve().parents[1]
for sub in ("suite-core", "suite-api"):
    p = str(_REPO / sub)
    if p not in sys.path:
        sys.path.insert(0, p)

# ---------------------------------------------------------------------------
# Audit chain
# ---------------------------------------------------------------------------
from core.audit_chain import AuditChain, GENESIS_HASH, reset_audit_chain  # noqa: E402


@pytest.fixture
def tmp_db(tmp_path):
    return str(tmp_path / "chain.db")


def test_audit_chain_genesis(tmp_db):
    chain = AuditChain(tmp_db, sign_checkpoints=False)
    try:
        assert chain.count() == 0
        assert chain.tip() is None
        assert chain.verify_full().ok is True  # empty chain is valid
    finally:
        chain.close()


def test_audit_chain_append_and_verify(tmp_db):
    chain = AuditChain(tmp_db, sign_checkpoints=False)
    try:
        e1 = chain.append("user.login", {"user": "alice"}, actor="alice")
        e2 = chain.append("finding.triage", {"id": "f-1", "severity": "high"})
        e3 = chain.append("export.csv", {"rows": 42})

        assert e1.prev_hash == GENESIS_HASH
        assert e2.prev_hash == e1.entry_hash
        assert e3.prev_hash == e2.entry_hash
        assert chain.count() == 3

        result = chain.verify_full()
        assert result.ok is True
        assert result.total_entries == 3
        assert result.first_broken_seq is None
    finally:
        chain.close()


def test_audit_chain_tamper_detected(tmp_db):
    chain = AuditChain(tmp_db, sign_checkpoints=False)
    try:
        chain.append("a", {"x": 1})
        chain.append("b", {"x": 2})
        chain.append("c", {"x": 3})
    finally:
        chain.close()

    # Mutate row 2 directly in SQLite
    conn = sqlite3.connect(tmp_db)
    conn.execute("UPDATE audit_chain SET payload = ? WHERE seq = 2", ('{"x":99}',))
    conn.commit()
    conn.close()

    chain2 = AuditChain(tmp_db, sign_checkpoints=False)
    try:
        result = chain2.verify_full()
        assert result.ok is False
        assert result.first_broken_seq == 2
        assert result.error is not None
    finally:
        chain2.close()


def test_audit_chain_checkpoint_unsigned(tmp_db):
    chain = AuditChain(tmp_db, checkpoint_interval=3, sign_checkpoints=False)
    try:
        for i in range(3):
            chain.append("test", {"i": i})
        # After 3 appends, a checkpoint is emitted (also chained)
        assert chain.count() == 4
        tip = chain.tip()
        assert tip is not None
        assert tip.is_checkpoint is True
        assert chain.verify_full().ok is True
    finally:
        chain.close()


# ---------------------------------------------------------------------------
# HSM software provider (always available — uses cryptography)
# ---------------------------------------------------------------------------
from core.hsm_provider import (  # noqa: E402
    SoftwareProvider,
    KeyHandle,
    get_hsm,
    reset_hsm,
)


@pytest.fixture(autouse=True)
def _reset_hsm():
    reset_hsm()
    yield
    reset_hsm()


def test_software_provider_aes_round_trip(tmp_path, monkeypatch):
    monkeypatch.delenv("FIPS_MODE", raising=False)
    monkeypatch.setenv("FIXOPS_SOFTWARE_KEYSTORE", str(tmp_path))
    p = SoftwareProvider(keystore_dir=tmp_path)

    key = p.generate_aes_key("test-aes")
    assert isinstance(key, KeyHandle)
    assert key.key_type == "AES-256"

    ct = p.encrypt(key, b"hello world", aad=b"meta")
    pt = p.decrypt(key, ct, aad=b"meta")
    assert pt == b"hello world"

    with pytest.raises(Exception):
        p.decrypt(key, ct, aad=b"different-aad")


def test_software_provider_rsa_sign_verify(tmp_path, monkeypatch):
    monkeypatch.delenv("FIPS_MODE", raising=False)
    p = SoftwareProvider(keystore_dir=tmp_path)
    key = p.generate_rsa_keypair("test-rsa", key_size=2048)
    sig = p.sign(key, b"important message")
    assert p.verify(key, b"important message", sig) is True
    assert p.verify(key, b"tampered message", sig) is False


def test_software_provider_refuses_under_fips(monkeypatch, tmp_path):
    monkeypatch.setenv("FIPS_MODE", "1")
    with pytest.raises(RuntimeError, match="FIPS_MODE=1"):
        SoftwareProvider(keystore_dir=tmp_path)


def test_software_provider_list_and_delete(tmp_path, monkeypatch):
    monkeypatch.delenv("FIPS_MODE", raising=False)
    p = SoftwareProvider(keystore_dir=tmp_path)
    p.generate_aes_key("k1")
    p.generate_rsa_keypair("k2", key_size=2048)
    labels = {k.label for k in p.list_keys()}
    assert {"k1", "k2"}.issubset(labels)
    assert p.delete_key("k1") is True
    assert p.get_key("k1") is None


def test_get_hsm_falls_back_to_software_when_no_fips(tmp_path, monkeypatch):
    monkeypatch.delenv("FIPS_MODE", raising=False)
    monkeypatch.delenv("HSM_ENABLED", raising=False)
    monkeypatch.setenv("FIXOPS_SOFTWARE_KEYSTORE", str(tmp_path))
    h = get_hsm()
    assert h.backend_name() == "software"


# ---------------------------------------------------------------------------
# FIPS boot
# ---------------------------------------------------------------------------
from core.fips_boot import run_fips_boot, FIPSBootError  # noqa: E402


def test_fips_boot_skipped_when_unset(monkeypatch, tmp_path):
    monkeypatch.delenv("FIPS_MODE", raising=False)
    monkeypatch.setenv("FIXOPS_AUDIT_CHAIN_DB", str(tmp_path / "chain.db"))
    reset_audit_chain()
    r = run_fips_boot()
    assert r.fips_mode_requested is False
    assert r.fips_mode_active is False


def test_fips_boot_warns_when_no_kernel(monkeypatch, tmp_path):
    monkeypatch.setenv("FIPS_MODE", "1")
    monkeypatch.delenv("HSM_ENABLED", raising=False)
    monkeypatch.delenv("FIPS_STRICT_BOOT", raising=False)
    monkeypatch.setenv("FIXOPS_SOFTWARE_KEYSTORE", str(tmp_path))
    monkeypatch.setenv("FIXOPS_AUDIT_CHAIN_DB", str(tmp_path / "chain.db"))
    reset_audit_chain()
    r = run_fips_boot()
    assert r.fips_mode_requested is True
    # On Linux+FIPS this would be True; on dev hosts kernel_fips is None or False
    assert r.fips_mode_active is True
    assert r.boot_refused is False


def test_fips_boot_strict_refuses_without_hsm(monkeypatch, tmp_path):
    monkeypatch.setenv("FIPS_MODE", "1")
    monkeypatch.setenv("FIPS_STRICT_BOOT", "1")
    monkeypatch.setenv("HSM_ENABLED", "1")
    monkeypatch.delenv("PKCS11_MODULE", raising=False)
    monkeypatch.delenv("PKCS11_PIN", raising=False)
    monkeypatch.setenv("FIXOPS_AUDIT_CHAIN_DB", str(tmp_path / "chain.db"))
    reset_audit_chain()
    reset_hsm()
    # Either the HSM unavailability error or the kernel_fips=False (on Linux non-FIPS host)
    # gets converted to a refusal.
    with pytest.raises(FIPSBootError):
        run_fips_boot()
