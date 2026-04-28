"""RSA key cache tests — verify that the 2,111ms RSA-4096 keygen cost from
``docs/perf/brain_pipeline_profile_2026-04-27.md`` is paid at most once per
process and at most once per host (via persisted PEM).

Coverage:
  * First call generates + persists the keypair (PEM exists, perms 0600).
  * Second call (same paths) loads from cache or disk, well under 50 ms.
  * ``FIXOPS_RSA_PRIVATE_KEY_PATH`` env override is honoured.
  * Default fallback path persists under ``data/keys/rsa_private.pem``.
"""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path
from typing import Iterator

import pytest

from core.crypto import RSAKeyManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate_class_cache() -> Iterator[None]:
    """Snapshot + restore the class-level cache so tests don't bleed."""
    snapshot = dict(RSAKeyManager._KEY_CACHE)
    RSAKeyManager._KEY_CACHE.clear()
    yield
    RSAKeyManager._KEY_CACHE.clear()
    RSAKeyManager._KEY_CACHE.update(snapshot)


@pytest.fixture
def tmp_paths(tmp_path: Path) -> tuple[Path, Path]:
    return tmp_path / "rsa_private.pem", tmp_path / "rsa_public.pem"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_first_call_generates_and_persists_key(tmp_paths) -> None:
    """First call must materialise both PEMs on disk."""
    priv, pub = tmp_paths
    assert not priv.exists()
    assert not pub.exists()

    km = RSAKeyManager(
        private_key_path=str(priv),
        public_key_path=str(pub),
        key_size=2048,  # use 2048 to keep tests fast; cache mechanics are size-agnostic
    )
    _ = km.private_key

    assert priv.is_file(), "private key PEM should be persisted"
    assert pub.is_file(), "public key PEM should be persisted"


def test_second_call_loads_from_cache_under_50ms(tmp_paths) -> None:
    """Second call (same paths, fresh manager) must hit the class cache or disk
    fast — well under 50 ms — proving the 2,111 ms RSA-4096 keygen does not
    repeat. We measure on 4096 specifically since that is the production size.
    """
    priv, pub = tmp_paths
    # Warm-up: cold start pays keygen cost (or loads from existing PEM).
    km1 = RSAKeyManager(
        private_key_path=str(priv),
        public_key_path=str(pub),
        key_size=4096,
    )
    _ = km1.private_key  # force generation
    fp1 = km1.metadata.fingerprint

    # Second manager — same paths, fresh instance. Should hit the class cache
    # in O(1). Measure wall-clock time across the property access.
    start = time.perf_counter()
    km2 = RSAKeyManager(
        private_key_path=str(priv),
        public_key_path=str(pub),
        key_size=4096,
    )
    _ = km2.private_key
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    # 50 ms budget: cache hit should be well under 1 ms; on-disk PEM load is
    # a few ms; full keygen would be ~2,100 ms. 50 ms catches any regression.
    assert elapsed_ms < 50.0, (
        f"Second key access took {elapsed_ms:.1f} ms — cache or disk load "
        f"regression. Expected <50 ms (full keygen would be ~2100 ms)."
    )
    assert km2.metadata.fingerprint == fp1, "cached/loaded key must match original"


def test_persisted_private_key_has_0600_permissions(tmp_paths) -> None:
    """Private key PEM must be created with owner-only read/write (0600)."""
    priv, pub = tmp_paths
    km = RSAKeyManager(
        private_key_path=str(priv),
        public_key_path=str(pub),
        key_size=2048,
    )
    _ = km.private_key

    mode = stat.S_IMODE(priv.stat().st_mode)
    assert mode == 0o600, f"expected mode 0600, got {oct(mode)}"


def test_env_var_override_is_honoured(tmp_path: Path, monkeypatch) -> None:
    """``FIXOPS_RSA_PRIVATE_KEY_PATH`` must be used when the constructor is
    invoked with no explicit ``private_key_path``."""
    priv = tmp_path / "operator_supplied_priv.pem"
    pub = tmp_path / "operator_supplied_pub.pem"
    monkeypatch.setenv("FIXOPS_RSA_PRIVATE_KEY_PATH", str(priv))
    monkeypatch.setenv("FIXOPS_RSA_PUBLIC_KEY_PATH", str(pub))

    km = RSAKeyManager(key_size=2048)
    _ = km.private_key

    assert km.private_key_path == priv
    assert km.public_key_path == pub
    assert priv.is_file()
    assert pub.is_file()


def test_default_path_falls_back_to_data_keys(monkeypatch, tmp_path: Path) -> None:
    """When no env vars and no constructor args are supplied, the manager must
    target ``<repo>/data/keys/rsa_*.pem`` so keys persist across runs."""
    monkeypatch.delenv("FIXOPS_RSA_PRIVATE_KEY_PATH", raising=False)
    monkeypatch.delenv("FIXOPS_RSA_PUBLIC_KEY_PATH", raising=False)
    # Redirect default key dir at the class level so we don't pollute the repo.
    monkeypatch.setattr(RSAKeyManager, "_DEFAULT_KEY_DIR", tmp_path / "data" / "keys")

    km = RSAKeyManager(key_size=2048)
    expected_priv = tmp_path / "data" / "keys" / "rsa_private.pem"
    expected_pub = tmp_path / "data" / "keys" / "rsa_public.pem"
    assert km.private_key_path == expected_priv
    assert km.public_key_path == expected_pub

    _ = km.private_key
    assert expected_priv.is_file()
    assert expected_pub.is_file()
    assert stat.S_IMODE(expected_priv.stat().st_mode) == 0o600


def test_key_dir_has_0700_permissions(tmp_paths) -> None:
    """The directory holding private keys must be created with owner-only (0700)."""
    priv, pub = tmp_paths
    km = RSAKeyManager(
        private_key_path=str(priv),
        public_key_path=str(pub),
        key_size=2048,
    )
    _ = km.private_key

    dir_mode = stat.S_IMODE(priv.parent.stat().st_mode)
    assert dir_mode == 0o700, f"expected dir mode 0700, got {oct(dir_mode)}"


def test_data_keys_in_gitignore() -> None:
    """``data/keys/`` (and *.pem broadly) must be covered by .gitignore so
    private keys can never be accidentally committed."""
    repo_root = Path(__file__).resolve().parents[1]
    gitignore = repo_root / ".gitignore"
    assert gitignore.is_file(), ".gitignore not found at repo root"
    content = gitignore.read_text()
    # *.pem covers rsa_private.pem; data/* covers data/keys/
    assert "*.pem" in content or "data/keys" in content or "data/*" in content, (
        "Neither '*.pem', 'data/keys', nor 'data/*' found in .gitignore — "
        "private keys are at risk of being committed"
    )


def test_class_cache_survives_across_instances(tmp_paths) -> None:
    """The class-level cache must let a second instance skip both keygen and
    PEM read. Verify by deleting the on-disk PEM after the first instance and
    confirming the second instance still resolves the same fingerprint."""
    priv, pub = tmp_paths
    km1 = RSAKeyManager(
        private_key_path=str(priv),
        public_key_path=str(pub),
        key_size=2048,
    )
    _ = km1.private_key
    fp1 = km1.metadata.fingerprint

    # Wipe the on-disk PEMs — only the in-process cache can answer now.
    priv.unlink()
    pub.unlink()

    km2 = RSAKeyManager(
        private_key_path=str(priv),
        public_key_path=str(pub),
        key_size=2048,
    )
    _ = km2.private_key
    assert km2.metadata.fingerprint == fp1, "class cache miss — unexpected regeneration"
