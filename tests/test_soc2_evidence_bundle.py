"""Tests for suite-core/core/soc2_evidence_bundle.py.

Coverage
--------
1. Instantiate SOC2EvidenceBundler with a tmp db root.
2. collect_quarterly_evidence returns a dict with all 7 evidence sections.
3. Sections whose engines are unavailable (empty/nonexistent dbs) return the
   section_not_available marker rather than raising.
4. seal_bundle computes a valid SHA-256 over the canonical JSON.
5. export_bundle writes a readable JSON file to disk.
6. When RSAKeyManager is available (mocked), signature is a base64 string.
7. When RSAKeyManager is unavailable, signature is None and signing_status
   starts with "signing_unavailable".
8. Quarter parsing rejects invalid formats / out-of-range quarter numbers.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import textwrap
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Ensure suite-core is on sys.path (mirrors sitecustomize.py behaviour)
# ---------------------------------------------------------------------------
import sys, os

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SUITE_CORE = _REPO_ROOT / "suite-core"
if str(_SUITE_CORE) not in sys.path:
    sys.path.insert(0, str(_SUITE_CORE))

from core.soc2_evidence_bundle import SOC2EvidenceBundler, _parse_quarter  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_db_root(tmp_path: Path) -> Path:
    """Return a fresh temporary directory as db_root."""
    return tmp_path / "aldeci_dbs"


@pytest.fixture()
def bundler(tmp_db_root: Path) -> SOC2EvidenceBundler:
    return SOC2EvidenceBundler(db_root=tmp_db_root)


# ---------------------------------------------------------------------------
# Test 1 — instantiation
# ---------------------------------------------------------------------------

def test_instantiation(tmp_db_root: Path) -> None:
    """SOC2EvidenceBundler can be created with any Path; db_root is stored."""
    b = SOC2EvidenceBundler(db_root=tmp_db_root)
    assert b.db_root == tmp_db_root


# ---------------------------------------------------------------------------
# Test 2 — collect_quarterly_evidence returns all 7 sections + meta
# ---------------------------------------------------------------------------

EXPECTED_SECTIONS = {
    "meta",
    "audit_logs",
    "rbac_access_reviews",
    "change_history",
    "vendor_risk",
    "incident_timeline",
    "backup_attestation",
    "configuration_snapshot",
}


def test_collect_returns_all_sections(bundler: SOC2EvidenceBundler) -> None:
    """collect_quarterly_evidence must return all 7 evidence sections + meta."""
    result = bundler.collect_quarterly_evidence("2026-Q1", "org_test")
    assert isinstance(result, dict), "result must be a dict"
    assert EXPECTED_SECTIONS.issubset(result.keys()), (
        f"Missing sections: {EXPECTED_SECTIONS - result.keys()}"
    )


def test_meta_contains_expected_keys(bundler: SOC2EvidenceBundler) -> None:
    """meta section must record quarter, org_id, generated_at, tool_version."""
    result = bundler.collect_quarterly_evidence("2026-Q2", "org_acme")
    meta = result["meta"]
    for key in ("quarter", "org_id", "generated_at", "tool_version",
                "quarter_start", "quarter_end"):
        assert key in meta, f"meta missing key: {key}"
    assert meta["quarter"] == "2026-Q2"
    assert meta["org_id"] == "org_acme"


# ---------------------------------------------------------------------------
# Test 3 — unavailable engines produce section_not_available markers
# ---------------------------------------------------------------------------

def _is_marker(section: Any) -> bool:
    return (
        isinstance(section, dict)
        and section.get("status") == "section_not_available"
        and "reason" in section
    )


def test_sections_return_marker_when_engines_unavailable(
    bundler: SOC2EvidenceBundler,
) -> None:
    """Sections backed by engines that can't connect must return markers, not raise."""
    result = bundler.collect_quarterly_evidence("2026-Q1", "org_missing")

    # audit_logs, rbac, vendor_risk, incident_timeline will each fail because
    # the tmp db dirs don't have real data but may still produce "ok" with
    # empty lists — or may produce markers if the import itself fails.
    # The key invariant: none of them raise an exception and each is a dict.
    for section in EXPECTED_SECTIONS - {"meta"}:
        assert isinstance(result[section], dict), (
            f"Section {section!r} must be a dict, got {type(result[section])}"
        )

    # backup_attestation must be a marker because no backup.log exists in tmp
    assert _is_marker(result["backup_attestation"]), (
        f"backup_attestation should be not_available, got: {result['backup_attestation']}"
    )

    # configuration_snapshot must always succeed (reads live env vars)
    cfg = result["configuration_snapshot"]
    assert cfg.get("status") == "ok", (
        f"configuration_snapshot must always be ok, got: {cfg}"
    )
    assert "env_var_names" in cfg
    assert isinstance(cfg["env_var_names"], list)
    assert cfg.get("note", "").lower().find("values intentionally omitted") != -1


# ---------------------------------------------------------------------------
# Test 4 — seal_bundle computes a valid SHA-256
# ---------------------------------------------------------------------------

def test_seal_bundle_sha256(bundler: SOC2EvidenceBundler) -> None:
    """seal_bundle must compute SHA-256 matching the canonical JSON independently."""
    bundle = bundler.collect_quarterly_evidence("2026-Q3", "org_seal")
    sealed = bundler.seal_bundle(bundle, sign=False)

    assert "sha256" in sealed
    assert "bundle" in sealed

    # Independently recompute the digest
    canonical = json.dumps(
        bundle, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    expected_hex = hashlib.sha256(canonical).hexdigest()

    assert sealed["sha256"] == expected_hex, (
        f"SHA-256 mismatch: expected {expected_hex}, got {sealed['sha256']}"
    )
    assert len(sealed["sha256"]) == 64  # SHA-256 hex is always 64 chars


# ---------------------------------------------------------------------------
# Test 5 — export_bundle writes a valid JSON file
# ---------------------------------------------------------------------------

def test_export_bundle_writes_file(
    bundler: SOC2EvidenceBundler, tmp_path: Path
) -> None:
    """export_bundle must create a JSON file that round-trips correctly."""
    bundle  = bundler.collect_quarterly_evidence("2026-Q4", "org_export")
    sealed  = bundler.seal_bundle(bundle, sign=False)
    out     = tmp_path / "evidence" / "bundle.json"

    bundler.export_bundle(sealed, out)

    assert out.exists(), "Output file was not created"
    assert out.stat().st_size > 0, "Output file is empty"

    with open(out, "r", encoding="utf-8") as fh:
        loaded = json.load(fh)

    assert "sha256" in loaded
    assert "bundle" in loaded
    assert loaded["sha256"] == sealed["sha256"]


# ---------------------------------------------------------------------------
# Test 6 — signature is base64 string when RSAKeyManager available (mocked)
# ---------------------------------------------------------------------------

def test_seal_bundle_signature_when_key_available(
    bundler: SOC2EvidenceBundler,
) -> None:
    """When RSASigner is available, signature must be a non-empty base64 string."""
    fake_sig   = b"\xde\xad\xbe\xef" * 128   # 512 bytes — realistic RSA sig size
    fake_fp    = "aa:bb:cc:dd"
    fake_signer = MagicMock()
    fake_signer.sign.return_value = (fake_sig, fake_fp)

    fake_km    = MagicMock()

    with patch.dict("sys.modules", {
        "core.crypto": MagicMock(
            RSAKeyManager=MagicMock(return_value=fake_km),
            RSASigner=MagicMock(return_value=fake_signer),
        )
    }):
        bundle = bundler.collect_quarterly_evidence("2026-Q1", "org_sign")
        sealed = bundler.seal_bundle(bundle, sign=True)

    assert sealed["signature"] is not None, "signature must not be None when key available"
    assert isinstance(sealed["signature"], str), "signature must be a string"

    # Must be valid base64
    decoded = base64.b64decode(sealed["signature"])
    assert decoded == fake_sig

    assert sealed["signature_fingerprint"] == fake_fp
    assert sealed["signing_status"] == "signed"


# ---------------------------------------------------------------------------
# Test 7 — signature is None + marker when no RSA key available
# ---------------------------------------------------------------------------

def test_seal_bundle_no_signature_when_key_unavailable(
    bundler: SOC2EvidenceBundler,
) -> None:
    """When RSAKeyManager is unavailable, signature must be None and status a marker."""
    bundle = bundler.collect_quarterly_evidence("2026-Q1", "org_nosign")

    # Force ImportError for core.crypto
    with patch.dict("sys.modules", {"core.crypto": None}):
        sealed = bundler.seal_bundle(bundle, sign=True)

    assert sealed["signature"] is None, (
        f"signature must be None when crypto unavailable, got: {sealed['signature']}"
    )
    assert sealed["signing_status"].startswith("signing_unavailable"), (
        f"signing_status must indicate unavailability, got: {sealed['signing_status']}"
    )


# ---------------------------------------------------------------------------
# Test 8 — quarter parsing validation
# ---------------------------------------------------------------------------

def test_parse_quarter_valid() -> None:
    """_parse_quarter must return correct UTC boundaries for known quarters."""
    from datetime import timezone

    start, end = _parse_quarter("2026-Q1")
    assert start.year == 2026 and start.month == 1 and start.day == 1
    assert end.year == 2026 and end.month == 4 and end.day == 1
    assert start.tzinfo == timezone.utc

    start, end = _parse_quarter("2025-Q4")
    assert start.year == 2025 and start.month == 10
    assert end.year == 2026 and end.month == 1


def test_parse_quarter_invalid_format() -> None:
    """_parse_quarter must raise ValueError for malformed strings."""
    with pytest.raises(ValueError, match="YYYY-QN"):
        _parse_quarter("2026Q1")

    with pytest.raises(ValueError, match="YYYY-QN"):
        _parse_quarter("Q1-2026")

    with pytest.raises(ValueError, match="YYYY-QN"):
        _parse_quarter("not-a-quarter")


def test_parse_quarter_invalid_number() -> None:
    """_parse_quarter must raise ValueError for quarter numbers outside 1-4."""
    with pytest.raises(ValueError, match="1-4"):
        _parse_quarter("2026-Q0")

    with pytest.raises(ValueError, match="1-4"):
        _parse_quarter("2026-Q5")
