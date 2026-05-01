"""Air-gap bundle ed25519 DSSE signing — SCIF safety tests.

Locks down the 2026-05-02 hardening:

  1. Real ed25519 signatures (base64, NOT ``sha256-fallback:``).
  2. Missing dsse_signer raises RuntimeError loudly (no silent degradation).
  3. Verifier refuses any signature with the legacy ``sha256-fallback:`` prefix.
  4. Tampering the manifest after signing trips ed25519 verification.
"""
from __future__ import annotations

import base64
import io
import json
import tarfile
from pathlib import Path

import pytest

import core.air_gap_bundle_engine as engine_mod
from core.air_gap_bundle_engine import AirGapBundleEngine, _LEGACY_SHA256_PREFIX


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path: Path) -> AirGapBundleEngine:
    """Engine isolated to a tmp dir — never touches the real DB / keys."""
    db_path = tmp_path / "airgap.db"
    bundle_dir = tmp_path / "bundles"
    return AirGapBundleEngine(
        db_path=str(db_path),
        bundle_dir=bundle_dir,
        cve_db_path=tmp_path / "cve.db",
        ti_db_path=tmp_path / "ti.db",
        policy_db_path=tmp_path / "policy.db",
    )


def _export_demo_bundle(engine: AirGapBundleEngine):
    return engine.export_bundle(
        org_id="org-test",
        include_cve=True,
        include_ti=False,
        include_policy=False,
        extra_cve_rows=[
            {
                "cve_id": "CVE-2026-0001",
                "cvss_score": 9.8,
                "cvss_severity": "CRITICAL",
                "description": "test",
            }
        ],
    )


def _read_manifest(archive_path: Path) -> dict:
    with tarfile.open(str(archive_path), "r:gz") as tar:
        f = tar.extractfile("MANIFEST.json")
        assert f is not None
        return json.loads(f.read().decode("utf-8"))


def _rewrite_manifest(archive_path: Path, manifest: dict) -> None:
    """Repack the .tar.gz with a mutated MANIFEST.json — leaves entries intact."""
    # Read all members
    members = {}
    with tarfile.open(str(archive_path), "r:gz") as tar:
        for m in tar.getmembers():
            f = tar.extractfile(m)
            members[m.name] = f.read() if f is not None else b""
    members["MANIFEST.json"] = json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8")
    archive_path.unlink()
    with tarfile.open(str(archive_path), "w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


# ---------------------------------------------------------------------------
# 1. Real ed25519 sign succeeds
# ---------------------------------------------------------------------------


def test_sign_with_real_ed25519_succeeds(engine: AirGapBundleEngine):
    bundle = _export_demo_bundle(engine)
    sig = bundle["signature_placeholder"]
    assert sig, "signature must be present"
    assert not sig.startswith(_LEGACY_SHA256_PREFIX), (
        "sha256-fallback prefix must NOT appear — ed25519 only"
    )
    # Real ed25519 signatures are 64 raw bytes → 88 chars base64 (with padding)
    raw = base64.b64decode(sig.encode("ascii"))
    assert len(raw) == 64, f"ed25519 signatures are 64 raw bytes, got {len(raw)}"

    # Round-trip verify
    result = engine.verify_bundle(bundle["archive_path"])
    assert result["ok"] is True, f"verify failed: {result['errors']}"


# ---------------------------------------------------------------------------
# 2. Missing dsse_signer raises RuntimeError
# ---------------------------------------------------------------------------


def test_missing_signer_raises_runtime_error(
    engine: AirGapBundleEngine, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(engine_mod, "_get_dsse_signer", None)
    with pytest.raises(RuntimeError) as exc_info:
        _export_demo_bundle(engine)
    msg = str(exc_info.value)
    assert "ed25519" in msg.lower()
    assert "sha256 fallback removed" in msg.lower()


# ---------------------------------------------------------------------------
# 3. Legacy sha256 fallback signature rejected
# ---------------------------------------------------------------------------


def test_legacy_sha256_signature_rejected(engine: AirGapBundleEngine):
    bundle = _export_demo_bundle(engine)
    archive_path = Path(bundle["archive_path"])
    manifest = _read_manifest(archive_path)
    # Replace the real ed25519 sig with a sha256-fallback-prefixed one
    manifest["signature"] = _LEGACY_SHA256_PREFIX + "deadbeef" * 8
    _rewrite_manifest(archive_path, manifest)

    result = engine.verify_bundle(archive_path)
    assert result["ok"] is False
    joined = " | ".join(result["errors"]).lower()
    assert "legacy sha256 fallback" in joined or "sha256 fallback" in joined
    assert "re-signed" in joined or "re-sign" in joined


# ---------------------------------------------------------------------------
# 4. Tampered manifest fails ed25519 verification
# ---------------------------------------------------------------------------


def test_tampered_manifest_fails_verify(engine: AirGapBundleEngine):
    bundle = _export_demo_bundle(engine)
    archive_path = Path(bundle["archive_path"])
    manifest = _read_manifest(archive_path)
    # Mutate a non-signature, non-manifest_sha field — counts is part of the
    # signed core. Changing it must invalidate the ed25519 signature.
    manifest["counts"]["cve"] = 9999
    _rewrite_manifest(archive_path, manifest)

    result = engine.verify_bundle(archive_path)
    assert result["ok"] is False
    # Either the manifest_sha256 or the ed25519 sig will catch it — both
    # are acceptable failure paths. Both indicate tampering was detected.
    joined = " | ".join(result["errors"]).lower()
    assert any(
        marker in joined
        for marker in ("manifest_sha256 mismatch", "ed25519", "signature mismatch")
    )
