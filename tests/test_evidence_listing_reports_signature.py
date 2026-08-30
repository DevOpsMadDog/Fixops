"""A signed bundle must not be listed as unsigned.

``POST /api/v1/evidence/bundles/generate`` signs every bundle it produces —
real RSA over the artifact's content hash — and writes the signature to a
``.sig.json`` sidecar so a third party can verify it with nothing but the public
key. That is the product's flagship claim: evidence an auditor can check without
trusting us.

The listing endpoint then hardcoded, for exactly those bundles::

    "signed_by": None,
    "signature_valid": False,

So the generate response said ``signature_valid: True`` while the console showed
**"unsigned"** on the same bundle, one screen away. Our own UI contradicted the
headline claim on the only path a customer uses.

Verified in a browser after the fix: bundles with a sidecar render
"signed · fixops:<fingerprint>", and bundles without one still render
"unsigned" — because they genuinely are. The fix reads what is on disk; it does
not assume success.
"""

from __future__ import annotations

import json
import os
import pathlib

import pytest


@pytest.fixture()
def evidence_root(tmp_path, monkeypatch) -> pathlib.Path:
    root = tmp_path / "evidence_artifacts"
    (root / "acme").mkdir(parents=True)
    monkeypatch.setenv("FIXOPS_EVIDENCE_STORAGE_ROOT", str(root))
    return root


def _sidecar(root: pathlib.Path, org: str, bundle_id: str, **overrides) -> None:
    payload = {
        "bundle_id": bundle_id,
        "content_sha256": "a" * 64,
        "signature_b64": "ZmFrZS1zaWduYXR1cmU=",
        "signature_algorithm": "RSA-PKCS1v15-SHA256",
        "signed_payload": "sha256_content_hash",
        "key_fingerprint": "0be15c5769d447b66af41fcb823aa2355512dce51bd5e51c4875a2e",
        "signed_at": "2026-08-30T04:38:07.995453+00:00",
    }
    payload.update(overrides)
    (root / org / f"{bundle_id}.sig.json").write_text(json.dumps(payload), encoding="utf-8")


def test_a_bundle_with_a_sidecar_reports_signed(evidence_root) -> None:
    from apps.api.evidence_router import _read_signature_sidecar

    _sidecar(evidence_root, "acme", "EP-signed")
    result = _read_signature_sidecar("acme", "EP-signed")

    assert result["signature_valid"] is True
    assert result["signed_by"] == "fixops:0be15c5769d447b6"
    assert result["signature_algorithm"] == "RSA-PKCS1v15-SHA256"


def test_a_bundle_with_no_sidecar_reports_nothing(evidence_root) -> None:
    """Absent means genuinely unsigned. The caller's own defaults then apply —
    this must not invent a signature to make the screen look better."""
    from apps.api.evidence_router import _read_signature_sidecar

    assert _read_signature_sidecar("acme", "EP-never-signed") == {}


def test_a_sidecar_missing_its_signature_is_not_treated_as_signed(evidence_root) -> None:
    """A malformed or truncated sidecar must not read as a valid signature."""
    from apps.api.evidence_router import _read_signature_sidecar

    _sidecar(evidence_root, "acme", "EP-empty", signature_b64="")
    assert _read_signature_sidecar("acme", "EP-empty") == {}

    _sidecar(evidence_root, "acme", "EP-nokey", key_fingerprint="")
    assert _read_signature_sidecar("acme", "EP-nokey") == {}


def test_an_unreadable_sidecar_does_not_raise(evidence_root) -> None:
    """A listing must never 500 because one sidecar is corrupt."""
    from apps.api.evidence_router import _read_signature_sidecar

    (evidence_root / "acme" / "EP-corrupt.sig.json").write_text("{not json", encoding="utf-8")
    assert _read_signature_sidecar("acme", "EP-corrupt") == {}


def test_one_tenants_signature_is_not_read_for_another(evidence_root) -> None:
    """The sidecar path is org-scoped; a bundle id alone must not cross tenants."""
    from apps.api.evidence_router import _read_signature_sidecar

    (evidence_root / "other").mkdir(exist_ok=True)
    _sidecar(evidence_root, "other", "EP-theirs")
    assert _read_signature_sidecar("acme", "EP-theirs") == {}


def test_the_listing_no_longer_hardcodes_unsigned() -> None:
    """Guard against the regression returning as a literal."""
    src = (
        pathlib.Path(__file__).resolve().parents[1]
        / "suite-evidence-risk/api/evidence_router.py"
    ).read_text()
    assert "_read_signature_sidecar(org_id, pack.pack_id)" in src, (
        "the generator-backed listing branch no longer consults the sidecar"
    )
