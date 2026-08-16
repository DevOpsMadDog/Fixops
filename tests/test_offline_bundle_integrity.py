"""The offline bundle is the only route by which data enters an air-gapped site.

An accredited deployment has no internet, so threat intelligence arrives on removable
media. That makes the bundle importer the single control protecting the boundary — and
until 2026-08-17 it was optional. The check read::

    expected_checksum = manifest.get("checksum_sha256", "")
    if expected_checksum and actual_checksum != expected_checksum:
        raise ValueError(...)

so a manifest that simply *omitted* the field skipped verification entirely. Demonstrated
before the fix: a bundle containing attacker-chosen records, with no checksum in its
manifest, imported cleanly and was recorded with ``is_valid=True``.

Nor was anything signed, despite ``export_to_bundle`` describing its output as a "signed
ZIP bundle" — a recipient could establish that a bundle was internally consistent, but
never where it came from.

These tests pin both halves: integrity is mandatory, and provenance is mandatory inside
an accredited boundary.

See docs/architecture/adr/003-offline-threat-feed-bundle.md.
"""

from __future__ import annotations

import gzip
import json
import zipfile
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from core.airgap_config import OfflineVulnDBManager


def _write_bundle(
    directory: Path,
    *,
    records: Optional[list] = None,
    checksum: Optional[str] = "auto",
    signature: Optional[Dict[str, Any]] = None,
    name: str = "bundle.zip",
) -> Path:
    """Build a bundle; ``checksum=None`` omits the field entirely."""
    import hashlib

    db_file = directory / "vuln_db.json.gz"
    with gzip.open(db_file, "wt", encoding="utf-8") as handle:
        json.dump(records if records is not None else [{"cve": "CVE-2021-44228"}], handle)

    manifest: Dict[str, Any] = {
        "db_id": "test",
        "source": "usb",
        "version": "2026.08.17",
        "cve_count": len(records) if records is not None else 1,
    }
    if checksum == "auto":
        manifest["checksum_sha256"] = hashlib.sha256(db_file.read_bytes()).hexdigest()
    elif checksum is not None:
        manifest["checksum_sha256"] = checksum
    if signature is not None:
        manifest["signature"] = signature

    manifest_file = directory / "manifest.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    bundle = directory / name
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.write(db_file, "vuln_db.json.gz")
        archive.write(manifest_file, "manifest.json")
    return bundle


@pytest.fixture()
def manager(tmp_path: Path) -> OfflineVulnDBManager:
    return OfflineVulnDBManager(base_path=tmp_path / "store")


def test_bundle_without_a_checksum_is_refused(
    manager: OfflineVulnDBManager, tmp_path: Path
) -> None:
    """The exact bypass: omit the field, skip verification.

    An attacker supplying a bundle only had to leave ``checksum_sha256`` out.
    """
    bundle = _write_bundle(
        tmp_path, records=[{"cve": "CVE-0000-0001", "note": "attacker"}], checksum=None
    )
    with pytest.raises(ValueError, match="no checksum_sha256"):
        manager.import_from_bundle(str(bundle))


def test_bundle_with_an_empty_checksum_is_refused(
    manager: OfflineVulnDBManager, tmp_path: Path
) -> None:
    """An empty string is as unverifiable as a missing field."""
    bundle = _write_bundle(tmp_path, checksum="   ")
    with pytest.raises(ValueError, match="no checksum_sha256"):
        manager.import_from_bundle(str(bundle))


def test_tampered_contents_are_refused(
    manager: OfflineVulnDBManager, tmp_path: Path
) -> None:
    bundle = _write_bundle(tmp_path, checksum="0" * 64)
    with pytest.raises(ValueError, match="Checksum mismatch"):
        manager.import_from_bundle(str(bundle))


def test_a_well_formed_bundle_still_imports(
    manager: OfflineVulnDBManager, tmp_path: Path
) -> None:
    """Closing the hole must not break the legitimate path."""
    bundle = _write_bundle(tmp_path, records=[{"cve": "CVE-2021-44228"}])
    info = manager.import_from_bundle(str(bundle))
    assert info.cve_count == 1
    assert info.is_valid


def test_path_traversal_in_a_bundle_is_refused(
    manager: OfflineVulnDBManager, tmp_path: Path
) -> None:
    """A bundle arriving on removable media is untrusted input."""
    bundle = tmp_path / "evil.zip"
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("../escaped.txt", "pwned")
        archive.writestr("manifest.json", "{}")
    with pytest.raises(ValueError, match="Unsafe path"):
        manager.import_from_bundle(str(bundle))


def test_export_produces_a_signed_bundle_that_reimports(tmp_path: Path) -> None:
    """Round-trip: what we export must be exactly what import accepts."""
    source = OfflineVulnDBManager(base_path=tmp_path / "src")
    inbox = tmp_path / "in"
    inbox.mkdir()
    bundle = _write_bundle(inbox, records=[{"cve": "CVE-2021-44228"}])
    source.import_from_bundle(str(bundle))

    exported = source.export_to_bundle(str(tmp_path / "out" / "export.zip"))

    with zipfile.ZipFile(exported) as archive:
        manifest = json.loads(archive.read("manifest.json"))
    assert manifest.get("checksum_sha256"), "exported bundle carries no checksum"

    destination = OfflineVulnDBManager(base_path=tmp_path / "dst")
    info = destination.import_from_bundle(exported)
    assert info.is_valid


def test_unsigned_bundle_is_refused_under_the_scif_profile(
    manager: OfflineVulnDBManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Inside an accreditation boundary, provenance is not optional.

    Outside one an unsigned bundle is merely warned about; inside one it must be refused,
    because "internally consistent" says nothing about where the data came from.
    """
    monkeypatch.setenv("FIXOPS_PROFILE", "scif")
    monkeypatch.setenv("FIXOPS_AIRGAP_MODE", "enforced")
    bundle = _write_bundle(tmp_path)

    with pytest.raises(ValueError, match="unsigned"):
        manager.import_from_bundle(str(bundle))


def test_unsigned_bundle_is_permitted_outside_an_accredited_boundary(
    manager: OfflineVulnDBManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FIXOPS_PROFILE", raising=False)
    monkeypatch.delenv("FIXOPS_AIRGAP_MODE", raising=False)
    bundle = _write_bundle(tmp_path)
    assert manager.import_from_bundle(str(bundle)).is_valid


def test_a_forged_signature_is_refused(
    manager: OfflineVulnDBManager, tmp_path: Path
) -> None:
    """A signature that cannot be verified must fail the import, not be ignored."""
    bundle = _write_bundle(
        tmp_path,
        signature={
            "version": 1,
            "classical_algorithm": "RSA-4096-SHA256",
            "quantum_algorithm": "ML-DSA-65",
            "classical_signature": "bm90LWEtc2lnbmF0dXJl",  # "not-a-signature"
            "quantum_signature": "bm90LWEtc2lnbmF0dXJl",
            "content_hash": "0" * 64,
        },
    )
    with pytest.raises(ValueError, match="signature"):
        manager.import_from_bundle(str(bundle))
