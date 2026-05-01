"""Tests for the air-gap NVD bundle builder.

Covers ``core.airgap_config.build_nvd_bundle`` (module-level helper that turns
a raw NVD 2.0 JSON feed into an importable ZIP) and the symmetric
``OfflineVulnDBManager.export_bundle`` (SCIF-to-SCIF transfer). The build
output MUST be importable by the unmodified ``import_from_bundle`` flow.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from core.airgap_config import OfflineVulnDBManager, build_nvd_bundle


def _minimal_nvd_payload(cve_id: str = "CVE-2099-0001") -> dict:
    """Return a minimal NVD 2.0 dict with a single CVE entry."""
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2099-01-01T00:00:00.000",
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "sourceIdentifier": "test@aldeci.local",
                    "descriptions": [
                        {"lang": "en", "value": "Synthetic CVE for bundle builder tests."}
                    ],
                    "metrics": {},
                    "weaknesses": [],
                    "configurations": [],
                    "references": [],
                }
            }
        ],
    }


def test_build_from_minimal_nvd_json(tmp_path: Path) -> None:
    """Round-trip: write minimal NVD JSON → build bundle → manifest+gz parse, checksum matches."""
    src = tmp_path / "nvd_min.json"
    raw_bytes = json.dumps(_minimal_nvd_payload()).encode("utf-8")
    src.write_bytes(raw_bytes)

    out = tmp_path / "bundle.zip"
    manifest = build_nvd_bundle(
        str(src), str(out), feed_date_range=("2099-01-01", "2099-01-02")
    )

    # Returned manifest is well-formed
    assert manifest["version"] == "1.0"
    assert manifest["format"] == "NVD-2.0"
    assert manifest["cve_count"] == 1
    assert manifest["compression"] == "gzip"
    assert manifest["db_filename"] == OfflineVulnDBManager.DB_FILENAME
    assert manifest["feed_date_range"] == ["2099-01-01", "2099-01-02"]
    assert isinstance(manifest["checksum_sha256"], str)
    assert len(manifest["checksum_sha256"]) == 64  # SHA-256 hex
    assert manifest["created_at"]  # non-empty timestamp

    # ZIP contains both required members
    assert zipfile.is_zipfile(out), "build_nvd_bundle did not produce a valid ZIP"
    with zipfile.ZipFile(out, "r") as zf:
        names = set(zf.namelist())
        assert OfflineVulnDBManager.MANIFEST_FILENAME in names
        assert OfflineVulnDBManager.DB_FILENAME in names

        gz_bytes = zf.read(OfflineVulnDBManager.DB_FILENAME)
        # Checksum recorded in manifest equals SHA-256 of the gzipped bytes
        assert hashlib.sha256(gz_bytes).hexdigest() == manifest["checksum_sha256"]
        # Gzip decompresses to original NVD JSON
        assert json.loads(gzip.decompress(gz_bytes))["vulnerabilities"][0]["cve"]["id"] == "CVE-2099-0001"


def test_build_round_trip(tmp_path: Path) -> None:
    """build_nvd_bundle output is importable by OfflineVulnDBManager.import_from_bundle unchanged."""
    src = tmp_path / "nvd.json"
    src.write_bytes(json.dumps(_minimal_nvd_payload("CVE-2099-9999")).encode("utf-8"))

    bundle_path = tmp_path / "bundle.zip"
    build_nvd_bundle(str(src), str(bundle_path))

    base = tmp_path / "vuln_db_store"
    mgr = OfflineVulnDBManager(base_path=base)
    info = mgr.import_from_bundle(str(bundle_path))

    assert info.cve_count == 1
    assert info.is_valid
    assert info.validation_errors == []
    # CVE accessible from the imported store (read the gzip back like
    # downstream consumers — lookup_cve currently only handles the NVD 1.1
    # CVE_data_meta.ID layout, which is a separate gap tracked elsewhere).
    db_file = base / OfflineVulnDBManager.DB_FILENAME
    assert db_file.exists()
    with gzip.open(db_file, "rt", encoding="utf-8") as fh:
        decoded = json.load(fh)
    ids = [v.get("cve", {}).get("id") for v in decoded["vulnerabilities"]]
    assert "CVE-2099-9999" in ids


def test_invalid_nvd_json_raises(tmp_path: Path) -> None:
    """Non-JSON / malformed input raises ValueError (not bare json.JSONDecodeError)."""
    bad = tmp_path / "not_json.json"
    bad.write_bytes(b"this is not json at all <<<")

    out = tmp_path / "bundle.zip"
    with pytest.raises(ValueError, match=r"Invalid NVD JSON"):
        build_nvd_bundle(str(bad), str(out))

    # Top-level non-dict is also rejected
    arr = tmp_path / "list.json"
    arr.write_bytes(b"[1, 2, 3]")
    with pytest.raises(ValueError, match=r"NVD 2\.0 feed must be a JSON object"):
        build_nvd_bundle(str(arr), str(out))


def test_empty_vulnerabilities_raises(tmp_path: Path) -> None:
    """Zero-CVE feeds are rejected — refusing to ship empty bundles to a SCIF."""
    src = tmp_path / "empty.json"
    payload = _minimal_nvd_payload()
    payload["vulnerabilities"] = []
    src.write_bytes(json.dumps(payload).encode("utf-8"))

    out = tmp_path / "bundle.zip"
    with pytest.raises(ValueError, match=r"zero CVE entries"):
        build_nvd_bundle(str(src), str(out))

    # Missing 'vulnerabilities' key entirely
    no_key = tmp_path / "no_key.json"
    no_key.write_bytes(b'{"format": "NVD_CVE", "version": "2.0"}')
    with pytest.raises(ValueError, match=r"missing 'vulnerabilities' list"):
        build_nvd_bundle(str(no_key), str(out))


def test_export_bundle_round_trips(tmp_path: Path) -> None:
    """Build → import → export → re-import preserves CVE accessibility (SCIF-to-SCIF)."""
    # Build initial bundle from raw NVD JSON
    src = tmp_path / "nvd.json"
    src.write_bytes(json.dumps(_minimal_nvd_payload("CVE-2099-7777")).encode("utf-8"))
    initial_bundle = tmp_path / "initial.zip"
    build_nvd_bundle(str(src), str(initial_bundle))

    # SCIF #1 imports it
    scif1_store = tmp_path / "scif1"
    scif1 = OfflineVulnDBManager(base_path=scif1_store)
    scif1.import_from_bundle(str(initial_bundle))
    assert scif1.is_available()

    # SCIF #1 exports a transportable bundle
    transport = tmp_path / "transport.zip"
    manifest = scif1.export_bundle(str(transport))
    assert manifest["format"] == "NVD-2.0"
    assert manifest["cve_count"] == 1
    assert manifest["db_filename"] == OfflineVulnDBManager.DB_FILENAME
    assert transport.exists() and zipfile.is_zipfile(transport)

    # SCIF #2 imports the transportable bundle and recovers the CVE
    scif2_store = tmp_path / "scif2"
    scif2 = OfflineVulnDBManager(base_path=scif2_store)
    info = scif2.import_from_bundle(str(transport))
    assert info.cve_count == 1
    assert info.is_valid

    # Verify the CVE survived the SCIF→SCIF hop by reading the imported gzip
    # (same caveat as test_build_round_trip re: lookup_cve / NVD 2.0 schema).
    db_file = scif2_store / OfflineVulnDBManager.DB_FILENAME
    with gzip.open(db_file, "rt", encoding="utf-8") as fh:
        decoded = json.load(fh)
    ids = [v.get("cve", {}).get("id") for v in decoded["vulnerabilities"]]
    assert "CVE-2099-7777" in ids
