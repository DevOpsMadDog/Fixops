"""Tests for AirGapBundleEngine — GAP-001 (Sonatype SAGE parity).

Covers:
  - ensure_schema creates all 4 tables
  - export_bundle with all-defaults + selective includes
  - manifest content (sha256, signature, counts, entries)
  - verify_bundle happy path
  - verify_bundle catches tampered manifest
  - verify_bundle catches tampered entry
  - verify_bundle catches tampered signature
  - apply_bundle idempotent upsert (real apply)
  - apply_bundle dry_run does not mutate targets
  - apply_bundle re-run is no-op on same data
  - apply_bundle respects require_verified
  - org_id isolation on list_bundles / stats
  - all three entry types round-trip (cve + ti + policy)
  - record_transfer lifecycle + invalid transport rejection
  - list_bundles filters (status, org_id) + invalid status rejection
  - get_bundle returns manifest, entries, transfers, applications
  - stats correctness (counts, by_status, entries_by_type, total_size_bytes)
  - full export -> verify -> apply happy-path cycle
"""
from __future__ import annotations

import json
import tarfile
from pathlib import Path

import pytest

from core.air_gap_bundle_engine import (
    AirGapBundleEngine,
    _MANIFEST_NAME,
    _SIGNATURE_ALGO,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    """Fresh engine with all source DBs redirected to tmp_path."""
    return AirGapBundleEngine(
        db_path=str(tmp_path / "air_gap.db"),
        bundle_dir=tmp_path / "bundles",
        cve_db_path=tmp_path / "cve.db",
        ti_db_path=tmp_path / "ti.db",
        policy_db_path=tmp_path / "policy.db",
    )


@pytest.fixture
def sample_cve_rows():
    return [
        {
            "cve_id": "CVE-2021-44228",
            "cvss_score": 10.0,
            "cvss_severity": "critical",
            "description": "Log4Shell",
            "epss_score": 0.97,
            "is_kev": 1,
            "kev_due_date": "2021-12-24",
            "cwe": "CWE-917",
            "published": "2021-12-10",
            "source": "seed",
            "enriched_at": "2026-04-22T00:00:00+00:00",
        },
        {
            "cve_id": "CVE-2022-0778",
            "cvss_score": 7.5,
            "cvss_severity": "high",
            "description": "OpenSSL DoS",
            "epss_score": 0.71,
            "is_kev": 1,
            "source": "seed",
        },
        {
            "cve_id": "CVE-2021-26855",
            "cvss_score": 9.8,
            "cvss_severity": "critical",
            "description": "ProxyLogon",
            "is_kev": 1,
        },
    ]


@pytest.fixture
def sample_ti_rows():
    return [
        {
            "id": "ti-1",
            "org_id": "orgA",
            "indicator_value": "1.2.3.4",
            "indicator_type": "ip",
            "source": "OTX",
            "confidence": 0.9,
            "severity": "high",
            "tlp": "amber",
            "tags": ["botnet", "c2"],
            "active": 1,
        },
        {
            "id": "ti-2",
            "org_id": "orgA",
            "indicator_value": "evil.example.com",
            "indicator_type": "domain",
            "source": "URLhaus",
            "confidence": 0.85,
            "severity": "high",
            "active": 1,
        },
    ]


@pytest.fixture
def sample_policy_rows():
    return [
        {
            "id": "pol-1",
            "name": "block_critical_cve",
            "description": "Block deploys with CVSS>=9",
            "scope": "deployments",
            "language": "aldeci_rules",
            "rules": [{"field": "cvss_score", "op": ">=", "value": 9.0}],
            "decision_on_match": "deny",
            "enabled": 1,
            "version": 2,
            "org_id": "orgA",
        },
    ]


@pytest.fixture
def exported(engine, sample_cve_rows, sample_ti_rows, sample_policy_rows):
    return engine.export_bundle(
        org_id="orgA",
        include_cve=True,
        include_ti=True,
        include_policy=True,
        exported_by="tester",
        extra_cve_rows=sample_cve_rows,
        extra_ti_rows=sample_ti_rows,
        extra_policy_rows=sample_policy_rows,
    )


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_ensure_schema_creates_all_tables(engine):
    with engine._conn() as conn:
        names = {
            r["name"]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    for table in {"bundles", "bundle_entries", "bundle_transfers", "bundle_applications"}:
        assert table in names, f"missing table: {table}"


def test_ensure_schema_is_idempotent(engine):
    # calling twice must not error
    engine.ensure_schema()
    engine.ensure_schema()


# ---------------------------------------------------------------------------
# export_bundle
# ---------------------------------------------------------------------------


def test_export_bundle_requires_org_id(engine):
    with pytest.raises(ValueError, match="org_id"):
        engine.export_bundle(org_id="")


def test_export_bundle_requires_some_content(engine):
    with pytest.raises(ValueError, match="include_"):
        engine.export_bundle(
            org_id="orgA",
            include_cve=False,
            include_ti=False,
            include_policy=False,
        )


def test_export_bundle_writes_archive(exported, tmp_path):
    assert exported["status"] == "exported"
    archive = Path(exported["archive_path"])
    assert archive.exists()
    assert archive.suffix == ".gz"
    assert exported["size_bytes"] > 0


def test_export_bundle_manifest_has_required_fields(exported):
    m = exported["manifest"]
    for key in (
        "bundle_id",
        "version",
        "created_at",
        "produced_by",
        "entries",
        "counts",
        "manifest_sha256",
        "signature_algo",
        "signature",
    ):
        assert key in m, f"missing manifest key: {key}"
    assert m["produced_by"] == "fixops"
    assert m["signature_algo"] == _SIGNATURE_ALGO


def test_export_bundle_counts_are_accurate(exported):
    counts = exported["counts"]
    assert counts["cve"] == 3
    assert counts["ti"] == 2
    assert counts["policy"] == 1
    assert counts["total"] == 6


def test_export_bundle_entries_all_have_sha256(exported):
    for e in exported["manifest"]["entries"]:
        assert len(e["sha256"]) == 64
        assert e["type"] in {"cve", "ti_indicator", "policy"}
        assert e["size"] > 0


def test_export_bundle_unique_bundle_id(engine, sample_cve_rows):
    b1 = engine.export_bundle(org_id="orgA", include_ti=False, include_policy=False, extra_cve_rows=sample_cve_rows)
    b2 = engine.export_bundle(org_id="orgA", include_ti=False, include_policy=False, extra_cve_rows=sample_cve_rows)
    assert b1["bundle_id"] != b2["bundle_id"]


def test_export_bundle_selective_cve_only(engine, sample_cve_rows):
    out = engine.export_bundle(
        org_id="orgA",
        include_cve=True,
        include_ti=False,
        include_policy=False,
        extra_cve_rows=sample_cve_rows,
    )
    assert out["counts"]["cve"] == 3
    assert out["counts"]["ti"] == 0
    assert out["counts"]["policy"] == 0


def test_export_bundle_custom_version(engine, sample_cve_rows):
    out = engine.export_bundle(
        org_id="orgA",
        bundle_version="2026.04.22-custom",
        extra_cve_rows=sample_cve_rows,
        include_ti=False,
        include_policy=False,
    )
    assert out["version"] == "2026.04.22-custom"


def test_export_bundle_persists_rows(engine, sample_cve_rows):
    out = engine.export_bundle(
        org_id="orgA", extra_cve_rows=sample_cve_rows, include_ti=False, include_policy=False
    )
    bundles = engine.list_bundles(org_id="orgA")
    assert len(bundles) == 1
    assert bundles[0]["bundle_id"] == out["bundle_id"]


def test_export_bundle_archive_contains_manifest(exported):
    archive = Path(exported["archive_path"])
    with tarfile.open(str(archive), "r:gz") as tar:
        names = tar.getnames()
    assert _MANIFEST_NAME in names


def test_export_bundle_archive_contains_entries(exported):
    archive = Path(exported["archive_path"])
    with tarfile.open(str(archive), "r:gz") as tar:
        names = tar.getnames()
    # at least one entry per type
    assert any(n.startswith("entries/cve/") for n in names)
    assert any(n.startswith("entries/ti_indicator/") for n in names)
    assert any(n.startswith("entries/policy/") for n in names)


# ---------------------------------------------------------------------------
# verify_bundle — happy path
# ---------------------------------------------------------------------------


def test_verify_bundle_happy_path(engine, exported):
    result = engine.verify_bundle(exported["bundle_id"])
    assert result["ok"] is True
    assert result["entries_failed"] == 0
    assert result["entries_checked"] == 6
    assert result["errors"] == []


def test_verify_bundle_updates_status_to_verified(engine, exported):
    engine.verify_bundle(exported["bundle_id"])
    row = engine.get_bundle(exported["bundle_id"])
    assert row["status"] == "verified"


def test_verify_bundle_by_file_path_works(engine, exported):
    result = engine.verify_bundle(exported["archive_path"])
    assert result["ok"] is True


def test_verify_bundle_missing_id_returns_error(engine):
    result = engine.verify_bundle("bundle-nonexistent-xxx")
    assert result["ok"] is False
    assert "not found" in " ".join(result["errors"]).lower() or result["errors"]


# ---------------------------------------------------------------------------
# verify_bundle — tamper detection
# ---------------------------------------------------------------------------


def _rewrite_archive(src: Path, tamper_manifest=None, tamper_entry=None):
    """Create a tampered copy of an archive."""
    tmp = src.with_suffix(".tampered.tar.gz")
    with tarfile.open(str(src), "r:gz") as src_tar:
        members = src_tar.getmembers()
        contents = {m.name: src_tar.extractfile(m).read() for m in members if src_tar.extractfile(m)}
    if tamper_manifest is not None:
        manifest = json.loads(contents[_MANIFEST_NAME].decode())
        tamper_manifest(manifest)
        contents[_MANIFEST_NAME] = json.dumps(manifest, sort_keys=True, indent=2).encode()
    if tamper_entry is not None:
        for name in list(contents.keys()):
            if name.startswith("entries/"):
                contents[name] = tamper_entry(contents[name])
                break
    with tarfile.open(str(tmp), "w:gz") as tar:
        import io, time
        for name, data in contents.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(data))
    return tmp


def test_verify_bundle_detects_tampered_manifest(engine, exported):
    archive = Path(exported["archive_path"])
    tampered = _rewrite_archive(
        archive, tamper_manifest=lambda m: m["counts"].update({"cve": 999})
    )
    result = engine.verify_bundle(tampered)
    assert result["ok"] is False
    assert any("manifest_sha256" in e or "signature" in e for e in result["errors"])


def test_verify_bundle_detects_tampered_entry(engine, exported):
    archive = Path(exported["archive_path"])
    tampered = _rewrite_archive(archive, tamper_entry=lambda b: b + b"TAMPERED")
    result = engine.verify_bundle(tampered)
    assert result["ok"] is False
    assert result["entries_failed"] >= 1
    assert any("sha256 mismatch" in e for e in result["errors"])


def test_verify_bundle_detects_signature_mismatch(engine, exported):
    archive = Path(exported["archive_path"])
    tampered = _rewrite_archive(
        archive, tamper_manifest=lambda m: m.update({"signature": "0" * 64})
    )
    result = engine.verify_bundle(tampered)
    assert result["ok"] is False
    assert any("signature" in e.lower() for e in result["errors"])


# ---------------------------------------------------------------------------
# apply_bundle
# ---------------------------------------------------------------------------


def test_apply_bundle_happy_path(engine, exported):
    result = engine.apply_bundle(exported["bundle_id"])
    assert result["status"] == "applied"
    assert result["applied"] == 6
    assert result["failed"] == 0
    assert result["dry_run"] is False


def test_apply_bundle_dry_run_skips_all(engine, exported):
    result = engine.apply_bundle(exported["bundle_id"], dry_run=True)
    assert result["dry_run"] is True
    assert result["skipped"] == 6
    assert result["applied"] == 0
    # dry-run must not change bundle status to applied
    row = engine.get_bundle(exported["bundle_id"])
    assert row["status"] != "applied"


def test_apply_bundle_updates_cve_cache(engine, exported):
    engine.apply_bundle(exported["bundle_id"])
    import sqlite3
    conn = sqlite3.connect(str(engine.cve_db_path))
    rows = conn.execute("SELECT cve_id FROM cve_cache").fetchall()
    conn.close()
    ids = {r[0] for r in rows}
    assert "CVE-2021-44228" in ids
    assert "CVE-2022-0778" in ids
    assert "CVE-2021-26855" in ids


def test_apply_bundle_updates_threat_indicators(engine, exported):
    engine.apply_bundle(exported["bundle_id"])
    import sqlite3
    conn = sqlite3.connect(str(engine.ti_db_path))
    rows = conn.execute("SELECT id, indicator_value FROM threat_indicators").fetchall()
    conn.close()
    values = {r[1] for r in rows}
    assert "1.2.3.4" in values
    assert "evil.example.com" in values


def test_apply_bundle_updates_policies(engine, exported):
    engine.apply_bundle(exported["bundle_id"])
    import sqlite3
    conn = sqlite3.connect(str(engine.policy_db_path))
    rows = conn.execute("SELECT name FROM policies").fetchall()
    conn.close()
    assert any("block_critical_cve" == r[0] for r in rows)


def test_apply_bundle_is_idempotent(engine, exported):
    r1 = engine.apply_bundle(exported["bundle_id"])
    r2 = engine.apply_bundle(exported["bundle_id"])
    assert r1["applied"] == r2["applied"]
    # the row count in the target tables must equal exactly what we exported
    import sqlite3
    conn = sqlite3.connect(str(engine.cve_db_path))
    count = conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0]
    conn.close()
    assert count == 3  # no duplicates


def test_apply_bundle_missing_id_raises(engine):
    with pytest.raises(KeyError):
        engine.apply_bundle("bundle-missing")


def test_apply_bundle_respects_require_verified(engine, exported):
    # tamper the manifest so verify fails
    archive = Path(exported["archive_path"])
    tampered = _rewrite_archive(
        archive, tamper_manifest=lambda m: m["counts"].update({"cve": 999})
    )
    # move tampered over the original
    archive.unlink()
    tampered.rename(archive)
    result = engine.apply_bundle(exported["bundle_id"], require_verified=True)
    assert result["status"] == "apply_failed"
    assert result["applied"] == 0


def test_apply_bundle_bypass_verify_with_flag(engine, exported):
    result = engine.apply_bundle(
        exported["bundle_id"], require_verified=False
    )
    assert result["status"] == "applied"


def test_apply_bundle_records_application_row(engine, exported):
    engine.apply_bundle(exported["bundle_id"])
    row = engine.get_bundle(exported["bundle_id"])
    assert len(row["applications"]) == 1
    assert row["applications"][0]["applied_status"] == "applied"


# ---------------------------------------------------------------------------
# record_transfer
# ---------------------------------------------------------------------------


def test_record_transfer_happy_path(engine, exported):
    t = engine.record_transfer(
        bundle_id=exported["bundle_id"],
        from_site="hq",
        to_site="scif-delta",
        transport_method="data_diode",
        checksum_verified=True,
        notes="escort: J. Smith",
    )
    assert t["bundle_id"] == exported["bundle_id"]
    assert t["from_site"] == "hq"
    assert t["to_site"] == "scif-delta"
    assert t["transport_method"] == "data_diode"
    assert t["checksum_verified"] is True


def test_record_transfer_invalid_method_raises(engine, exported):
    with pytest.raises(ValueError, match="transport_method"):
        engine.record_transfer(
            bundle_id=exported["bundle_id"], transport_method="carrier_pigeon"
        )


def test_record_transfer_unknown_bundle_raises(engine):
    with pytest.raises(KeyError):
        engine.record_transfer(bundle_id="bundle-unknown", from_site="x")


def test_record_transfer_advances_status_to_transferred(engine, exported):
    engine.record_transfer(bundle_id=exported["bundle_id"], transport_method="manual_usb")
    row = engine.get_bundle(exported["bundle_id"])
    assert row["status"] == "transferred"


def test_record_transfer_appears_in_get_bundle(engine, exported):
    engine.record_transfer(bundle_id=exported["bundle_id"], transport_method="sftp", notes="test")
    row = engine.get_bundle(exported["bundle_id"])
    assert len(row["transfers"]) == 1
    assert row["transfers"][0]["notes"] == "test"


# ---------------------------------------------------------------------------
# list_bundles / get_bundle / stats
# ---------------------------------------------------------------------------


def test_list_bundles_filters_by_org(engine, sample_cve_rows):
    engine.export_bundle(org_id="orgA", extra_cve_rows=sample_cve_rows, include_ti=False, include_policy=False)
    engine.export_bundle(org_id="orgB", extra_cve_rows=sample_cve_rows, include_ti=False, include_policy=False)
    a = engine.list_bundles(org_id="orgA")
    b = engine.list_bundles(org_id="orgB")
    assert len(a) == 1 and a[0]["org_id"] == "orgA"
    assert len(b) == 1 and b[0]["org_id"] == "orgB"


def test_list_bundles_filters_by_status(engine, sample_cve_rows):
    out = engine.export_bundle(org_id="orgA", extra_cve_rows=sample_cve_rows, include_ti=False, include_policy=False)
    engine.verify_bundle(out["bundle_id"])
    verified = engine.list_bundles(org_id="orgA", status="verified")
    exported_only = engine.list_bundles(org_id="orgA", status="exported")
    assert len(verified) == 1
    assert len(exported_only) == 0


def test_list_bundles_invalid_status_raises(engine):
    with pytest.raises(ValueError, match="status"):
        engine.list_bundles(status="wacky")


def test_get_bundle_returns_none_for_missing(engine):
    assert engine.get_bundle("nonexistent") is None


def test_get_bundle_includes_entries_and_manifest(engine, exported):
    row = engine.get_bundle(exported["bundle_id"])
    assert row is not None
    assert len(row["entries"]) == 6
    assert "manifest" in row
    assert row["manifest"]["bundle_id"] == exported["bundle_id"]


def test_stats_counts_are_correct(engine, sample_cve_rows, sample_ti_rows, sample_policy_rows):
    engine.export_bundle(
        org_id="orgA",
        extra_cve_rows=sample_cve_rows,
        extra_ti_rows=sample_ti_rows,
        extra_policy_rows=sample_policy_rows,
    )
    engine.export_bundle(
        org_id="orgA", extra_cve_rows=sample_cve_rows, include_ti=False, include_policy=False
    )
    s = engine.stats(org_id="orgA")
    assert s["total_bundles"] == 2
    assert s["by_status"].get("exported") == 2
    assert s["total_size_bytes"] > 0
    assert s["entries_by_type"].get("cve") == 6  # 3+3
    assert s["entries_by_type"].get("ti_indicator") == 2
    assert s["entries_by_type"].get("policy") == 1


def test_stats_scoped_by_org(engine, sample_cve_rows):
    engine.export_bundle(org_id="orgA", extra_cve_rows=sample_cve_rows, include_ti=False, include_policy=False)
    engine.export_bundle(org_id="orgB", extra_cve_rows=sample_cve_rows, include_ti=False, include_policy=False)
    a = engine.stats(org_id="orgA")
    b = engine.stats(org_id="orgB")
    global_ = engine.stats()
    assert a["total_bundles"] == 1
    assert b["total_bundles"] == 1
    assert global_["total_bundles"] == 2


def test_stats_empty_org(engine):
    s = engine.stats(org_id="empty_org")
    assert s["total_bundles"] == 0
    assert s["total_size_bytes"] == 0
    assert s["by_status"] == {}


# ---------------------------------------------------------------------------
# Full cycle
# ---------------------------------------------------------------------------


def test_full_export_verify_apply_cycle(engine, sample_cve_rows, sample_ti_rows, sample_policy_rows):
    # export
    b = engine.export_bundle(
        org_id="orgA",
        extra_cve_rows=sample_cve_rows,
        extra_ti_rows=sample_ti_rows,
        extra_policy_rows=sample_policy_rows,
    )
    assert b["status"] == "exported"
    # transfer
    engine.record_transfer(bundle_id=b["bundle_id"], from_site="prod-site", to_site="airgap-site")
    assert engine.get_bundle(b["bundle_id"])["status"] == "transferred"
    # verify
    v = engine.verify_bundle(b["bundle_id"])
    assert v["ok"] is True
    assert engine.get_bundle(b["bundle_id"])["status"] == "verified"
    # apply
    a = engine.apply_bundle(b["bundle_id"])
    assert a["status"] == "applied"
    assert a["applied"] == 6
    # final status is applied
    final = engine.get_bundle(b["bundle_id"])
    assert final["status"] == "applied"
    assert len(final["applications"]) == 1
    assert len(final["transfers"]) == 1


def test_entry_type_coverage_in_manifest(exported):
    types = {e["type"] for e in exported["manifest"]["entries"]}
    assert types == {"cve", "ti_indicator", "policy"}
