"""Tests for BinaryFingerprintEngine (GAP-008).

Covers:
  * deterministic sha256 / tlsh-approx / ssdeep-approx
  * tlsh similarity on modified vs original blobs
  * known-bad exact match + approx match + miss
  * org_id isolation on the fingerprint registry
  * entropy (all-zero vs random)
  * schema idempotency
  * register / query_similar / check_known_bad / stats APIs

Total: 32 tests
"""

from __future__ import annotations

import hashlib
import math
import os
import pytest

from core.binary_fingerprint_engine import (
    BinaryFingerprintEngine,
    _compute_tlsh_approx,
    _compute_ssdeep_approx,
    _shannon_entropy,
    _tlsh_similarity,
    _KNOWN_BAD_SEED,
)


@pytest.fixture
def engine(tmp_path):
    return BinaryFingerprintEngine(db_path=str(tmp_path / "bfp_test.db"))


# ---------------------------------------------------------------------------
# 1. Initialisation / schema
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = str(tmp_path / "bfp_init.db")
    BinaryFingerprintEngine(db_path=db)
    assert os.path.exists(db)


def test_ensure_schema_idempotent(tmp_path):
    db = str(tmp_path / "bfp_idem.db")
    e = BinaryFingerprintEngine(db_path=db)
    e.ensure_schema()
    e.ensure_schema()
    # no exception + table still present
    stats = e.stats(org_id="org-x")
    assert stats["fingerprints_seen"] == 0


def test_schema_has_expected_tables(engine):
    import sqlite3
    conn = sqlite3.connect(engine.db_path)
    rows = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    for t in ("binary_fingerprints", "known_bad_fingerprints", "fingerprint_matches"):
        assert t in rows, f"missing table: {t}"
    conn.close()


# ---------------------------------------------------------------------------
# 2. compute_fingerprint — determinism + fields
# ---------------------------------------------------------------------------


def test_compute_fingerprint_returns_all_fields(engine):
    fp = engine.compute_fingerprint(b"hello world")
    for key in ("sha256", "tlsh_hash", "ssdeep_hash", "size_bytes", "first_kb_hex", "entropy"):
        assert key in fp


def test_compute_sha256_matches_hashlib(engine):
    blob = b"deterministic input"
    fp = engine.compute_fingerprint(blob)
    assert fp["sha256"] == hashlib.sha256(blob).hexdigest()


def test_compute_fingerprint_deterministic(engine):
    blob = b"\x00\x01\x02\x03" * 100
    a = engine.compute_fingerprint(blob)
    b = engine.compute_fingerprint(blob)
    assert a == b


def test_compute_fingerprint_size_bytes(engine):
    blob = b"x" * 1234
    fp = engine.compute_fingerprint(blob)
    assert fp["size_bytes"] == 1234


def test_compute_fingerprint_first_kb_truncates(engine):
    blob = b"A" * 2048
    fp = engine.compute_fingerprint(blob)
    assert len(fp["first_kb_hex"]) == 1024 * 2  # hex doubles byte count


def test_compute_fingerprint_empty_blob(engine):
    fp = engine.compute_fingerprint(b"")
    assert fp["size_bytes"] == 0
    assert fp["sha256"] == hashlib.sha256(b"").hexdigest()
    assert fp["entropy"] == 0.0
    assert fp["first_kb_hex"] == ""


def test_compute_fingerprint_none_treated_as_empty(engine):
    fp = engine.compute_fingerprint(None)
    assert fp["size_bytes"] == 0


def test_compute_fingerprint_rejects_non_bytes(engine):
    with pytest.raises(TypeError):
        engine.compute_fingerprint("not bytes")  # type: ignore[arg-type]


def test_compute_fingerprint_accepts_bytearray(engine):
    fp = engine.compute_fingerprint(bytearray(b"hello"))
    assert fp["size_bytes"] == 5


# ---------------------------------------------------------------------------
# 3. TLSH approximation — similarity on mutations
# ---------------------------------------------------------------------------


def test_tlsh_approx_format():
    h = _compute_tlsh_approx(b"\x00" * 1000)
    assert h.startswith("T1")
    # "T1" prefix + 5 buckets * 7 bytes * 2 hex = 72 chars total
    assert len(h) == 72
    assert len(h[2:]) == 70


def test_tlsh_similarity_self_is_one():
    h = _compute_tlsh_approx(b"same payload" * 50)
    assert _tlsh_similarity(h, h) == 1.0


def test_tlsh_similarity_modified_blob_stays_close():
    base = bytes(range(256)) * 20
    mutated = bytearray(base)
    # flip a few bytes in a single bucket to preserve most bucket prefixes
    mutated[-5:] = b"\x00\x00\x00\x00\x00"
    sim = _tlsh_similarity(
        _compute_tlsh_approx(base),
        _compute_tlsh_approx(bytes(mutated)),
    )
    assert sim >= 0.6


def test_tlsh_similarity_totally_different_blobs_low():
    a = _compute_tlsh_approx(b"\x00" * 2048)
    b = _compute_tlsh_approx(b"\xff" * 2048)
    assert _tlsh_similarity(a, b) <= 0.2


def test_tlsh_similarity_malformed_inputs_return_zero():
    assert _tlsh_similarity("", "T1" + "A" * 68) == 0.0
    assert _tlsh_similarity("bogus", "also-bogus") == 0.0


# ---------------------------------------------------------------------------
# 4. ssdeep approximation — shape
# ---------------------------------------------------------------------------


def test_ssdeep_approx_format_contains_colons():
    h = _compute_ssdeep_approx(b"some payload of medium size" * 40)
    assert h.count(":") == 2
    bs, ha, hb = h.split(":")
    assert bs.isdigit()
    assert len(ha) > 0
    assert len(hb) > 0


def test_ssdeep_approx_empty():
    assert _compute_ssdeep_approx(b"") == "3::"


def test_ssdeep_approx_deterministic():
    blob = b"payload" * 100
    assert _compute_ssdeep_approx(blob) == _compute_ssdeep_approx(blob)


# ---------------------------------------------------------------------------
# 5. Shannon entropy
# ---------------------------------------------------------------------------


def test_entropy_all_zero_is_zero():
    assert _shannon_entropy(b"\x00" * 2048) == 0.0


def test_entropy_uniform_is_near_8():
    blob = bytes(range(256)) * 16  # perfectly uniform byte distribution
    e = _shannon_entropy(blob)
    assert 7.99 <= e <= 8.0


def test_entropy_ordering_low_vs_high():
    low = _shannon_entropy(b"\x00" * 1024)
    high = _shannon_entropy(bytes(range(256)) * 4)
    assert low < high


# ---------------------------------------------------------------------------
# 6. register_artifact
# ---------------------------------------------------------------------------


def test_register_artifact_persists(engine):
    rec = engine.register_artifact("org1", "s3://bucket/obj", b"content-a")
    assert rec["org_id"] == "org1"
    assert rec["artifact_ref"] == "s3://bucket/obj"
    assert rec["sha256"] == hashlib.sha256(b"content-a").hexdigest()
    stats = engine.stats("org1")
    assert stats["fingerprints_seen"] == 1


def test_register_artifact_requires_org_id(engine):
    with pytest.raises(ValueError):
        engine.register_artifact("", "x", b"payload")


def test_register_artifact_org_isolation(engine):
    engine.register_artifact("orgA", "a.bin", b"payload-A")
    engine.register_artifact("orgB", "b.bin", b"payload-B")
    assert engine.stats("orgA")["fingerprints_seen"] == 1
    assert engine.stats("orgB")["fingerprints_seen"] == 1


# ---------------------------------------------------------------------------
# 7. query_similar
# ---------------------------------------------------------------------------


def test_query_similar_exact_match(engine):
    engine.register_artifact("orgQ", "q.bin", b"abc123" * 50)
    result = engine.query_similar("orgQ", b"abc123" * 50)
    assert result["exact_matches"] == 1
    assert result["matches"][0]["match_type"] == "exact"
    assert result["matches"][0]["similarity"] == 1.0


def test_query_similar_no_match(engine):
    engine.register_artifact("orgQ", "q.bin", b"seed-A" * 10)
    result = engine.query_similar("orgQ", b"totally-different-payload" * 10)
    assert result["exact_matches"] == 0


def test_query_similar_respects_org_isolation(engine):
    engine.register_artifact("orgA", "a.bin", b"shared")
    result = engine.query_similar("orgB", b"shared")
    assert result["exact_matches"] == 0
    assert result["approx_matches"] == 0


def test_query_similar_invalid_similarity_raises(engine):
    with pytest.raises(ValueError):
        engine.query_similar("orgX", b"blob", min_similarity=1.5)


# ---------------------------------------------------------------------------
# 8. check_known_bad
# ---------------------------------------------------------------------------


def test_check_known_bad_returns_none_for_clean_blob(engine):
    verdict = engine.check_known_bad(b"definitely clean content 123")
    assert verdict is None


def test_check_known_bad_seeds_registry(engine, monkeypatch):
    # Force air-gap + unreachable MalwareBazaar so the synthetic placeholders
    # are the seeded source-of-truth (new contract — see MalwareBazaar tests).
    monkeypatch.setenv("FIXOPS_AIR_GAP", "1")
    from unittest.mock import patch
    with patch(
        "core.binary_fingerprint_engine._requests.post",
        side_effect=ConnectionError("offline"),
    ):
        engine.check_known_bad(b"nothing")
    import sqlite3
    conn = sqlite3.connect(engine.db_path)
    count = conn.execute("SELECT COUNT(*) FROM known_bad_fingerprints").fetchone()[0]
    conn.close()
    assert count == len(_KNOWN_BAD_SEED)


def test_check_known_bad_exact_match_records_event(engine):
    # New contract: directly upsert a known-bad entry rather than relying on
    # the auto-seed (which now defers to MalwareBazaar when online).
    blob = b"bad-artifact-v1"
    sha = hashlib.sha256(blob).hexdigest()
    engine._upsert_known_bad(
        {
            "sha256": sha,
            "tlsh_hash": "T1" + "A" * 70,
            "ssdeep_hash": "3:abc:def",
            "threat_label": "mirai-variant-test-placeholder",
            "source": "test:fixture",
        }
    )
    verdict = engine.check_known_bad(blob, org_id="orgZ", candidate_id="candZ")
    assert verdict is not None
    assert verdict["verdict"] == "known_bad"
    assert verdict["match_type"] == "exact"
    assert verdict["similarity"] == 1.0
    # Match row recorded
    assert engine.stats("orgZ")["known_bad_matches"] == 1


def test_check_known_bad_approx_match_when_tlsh_close(engine):
    # New contract: seed an entry whose tlsh equals the query blob's tlsh.
    blob = b"blob-for-near-match" * 40
    tlsh = _compute_tlsh_approx(blob)
    engine._upsert_known_bad(
        {
            "sha256": "9" * 64,
            "tlsh_hash": tlsh,
            "ssdeep_hash": "6:near:match",
            "threat_label": "emotet-like-test-placeholder",
            "source": "test:fixture",
        }
    )
    verdict = engine.check_known_bad(blob, org_id="orgA")
    assert verdict is not None
    assert verdict["match_type"] in ("exact", "tlsh_approx")
    assert verdict["similarity"] >= 0.8


# ---------------------------------------------------------------------------
# 9. stats
# ---------------------------------------------------------------------------


def test_stats_empty_org(engine):
    s = engine.stats("empty-org")
    assert s["fingerprints_seen"] == 0
    assert s["unique_sha256"] == 0
    assert s["known_bad_matches"] == 0
    assert s["total_bytes"] == 0
    assert s["avg_entropy"] == 0.0


def test_stats_counts_registered(engine):
    engine.register_artifact("org-stats", "a.bin", b"aaa")
    engine.register_artifact("org-stats", "b.bin", b"aaa")  # duplicate sha256
    engine.register_artifact("org-stats", "c.bin", b"bbb")
    s = engine.stats("org-stats")
    assert s["fingerprints_seen"] == 3
    assert s["unique_sha256"] == 2
    assert s["total_bytes"] == 9


def test_stats_requires_org_id(engine):
    with pytest.raises(ValueError):
        engine.stats("")
