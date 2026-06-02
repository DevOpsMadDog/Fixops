"""Locks the honest content-integrity behaviour of EvidenceChainEngine.verify_integrity.

Regression guard for the SCIF-critical fix: verify_integrity must RE-HASH the artifact at
storage_location (not trust a non-empty stored hash). Tampered content -> verified=False.
"""
from __future__ import annotations

import hashlib

import pytest

from core.evidence_chain_engine import EvidenceChainEngine


@pytest.fixture
def eng():
    return EvidenceChainEngine()


def _case(eng, org):
    c = eng.create_case(org, {"case_name": "t", "description": "d"})
    return c["case_id"]


def test_matching_artifact_is_verified(eng, tmp_path):
    org = "ev-rehash-match"
    cid = _case(eng, org)
    fp = tmp_path / "art.bin"
    fp.write_bytes(b"REAL EVIDENCE CONTENT")
    sha = hashlib.sha256(b"REAL EVIDENCE CONTENT").hexdigest()
    ev = eng.add_evidence(org, cid, {
        "evidence_type": "file", "filename": "art.bin",
        "hash_sha256": sha, "storage_location": str(fp), "size_bytes": 21,
    })
    r = eng.verify_integrity(org, ev["evidence_id"])
    assert r["hash_recomputed"] is True
    assert r["content_integrity"] == "verified"
    assert r["hash_match"] is True
    assert r["verified"] is True


def test_tampered_artifact_fails(eng, tmp_path):
    org = "ev-rehash-tamper"
    cid = _case(eng, org)
    fp = tmp_path / "art.bin"
    fp.write_bytes(b"ORIGINAL")
    sha = hashlib.sha256(b"ORIGINAL").hexdigest()
    ev = eng.add_evidence(org, cid, {
        "evidence_type": "file", "filename": "art.bin",
        "hash_sha256": sha, "storage_location": str(fp), "size_bytes": 8,
    })
    # tamper the on-disk artifact after recording
    fp.write_bytes(b"TAMPERED CONTENT!!!")
    r = eng.verify_integrity(org, ev["evidence_id"])
    assert r["hash_recomputed"] is True
    assert r["content_integrity"] == "tampered"
    assert r["hash_match"] is False
    assert r["verified"] is False  # the bug was returning True here


def test_no_artifact_is_unverified_not_faked(eng, tmp_path):
    org = "ev-rehash-noart"
    cid = _case(eng, org)
    ev = eng.add_evidence(org, cid, {
        "evidence_type": "file", "filename": "x",
        "hash_sha256": "deadbeef", "storage_location": "", "size_bytes": 0,
    })
    r = eng.verify_integrity(org, ev["evidence_id"])
    assert r["hash_recomputed"] is False
    assert r["content_integrity"] == "unverified_no_artifact"  # honest, not a fake "verified"
