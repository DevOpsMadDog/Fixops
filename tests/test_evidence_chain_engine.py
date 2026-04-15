"""Tests for EvidenceChainEngine.

Covers: init, create case, add evidence (hash stored), custody transfer
(trail grows), verify_integrity (returns verified bool), seal_evidence
(can't transfer after sealed), close case, stats structure, org isolation.

Total: 30 tests
"""

from __future__ import annotations

import os
import pytest
from core.evidence_chain_engine import EvidenceChainEngine


@pytest.fixture
def engine(tmp_path):
    return EvidenceChainEngine(db_path=str(tmp_path / "test.db"))


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = str(tmp_path / "ec_init.db")
    EvidenceChainEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "ec_idem.db")
    EvidenceChainEngine(db_path=db)
    EvidenceChainEngine(db_path=db)


# ---------------------------------------------------------------------------
# 2. Cases
# ---------------------------------------------------------------------------


def test_create_case_returns_dict(engine):
    case = engine.create_case("org1", {
        "case_number": "CASE-001",
        "case_title": "Ransomware Investigation",
        "case_type": "forensic",
        "investigator": "alice",
    })
    assert case["case_id"]
    assert case["case_number"] == "CASE-001"
    assert case["case_title"] == "Ransomware Investigation"
    assert case["case_type"] == "forensic"
    assert case["status"] == "open"


def test_create_case_invalid_type_defaults(engine):
    case = engine.create_case("org1", {"case_type": "bogus"})
    assert case["case_type"] == "internal"


def test_list_cases_empty(engine):
    assert engine.list_cases("no-org") == []


def test_list_cases_returns_all(engine):
    engine.create_case("org1", {"case_title": "C1"})
    engine.create_case("org1", {"case_title": "C2"})
    assert len(engine.list_cases("org1")) == 2


def test_list_cases_filter_by_status(engine):
    engine.create_case("org1", {"case_title": "Open"})
    case2 = engine.create_case("org1", {"case_title": "To Close"})
    engine.close_case("org1", case2["case_id"], "alice", "resolved")
    open_cases = engine.list_cases("org1", status="open")
    assert len(open_cases) == 1
    assert open_cases[0]["case_title"] == "Open"


def test_close_case(engine):
    case = engine.create_case("org1", {"case_title": "Investigation"})
    closed = engine.close_case("org1", case["case_id"], "bob", "case resolved")
    assert closed["status"] == "closed"
    assert closed["closed_by"] == "bob"
    assert closed["outcome"] == "case resolved"
    assert closed["closed_at"]


# ---------------------------------------------------------------------------
# 3. Evidence
# ---------------------------------------------------------------------------


def _make_case(engine, org="org1"):
    return engine.create_case(org, {"case_title": "Test Case", "case_type": "forensic"})


def test_add_evidence_returns_dict(engine):
    case = _make_case(engine)
    ev = engine.add_evidence("org1", case["case_id"], {
        "evidence_type": "file",
        "filename": "malware.exe",
        "hash_md5": "abc123",
        "hash_sha256": "def456",
        "size_bytes": 8192,
        "collected_by": "alice",
        "collection_method": "disk_image",
        "storage_location": "/secure/vault/001",
    })
    assert ev["evidence_id"]
    assert ev["filename"] == "malware.exe"
    assert ev["hash_md5"] == "abc123"
    assert ev["hash_sha256"] == "def456"
    assert ev["chain_of_custody_id"]
    assert ev["sealed"] is False


def test_add_evidence_invalid_type_defaults(engine):
    case = _make_case(engine)
    ev = engine.add_evidence("org1", case["case_id"], {"evidence_type": "bogus"})
    assert ev["evidence_type"] == "file"


def test_list_evidence_empty(engine):
    case = _make_case(engine)
    assert engine.list_evidence("org1", case["case_id"]) == []


def test_list_evidence_returns_items(engine):
    case = _make_case(engine)
    engine.add_evidence("org1", case["case_id"], {"filename": "f1.log", "hash_md5": "h1"})
    engine.add_evidence("org1", case["case_id"], {"filename": "f2.log", "hash_md5": "h2"})
    items = engine.list_evidence("org1", case["case_id"])
    assert len(items) == 2


# ---------------------------------------------------------------------------
# 4. Chain of Custody
# ---------------------------------------------------------------------------


def _make_evidence(engine, org="org1"):
    case = _make_case(engine, org)
    ev = engine.add_evidence(org, case["case_id"], {
        "filename": "evidence.bin",
        "hash_md5": "md5hash",
        "hash_sha256": "sha256hash",
        "collected_by": "alice",
    })
    return case, ev


def test_get_custody_chain_initial(engine):
    _, ev = _make_evidence(engine)
    chain = engine.get_custody_chain("org1", ev["evidence_id"])
    assert chain["evidence_id"] == ev["evidence_id"]
    assert chain["chain_of_custody_id"]
    assert len(chain["custody_chain"]) == 1
    assert chain["custody_chain"][0]["event"] == "collected"


def test_transfer_custody_grows_chain(engine):
    _, ev = _make_evidence(engine)
    engine.transfer_custody("org1", ev["evidence_id"], {
        "from_person": "alice",
        "to_person": "bob",
        "transfer_reason": "lab analysis",
        "location_change": "field->lab",
    })
    chain = engine.get_custody_chain("org1", ev["evidence_id"])
    assert len(chain["custody_chain"]) == 2
    assert chain["custody_chain"][1]["event"] == "transfer"
    assert chain["custody_chain"][1]["to_person"] == "bob"


def test_transfer_custody_multiple(engine):
    _, ev = _make_evidence(engine)
    engine.transfer_custody("org1", ev["evidence_id"], {"from_person": "a", "to_person": "b"})
    engine.transfer_custody("org1", ev["evidence_id"], {"from_person": "b", "to_person": "c"})
    chain = engine.get_custody_chain("org1", ev["evidence_id"])
    assert len(chain["custody_chain"]) == 3


# ---------------------------------------------------------------------------
# 5. Seal Evidence
# ---------------------------------------------------------------------------


def test_seal_evidence(engine):
    _, ev = _make_evidence(engine)
    sealed = engine.seal_evidence("org1", ev["evidence_id"], "supervisor")
    assert sealed["sealed"] is True
    assert sealed["sealed_by"] == "supervisor"
    assert sealed["sealed_at"]


def test_transfer_after_seal_raises(engine):
    _, ev = _make_evidence(engine)
    engine.seal_evidence("org1", ev["evidence_id"], "supervisor")
    with pytest.raises(ValueError, match="sealed"):
        engine.transfer_custody("org1", ev["evidence_id"], {
            "from_person": "alice", "to_person": "charlie"
        })


# ---------------------------------------------------------------------------
# 6. Verify Integrity
# ---------------------------------------------------------------------------


def test_verify_integrity_with_hashes(engine):
    _, ev = _make_evidence(engine)
    result = engine.verify_integrity("org1", ev["evidence_id"])
    assert "verified" in result
    assert "hash_match" in result
    assert "chain_intact" in result
    assert result["verified"] is True
    assert result["hash_match"] is True
    assert result["chain_intact"] is True


def test_verify_integrity_no_hash(engine):
    case = _make_case(engine)
    ev = engine.add_evidence("org1", case["case_id"], {
        "filename": "nohash.log",
        "hash_md5": "",
        "hash_sha256": "",
    })
    result = engine.verify_integrity("org1", ev["evidence_id"])
    assert result["hash_match"] is False
    assert result["verified"] is False


def test_verify_integrity_missing_evidence(engine):
    result = engine.verify_integrity("org1", "nonexistent-id")
    assert result["verified"] is False
    assert result["hash_match"] is False
    assert result["chain_intact"] is False


# ---------------------------------------------------------------------------
# 7. Stats
# ---------------------------------------------------------------------------


def test_stats_structure(engine):
    stats = engine.get_evidence_stats("org1")
    assert "total_cases" in stats
    assert "open_cases" in stats
    assert "total_evidence" in stats
    assert "sealed_count" in stats
    assert "transfer_count" in stats
    assert "by_case_type" in stats


def test_stats_counts(engine):
    case = _make_case(engine)
    ev = engine.add_evidence("org1", case["case_id"], {
        "hash_md5": "m", "hash_sha256": "s"
    })
    engine.seal_evidence("org1", ev["evidence_id"], "admin")
    engine.add_evidence("org1", case["case_id"], {"hash_md5": "m2"})

    stats = engine.get_evidence_stats("org1")
    assert stats["total_cases"] == 1
    assert stats["open_cases"] == 1
    assert stats["total_evidence"] == 2
    assert stats["sealed_count"] == 1


def test_stats_transfer_count(engine):
    _, ev = _make_evidence(engine)
    engine.transfer_custody("org1", ev["evidence_id"], {"from_person": "a", "to_person": "b"})
    stats = engine.get_evidence_stats("org1")
    assert stats["transfer_count"] == 1


def test_stats_by_case_type(engine):
    engine.create_case("org1", {"case_type": "forensic"})
    engine.create_case("org1", {"case_type": "forensic"})
    engine.create_case("org1", {"case_type": "legal"})
    stats = engine.get_evidence_stats("org1")
    assert stats["by_case_type"]["forensic"] == 2
    assert stats["by_case_type"]["legal"] == 1


# ---------------------------------------------------------------------------
# 8. Org Isolation
# ---------------------------------------------------------------------------


def test_org_isolation_cases(engine):
    engine.create_case("org-A", {"case_title": "A-case"})
    engine.create_case("org-B", {"case_title": "B-case"})
    assert len(engine.list_cases("org-A")) == 1
    assert len(engine.list_cases("org-B")) == 1


def test_org_isolation_evidence(engine):
    case_a = engine.create_case("org-A", {"case_title": "A"})
    case_b = engine.create_case("org-B", {"case_title": "B"})
    engine.add_evidence("org-A", case_a["case_id"], {"filename": "fa.log"})
    engine.add_evidence("org-B", case_b["case_id"], {"filename": "fb.log"})
    assert len(engine.list_evidence("org-A", case_a["case_id"])) == 1
    assert len(engine.list_evidence("org-B", case_b["case_id"])) == 1
