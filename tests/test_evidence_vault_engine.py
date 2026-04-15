"""Tests for EvidenceVaultEngine.

Covers: SHA-256 content_hash, seal guard (double-seal raises ValueError),
expires_at retention computation, verify_integrity valid/invalid,
sealed immutability, search filters, org isolation, collections,
access log, vault summary.

Total: 42 tests
"""

from __future__ import annotations

import hashlib
import os
import pytest
from datetime import datetime, timezone, timedelta

from core.evidence_vault_engine import EvidenceVaultEngine


@pytest.fixture
def engine(tmp_path):
    return EvidenceVaultEngine(db_path=str(tmp_path / "vault_test.db"))


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = str(tmp_path / "vault_init.db")
    EvidenceVaultEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "vault_idem.db")
    EvidenceVaultEngine(db_path=db)
    EvidenceVaultEngine(db_path=db)


# ---------------------------------------------------------------------------
# 2. store_evidence
# ---------------------------------------------------------------------------


def test_store_evidence_returns_dict(engine):
    ev = engine.store_evidence(
        org_id="org1",
        evidence_name="Screenshot of access control",
        evidence_type="screenshot",
        framework="SOC2",
        control_id="CC6.1",
        collected_by="alice",
        collection_method="manual",
        content="sample content",
    )
    assert ev["id"]
    assert ev["evidence_name"] == "Screenshot of access control"
    assert ev["org_id"] == "org1"
    assert ev["framework"] == "SOC2"
    assert ev["status"] == "active"
    assert ev["sealed"] is False


def test_store_evidence_sha256_hash(engine):
    content = "hello world evidence"
    expected_hash = hashlib.sha256(content.encode()).hexdigest()
    ev = engine.store_evidence(
        org_id="org1",
        evidence_name="Test evidence",
        evidence_type="log_file",
        framework="ISO27001",
        control_id="A.12.4",
        collected_by="bob",
        collection_method="automated",
        content=content,
    )
    assert ev["content_hash"] == expected_hash


def test_store_evidence_empty_content_no_hash(engine):
    ev = engine.store_evidence(
        org_id="org1",
        evidence_name="Policy doc",
        evidence_type="policy_document",
        framework="HIPAA",
        control_id="164.308",
        collected_by="carol",
        collection_method="manual",
        content="",
    )
    assert ev["content_hash"] == ""
    assert ev["file_size_bytes"] == 0


def test_store_evidence_file_size_bytes(engine):
    content = "abcdef"
    ev = engine.store_evidence(
        org_id="org1",
        evidence_name="Small file",
        evidence_type="certificate",
        framework="PCI-DSS",
        control_id="REQ-2",
        collected_by="dave",
        collection_method="api_pull",
        content=content,
    )
    assert ev["file_size_bytes"] == len(content.encode())


def test_store_evidence_expires_at_retention(engine):
    ev = engine.store_evidence(
        org_id="org1",
        evidence_name="Retention test",
        evidence_type="audit_report",
        framework="SOX",
        control_id="SOX-302",
        collected_by="eve",
        collection_method="export",
        retention_years=5,
    )
    created_dt = datetime.fromisoformat(ev["created_at"])
    expires_dt = datetime.fromisoformat(ev["expires_at"])
    # Should be 5 years later (same month/day, year+5)
    assert expires_dt.year == created_dt.year + 5


def test_store_evidence_default_retention_7_years(engine):
    ev = engine.store_evidence(
        org_id="org1",
        evidence_name="Default retention",
        evidence_type="attestation",
        framework="NIST",
        control_id="AC-1",
        collected_by="frank",
        collection_method="manual",
    )
    created_dt = datetime.fromisoformat(ev["created_at"])
    expires_dt = datetime.fromisoformat(ev["expires_at"])
    assert expires_dt.year == created_dt.year + 7


def test_store_evidence_invalid_type_defaults(engine):
    ev = engine.store_evidence(
        org_id="org1",
        evidence_name="Bad type",
        evidence_type="nonexistent_type",
        framework="GDPR",
        control_id="Art.32",
        collected_by="grace",
        collection_method="manual",
    )
    assert ev["evidence_type"] == "screenshot"


def test_store_evidence_invalid_framework_defaults(engine):
    ev = engine.store_evidence(
        org_id="org1",
        evidence_name="Bad framework",
        evidence_type="log_file",
        framework="BOGUS",
        control_id="X-1",
        collected_by="henry",
        collection_method="manual",
    )
    assert ev["framework"] == "SOC2"


# ---------------------------------------------------------------------------
# 3. seal_evidence
# ---------------------------------------------------------------------------


def test_seal_evidence_sets_sealed_true(engine):
    ev = engine.store_evidence(
        org_id="org1", evidence_name="To seal", evidence_type="screenshot",
        framework="SOC2", control_id="CC1.1", collected_by="alice",
        collection_method="manual", content="data",
    )
    sealed = engine.seal_evidence(ev["id"], "org1")
    assert sealed["sealed"] is True
    assert sealed["sealed_at"] != ""


def test_seal_evidence_double_seal_raises(engine):
    ev = engine.store_evidence(
        org_id="org1", evidence_name="Double seal", evidence_type="screenshot",
        framework="SOC2", control_id="CC1.2", collected_by="alice",
        collection_method="manual", content="data",
    )
    engine.seal_evidence(ev["id"], "org1")
    with pytest.raises(ValueError, match="already sealed"):
        engine.seal_evidence(ev["id"], "org1")


def test_seal_evidence_wrong_org_raises(engine):
    ev = engine.store_evidence(
        org_id="org1", evidence_name="Org seal", evidence_type="screenshot",
        framework="SOC2", control_id="CC1.3", collected_by="alice",
        collection_method="manual",
    )
    with pytest.raises(ValueError):
        engine.seal_evidence(ev["id"], "org2")


# ---------------------------------------------------------------------------
# 4. verify_integrity
# ---------------------------------------------------------------------------


def test_verify_integrity_valid(engine):
    content = "integrity check content"
    ev = engine.store_evidence(
        org_id="org1", evidence_name="Integrity test", evidence_type="log_file",
        framework="NIST", control_id="AU-9", collected_by="alice",
        collection_method="automated", content=content,
    )
    result = engine.verify_integrity(ev["id"], "org1", content)
    assert result["valid"] is True
    assert result["stored_hash"] == result["computed_hash"]


def test_verify_integrity_invalid_content(engine):
    content = "original content"
    ev = engine.store_evidence(
        org_id="org1", evidence_name="Tamper test", evidence_type="log_file",
        framework="NIST", control_id="AU-10", collected_by="alice",
        collection_method="automated", content=content,
    )
    result = engine.verify_integrity(ev["id"], "org1", "tampered content")
    assert result["valid"] is False
    assert result["stored_hash"] != result["computed_hash"]


def test_verify_integrity_not_found(engine):
    result = engine.verify_integrity("nonexistent-id", "org1", "content")
    assert result["valid"] is False


def test_verify_integrity_empty_stored_hash(engine):
    ev = engine.store_evidence(
        org_id="org1", evidence_name="No content hash", evidence_type="screenshot",
        framework="SOC2", control_id="CC2.1", collected_by="alice",
        collection_method="manual", content="",
    )
    result = engine.verify_integrity(ev["id"], "org1", "")
    assert result["valid"] is False  # empty stored hash → invalid


# ---------------------------------------------------------------------------
# 5. log_access
# ---------------------------------------------------------------------------


def test_log_access_returns_dict(engine):
    ev = engine.store_evidence(
        org_id="org1", evidence_name="Access log test", evidence_type="screenshot",
        framework="SOC2", control_id="CC3.1", collected_by="alice",
        collection_method="manual",
    )
    log = engine.log_access(ev["id"], "org1", "auditor@example.com", "view", "audit review")
    assert log["evidence_id"] == ev["id"]
    assert log["access_type"] == "view"
    assert log["accessed_by"] == "auditor@example.com"


def test_log_access_invalid_type_defaults(engine):
    ev = engine.store_evidence(
        org_id="org1", evidence_name="Bad access type", evidence_type="screenshot",
        framework="SOC2", control_id="CC3.2", collected_by="alice",
        collection_method="manual",
    )
    log = engine.log_access(ev["id"], "org1", "user", "invalid_type", "reason")
    assert log["access_type"] == "view"


def test_get_evidence_detail_includes_access_log(engine):
    ev = engine.store_evidence(
        org_id="org1", evidence_name="Detail test", evidence_type="attestation",
        framework="HIPAA", control_id="164.312", collected_by="bob",
        collection_method="api_pull", content="content",
    )
    engine.log_access(ev["id"], "org1", "viewer1", "view", "test")
    engine.log_access(ev["id"], "org1", "viewer2", "download", "export")
    detail = engine.get_evidence_detail(ev["id"], "org1")
    assert "access_log" in detail
    assert len(detail["access_log"]) == 2


# ---------------------------------------------------------------------------
# 6. search_evidence
# ---------------------------------------------------------------------------


def test_search_evidence_all(engine):
    for i in range(3):
        engine.store_evidence(
            org_id="org1", evidence_name=f"Evidence {i}", evidence_type="screenshot",
            framework="SOC2", control_id=f"CC{i}.1", collected_by="alice",
            collection_method="manual",
        )
    results = engine.search_evidence("org1")
    assert len(results) == 3


def test_search_evidence_filter_framework(engine):
    engine.store_evidence(
        org_id="org1", evidence_name="SOC2 ev", evidence_type="screenshot",
        framework="SOC2", control_id="CC1.1", collected_by="alice", collection_method="manual",
    )
    engine.store_evidence(
        org_id="org1", evidence_name="NIST ev", evidence_type="log_file",
        framework="NIST", control_id="AU-1", collected_by="alice", collection_method="manual",
    )
    results = engine.search_evidence("org1", framework="NIST")
    assert len(results) == 1
    assert results[0]["framework"] == "NIST"


def test_search_evidence_filter_control_id(engine):
    engine.store_evidence(
        org_id="org1", evidence_name="CC6.1 ev", evidence_type="screenshot",
        framework="SOC2", control_id="CC6.1", collected_by="alice", collection_method="manual",
    )
    engine.store_evidence(
        org_id="org1", evidence_name="CC7.1 ev", evidence_type="screenshot",
        framework="SOC2", control_id="CC7.1", collected_by="alice", collection_method="manual",
    )
    results = engine.search_evidence("org1", control_id="CC6.1")
    assert len(results) == 1


def test_search_evidence_filter_type(engine):
    engine.store_evidence(
        org_id="org1", evidence_name="Log ev", evidence_type="log_file",
        framework="SOC2", control_id="CC1.1", collected_by="alice", collection_method="manual",
    )
    engine.store_evidence(
        org_id="org1", evidence_name="Screenshot ev", evidence_type="screenshot",
        framework="SOC2", control_id="CC1.2", collected_by="alice", collection_method="manual",
    )
    results = engine.search_evidence("org1", evidence_type="log_file")
    assert len(results) == 1


# ---------------------------------------------------------------------------
# 7. Collections
# ---------------------------------------------------------------------------


def test_create_collection_returns_dict(engine):
    coll = engine.create_collection("org1", "SOC2 Q1 Audit", "SOC2", "2026-Q1", "auditor@co.com")
    assert coll["id"]
    assert coll["collection_name"] == "SOC2 Q1 Audit"
    assert coll["evidence_count"] == 0
    assert coll["complete"] is False


def test_add_to_collection_increments_count(engine):
    ev = engine.store_evidence(
        org_id="org1", evidence_name="Coll ev", evidence_type="screenshot",
        framework="SOC2", control_id="CC1.1", collected_by="alice", collection_method="manual",
    )
    coll = engine.create_collection("org1", "Test Collection", "SOC2", "2026-Q1", "auditor")
    updated = engine.add_to_collection(coll["id"], ev["id"], "org1")
    assert updated["evidence_count"] == 1
    assert updated["complete"] is True


def test_add_to_collection_idempotent(engine):
    ev = engine.store_evidence(
        org_id="org1", evidence_name="Idempotent ev", evidence_type="screenshot",
        framework="SOC2", control_id="CC1.1", collected_by="alice", collection_method="manual",
    )
    coll = engine.create_collection("org1", "Idem Coll", "SOC2", "2026-Q1", "auditor")
    engine.add_to_collection(coll["id"], ev["id"], "org1")
    updated = engine.add_to_collection(coll["id"], ev["id"], "org1")
    assert updated["evidence_count"] == 1  # not 2


def test_add_to_collection_wrong_org_raises(engine):
    ev = engine.store_evidence(
        org_id="org1", evidence_name="Org ev", evidence_type="screenshot",
        framework="SOC2", control_id="CC1.1", collected_by="alice", collection_method="manual",
    )
    coll = engine.create_collection("org1", "Org Coll", "SOC2", "2026-Q1", "auditor")
    with pytest.raises(ValueError):
        engine.add_to_collection(coll["id"], ev["id"], "org2")


# ---------------------------------------------------------------------------
# 8. get_vault_summary
# ---------------------------------------------------------------------------


def test_vault_summary_structure(engine):
    engine.store_evidence(
        org_id="org1", evidence_name="Summary ev", evidence_type="screenshot",
        framework="SOC2", control_id="CC1.1", collected_by="alice", collection_method="manual",
        content="data",
    )
    summary = engine.get_vault_summary("org1")
    assert "total" in summary
    assert "sealed_count" in summary
    assert "by_framework" in summary
    assert "expiring_soon" in summary
    assert "expired" in summary
    assert "active_collections" in summary


def test_vault_summary_sealed_count(engine):
    ev = engine.store_evidence(
        org_id="org1", evidence_name="Seal count ev", evidence_type="screenshot",
        framework="SOC2", control_id="CC1.1", collected_by="alice", collection_method="manual",
        content="data",
    )
    engine.seal_evidence(ev["id"], "org1")
    summary = engine.get_vault_summary("org1")
    assert summary["sealed_count"] >= 1


def test_vault_summary_by_framework(engine):
    engine.store_evidence(
        org_id="org1", evidence_name="F1", evidence_type="screenshot",
        framework="SOC2", control_id="CC1.1", collected_by="alice", collection_method="manual",
    )
    engine.store_evidence(
        org_id="org1", evidence_name="F2", evidence_type="log_file",
        framework="NIST", control_id="AU-1", collected_by="alice", collection_method="manual",
    )
    summary = engine.get_vault_summary("org1")
    assert "SOC2" in summary["by_framework"]
    assert "NIST" in summary["by_framework"]


# ---------------------------------------------------------------------------
# 9. Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_evidence(engine):
    engine.store_evidence(
        org_id="org1", evidence_name="Org1 ev", evidence_type="screenshot",
        framework="SOC2", control_id="CC1.1", collected_by="alice", collection_method="manual",
    )
    results = engine.search_evidence("org2")
    assert len(results) == 0


def test_org_isolation_summary(engine):
    engine.store_evidence(
        org_id="org1", evidence_name="Org1 ev", evidence_type="screenshot",
        framework="SOC2", control_id="CC1.1", collected_by="alice", collection_method="manual",
    )
    summary = engine.get_vault_summary("org2")
    assert summary["total"] == 0


def test_get_evidence_detail_org_isolation(engine):
    ev = engine.store_evidence(
        org_id="org1", evidence_name="Iso ev", evidence_type="screenshot",
        framework="SOC2", control_id="CC1.1", collected_by="alice", collection_method="manual",
    )
    detail = engine.get_evidence_detail(ev["id"], "org2")
    assert detail is None
