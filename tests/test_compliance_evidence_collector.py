"""Tests for ComplianceEvidenceCollector engine.

Covers: init, create_request, submit_evidence, approve/reject workflow,
auto_collect, audit_readiness, stats, and org isolation.

Total: 35 tests.
"""

from __future__ import annotations

import pytest
from core.compliance_evidence_collector import ComplianceEvidenceCollector


@pytest.fixture()
def engine(tmp_path):
    return ComplianceEvidenceCollector(db_path=str(tmp_path / "test.db"))


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "ce_init.db")
    e = ComplianceEvidenceCollector(db_path=db)
    assert e is not None


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "ce_idem.db")
    ComplianceEvidenceCollector(db_path=db)
    e2 = ComplianceEvidenceCollector(db_path=db)
    assert e2 is not None


# ---------------------------------------------------------------------------
# 2. Create evidence request
# ---------------------------------------------------------------------------

def test_create_request_returns_dict(engine):
    r = engine.create_evidence_request("org1", {
        "framework": "SOC2",
        "control_id": "CC6.1",
        "control_name": "Logical Access",
        "description": "Provide access logs",
        "due_date": "2026-06-30",
        "assignee": "alice@example.com",
    })
    assert r["request_id"]
    assert r["framework"] == "SOC2"
    assert r["status"] == "pending"


def test_create_request_all_frameworks(engine):
    for fw in ["SOC2", "ISO27001", "PCI-DSS", "HIPAA"]:
        r = engine.create_evidence_request("org1", {"framework": fw})
        assert r["framework"] == fw


def test_create_request_invalid_framework(engine):
    with pytest.raises(ValueError, match="Invalid framework"):
        engine.create_evidence_request("org1", {"framework": "GDPR"})


def test_create_request_sets_pending_status(engine):
    r = engine.create_evidence_request("org1", {"framework": "SOC2"})
    assert r["status"] == "pending"


def test_create_request_has_timestamps(engine):
    r = engine.create_evidence_request("org1", {"framework": "SOC2"})
    assert r["created_at"]
    assert r["updated_at"]


# ---------------------------------------------------------------------------
# 3. List evidence requests
# ---------------------------------------------------------------------------

def test_list_requests_empty(engine):
    assert engine.list_evidence_requests("org1") == []


def test_list_requests_returns_created(engine):
    engine.create_evidence_request("org1", {"framework": "SOC2"})
    engine.create_evidence_request("org1", {"framework": "ISO27001"})
    rows = engine.list_evidence_requests("org1")
    assert len(rows) == 2


def test_list_requests_filter_framework(engine):
    engine.create_evidence_request("org1", {"framework": "SOC2"})
    engine.create_evidence_request("org1", {"framework": "HIPAA"})
    rows = engine.list_evidence_requests("org1", framework="SOC2")
    assert all(r["framework"] == "SOC2" for r in rows)
    assert len(rows) == 1


def test_list_requests_filter_status(engine):
    r = engine.create_evidence_request("org1", {"framework": "SOC2"})
    engine.submit_evidence("org1", r["request_id"], {
        "evidence_type": "document", "filename": "f.pdf", "content_summary": "s", "source_system": "IAM"
    })
    pending = engine.list_evidence_requests("org1", status="pending")
    collecting = engine.list_evidence_requests("org1", status="collecting")
    assert len(pending) == 0
    assert len(collecting) == 1


# ---------------------------------------------------------------------------
# 4. Submit evidence
# ---------------------------------------------------------------------------

def test_submit_evidence_returns_item(engine):
    r = engine.create_evidence_request("org1", {"framework": "SOC2"})
    item = engine.submit_evidence("org1", r["request_id"], {
        "evidence_type": "log",
        "filename": "access.log",
        "content_summary": "30 days of access logs",
        "source_system": "SIEM",
    })
    assert item["evidence_id"]
    assert item["evidence_type"] == "log"
    assert item["auto_collected"] == 0


def test_submit_evidence_advances_status(engine):
    r = engine.create_evidence_request("org1", {"framework": "SOC2"})
    engine.submit_evidence("org1", r["request_id"], {"evidence_type": "document"})
    rows = engine.list_evidence_requests("org1", status="collecting")
    assert len(rows) == 1


def test_submit_evidence_all_types(engine):
    for et in ["document", "screenshot", "log", "config", "attestation"]:
        r = engine.create_evidence_request("org1", {"framework": "SOC2"})
        item = engine.submit_evidence("org1", r["request_id"], {"evidence_type": et})
        assert item["evidence_type"] == et


def test_submit_evidence_invalid_type(engine):
    r = engine.create_evidence_request("org1", {"framework": "SOC2"})
    with pytest.raises(ValueError, match="Invalid evidence_type"):
        engine.submit_evidence("org1", r["request_id"], {"evidence_type": "video"})


def test_submit_evidence_wrong_org(engine):
    r = engine.create_evidence_request("org1", {"framework": "SOC2"})
    with pytest.raises(ValueError):
        engine.submit_evidence("org2", r["request_id"], {"evidence_type": "document"})


# ---------------------------------------------------------------------------
# 5. List evidence
# ---------------------------------------------------------------------------

def test_list_evidence_empty(engine):
    r = engine.create_evidence_request("org1", {"framework": "SOC2"})
    assert engine.list_evidence("org1", r["request_id"]) == []


def test_list_evidence_multiple(engine):
    r = engine.create_evidence_request("org1", {"framework": "SOC2"})
    engine.submit_evidence("org1", r["request_id"], {"evidence_type": "log"})
    engine.submit_evidence("org1", r["request_id"], {"evidence_type": "config"})
    items = engine.list_evidence("org1", r["request_id"])
    assert len(items) == 2


def test_list_evidence_not_found(engine):
    with pytest.raises(ValueError):
        engine.list_evidence("org1", "nonexistent-id")


# ---------------------------------------------------------------------------
# 6. Approve / reject workflow
# ---------------------------------------------------------------------------

def test_approve_returns_approval(engine):
    r = engine.create_evidence_request("org1", {"framework": "SOC2"})
    result = engine.approve_evidence("org1", r["request_id"], "bob@example.com", "LGTM")
    assert result["action"] == "approved"
    assert result["approved_by"] == "bob@example.com"


def test_approve_sets_status(engine):
    r = engine.create_evidence_request("org1", {"framework": "SOC2"})
    engine.approve_evidence("org1", r["request_id"], "auditor")
    rows = engine.list_evidence_requests("org1", status="approved")
    assert len(rows) == 1


def test_reject_returns_rejection(engine):
    r = engine.create_evidence_request("org1", {"framework": "SOC2"})
    result = engine.reject_evidence("org1", r["request_id"], "carol@example.com", "Missing signature")
    assert result["action"] == "rejected"
    assert result["rejected_by"] == "carol@example.com"


def test_reject_sets_status(engine):
    r = engine.create_evidence_request("org1", {"framework": "SOC2"})
    engine.reject_evidence("org1", r["request_id"], "auditor", "incomplete")
    rows = engine.list_evidence_requests("org1", status="rejected")
    assert len(rows) == 1


def test_approve_wrong_org(engine):
    r = engine.create_evidence_request("org1", {"framework": "SOC2"})
    with pytest.raises(ValueError):
        engine.approve_evidence("org2", r["request_id"], "attacker")


# ---------------------------------------------------------------------------
# 7. Auto-collect
# ---------------------------------------------------------------------------

def test_auto_collect_returns_list(engine):
    items = engine.auto_collect("org1", "SOC2")
    assert isinstance(items, list)
    assert len(items) > 0


def test_auto_collect_all_frameworks(engine):
    for fw in ["SOC2", "ISO27001", "PCI-DSS", "HIPAA"]:
        items = engine.auto_collect("org1", fw)
        assert len(items) > 0


def test_auto_collect_items_have_required_fields(engine):
    items = engine.auto_collect("org1", "SOC2")
    for item in items:
        assert "evidence_id" in item
        assert "request_id" in item
        assert "source_system" in item
        assert item["auto_collected"] == 1


def test_auto_collect_creates_requests(engine):
    engine.auto_collect("org1", "ISO27001")
    rows = engine.list_evidence_requests("org1", framework="ISO27001")
    assert len(rows) > 0


def test_auto_collect_invalid_framework(engine):
    with pytest.raises(ValueError, match="Invalid framework"):
        engine.auto_collect("org1", "GDPR")


# ---------------------------------------------------------------------------
# 8. Audit readiness
# ---------------------------------------------------------------------------

def test_audit_readiness_structure(engine):
    result = engine.get_audit_readiness("org1", "SOC2")
    assert "framework" in result
    assert "total_controls" in result
    assert "controls_with_evidence" in result
    assert "controls_approved" in result
    assert "readiness_pct" in result
    assert "missing_controls" in result


def test_audit_readiness_zero_initially(engine):
    result = engine.get_audit_readiness("org1", "SOC2")
    assert result["controls_approved"] == 0
    assert result["readiness_pct"] == 0.0


def test_audit_readiness_improves_after_auto_collect_and_approve(engine):
    items = engine.auto_collect("org1", "SOC2")
    # Approve all requests
    requests = engine.list_evidence_requests("org1", framework="SOC2")
    for req in requests:
        engine.approve_evidence("org1", req["request_id"], "auditor")
    result = engine.get_audit_readiness("org1", "SOC2")
    assert result["controls_approved"] > 0
    assert result["readiness_pct"] > 0


def test_audit_readiness_invalid_framework(engine):
    with pytest.raises(ValueError):
        engine.get_audit_readiness("org1", "UNKNOWN")


def test_audit_readiness_missing_controls_is_list(engine):
    result = engine.get_audit_readiness("org1", "HIPAA")
    assert isinstance(result["missing_controls"], list)


# ---------------------------------------------------------------------------
# 9. Collection stats
# ---------------------------------------------------------------------------

def test_stats_structure(engine):
    stats = engine.get_collection_stats("org1")
    assert "total_requests" in stats
    assert "by_status" in stats
    assert "by_framework" in stats
    assert "auto_collected_count" in stats
    assert "manual_count" in stats
    assert "overall_readiness_pct" in stats


def test_stats_zero_initially(engine):
    stats = engine.get_collection_stats("org1")
    assert stats["total_requests"] == 0
    assert stats["overall_readiness_pct"] == 0.0


def test_stats_counts_auto_collected(engine):
    engine.auto_collect("org1", "SOC2")
    stats = engine.get_collection_stats("org1")
    assert stats["auto_collected_count"] > 0
    assert stats["manual_count"] == 0


def test_stats_counts_manual(engine):
    r = engine.create_evidence_request("org1", {"framework": "PCI-DSS"})
    engine.submit_evidence("org1", r["request_id"], {"evidence_type": "document", "filename": "f.pdf"})
    stats = engine.get_collection_stats("org1")
    assert stats["manual_count"] == 1


# ---------------------------------------------------------------------------
# 10. Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation_requests(engine):
    engine.create_evidence_request("org1", {"framework": "SOC2"})
    engine.create_evidence_request("org2", {"framework": "ISO27001"})
    assert len(engine.list_evidence_requests("org1")) == 1
    assert len(engine.list_evidence_requests("org2")) == 1


def test_org_isolation_evidence(engine):
    r1 = engine.create_evidence_request("org1", {"framework": "SOC2"})
    r2 = engine.create_evidence_request("org2", {"framework": "SOC2"})
    engine.submit_evidence("org1", r1["request_id"], {"evidence_type": "log"})
    # org2 should not see org1 evidence
    assert engine.list_evidence("org2", r2["request_id"]) == []


def test_org_isolation_stats(engine):
    engine.auto_collect("org1", "SOC2")
    stats_org1 = engine.get_collection_stats("org1")
    stats_org2 = engine.get_collection_stats("org2")
    assert stats_org1["total_requests"] > 0
    assert stats_org2["total_requests"] == 0


# ---------------------------------------------------------------------------
# 11. collect_all — gather evidence from all wired engines
# ---------------------------------------------------------------------------

def test_collect_all_returns_dict(engine):
    result = engine.collect_all("org1")
    assert isinstance(result, dict)
    assert "total_collected" in result
    assert "results" in result
    assert "org_id" in result
    assert result["org_id"] == "org1"


def test_collect_all_collects_six_sources(engine):
    result = engine.collect_all("org1")
    assert result["total_collected"] == 6


def test_collect_all_sources_have_required_fields(engine):
    result = engine.collect_all("org1")
    required = {"source_system", "framework", "control_id", "control_name",
                "evidence_type", "evidence_id", "request_id", "status"}
    for item in result["results"]:
        assert required.issubset(item.keys()), f"Missing fields in {item}"


def test_collect_all_creates_evidence_requests_in_db(engine):
    engine.collect_all("org1")
    requests = engine.list_evidence_requests("org1")
    # Should have 6 new requests (one per engine source)
    assert len(requests) >= 6


def test_collect_all_items_are_auto_collected(engine):
    engine.collect_all("org1")
    stats = engine.get_collection_stats("org1")
    assert stats["auto_collected_count"] >= 6


def test_collect_all_org_isolation(engine):
    engine.collect_all("org1")
    engine.collect_all("org2")
    r1 = engine.list_evidence_requests("org1")
    r2 = engine.list_evidence_requests("org2")
    assert len(r1) == 6
    assert len(r2) == 6
    # No overlap in request IDs
    ids1 = {r["request_id"] for r in r1}
    ids2 = {r["request_id"] for r in r2}
    assert ids1.isdisjoint(ids2)


def test_collect_all_maps_correct_controls(engine):
    result = engine.collect_all("org1")
    control_ids = {item["control_id"] for item in result["results"]}
    assert "CC7.2" in control_ids   # AlertTriage → SOC2 CC7.2
    assert "CC6.1" in control_ids   # AccessControl → SOC2 CC6.1
    assert "CC1.4" in control_ids   # SecurityTraining → SOC2 CC1.4
    assert "CC7.3" in control_ids   # IncidentResponse → SOC2 CC7.3
    assert "AC-7" in control_ids    # PasswordPolicy → NIST AC-7
    assert "Req-11.2" in control_ids  # VulnScan → PCI-DSS 11.2


def test_collect_all_has_collected_at_timestamp(engine):
    result = engine.collect_all("org1")
    assert result["collected_at"]
    # Should be a valid ISO timestamp
    from datetime import datetime
    datetime.fromisoformat(result["collected_at"].replace("Z", "+00:00"))
