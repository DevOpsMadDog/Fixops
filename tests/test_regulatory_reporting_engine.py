"""Tests for RegulatoryReportingEngine.

Covers: regulation CRUD, valid/invalid types, compliance score clamping,
compliance level derivation, report lifecycle (draft→submitted), stats,
org isolation.
"""

from __future__ import annotations

import pytest

from core.regulatory_reporting_engine import (
    ComplianceScoreUpdate,
    RegulationCreate,
    RegulatoryReportingEngine,
    ReportCreate,
    ReportSubmit,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return RegulatoryReportingEngine(db_path=str(tmp_path / "test_reg.db"))


def _reg(name="GDPR Compliance", regulation_type="gdpr", **kw) -> RegulationCreate:
    return RegulationCreate(name=name, regulation_type=regulation_type, **kw)


def _report(regulation_id, report_type="annual", **kw) -> ReportCreate:
    return ReportCreate(
        regulation_id=regulation_id,
        report_type=report_type,
        period_start="2026-01-01",
        period_end="2026-03-31",
        **kw,
    )


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = tmp_path / "rr.db"
    RegulatoryReportingEngine(db_path=str(db))
    assert db.exists()


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "rr.db")
    RegulatoryReportingEngine(db_path=db)
    RegulatoryReportingEngine(db_path=db)  # should not raise


# ---------------------------------------------------------------------------
# 2. Register regulation — valid types
# ---------------------------------------------------------------------------


def test_register_regulation_returns_record(engine):
    reg = engine.register_regulation("org1", _reg())
    assert reg["name"] == "GDPR Compliance"
    assert reg["regulation_type"] == "gdpr"
    assert reg["jurisdiction"] == "global"
    assert reg["compliance_score"] == 0
    assert reg["compliance_level"] == "non_compliant"
    assert reg["status"] == "active"
    assert "id" in reg


def test_register_generates_unique_ids(engine):
    r1 = engine.register_regulation("org1", _reg(name="A"))
    r2 = engine.register_regulation("org1", _reg(name="B"))
    assert r1["id"] != r2["id"]


@pytest.mark.parametrize("rtype", [
    "gdpr", "hipaa", "pci_dss", "sox", "iso27001", "nist", "ccpa", "fedramp", "custom"
])
def test_register_all_valid_regulation_types(engine, rtype):
    reg = engine.register_regulation("org1", _reg(regulation_type=rtype))
    assert reg["regulation_type"] == rtype


def test_register_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="regulation_type"):
        engine.register_regulation("org1", _reg(regulation_type="unknown_type"))


def test_register_custom_jurisdiction(engine):
    reg = engine.register_regulation(
        "org1", _reg(jurisdiction="EU")
    )
    assert reg["jurisdiction"] == "EU"


def test_register_default_jurisdiction_is_global(engine):
    reg = engine.register_regulation("org1", _reg())
    assert reg["jurisdiction"] == "global"


# ---------------------------------------------------------------------------
# 3. List regulations
# ---------------------------------------------------------------------------


def test_list_regulations_empty(engine):
    assert engine.list_regulations("org1") == []


def test_list_regulations_returns_all(engine):
    engine.register_regulation("org1", _reg(name="A", regulation_type="gdpr"))
    engine.register_regulation("org1", _reg(name="B", regulation_type="hipaa"))
    regs = engine.list_regulations("org1")
    assert len(regs) == 2


def test_list_regulations_filtered_by_type(engine):
    engine.register_regulation("org1", _reg(name="A", regulation_type="gdpr"))
    engine.register_regulation("org1", _reg(name="B", regulation_type="hipaa"))
    gdpr = engine.list_regulations("org1", regulation_type="gdpr")
    assert len(gdpr) == 1
    assert gdpr[0]["regulation_type"] == "gdpr"


# ---------------------------------------------------------------------------
# 4. Compliance score update
# ---------------------------------------------------------------------------


def test_update_compliance_score_basic(engine):
    reg = engine.register_regulation("org1", _reg())
    updated = engine.update_compliance_score("org1", reg["id"], 75.0)
    assert updated["compliance_score"] == 75.0
    assert updated["compliance_level"] == "mostly_compliant"
    assert updated["assessed_at"] is not None


@pytest.mark.parametrize("score,expected_level", [
    (95.0, "compliant"),
    (90.0, "compliant"),
    (89.9, "mostly_compliant"),
    (70.0, "mostly_compliant"),
    (69.9, "partially_compliant"),
    (50.0, "partially_compliant"),
    (49.9, "non_compliant"),
    (0.0, "non_compliant"),
])
def test_compliance_level_derivation(engine, score, expected_level):
    reg = engine.register_regulation("org1", _reg())
    updated = engine.update_compliance_score("org1", reg["id"], score)
    assert updated["compliance_level"] == expected_level


def test_score_clamped_above_100(engine):
    reg = engine.register_regulation("org1", _reg())
    updated = engine.update_compliance_score("org1", reg["id"], 150.0)
    assert updated["compliance_score"] == 100.0
    assert updated["compliance_level"] == "compliant"


def test_score_clamped_below_0(engine):
    reg = engine.register_regulation("org1", _reg())
    updated = engine.update_compliance_score("org1", reg["id"], -10.0)
    assert updated["compliance_score"] == 0.0
    assert updated["compliance_level"] == "non_compliant"


def test_update_score_with_notes(engine):
    reg = engine.register_regulation("org1", _reg())
    updated = engine.update_compliance_score("org1", reg["id"], 80.0, notes="Reviewed Q1")
    assert updated["notes"] == "Reviewed Q1"


def test_update_score_wrong_org_raises(engine):
    reg = engine.register_regulation("org1", _reg())
    with pytest.raises(ValueError):
        engine.update_compliance_score("org2", reg["id"], 80.0)


# ---------------------------------------------------------------------------
# 5. Report lifecycle
# ---------------------------------------------------------------------------


def test_create_report_returns_draft(engine):
    reg = engine.register_regulation("org1", _reg())
    rpt = engine.create_report("org1", _report(reg["id"]))
    assert rpt["status"] == "draft"
    assert rpt["report_type"] == "annual"
    assert rpt["period_start"] == "2026-01-01"
    assert rpt["period_end"] == "2026-03-31"
    assert rpt["submitted_by"] is None
    assert "id" in rpt


def test_create_report_invalid_type_raises(engine):
    reg = engine.register_regulation("org1", _reg())
    with pytest.raises(ValueError, match="report_type"):
        engine.create_report("org1", _report(reg["id"], report_type="invalid"))


@pytest.mark.parametrize("rtype", [
    "annual", "quarterly", "monthly", "incident", "audit", "self_assessment"
])
def test_create_report_all_valid_types(engine, rtype):
    reg = engine.register_regulation("org1", _reg())
    rpt = engine.create_report("org1", _report(reg["id"], report_type=rtype))
    assert rpt["report_type"] == rtype


def test_submit_report_transitions_status(engine):
    reg = engine.register_regulation("org1", _reg())
    rpt = engine.create_report("org1", _report(reg["id"]))
    submitted = engine.submit_report("org1", rpt["id"], submitted_by="alice")
    assert submitted["status"] == "submitted"
    assert submitted["submitted_by"] == "alice"
    assert submitted["submitted_at"] is not None


def test_submit_report_wrong_org_raises(engine):
    reg = engine.register_regulation("org1", _reg())
    rpt = engine.create_report("org1", _report(reg["id"]))
    with pytest.raises(ValueError):
        engine.submit_report("org2", rpt["id"], submitted_by="alice")


def test_create_report_wrong_regulation_org_raises(engine):
    reg = engine.register_regulation("org1", _reg())
    with pytest.raises(ValueError):
        engine.create_report("org2", _report(reg["id"]))


# ---------------------------------------------------------------------------
# 6. List reports
# ---------------------------------------------------------------------------


def test_list_reports_empty(engine):
    assert engine.list_reports("org1") == []


def test_list_reports_filtered_by_regulation(engine):
    reg1 = engine.register_regulation("org1", _reg(name="R1"))
    reg2 = engine.register_regulation("org1", _reg(name="R2"))
    engine.create_report("org1", _report(reg1["id"]))
    engine.create_report("org1", _report(reg2["id"]))
    result = engine.list_reports("org1", regulation_id=reg1["id"])
    assert len(result) == 1
    assert result[0]["regulation_id"] == reg1["id"]


def test_list_reports_filtered_by_status(engine):
    reg = engine.register_regulation("org1", _reg())
    rpt = engine.create_report("org1", _report(reg["id"]))
    engine.create_report("org1", _report(reg["id"]))
    engine.submit_report("org1", rpt["id"], "alice")
    drafts = engine.list_reports("org1", status="draft")
    submitted = engine.list_reports("org1", status="submitted")
    assert len(drafts) == 1
    assert len(submitted) == 1


# ---------------------------------------------------------------------------
# 7. Stats
# ---------------------------------------------------------------------------


def test_stats_empty(engine):
    stats = engine.get_regulatory_stats("org1")
    assert stats["total_regulations"] == 0
    assert stats["avg_compliance_score"] == 0.0
    assert stats["compliant_count"] == 0
    assert stats["non_compliant_count"] == 0
    assert stats["total_reports"] == 0
    assert stats["submitted_reports"] == 0
    assert stats["pending_reports"] == 0


def test_stats_compliant_count(engine):
    r1 = engine.register_regulation("org1", _reg(name="A"))
    r2 = engine.register_regulation("org1", _reg(name="B"))
    r3 = engine.register_regulation("org1", _reg(name="C"))
    engine.update_compliance_score("org1", r1["id"], 95.0)
    engine.update_compliance_score("org1", r2["id"], 92.0)
    engine.update_compliance_score("org1", r3["id"], 30.0)
    stats = engine.get_regulatory_stats("org1")
    assert stats["compliant_count"] == 2
    assert stats["non_compliant_count"] == 1


def test_stats_avg_compliance_score(engine):
    r1 = engine.register_regulation("org1", _reg(name="A"))
    r2 = engine.register_regulation("org1", _reg(name="B"))
    engine.update_compliance_score("org1", r1["id"], 80.0)
    engine.update_compliance_score("org1", r2["id"], 60.0)
    stats = engine.get_regulatory_stats("org1")
    assert stats["avg_compliance_score"] == 70.0


def test_stats_submitted_vs_pending(engine):
    reg = engine.register_regulation("org1", _reg())
    rpt1 = engine.create_report("org1", _report(reg["id"]))
    rpt2 = engine.create_report("org1", _report(reg["id"]))
    engine.submit_report("org1", rpt1["id"], "bob")
    stats = engine.get_regulatory_stats("org1")
    assert stats["total_reports"] == 2
    assert stats["submitted_reports"] == 1
    assert stats["pending_reports"] == 1


def test_stats_by_type(engine):
    engine.register_regulation("org1", _reg(name="A", regulation_type="gdpr"))
    engine.register_regulation("org1", _reg(name="B", regulation_type="gdpr"))
    engine.register_regulation("org1", _reg(name="C", regulation_type="hipaa"))
    stats = engine.get_regulatory_stats("org1")
    assert stats["by_type"]["gdpr"] == 2
    assert stats["by_type"]["hipaa"] == 1


# ---------------------------------------------------------------------------
# 8. Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_regulations(engine):
    engine.register_regulation("org1", _reg(name="A"))
    engine.register_regulation("org2", _reg(name="B"))
    assert len(engine.list_regulations("org1")) == 1
    assert len(engine.list_regulations("org2")) == 1


def test_org_isolation_reports(engine):
    reg1 = engine.register_regulation("org1", _reg())
    reg2 = engine.register_regulation("org2", _reg())
    engine.create_report("org1", _report(reg1["id"]))
    engine.create_report("org2", _report(reg2["id"]))
    assert len(engine.list_reports("org1")) == 1
    assert len(engine.list_reports("org2")) == 1


def test_org_isolation_stats(engine):
    engine.register_regulation("org1", _reg(name="A"))
    engine.register_regulation("org1", _reg(name="B"))
    engine.register_regulation("org2", _reg(name="C"))
    s1 = engine.get_regulatory_stats("org1")
    s2 = engine.get_regulatory_stats("org2")
    assert s1["total_regulations"] == 2
    assert s2["total_regulations"] == 1
