"""Tests for GRCEngine — 25 tests covering init, CRUD, stats, org isolation."""
from __future__ import annotations

import os
import tempfile
import pytest

from core.grc_engine import GRCEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_grc.db")
    return GRCEngine(db_path=db)


ORG = "org-test"
ORG2 = "org-other"

# ---------------------------------------------------------------------------
# 1. Init
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = str(tmp_path / "sub" / "grc.db")
    eng = GRCEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "grc.db")
    GRCEngine(db_path=db)
    GRCEngine(db_path=db)  # second init must not raise


# ---------------------------------------------------------------------------
# 2. Frameworks
# ---------------------------------------------------------------------------


def test_add_framework_returns_dict(engine):
    fw = engine.add_framework(ORG, {"name": "SOC2", "version": "2017"})
    assert fw["framework_id"]
    assert fw["name"] == "SOC2"
    assert fw["org_id"] == ORG


def test_add_framework_defaults(engine):
    fw = engine.add_framework(ORG, {"name": "ISO27001"})
    assert fw["compliance_score"] == 0.0
    assert fw["total_controls"] == 0


def test_list_frameworks_empty(engine):
    assert engine.list_frameworks(ORG) == []


def test_list_frameworks_returns_all(engine):
    engine.add_framework(ORG, {"name": "SOC2"})
    engine.add_framework(ORG, {"name": "PCI-DSS"})
    fws = engine.list_frameworks(ORG)
    assert len(fws) == 2


def test_list_frameworks_org_isolation(engine):
    engine.add_framework(ORG, {"name": "GDPR"})
    assert engine.list_frameworks(ORG2) == []


# ---------------------------------------------------------------------------
# 3. Controls
# ---------------------------------------------------------------------------


def test_add_control_returns_dict(engine):
    fw = engine.add_framework(ORG, {"name": "NIST-CSF"})
    ctrl = engine.add_control(ORG, fw["framework_id"], {
        "control_ref": "ID.AM-1",
        "title": "Asset inventory",
        "status": "implemented",
        "owner": "alice",
    })
    assert ctrl["control_id"]
    assert ctrl["control_ref"] == "ID.AM-1"
    assert ctrl["status"] == "implemented"


def test_add_control_recalcs_framework_score(engine):
    fw = engine.add_framework(ORG, {"name": "CIS"})
    engine.add_control(ORG, fw["framework_id"], {"status": "implemented"})
    engine.add_control(ORG, fw["framework_id"], {"status": "not_implemented"})
    fws = engine.list_frameworks(ORG)
    assert fws[0]["compliance_score"] == 50.0


def test_list_controls_empty(engine):
    fw = engine.add_framework(ORG, {"name": "HIPAA"})
    assert engine.list_controls(ORG, fw["framework_id"]) == []


def test_list_controls_filter_status(engine):
    fw = engine.add_framework(ORG, {"name": "PCI-DSS"})
    engine.add_control(ORG, fw["framework_id"], {"status": "implemented"})
    engine.add_control(ORG, fw["framework_id"], {"status": "partial"})
    impl = engine.list_controls(ORG, status="implemented")
    assert len(impl) == 1


def test_list_controls_filter_framework(engine):
    fw1 = engine.add_framework(ORG, {"name": "SOC2"})
    fw2 = engine.add_framework(ORG, {"name": "GDPR"})
    engine.add_control(ORG, fw1["framework_id"], {})
    engine.add_control(ORG, fw2["framework_id"], {})
    assert len(engine.list_controls(ORG, fw1["framework_id"])) == 1


def test_update_control_status_ok(engine):
    fw = engine.add_framework(ORG, {"name": "ISO27001"})
    ctrl = engine.add_control(ORG, fw["framework_id"], {"status": "not_implemented"})
    result = engine.update_control_status(ORG, ctrl["control_id"], "implemented", "Evidence uploaded")
    assert result is True
    updated = engine.list_controls(ORG)
    assert updated[0]["status"] == "implemented"
    assert len(updated[0]["evidence_notes"]) == 1


def test_update_control_status_invalid(engine):
    fw = engine.add_framework(ORG, {"name": "CIS"})
    ctrl = engine.add_control(ORG, fw["framework_id"], {})
    result = engine.update_control_status(ORG, ctrl["control_id"], "nonexistent")
    assert result is False


def test_update_control_status_not_found(engine):
    result = engine.update_control_status(ORG, "no-such-id", "implemented")
    assert result is False


# ---------------------------------------------------------------------------
# 4. Risks
# ---------------------------------------------------------------------------


def test_add_risk_returns_dict(engine):
    risk = engine.add_risk(ORG, {
        "title": "Data breach",
        "category": "compliance",
        "likelihood": 4,
        "impact": 5,
        "treatment": "mitigate",
        "owner": "bob",
    })
    assert risk["risk_id"]
    assert risk["risk_score"] == 20
    assert risk["category"] == "compliance"


def test_add_risk_defaults(engine):
    risk = engine.add_risk(ORG, {"title": "Cloud outage"})
    assert risk["risk_score"] == 9  # 3 × 3
    assert risk["status"] == "open"


def test_list_risks_filter_status(engine):
    engine.add_risk(ORG, {"title": "R1", "status": "open"})
    engine.add_risk(ORG, {"title": "R2", "status": "closed"})
    assert len(engine.list_risks(ORG, status="open")) == 1


def test_list_risks_filter_category(engine):
    engine.add_risk(ORG, {"title": "R1", "category": "financial"})
    engine.add_risk(ORG, {"title": "R2", "category": "strategic"})
    assert len(engine.list_risks(ORG, category="financial")) == 1


def test_update_risk_ok(engine):
    risk = engine.add_risk(ORG, {"title": "Old title", "likelihood": 2, "impact": 2})
    ok = engine.update_risk(ORG, risk["risk_id"], {"title": "New title", "likelihood": 4, "impact": 4})
    assert ok is True
    updated = engine.list_risks(ORG)
    assert updated[0]["title"] == "New title"
    assert updated[0]["risk_score"] == 16


def test_update_risk_not_found(engine):
    ok = engine.update_risk(ORG, "ghost-id", {"title": "X"})
    assert ok is False


# ---------------------------------------------------------------------------
# 5. Assessments
# ---------------------------------------------------------------------------


def test_create_assessment_returns_dict(engine):
    fw = engine.add_framework(ORG, {"name": "SOC2"})
    assess = engine.create_assessment(ORG, {
        "framework_id": fw["framework_id"],
        "assessor": "carol",
        "scope": "Full audit",
        "overall_score": 85.0,
        "findings_count": 3,
        "status": "completed",
    })
    assert assess["assessment_id"]
    assert assess["overall_score"] == 85.0
    assert assess["status"] == "completed"


def test_list_assessments_empty(engine):
    assert engine.list_assessments(ORG) == []


def test_list_assessments_filter_framework(engine):
    fw1 = engine.add_framework(ORG, {"name": "ISO27001"})
    fw2 = engine.add_framework(ORG, {"name": "PCI-DSS"})
    engine.create_assessment(ORG, {"framework_id": fw1["framework_id"]})
    engine.create_assessment(ORG, {"framework_id": fw2["framework_id"]})
    assert len(engine.list_assessments(ORG, fw1["framework_id"])) == 1


# ---------------------------------------------------------------------------
# 6. Stats
# ---------------------------------------------------------------------------


def test_get_grc_stats_empty(engine):
    stats = engine.get_grc_stats(ORG)
    assert stats["frameworks_count"] == 0
    assert stats["open_risks"] == 0
    assert stats["controls_implemented_pct"] == 0.0


def test_get_grc_stats_populated(engine):
    fw = engine.add_framework(ORG, {"name": "NIST-CSF"})
    engine.add_control(ORG, fw["framework_id"], {"status": "implemented"})
    engine.add_control(ORG, fw["framework_id"], {"status": "not_implemented"})
    engine.add_risk(ORG, {"title": "R1", "status": "open"})
    engine.add_risk(ORG, {"title": "R2", "status": "closed"})
    engine.create_assessment(ORG, {"framework_id": fw["framework_id"], "status": "completed"})
    stats = engine.get_grc_stats(ORG)
    assert stats["frameworks_count"] == 1
    assert stats["open_risks"] == 1
    assert stats["controls_implemented_pct"] == 50.0
    assert stats["assessments_completed"] == 1


# ---------------------------------------------------------------------------
# 7. Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_risks(engine):
    engine.add_risk(ORG, {"title": "Org1 risk"})
    assert engine.list_risks(ORG2) == []


def test_org_isolation_controls(engine):
    fw1 = engine.add_framework(ORG, {"name": "SOC2"})
    engine.add_control(ORG, fw1["framework_id"], {"title": "Org1 ctrl"})
    assert engine.list_controls(ORG2) == []
