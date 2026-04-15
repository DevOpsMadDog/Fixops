"""Tests for VendorComplianceEngine — 34 tests covering all methods + org isolation."""

from __future__ import annotations

import pytest
from core.vendor_compliance_engine import VendorComplianceEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "vc_test.db")
    return VendorComplianceEngine(db_path=db)


@pytest.fixture
def org():
    return "org-alpha"


@pytest.fixture
def org2():
    return "org-beta"


def _vendor(engine, org, name="Acme SaaS", vendor_category="saas", contract_type="annual"):
    return engine.register_vendor(org, {
        "name": name,
        "vendor_category": vendor_category,
        "contract_type": contract_type,
        "contact_name": "Jane Doe",
        "contact_email": "jane@acme.com",
        "contract_start": "2026-01-01",
        "contract_end": "2026-12-31",
    })


def _requirement(engine, org, vendor_id, req_name="SOC 2 Report", req_type="certification"):
    return engine.create_compliance_requirement(org, {
        "vendor_id": vendor_id,
        "requirement_name": req_name,
        "requirement_type": req_type,
        "due_date": "2026-12-31",
        "mandatory": True,
    })


# ---------------------------------------------------------------------------
# register_vendor
# ---------------------------------------------------------------------------

def test_register_vendor_returns_record(engine, org):
    v = _vendor(engine, org)
    assert v["name"] == "Acme SaaS"
    assert v["vendor_category"] == "saas"
    assert v["contract_type"] == "annual"
    assert v["org_id"] == org
    assert "id" in v
    assert v["status"] == "active"
    assert v["compliance_score"] == 0.0
    assert v["compliance_status"] == "non_compliant"


def test_register_vendor_missing_name_raises(engine, org):
    with pytest.raises(ValueError, match="name"):
        engine.register_vendor(org, {"name": "", "vendor_category": "saas", "contract_type": "annual"})


def test_register_vendor_invalid_category_raises(engine, org):
    with pytest.raises(ValueError, match="vendor_category"):
        engine.register_vendor(org, {"name": "X", "vendor_category": "unknown", "contract_type": "annual"})


def test_register_vendor_invalid_contract_type_raises(engine, org):
    with pytest.raises(ValueError, match="contract_type"):
        engine.register_vendor(org, {"name": "X", "vendor_category": "saas", "contract_type": "quarterly"})


def test_register_vendor_all_categories(engine, org):
    for cat in ("saas", "paas", "iaas", "professional_services", "hardware", "support"):
        v = engine.register_vendor(org, {"name": f"vendor-{cat}", "vendor_category": cat, "contract_type": "annual"})
        assert v["vendor_category"] == cat


def test_register_vendor_all_contract_types(engine, org):
    for ctype in ("annual", "multi_year", "month_to_month", "one_time"):
        v = engine.register_vendor(org, {"name": f"vendor-{ctype}", "vendor_category": "saas", "contract_type": ctype})
        assert v["contract_type"] == ctype


# ---------------------------------------------------------------------------
# list_vendors
# ---------------------------------------------------------------------------

def test_list_vendors_empty(engine, org):
    assert engine.list_vendors(org) == []


def test_list_vendors_org_isolation(engine, org, org2):
    _vendor(engine, org, "Alpha Vendor")
    _vendor(engine, org2, "Beta Vendor")
    result = engine.list_vendors(org)
    assert len(result) == 1
    assert result[0]["name"] == "Alpha Vendor"


def test_list_vendors_filter_by_category(engine, org):
    _vendor(engine, org, "SaaS Vendor", vendor_category="saas")
    _vendor(engine, org, "IaaS Vendor", vendor_category="iaas")
    result = engine.list_vendors(org, vendor_category="saas")
    assert len(result) == 1
    assert result[0]["name"] == "SaaS Vendor"


def test_list_vendors_filter_by_status(engine, org):
    _vendor(engine, org, "Active Vendor")
    result = engine.list_vendors(org, status="active")
    assert len(result) == 1
    assert result[0]["status"] == "active"


# ---------------------------------------------------------------------------
# get_vendor
# ---------------------------------------------------------------------------

def test_get_vendor_returns_record(engine, org):
    v = _vendor(engine, org)
    fetched = engine.get_vendor(org, v["id"])
    assert fetched is not None
    assert fetched["id"] == v["id"]
    assert fetched["name"] == "Acme SaaS"


def test_get_vendor_not_found_returns_none(engine, org):
    assert engine.get_vendor(org, "nonexistent-id") is None


def test_get_vendor_org_isolation(engine, org, org2):
    v = _vendor(engine, org)
    assert engine.get_vendor(org2, v["id"]) is None


# ---------------------------------------------------------------------------
# run_compliance_check
# ---------------------------------------------------------------------------

def test_compliance_check_fully_compliant(engine, org):
    v = _vendor(engine, org)
    result = engine.run_compliance_check(org, v["id"], {
        "data_processing_agreement": True,
        "security_questionnaire": True,
        "pen_test_report": True,
        "soc2_report": True,
        "gdpr_compliance": True,
        "insurance_certificate": True,
    })
    assert result["compliance_score"] == 100
    assert result["compliance_status"] == "compliant"
    assert result["vendor_id"] == v["id"]


def test_compliance_check_partial(engine, org):
    v = _vendor(engine, org)
    result = engine.run_compliance_check(org, v["id"], {
        "data_processing_agreement": True,
        "security_questionnaire": True,
        "pen_test_report": True,
        "soc2_report": False,
        "gdpr_compliance": False,
        "insurance_certificate": False,
    })
    assert result["compliance_status"] == "partial"
    assert 50 <= result["compliance_score"] < 80


def test_compliance_check_non_compliant(engine, org):
    v = _vendor(engine, org)
    result = engine.run_compliance_check(org, v["id"], {
        "data_processing_agreement": False,
        "security_questionnaire": False,
        "pen_test_report": False,
        "soc2_report": False,
        "gdpr_compliance": False,
        "insurance_certificate": False,
    })
    assert result["compliance_score"] == 0
    assert result["compliance_status"] == "non_compliant"


def test_compliance_check_updates_db(engine, org):
    v = _vendor(engine, org)
    engine.run_compliance_check(org, v["id"], {"soc2_report": True})
    updated = engine.get_vendor(org, v["id"])
    assert updated["checked_at"] is not None


def test_compliance_check_items_returned(engine, org):
    v = _vendor(engine, org)
    result = engine.run_compliance_check(org, v["id"], {"data_processing_agreement": True})
    assert "items" in result
    assert result["items"]["data_processing_agreement"] is True
    assert result["items"]["soc2_report"] is False


# ---------------------------------------------------------------------------
# create_compliance_requirement
# ---------------------------------------------------------------------------

def test_create_requirement_returns_record(engine, org):
    v = _vendor(engine, org)
    req = _requirement(engine, org, v["id"])
    assert req["requirement_name"] == "SOC 2 Report"
    assert req["requirement_type"] == "certification"
    assert req["status"] == "pending"
    assert req["vendor_id"] == v["id"]
    assert req["mandatory"] is True
    assert "id" in req


def test_create_requirement_missing_vendor_raises(engine, org):
    with pytest.raises(ValueError, match="vendor_id"):
        engine.create_compliance_requirement(org, {
            "vendor_id": "",
            "requirement_name": "SOC 2",
            "requirement_type": "certification",
            "due_date": "2026-12-31",
        })


def test_create_requirement_missing_name_raises(engine, org):
    v = _vendor(engine, org)
    with pytest.raises(ValueError, match="requirement_name"):
        engine.create_compliance_requirement(org, {
            "vendor_id": v["id"],
            "requirement_name": "",
            "requirement_type": "certification",
            "due_date": "2026-12-31",
        })


def test_create_requirement_invalid_type_raises(engine, org):
    v = _vendor(engine, org)
    with pytest.raises(ValueError, match="requirement_type"):
        engine.create_compliance_requirement(org, {
            "vendor_id": v["id"],
            "requirement_name": "Test",
            "requirement_type": "unknown",
            "due_date": "2026-12-31",
        })


def test_create_requirement_missing_due_date_raises(engine, org):
    v = _vendor(engine, org)
    with pytest.raises(ValueError, match="due_date"):
        engine.create_compliance_requirement(org, {
            "vendor_id": v["id"],
            "requirement_name": "Test",
            "requirement_type": "audit",
            "due_date": "",
        })


def test_create_requirement_all_types(engine, org):
    v = _vendor(engine, org)
    for rtype in ("documentation", "certification", "audit", "training", "technical"):
        req = engine.create_compliance_requirement(org, {
            "vendor_id": v["id"],
            "requirement_name": f"req-{rtype}",
            "requirement_type": rtype,
            "due_date": "2026-12-31",
        })
        assert req["requirement_type"] == rtype


# ---------------------------------------------------------------------------
# update_requirement_status
# ---------------------------------------------------------------------------

def test_update_status_to_completed(engine, org):
    v = _vendor(engine, org)
    req = _requirement(engine, org, v["id"])
    result = engine.update_requirement_status(org, req["id"], "completed", "All docs submitted")
    assert result["status"] == "completed"
    assert result["notes"] == "All docs submitted"
    assert result["completed_at"] is not None


def test_update_status_to_in_progress(engine, org):
    v = _vendor(engine, org)
    req = _requirement(engine, org, v["id"])
    result = engine.update_requirement_status(org, req["id"], "in_progress")
    assert result["status"] == "in_progress"
    assert result["completed_at"] is None


def test_update_status_invalid_raises(engine, org):
    v = _vendor(engine, org)
    req = _requirement(engine, org, v["id"])
    with pytest.raises(ValueError, match="status"):
        engine.update_requirement_status(org, req["id"], "rejected")


def test_update_status_waived(engine, org):
    v = _vendor(engine, org)
    req = _requirement(engine, org, v["id"])
    result = engine.update_requirement_status(org, req["id"], "waived", "Risk accepted")
    assert result["status"] == "waived"


# ---------------------------------------------------------------------------
# list_requirements
# ---------------------------------------------------------------------------

def test_list_requirements_empty(engine, org):
    assert engine.list_requirements(org) == []


def test_list_requirements_org_isolation(engine, org, org2):
    v1 = _vendor(engine, org)
    v2 = _vendor(engine, org2, "Beta Vendor")
    _requirement(engine, org, v1["id"])
    _requirement(engine, org2, v2["id"])
    assert len(engine.list_requirements(org)) == 1
    assert len(engine.list_requirements(org2)) == 1


def test_list_requirements_filter_by_vendor(engine, org):
    v1 = _vendor(engine, org, "Vendor A")
    v2 = _vendor(engine, org, "Vendor B")
    _requirement(engine, org, v1["id"], "Req A")
    _requirement(engine, org, v2["id"], "Req B")
    result = engine.list_requirements(org, vendor_id=v1["id"])
    assert len(result) == 1
    assert result[0]["requirement_name"] == "Req A"


def test_list_requirements_filter_by_status(engine, org):
    v = _vendor(engine, org)
    req = _requirement(engine, org, v["id"])
    engine.update_requirement_status(org, req["id"], "completed")
    pending = engine.list_requirements(org, status="pending")
    completed = engine.list_requirements(org, status="completed")
    assert len(pending) == 0
    assert len(completed) == 1


# ---------------------------------------------------------------------------
# get_vendor_compliance_stats
# ---------------------------------------------------------------------------

def test_get_stats_empty(engine, org):
    stats = engine.get_vendor_compliance_stats(org)
    assert stats["total_vendors"] == 0
    assert stats["avg_compliance_score"] == 0.0
    assert stats["total_requirements"] == 0


def test_get_stats_populated(engine, org):
    v1 = _vendor(engine, org, "Vendor A", vendor_category="saas")
    v2 = _vendor(engine, org, "Vendor B", vendor_category="paas")
    engine.run_compliance_check(org, v1["id"], {
        "data_processing_agreement": True,
        "security_questionnaire": True,
        "pen_test_report": True,
        "soc2_report": True,
        "gdpr_compliance": True,
        "insurance_certificate": True,
    })
    _requirement(engine, org, v1["id"])
    stats = engine.get_vendor_compliance_stats(org)
    assert stats["total_vendors"] == 2
    assert stats["compliant_vendors"] == 1
    assert stats["total_requirements"] == 1
    assert "saas" in stats["by_category"]
    assert "paas" in stats["by_category"]


def test_get_stats_org_isolation(engine, org, org2):
    _vendor(engine, org)
    _vendor(engine, org2, "Beta V1")
    _vendor(engine, org2, "Beta V2")
    assert engine.get_vendor_compliance_stats(org)["total_vendors"] == 1
    assert engine.get_vendor_compliance_stats(org2)["total_vendors"] == 2


def test_get_stats_non_compliant_count(engine, org):
    v1 = _vendor(engine, org, "Vendor A")
    v2 = _vendor(engine, org, "Vendor B")
    # v1 gets partial score (2/6 = 33% → non_compliant)
    engine.run_compliance_check(org, v1["id"], {"data_processing_agreement": True, "security_questionnaire": True})
    # v2 stays at 0 (non_compliant)
    stats = engine.get_vendor_compliance_stats(org)
    assert stats["non_compliant_vendors"] == 2
