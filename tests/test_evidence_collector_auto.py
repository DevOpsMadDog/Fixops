"""Tests for AutoEvidenceCollector — auto evidence collection for compliance frameworks."""
import os
import sys
import tempfile
import pytest

sys.path.insert(0, "suite-core")

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")

from core.evidence_collector import AutoEvidenceCollector


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def collector(tmp_path):
    db = str(tmp_path / "test_evidence.db")
    return AutoEvidenceCollector(db_path=db)


@pytest.fixture
def requirement(collector):
    return collector.define_requirement(
        framework="SOC2",
        control_id="CC6.1",
        control_name="Logical Access Controls",
        evidence_types=["scan_result", "config"],
        org_id="test-org",
    )


# ---------------------------------------------------------------------------
# Instantiation
# ---------------------------------------------------------------------------

def test_auto_evidence_collector_instantiates(tmp_path):
    db = str(tmp_path / "test.db")
    aec = AutoEvidenceCollector(db_path=db)
    assert aec is not None


# ---------------------------------------------------------------------------
# define_requirement
# ---------------------------------------------------------------------------

def test_define_requirement_returns_dict_with_requirement_id(collector):
    result = collector.define_requirement(
        framework="SOC2",
        control_id="CC6.1",
        control_name="Logical Access Controls",
        evidence_types=["scan_result", "audit_log"],
    )
    assert isinstance(result, dict)
    assert "requirement_id" in result
    assert len(result["requirement_id"]) == 36  # UUID


def test_define_requirement_returns_framework(collector):
    result = collector.define_requirement(
        framework="SOC2",
        control_id="CC6.2",
        control_name="User Auth",
        evidence_types=["config"],
    )
    assert result["framework"] == "SOC2"
    assert result["control_id"] == "CC6.2"
    assert result["control_name"] == "User Auth"


def test_define_requirement_invalid_framework_raises_value_error(collector):
    with pytest.raises(ValueError, match="Unknown framework"):
        collector.define_requirement(
            framework="MADE_UP_FRAMEWORK",
            control_id="X.1",
            control_name="Fake Control",
            evidence_types=["log"],
        )


def test_define_requirement_framework_aliases(collector):
    # soc2 (lowercase) should be normalised to SOC2
    result = collector.define_requirement(
        framework="soc2",
        control_id="CC6.1",
        control_name="Test",
        evidence_types=["scan_result"],
    )
    assert result["framework"] == "SOC2"


def test_define_requirement_pci_alias(collector):
    result = collector.define_requirement(
        framework="pci_dss",
        control_id="1.1",
        control_name="Network Controls",
        evidence_types=["config"],
    )
    assert result["framework"] == "PCI-DSS"


def test_define_requirement_multiple_frameworks(collector):
    r1 = collector.define_requirement("SOC2", "CC6.1", "Access", ["config"], org_id="org-a")
    r2 = collector.define_requirement("ISO27001", "A.5.1", "Policy", ["policy_doc"], org_id="org-a")
    assert r1["framework"] == "SOC2"
    assert r2["framework"] == "ISO27001"
    assert r1["requirement_id"] != r2["requirement_id"]


# ---------------------------------------------------------------------------
# collect_evidence
# ---------------------------------------------------------------------------

def test_collect_evidence_returns_dict_with_evidence_id(collector, requirement):
    result = collector.collect_evidence(
        requirement_id=requirement["requirement_id"],
        evidence_type="scan_report",
        source="scan_report",
        content={"description": "Nightly vuln scan"},
    )
    assert isinstance(result, dict)
    assert "evidence_id" in result
    assert len(result["evidence_id"]) == 36


def test_collect_evidence_returns_state_collected(collector, requirement):
    result = collector.collect_evidence(
        requirement_id=requirement["requirement_id"],
        evidence_type="audit_log",
        source="audit_log",
        content={"description": "Audit log snapshot"},
    )
    assert result["state"] == "collected"


def test_collect_evidence_invalid_requirement_raises(collector):
    with pytest.raises(ValueError, match="Requirement not found"):
        collector.collect_evidence(
            requirement_id="00000000-0000-0000-0000-000000000000",
            evidence_type="scan_report",
            source="scan_report",
            content={},
        )


# ---------------------------------------------------------------------------
# get_evidence / list_evidence
# ---------------------------------------------------------------------------

def test_get_evidence_retrieves_stored_evidence(collector, requirement):
    collected = collector.collect_evidence(
        requirement_id=requirement["requirement_id"],
        evidence_type="scan_report",
        source="scan_report",
        content={"description": "Test scan"},
    )
    ev = collector.get_evidence(collected["evidence_id"])
    assert ev is not None
    assert ev["id"] == collected["evidence_id"]


def test_get_evidence_missing_returns_none(collector):
    result = collector.get_evidence("00000000-0000-0000-0000-000000000000")
    assert result is None


def test_list_evidence_returns_list(collector, requirement):
    collector.collect_evidence(
        requirement_id=requirement["requirement_id"],
        evidence_type="scan_report",
        source="scan_report",
        content={},
    )
    items = collector.list_evidence(org_id="test-org")
    assert isinstance(items, list)
    assert len(items) >= 1


def test_list_evidence_framework_filter(collector):
    r_soc2 = collector.define_requirement("SOC2", "CC6.1", "Ctrl", ["config"], org_id="filter-org")
    r_iso = collector.define_requirement("ISO27001", "A.5.1", "Policy", ["policy_doc"], org_id="filter-org")
    collector.collect_evidence(r_soc2["requirement_id"], "configuration_snapshot", "configuration_snapshot", {})
    collector.collect_evidence(r_iso["requirement_id"], "policy_document", "policy_document", {})

    soc2_items = collector.list_evidence(framework="SOC2", org_id="filter-org")
    iso_items = collector.list_evidence(framework="ISO27001", org_id="filter-org")
    assert all(i["framework"] == "SOC2" for i in soc2_items)
    assert all(i["framework"] == "ISO27001" for i in iso_items)


# ---------------------------------------------------------------------------
# auto_collect
# ---------------------------------------------------------------------------

def test_auto_collect_returns_dict(collector):
    result = collector.auto_collect(framework="SOC2")
    assert isinstance(result, dict)


def test_auto_collect_has_coverage_pct_float(collector):
    result = collector.auto_collect(framework="SOC2")
    assert isinstance(result["coverage_pct"], float)


def test_auto_collect_coverage_pct_in_range(collector):
    result = collector.auto_collect(framework="SOC2")
    assert 0.0 <= result["coverage_pct"] <= 100.0


def test_auto_collect_has_required_keys(collector):
    result = collector.auto_collect(framework="PCI-DSS")
    for key in ("framework", "requirements_checked", "evidence_collected", "gaps", "coverage_pct"):
        assert key in result, f"Missing key: {key}"


def test_auto_collect_requirements_checked_positive(collector):
    result = collector.auto_collect(framework="ISO27001")
    assert result["requirements_checked"] >= 0


def test_auto_collect_evidence_collected_non_negative(collector):
    result = collector.auto_collect(framework="NIST-CSF")
    assert result["evidence_collected"] >= 0


def test_auto_collect_gaps_is_list(collector):
    result = collector.auto_collect(framework="HIPAA")
    assert isinstance(result["gaps"], list)


# ---------------------------------------------------------------------------
# get_coverage
# ---------------------------------------------------------------------------

def test_get_coverage_returns_dict(collector):
    result = collector.get_coverage(framework="SOC2")
    assert isinstance(result, dict)


def test_get_coverage_has_total_requirements_int(collector):
    result = collector.get_coverage(framework="SOC2")
    assert isinstance(result["total_requirements"], int)
    assert result["total_requirements"] > 0


def test_get_coverage_covered_lte_total(collector):
    result = collector.get_coverage(framework="SOC2")
    assert result["covered"] <= result["total_requirements"]


def test_get_coverage_coverage_pct_in_range(collector):
    result = collector.get_coverage(framework="PCI-DSS")
    assert 0.0 <= result["coverage_pct"] <= 100.0


def test_get_coverage_has_by_control_list(collector):
    result = collector.get_coverage(framework="ISO27001")
    assert isinstance(result["by_control"], list)
    assert len(result["by_control"]) > 0


def test_get_coverage_by_control_has_status(collector):
    result = collector.get_coverage(framework="SOC2")
    for ctrl in result["by_control"]:
        assert ctrl["status"] in ("covered", "partial", "missing")


# ---------------------------------------------------------------------------
# mark_expired
# ---------------------------------------------------------------------------

def test_mark_expired_changes_state(collector, requirement):
    collected = collector.collect_evidence(
        requirement_id=requirement["requirement_id"],
        evidence_type="audit_log",
        source="audit_log",
        content={"description": "Old audit log"},
    )
    result = collector.mark_expired(evidence_id=collected["evidence_id"], reason="Annual rotation")
    assert result["state"] == "expired"
    assert result["evidence_id"] == collected["evidence_id"]


def test_mark_expired_missing_evidence_raises(collector):
    with pytest.raises(ValueError, match="Evidence not found"):
        collector.mark_expired("00000000-0000-0000-0000-000000000000")


def test_mark_expired_persisted(collector, requirement):
    collected = collector.collect_evidence(
        requirement_id=requirement["requirement_id"],
        evidence_type="audit_log",
        source="audit_log",
        content={},
    )
    collector.mark_expired(collected["evidence_id"], reason="Test expiry")
    ev = collector.get_evidence(collected["evidence_id"])
    assert ev["status"] == "expired"


# ---------------------------------------------------------------------------
# get_gap_report
# ---------------------------------------------------------------------------

def test_get_gap_report_returns_dict(collector):
    result = collector.get_gap_report()
    assert isinstance(result, dict)


def test_get_gap_report_has_frameworks_list(collector):
    result = collector.get_gap_report()
    assert "frameworks" in result
    assert isinstance(result["frameworks"], list)


def test_get_gap_report_all_frameworks_present(collector):
    result = collector.get_gap_report()
    framework_names = {f["framework"] for f in result["frameworks"]}
    assert "SOC2" in framework_names
    assert "PCI-DSS" in framework_names
    assert "ISO27001" in framework_names


def test_get_gap_report_coverage_pct_in_range(collector):
    result = collector.get_gap_report()
    for fw in result["frameworks"]:
        assert 0.0 <= fw["coverage_pct"] <= 100.0


def test_get_gap_report_missing_controls_is_list(collector):
    result = collector.get_gap_report()
    for fw in result["frameworks"]:
        assert isinstance(fw["missing_controls"], list)
