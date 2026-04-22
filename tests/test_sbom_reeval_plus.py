"""Tests for GAP-041 format matrix + GAP-055 reeval scheduler + GAP-057 component claim.

30 tests covering:
  - 4 new format emitters produce syntactically valid output (SWID XML, ORT/CSAF JSON)
  - existing cyclonedx/spdx still emit valid JSON
  - schedule idempotency on (org_id, sbom_id, cron_expr)
  - next-run advances on mark_reeval_done
  - component-claim UNIQUE dedup
  - org_id isolation
"""

from __future__ import annotations

import json
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.sbom_engine import SBOMEngine
from core.sbom_export_engine import SBOMExportEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sbom_engine(tmp_path):
    return SBOMEngine(data_dir=str(tmp_path))


@pytest.fixture()
def export_engine(tmp_path):
    db_path = str(tmp_path / "export.db")
    eng = SBOMExportEngine(db_path=db_path)
    # Seed one project with a component + vuln so exports are non-trivial
    comp = eng.register_component(
        org_id="org_a",
        project_name="proj1",
        component_name="lodash",
        component_version="4.17.21",
        component_type="library",
        ecosystem="npm",
        license="MIT",
        purl="pkg:npm/lodash@4.17.21",
        cpe="cpe:2.3:a:lodash:lodash:4.17.21",
        supplier="Lodash Authors",
        hash_sha256="abc123",
    )
    eng.add_vuln(
        component_id=comp["id"],
        org_id="org_a",
        cve_id="CVE-2021-23337",
        severity="high",
        cvss_score=7.2,
        affects_version="<4.17.21",
        fixed_in="4.17.21",
    )
    return eng


# ---------------------------------------------------------------------------
# GAP-041: Format matrix (12 tests)
# ---------------------------------------------------------------------------


def test_generate_swid_returns_valid_xml(export_engine):
    xml_str = export_engine.generate_swid("org_a", "proj1")
    root = ET.fromstring(xml_str)
    assert root.tag.endswith("SoftwareIdentity")


def test_generate_swid_has_project_attributes(export_engine):
    xml_str = export_engine.generate_swid("org_a", "proj1", version_tag="2.0")
    root = ET.fromstring(xml_str)
    assert root.attrib["name"] == "proj1"
    assert root.attrib["version"] == "2.0"


def test_generate_swid_records_export(export_engine):
    export_engine.generate_swid("org_a", "proj1")
    history = export_engine.get_export_history("org_a", "proj1")
    assert any(h["format"] == "swid" for h in history)


def test_generate_swid_includes_component_payload(export_engine):
    xml_str = export_engine.generate_swid("org_a", "proj1")
    root = ET.fromstring(xml_str)
    payloads = root.findall(".//{http://standards.iso.org/iso/19770/-2/2015/schema.xsd}Payload")
    assert len(payloads) == 1


def test_generate_ort_returns_valid_json(export_engine):
    doc = export_engine.generate_ort("org_a", "proj1")
    # Should be json-serialisable
    parsed = json.loads(json.dumps(doc))
    assert "analyzer_result" in parsed


def test_generate_ort_packages_populated(export_engine):
    doc = export_engine.generate_ort("org_a", "proj1")
    pkgs = doc["analyzer_result"]["packages"]
    assert len(pkgs) == 1
    assert pkgs[0]["package"]["purl"] == "pkg:npm/lodash@4.17.21"


def test_generate_ort_projects_array(export_engine):
    doc = export_engine.generate_ort("org_a", "proj1")
    projs = doc["analyzer_result"]["projects"]
    assert len(projs) == 1
    assert "proj1" in projs[0]["id"]


def test_generate_csaf_returns_valid_json(export_engine):
    doc = export_engine.generate_csaf("org_a", "proj1")
    parsed = json.loads(json.dumps(doc))
    assert parsed["document"]["csaf_version"] == "2.0"


def test_generate_csaf_tracking_id(export_engine):
    doc = export_engine.generate_csaf("org_a", "proj1", version_tag="3.0")
    assert "org_a" in doc["document"]["tracking"]["id"]
    assert "proj1" in doc["document"]["tracking"]["id"]
    assert doc["document"]["tracking"]["version"] == "3.0"


def test_generate_csaf_product_tree_populated(export_engine):
    doc = export_engine.generate_csaf("org_a", "proj1")
    assert len(doc["product_tree"]["branches"]) == 1


def test_generate_csaf_vulnerabilities_populated(export_engine):
    doc = export_engine.generate_csaf("org_a", "proj1")
    vulns = doc["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["cve"] == "CVE-2021-23337"


def test_export_formats_dispatcher_has_all_5(export_engine):
    fmts = set(export_engine.export_formats.keys())
    assert fmts == {"cyclonedx", "spdx", "swid", "ort", "csaf"}


def test_export_dispatcher_rejects_unknown_format(export_engine):
    with pytest.raises(ValueError):
        export_engine.export("pdf", "org_a", "proj1")


def test_export_dispatcher_returns_swid_xml(export_engine):
    out = export_engine.export("swid", "org_a", "proj1")
    assert isinstance(out, str)
    ET.fromstring(out)  # must parse


def test_export_dispatcher_returns_cyclonedx_json(export_engine):
    out = export_engine.export("cyclonedx", "org_a", "proj1")
    assert isinstance(out, dict)
    assert out["bomFormat"] == "CycloneDX"


# ---------------------------------------------------------------------------
# GAP-055: Re-eval scheduler (10 tests)
# ---------------------------------------------------------------------------


def test_schedule_reeval_creates_record(sbom_engine):
    rec = sbom_engine.schedule_reeval("org_a", "sbom123", "@daily")
    assert rec["org_id"] == "org_a"
    assert rec["sbom_id"] == "sbom123"
    assert rec["cron_expr"] == "@daily"
    assert rec["enabled"] == 1
    assert rec["next_run_at"]


def test_schedule_reeval_idempotent(sbom_engine):
    rec1 = sbom_engine.schedule_reeval("org_a", "sbom123", "@daily")
    rec2 = sbom_engine.schedule_reeval("org_a", "sbom123", "@daily")
    assert rec1["id"] == rec2["id"]


def test_schedule_reeval_diff_cron_creates_new(sbom_engine):
    rec1 = sbom_engine.schedule_reeval("org_a", "sbom123", "@daily")
    rec2 = sbom_engine.schedule_reeval("org_a", "sbom123", "@hourly")
    assert rec1["id"] != rec2["id"]


def test_list_reeval_schedules(sbom_engine):
    sbom_engine.schedule_reeval("org_a", "s1", "@daily")
    sbom_engine.schedule_reeval("org_a", "s2", "@hourly")
    sched = sbom_engine.list_reeval_schedules("org_a")
    assert len(sched) == 2


def test_list_reeval_schedules_org_isolation(sbom_engine):
    sbom_engine.schedule_reeval("org_a", "s1", "@daily")
    sbom_engine.schedule_reeval("org_b", "s2", "@hourly")
    assert len(sbom_engine.list_reeval_schedules("org_a")) == 1
    assert len(sbom_engine.list_reeval_schedules("org_b")) == 1


def test_compute_next_run_hourly():
    base = datetime(2026, 4, 22, 10, 30, tzinfo=timezone.utc)
    nxt = SBOMEngine._compute_next_run("@hourly", base)
    assert nxt.hour == 11
    assert nxt.minute == 0


def test_compute_next_run_daily():
    base = datetime(2026, 4, 22, 10, 30, tzinfo=timezone.utc)
    nxt = SBOMEngine._compute_next_run("@daily", base)
    assert nxt.day == 23
    assert nxt.hour == 0


def test_compute_next_run_weekly_advances_to_sunday():
    # 2026-04-22 is a Wednesday
    base = datetime(2026, 4, 22, 10, 30, tzinfo=timezone.utc)
    nxt = SBOMEngine._compute_next_run("@weekly", base)
    assert nxt.weekday() == 6  # Sunday


def test_compute_next_run_5field_explicit():
    # 0 3 * * * → 03:00 every day
    base = datetime(2026, 4, 22, 10, 30, tzinfo=timezone.utc)
    nxt = SBOMEngine._compute_next_run("0 3 * * *", base)
    assert nxt.hour == 3
    assert nxt.minute == 0


def test_compute_next_run_malformed_falls_back_to_daily():
    base = datetime(2026, 4, 22, 10, 30, tzinfo=timezone.utc)
    nxt = SBOMEngine._compute_next_run("not a cron", base)
    # Fallback is +1 day
    assert (nxt - base).total_seconds() >= 23 * 3600


def test_mark_reeval_done_advances_next_run(sbom_engine):
    rec = sbom_engine.schedule_reeval("org_a", "sbom123", "@daily")
    first_next = rec["next_run_at"]
    updated = sbom_engine.mark_reeval_done(rec["id"], findings_delta=3)
    assert updated is not None
    assert updated["last_run_at"]
    assert updated["findings_delta"] == 3
    # next_run_at should now be a valid iso timestamp
    assert updated["next_run_at"]
    # Parse and assert it is after "now"
    nxt = datetime.fromisoformat(updated["next_run_at"])
    assert nxt > datetime.now(timezone.utc) - timedelta(seconds=5)


def test_mark_reeval_done_unknown_returns_none(sbom_engine):
    result = sbom_engine.mark_reeval_done("non-existent-id", findings_delta=0)
    assert result is None


# ---------------------------------------------------------------------------
# GAP-057: Component claim (7 tests)
# ---------------------------------------------------------------------------


def test_register_component_claim_creates_record(sbom_engine):
    rec = sbom_engine.register_component_claim(
        org_id="org_a",
        component_purl="pkg:npm/lodash@4.17.21",
        claimant="acme-inc",
        claim_type="owner",
        evidence_uri="https://example.com/attestation",
    )
    assert rec["org_id"] == "org_a"
    assert rec["purl"] == "pkg:npm/lodash@4.17.21"
    assert rec["claimant"] == "acme-inc"
    assert rec["claim_type"] == "owner"


def test_register_component_claim_unique_dedup(sbom_engine):
    rec1 = sbom_engine.register_component_claim(
        org_id="org_a",
        component_purl="pkg:npm/lodash@4.17.21",
        claimant="acme-inc",
    )
    rec2 = sbom_engine.register_component_claim(
        org_id="org_a",
        component_purl="pkg:npm/lodash@4.17.21",
        claimant="acme-inc",
        claim_type="maintainer",  # different type but UNIQUE is (org, purl, claimant)
    )
    assert rec1["id"] == rec2["id"]


def test_register_component_claim_different_claimants_distinct(sbom_engine):
    rec1 = sbom_engine.register_component_claim(
        org_id="org_a", component_purl="pkg:npm/x@1.0", claimant="acme"
    )
    rec2 = sbom_engine.register_component_claim(
        org_id="org_a", component_purl="pkg:npm/x@1.0", claimant="beta"
    )
    assert rec1["id"] != rec2["id"]


def test_register_component_claim_rejects_empty_purl(sbom_engine):
    with pytest.raises(ValueError):
        sbom_engine.register_component_claim(
            org_id="org_a", component_purl="", claimant="acme"
        )


def test_register_component_claim_rejects_invalid_type(sbom_engine):
    with pytest.raises(ValueError):
        sbom_engine.register_component_claim(
            org_id="org_a",
            component_purl="pkg:npm/x@1.0",
            claimant="acme",
            claim_type="junk",
        )


def test_list_component_claims_filter_by_purl(sbom_engine):
    sbom_engine.register_component_claim("org_a", "pkg:npm/x@1.0", "acme")
    sbom_engine.register_component_claim("org_a", "pkg:npm/y@1.0", "acme")
    only_x = sbom_engine.list_component_claims("org_a", purl="pkg:npm/x@1.0")
    assert len(only_x) == 1
    assert only_x[0]["purl"] == "pkg:npm/x@1.0"


def test_list_component_claims_org_isolation(sbom_engine):
    sbom_engine.register_component_claim("org_a", "pkg:npm/x@1.0", "acme")
    sbom_engine.register_component_claim("org_b", "pkg:npm/y@1.0", "beta")
    assert len(sbom_engine.list_component_claims("org_a")) == 1
    assert len(sbom_engine.list_component_claims("org_b")) == 1
