"""Tests for ComplianceMappingEngine — 35+ tests."""

from __future__ import annotations

import tempfile
import pytest
from core.compliance_mapping_engine import ComplianceMappingEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_compliance_mapping.db")
    return ComplianceMappingEngine(db_path=db)


ORG = "org-test"
ORG2 = "org-other"


# ---------------------------------------------------------------------------
# add_control
# ---------------------------------------------------------------------------

class TestAddControl:
    def test_add_control_minimal(self, engine):
        rec = engine.add_control(ORG, {
            "control_id": "CC6.1",
            "framework": "soc2",
            "control_name": "Logical Access",
        })
        assert rec["id"]
        assert rec["control_id"] == "CC6.1"
        assert rec["framework"] == "soc2"
        assert rec["control_name"] == "Logical Access"
        assert rec["control_status"] == "not_implemented"
        assert rec["evidence_count"] == 0
        assert rec["org_id"] == ORG

    def test_add_control_all_fields(self, engine):
        rec = engine.add_control(ORG, {
            "control_id": "AC-2",
            "framework": "nist_800_53",
            "control_name": "Account Management",
            "description": "Manage information system accounts",
            "control_status": "implemented",
            "implementation_notes": "Using AD groups",
            "owner": "alice",
            "last_reviewed": "2026-01-01T00:00:00Z",
        })
        assert rec["control_status"] == "implemented"
        assert rec["owner"] == "alice"
        assert rec["implementation_notes"] == "Using AD groups"

    def test_add_control_missing_control_id(self, engine):
        with pytest.raises(ValueError, match="control_id"):
            engine.add_control(ORG, {"control_name": "Test", "framework": "soc2"})

    def test_add_control_missing_control_name(self, engine):
        with pytest.raises(ValueError, match="control_name"):
            engine.add_control(ORG, {"control_id": "X.1", "framework": "soc2"})

    def test_add_control_invalid_framework(self, engine):
        with pytest.raises(ValueError, match="framework"):
            engine.add_control(ORG, {
                "control_id": "X.1",
                "control_name": "Test",
                "framework": "not_a_framework",
            })

    def test_add_control_invalid_status(self, engine):
        with pytest.raises(ValueError, match="control_status"):
            engine.add_control(ORG, {
                "control_id": "X.1",
                "control_name": "Test",
                "framework": "soc2",
                "control_status": "unknown",
            })

    def test_add_control_all_frameworks(self, engine):
        frameworks = [
            "nist_csf", "iso27001", "pci_dss", "soc2", "hipaa",
            "gdpr", "cis_controls", "nist_800_53",
        ]
        for fw in frameworks:
            rec = engine.add_control(ORG, {
                "control_id": f"C-{fw}",
                "control_name": fw.upper(),
                "framework": fw,
            })
            assert rec["framework"] == fw

    def test_add_control_all_statuses(self, engine):
        statuses = ["implemented", "partial", "not_implemented", "not_applicable"]
        for i, st in enumerate(statuses):
            rec = engine.add_control(ORG, {
                "control_id": f"S-{i}",
                "control_name": f"Control {i}",
                "framework": "nist_csf",
                "control_status": st,
            })
            assert rec["control_status"] == st

    def test_add_control_default_framework(self, engine):
        rec = engine.add_control(ORG, {"control_id": "X", "control_name": "X"})
        assert rec["framework"] == "nist_csf"


# ---------------------------------------------------------------------------
# list_controls / get_control
# ---------------------------------------------------------------------------

class TestListGetControls:
    def _seed(self, engine):
        c1 = engine.add_control(ORG, {
            "control_id": "CC6.1", "control_name": "A",
            "framework": "soc2", "control_status": "implemented",
        })
        c2 = engine.add_control(ORG, {
            "control_id": "AC-2", "control_name": "B",
            "framework": "nist_800_53", "control_status": "partial",
        })
        c3 = engine.add_control(ORG, {
            "control_id": "1.1", "control_name": "C",
            "framework": "soc2", "control_status": "not_implemented",
        })
        return c1, c2, c3

    def test_list_all(self, engine):
        self._seed(engine)
        controls = engine.list_controls(ORG)
        assert len(controls) == 3

    def test_list_filter_framework(self, engine):
        self._seed(engine)
        controls = engine.list_controls(ORG, framework="soc2")
        assert len(controls) == 2
        assert all(c["framework"] == "soc2" for c in controls)

    def test_list_filter_status(self, engine):
        self._seed(engine)
        controls = engine.list_controls(ORG, control_status="partial")
        assert len(controls) == 1
        assert controls[0]["control_id"] == "AC-2"

    def test_list_filter_both(self, engine):
        self._seed(engine)
        controls = engine.list_controls(ORG, framework="soc2", control_status="implemented")
        assert len(controls) == 1
        assert controls[0]["control_id"] == "CC6.1"

    def test_list_org_isolation(self, engine):
        self._seed(engine)
        engine.add_control(ORG2, {"control_id": "Z", "control_name": "Z", "framework": "gdpr"})
        assert len(engine.list_controls(ORG)) == 3
        assert len(engine.list_controls(ORG2)) == 1

    def test_get_control_found(self, engine):
        c1, _, _ = self._seed(engine)
        rec = engine.get_control(ORG, c1["id"])
        assert rec is not None
        assert rec["control_id"] == "CC6.1"

    def test_get_control_not_found(self, engine):
        result = engine.get_control(ORG, "nonexistent-id")
        assert result is None

    def test_get_control_org_isolation(self, engine):
        c1, _, _ = self._seed(engine)
        result = engine.get_control(ORG2, c1["id"])
        assert result is None


# ---------------------------------------------------------------------------
# update_control_status
# ---------------------------------------------------------------------------

class TestUpdateControlStatus:
    def test_update_status(self, engine):
        c = engine.add_control(ORG, {
            "control_id": "X", "control_name": "X", "framework": "soc2",
        })
        updated = engine.update_control_status(ORG, c["id"], "implemented")
        assert updated["control_status"] == "implemented"

    def test_update_status_with_notes(self, engine):
        c = engine.add_control(ORG, {
            "control_id": "X", "control_name": "X", "framework": "soc2",
        })
        updated = engine.update_control_status(
            ORG, c["id"], "partial", notes="Half done"
        )
        assert updated["control_status"] == "partial"
        assert updated["implementation_notes"] == "Half done"

    def test_update_status_invalid(self, engine):
        c = engine.add_control(ORG, {
            "control_id": "X", "control_name": "X", "framework": "soc2",
        })
        with pytest.raises(ValueError, match="control_status"):
            engine.update_control_status(ORG, c["id"], "bogus")

    def test_update_status_not_found(self, engine):
        with pytest.raises(KeyError):
            engine.update_control_status(ORG, "bad-id", "implemented")

    def test_update_sets_last_reviewed(self, engine):
        c = engine.add_control(ORG, {
            "control_id": "X", "control_name": "X", "framework": "soc2",
        })
        updated = engine.update_control_status(ORG, c["id"], "implemented")
        assert updated["last_reviewed"] is not None


# ---------------------------------------------------------------------------
# add_mapping / list_mappings
# ---------------------------------------------------------------------------

class TestMappings:
    def _make_mapping(self, engine, strength="strong"):
        return engine.add_mapping(ORG, {
            "source_control_id": "CC6.1",
            "target_control_id": "AC-2",
            "source_framework": "soc2",
            "target_framework": "nist_800_53",
            "mapping_strength": strength,
        })

    def test_add_mapping(self, engine):
        m = self._make_mapping(engine)
        assert m["id"]
        assert m["source_framework"] == "soc2"
        assert m["target_framework"] == "nist_800_53"
        assert m["mapping_strength"] == "strong"

    def test_add_mapping_missing_source_control(self, engine):
        with pytest.raises(ValueError, match="source_control_id"):
            engine.add_mapping(ORG, {
                "target_control_id": "X",
                "source_framework": "soc2",
                "target_framework": "nist_800_53",
                "mapping_strength": "strong",
            })

    def test_add_mapping_missing_target_control(self, engine):
        with pytest.raises(ValueError, match="target_control_id"):
            engine.add_mapping(ORG, {
                "source_control_id": "X",
                "source_framework": "soc2",
                "target_framework": "nist_800_53",
                "mapping_strength": "strong",
            })

    def test_add_mapping_invalid_source_framework(self, engine):
        with pytest.raises(ValueError, match="source_framework"):
            engine.add_mapping(ORG, {
                "source_control_id": "A",
                "target_control_id": "B",
                "source_framework": "bad",
                "target_framework": "soc2",
                "mapping_strength": "strong",
            })

    def test_add_mapping_invalid_target_framework(self, engine):
        with pytest.raises(ValueError, match="target_framework"):
            engine.add_mapping(ORG, {
                "source_control_id": "A",
                "target_control_id": "B",
                "source_framework": "soc2",
                "target_framework": "bad",
                "mapping_strength": "strong",
            })

    def test_add_mapping_invalid_strength(self, engine):
        with pytest.raises(ValueError, match="mapping_strength"):
            engine.add_mapping(ORG, {
                "source_control_id": "A",
                "target_control_id": "B",
                "source_framework": "soc2",
                "target_framework": "nist_800_53",
                "mapping_strength": "unknown",
            })

    def test_add_mapping_all_strengths(self, engine):
        for s in ["strong", "moderate", "weak"]:
            m = self._make_mapping(engine, strength=s)
            assert m["mapping_strength"] == s

    def test_list_mappings_all(self, engine):
        self._make_mapping(engine)
        self._make_mapping(engine)
        mappings = engine.list_mappings(ORG)
        assert len(mappings) == 2

    def test_list_mappings_filter_source(self, engine):
        self._make_mapping(engine)
        engine.add_mapping(ORG, {
            "source_control_id": "G1",
            "target_control_id": "AC-2",
            "source_framework": "gdpr",
            "target_framework": "nist_800_53",
            "mapping_strength": "moderate",
        })
        results = engine.list_mappings(ORG, source_framework="soc2")
        assert all(m["source_framework"] == "soc2" for m in results)

    def test_list_mappings_filter_target(self, engine):
        self._make_mapping(engine)
        results = engine.list_mappings(ORG, target_framework="nist_800_53")
        assert len(results) == 1

    def test_list_mappings_org_isolation(self, engine):
        self._make_mapping(engine)
        assert len(engine.list_mappings(ORG2)) == 0


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

class TestEvidence:
    def _seed_control(self, engine):
        return engine.add_control(ORG, {
            "control_id": "CC6.1", "control_name": "A", "framework": "soc2",
        })

    def test_add_evidence(self, engine):
        c = self._seed_control(engine)
        ev = engine.add_evidence(ORG, c["id"], {
            "evidence_type": "policy",
            "description": "Access control policy v2",
        })
        assert ev["id"]
        assert ev["evidence_type"] == "policy"
        assert ev["control_id"] == c["id"]

    def test_add_evidence_increments_count(self, engine):
        c = self._seed_control(engine)
        engine.add_evidence(ORG, c["id"], {
            "evidence_type": "screenshot", "description": "MFA enabled",
        })
        engine.add_evidence(ORG, c["id"], {
            "evidence_type": "log", "description": "Audit log excerpt",
        })
        updated = engine.get_control(ORG, c["id"])
        assert updated["evidence_count"] == 2

    def test_add_evidence_missing_evidence_type(self, engine):
        c = self._seed_control(engine)
        with pytest.raises(ValueError, match="evidence_type"):
            engine.add_evidence(ORG, c["id"], {"description": "test"})

    def test_add_evidence_missing_description(self, engine):
        c = self._seed_control(engine)
        with pytest.raises(ValueError, match="description"):
            engine.add_evidence(ORG, c["id"], {"evidence_type": "policy"})

    def test_add_evidence_optional_fields(self, engine):
        c = self._seed_control(engine)
        ev = engine.add_evidence(ORG, c["id"], {
            "evidence_type": "screenshot",
            "description": "Test",
            "file_reference": "s3://bucket/file.png",
            "collector": "auto-collector",
            "expires_at": "2027-01-01T00:00:00Z",
        })
        assert ev["file_reference"] == "s3://bucket/file.png"
        assert ev["collector"] == "auto-collector"

    def test_list_evidence_all(self, engine):
        c1 = self._seed_control(engine)
        c2 = engine.add_control(ORG, {
            "control_id": "X", "control_name": "X", "framework": "soc2",
        })
        engine.add_evidence(ORG, c1["id"], {"evidence_type": "a", "description": "a"})
        engine.add_evidence(ORG, c2["id"], {"evidence_type": "b", "description": "b"})
        evs = engine.list_evidence(ORG)
        assert len(evs) == 2

    def test_list_evidence_filter_by_control(self, engine):
        c1 = self._seed_control(engine)
        c2 = engine.add_control(ORG, {
            "control_id": "X", "control_name": "X", "framework": "soc2",
        })
        engine.add_evidence(ORG, c1["id"], {"evidence_type": "a", "description": "a"})
        engine.add_evidence(ORG, c2["id"], {"evidence_type": "b", "description": "b"})
        evs = engine.list_evidence(ORG, control_id_param=c1["id"])
        assert len(evs) == 1
        assert evs[0]["control_id"] == c1["id"]


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestStats:
    def test_empty_stats(self, engine):
        stats = engine.get_mapping_stats(ORG)
        assert stats["total_controls"] == 0
        assert stats["total_mappings"] == 0
        assert stats["implementation_rate"] == 0.0
        assert stats["controls_with_evidence"] == 0

    def test_stats_by_framework(self, engine):
        engine.add_control(ORG, {
            "control_id": "A", "control_name": "A", "framework": "soc2",
        })
        engine.add_control(ORG, {
            "control_id": "B", "control_name": "B", "framework": "soc2",
        })
        engine.add_control(ORG, {
            "control_id": "C", "control_name": "C", "framework": "gdpr",
        })
        stats = engine.get_mapping_stats(ORG)
        assert stats["total_controls"] == 3
        assert stats["by_framework"]["soc2"] == 2
        assert stats["by_framework"]["gdpr"] == 1

    def test_stats_implementation_rate(self, engine):
        engine.add_control(ORG, {
            "control_id": "A", "control_name": "A", "framework": "soc2",
            "control_status": "implemented",
        })
        engine.add_control(ORG, {
            "control_id": "B", "control_name": "B", "framework": "soc2",
            "control_status": "partial",
        })
        engine.add_control(ORG, {
            "control_id": "C", "control_name": "C", "framework": "soc2",
            "control_status": "not_implemented",
        })
        engine.add_control(ORG, {
            "control_id": "D", "control_name": "D", "framework": "soc2",
            "control_status": "not_implemented",
        })
        stats = engine.get_mapping_stats(ORG)
        # 2 of 4 implemented/partial = 50%
        assert stats["implementation_rate"] == 50.0

    def test_stats_total_mappings(self, engine):
        engine.add_mapping(ORG, {
            "source_control_id": "A", "target_control_id": "B",
            "source_framework": "soc2", "target_framework": "nist_800_53",
            "mapping_strength": "strong",
        })
        engine.add_mapping(ORG, {
            "source_control_id": "C", "target_control_id": "D",
            "source_framework": "gdpr", "target_framework": "iso27001",
            "mapping_strength": "moderate",
        })
        stats = engine.get_mapping_stats(ORG)
        assert stats["total_mappings"] == 2

    def test_stats_controls_with_evidence(self, engine):
        c1 = engine.add_control(ORG, {
            "control_id": "A", "control_name": "A", "framework": "soc2",
        })
        engine.add_control(ORG, {
            "control_id": "B", "control_name": "B", "framework": "soc2",
        })
        engine.add_evidence(ORG, c1["id"], {
            "evidence_type": "policy", "description": "Test",
        })
        stats = engine.get_mapping_stats(ORG)
        assert stats["controls_with_evidence"] == 1

    def test_stats_by_status(self, engine):
        for st in ["implemented", "partial", "not_implemented"]:
            engine.add_control(ORG, {
                "control_id": st, "control_name": st,
                "framework": "soc2", "control_status": st,
            })
        stats = engine.get_mapping_stats(ORG)
        assert stats["by_status"]["implemented"] == 1
        assert stats["by_status"]["partial"] == 1
        assert stats["by_status"]["not_implemented"] == 1

    def test_stats_org_isolation(self, engine):
        engine.add_control(ORG, {
            "control_id": "A", "control_name": "A", "framework": "soc2",
        })
        engine.add_control(ORG2, {
            "control_id": "B", "control_name": "B", "framework": "gdpr",
        })
        assert engine.get_mapping_stats(ORG)["total_controls"] == 1
        assert engine.get_mapping_stats(ORG2)["total_controls"] == 1
