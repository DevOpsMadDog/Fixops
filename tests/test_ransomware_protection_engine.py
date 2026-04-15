"""Tests for RansomwareProtectionEngine — 35+ tests."""

from __future__ import annotations

import json
import os
import tempfile
import time
from datetime import datetime, timezone, timedelta

import pytest

from core.ransomware_protection_engine import RansomwareProtectionEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "ransomware_test.db")
    return RansomwareProtectionEngine(db_path=db)


@pytest.fixture
def engine2(tmp_path):
    db = str(tmp_path / "ransomware_test2.db")
    return RansomwareProtectionEngine(db_path=db)


ORG = "org-alpha"
ORG2 = "org-beta"

# ---------------------------------------------------------------------------
# Detection registration
# ---------------------------------------------------------------------------

class TestRegisterDetection:
    def test_register_basic(self, engine):
        d = engine.register_detection(ORG, "RansomX", "behavioral")
        assert d["id"]
        assert d["org_id"] == ORG
        assert d["detection_name"] == "RansomX"
        assert d["detection_type"] == "behavioral"
        assert d["status"] == "active"
        assert d["containment_status"] == "none"
        assert d["contained_at"] is None

    def test_affected_systems_json(self, engine):
        d = engine.register_detection(
            ORG, "CryptoLock", affected_systems=["server1", "server2"]
        )
        assert isinstance(d["affected_systems"], list)
        assert "server1" in d["affected_systems"]

    def test_file_extensions_json(self, engine):
        d = engine.register_detection(
            ORG, "Ext", file_extensions=[".encrypted", ".locked"]
        )
        assert ".encrypted" in d["file_extensions"]

    def test_confidence_clamped_high(self, engine):
        d = engine.register_detection(ORG, "Over", confidence=5.0)
        assert d["confidence"] == 1.0

    def test_confidence_clamped_low(self, engine):
        d = engine.register_detection(ORG, "Under", confidence=-0.5)
        assert d["confidence"] == 0.0

    def test_confidence_valid(self, engine):
        d = engine.register_detection(ORG, "Mid", confidence=0.75)
        assert d["confidence"] == pytest.approx(0.75)

    def test_invalid_detection_type(self, engine):
        with pytest.raises(ValueError):
            engine.register_detection(ORG, "Bad", detection_type="unknown_type")

    def test_all_valid_detection_types(self, engine):
        for dtype in ("behavioral", "signature", "honeypot", "heuristic", "network", "endpoint"):
            d = engine.register_detection(ORG, f"test_{dtype}", detection_type=dtype)
            assert d["detection_type"] == dtype

    def test_detected_at_set(self, engine):
        d = engine.register_detection(ORG, "TimedDetect")
        assert d["detected_at"]
        datetime.fromisoformat(d["detected_at"])  # parseable

    def test_severity_stored(self, engine):
        d = engine.register_detection(ORG, "Critical", severity="critical")
        assert d["severity"] == "critical"


# ---------------------------------------------------------------------------
# Containment lifecycle
# ---------------------------------------------------------------------------

class TestContainment:
    def test_update_to_in_progress(self, engine):
        d = engine.register_detection(ORG, "R1")
        updated = engine.update_containment(d["id"], ORG, "in_progress")
        assert updated["containment_status"] == "in_progress"
        assert updated["contained_at"] is None  # not yet contained

    def test_update_to_contained_sets_contained_at(self, engine):
        d = engine.register_detection(ORG, "R2")
        updated = engine.update_containment(d["id"], ORG, "contained")
        assert updated["containment_status"] == "contained"
        assert updated["contained_at"] is not None
        assert updated["status"] == "contained"

    def test_update_to_eradicated(self, engine):
        d = engine.register_detection(ORG, "R3")
        updated = engine.update_containment(d["id"], ORG, "eradicated")
        assert updated["containment_status"] == "eradicated"

    def test_invalid_containment_status(self, engine):
        d = engine.register_detection(ORG, "R4")
        with pytest.raises(ValueError):
            engine.update_containment(d["id"], ORG, "neutralized")

    def test_containment_wrong_org(self, engine):
        d = engine.register_detection(ORG, "R5")
        with pytest.raises(ValueError):
            engine.update_containment(d["id"], ORG2, "contained")

    def test_list_detections_by_status(self, engine):
        engine.register_detection(ORG, "Active1")
        d2 = engine.register_detection(ORG, "Active2")
        engine.update_containment(d2["id"], ORG, "contained")
        active = engine.list_detections(ORG, status="active")
        contained = engine.list_detections(ORG, status="contained")
        assert len(active) == 1
        assert len(contained) == 1

    def test_list_detections_all(self, engine):
        engine.register_detection(ORG, "A")
        engine.register_detection(ORG, "B")
        all_d = engine.list_detections(ORG)
        assert len(all_d) == 2


# ---------------------------------------------------------------------------
# Backup registration and validation
# ---------------------------------------------------------------------------

class TestBackup:
    def test_register_backup(self, engine):
        b = engine.register_backup(ORG, "db-server", backup_type="full")
        assert b["id"]
        assert b["system_name"] == "db-server"
        assert b["validation_status"] == "unknown"
        assert b["immutable"] == 0
        assert b["encrypted"] == 0

    def test_register_immutable_encrypted(self, engine):
        b = engine.register_backup(ORG, "critical", immutable=True, encrypted=True)
        assert b["immutable"] == 1
        assert b["encrypted"] == 1

    def test_invalid_backup_type(self, engine):
        with pytest.raises(ValueError):
            engine.register_backup(ORG, "sys", backup_type="tape")

    def test_all_valid_backup_types(self, engine):
        for bt in ("full", "incremental", "differential", "snapshot", "cloud"):
            b = engine.register_backup(ORG, f"sys_{bt}", backup_type=bt)
            assert b["backup_type"] == bt

    def test_validate_backup_valid(self, engine):
        b = engine.register_backup(ORG, "webserver")
        v = engine.validate_backup(b["id"], ORG, "valid", recovery_time_mins=30)
        assert v["validation_status"] == "valid"
        assert v["recovery_time_mins"] == 30
        assert v["last_validated"] is not None

    def test_validate_backup_invalid(self, engine):
        b = engine.register_backup(ORG, "oldserver")
        v = engine.validate_backup(b["id"], ORG, "invalid")
        assert v["validation_status"] == "invalid"

    def test_validate_invalid_status(self, engine):
        b = engine.register_backup(ORG, "s1")
        with pytest.raises(ValueError):
            engine.validate_backup(b["id"], ORG, "corrupt")

    def test_validate_wrong_org(self, engine):
        b = engine.register_backup(ORG, "s2")
        with pytest.raises(ValueError):
            engine.validate_backup(b["id"], ORG2, "valid")

    def test_unvalidated_backups_unknown(self, engine):
        engine.register_backup(ORG, "unknown_sys")
        unvalidated = engine.get_unvalidated_backups(ORG)
        assert len(unvalidated) == 1

    def test_unvalidated_backups_excludes_valid(self, engine):
        b_valid = engine.register_backup(ORG, "valid_sys")
        engine.validate_backup(b_valid["id"], ORG, "valid")
        b_unknown = engine.register_backup(ORG, "unknown_sys2")
        unvalidated = engine.get_unvalidated_backups(ORG)
        ids = [u["id"] for u in unvalidated]
        assert b_valid["id"] not in ids
        assert b_unknown["id"] in ids


# ---------------------------------------------------------------------------
# Playbooks
# ---------------------------------------------------------------------------

class TestPlaybooks:
    def test_create_playbook(self, engine):
        p = engine.create_playbook(ORG, "Isolate Network", trigger_type="automatic",
                                   steps=["step1", "step2"], estimated_mins=45)
        assert p["id"]
        assert p["playbook_name"] == "Isolate Network"
        assert p["execution_count"] == 0
        assert isinstance(p["steps"], list)
        assert "step1" in p["steps"]

    def test_invalid_trigger_type(self, engine):
        with pytest.raises(ValueError):
            engine.create_playbook(ORG, "Bad", trigger_type="event_driven")

    def test_all_valid_trigger_types(self, engine):
        for tt in ("automatic", "manual", "threshold", "scheduled"):
            p = engine.create_playbook(ORG, f"pb_{tt}", trigger_type=tt)
            assert p["trigger_type"] == tt

    def test_execute_playbook_increments_count(self, engine):
        p = engine.create_playbook(ORG, "ContainPlaybook")
        assert p["execution_count"] == 0
        result = engine.execute_playbook(p["id"], ORG)
        assert result["execution_count"] == 1
        result2 = engine.execute_playbook(p["id"], ORG)
        assert result2["execution_count"] == 2

    def test_execute_playbook_sets_last_executed(self, engine):
        p = engine.create_playbook(ORG, "TimedPlaybook")
        result = engine.execute_playbook(p["id"], ORG)
        assert result["last_executed"] is not None

    def test_execute_wrong_org(self, engine):
        p = engine.create_playbook(ORG, "OrgPlaybook")
        with pytest.raises(ValueError):
            engine.execute_playbook(p["id"], ORG2)

    def test_execute_returns_steps(self, engine):
        steps = ["isolate", "backup", "notify"]
        p = engine.create_playbook(ORG, "StepPlaybook", steps=steps)
        result = engine.execute_playbook(p["id"], ORG)
        assert result["steps"] == steps


# ---------------------------------------------------------------------------
# Protection status and summary
# ---------------------------------------------------------------------------

class TestStatusAndSummary:
    def test_protection_status_empty(self, engine):
        status = engine.get_protection_status(ORG)
        assert status["active_detections"] == 0
        assert status["valid_backups"] == 0

    def test_protection_status_counts(self, engine):
        engine.register_detection(ORG, "Active1")
        d2 = engine.register_detection(ORG, "Contained1")
        engine.update_containment(d2["id"], ORG, "contained")
        engine.register_backup(ORG, "sys1")
        b2 = engine.register_backup(ORG, "sys2")
        engine.validate_backup(b2["id"], ORG, "valid")
        status = engine.get_protection_status(ORG)
        assert status["active_detections"] == 1
        assert status["contained_detections"] == 1
        assert status["valid_backups"] == 1
        assert status["invalid_backups"] == 0

    def test_immutable_backups_count(self, engine):
        engine.register_backup(ORG, "immut1", immutable=True)
        engine.register_backup(ORG, "immut2", immutable=True)
        engine.register_backup(ORG, "normal")
        status = engine.get_protection_status(ORG)
        assert status["immutable_backups"] == 2

    def test_systems_with_backups(self, engine):
        engine.register_backup(ORG, "sysA")
        engine.register_backup(ORG, "sysA")  # duplicate name
        engine.register_backup(ORG, "sysB")
        status = engine.get_protection_status(ORG)
        assert status["systems_with_backups"] == 2

    def test_backup_coverage_pct(self, engine):
        b1 = engine.register_backup(ORG, "s1")
        b2 = engine.register_backup(ORG, "s2")
        engine.register_backup(ORG, "s3")
        engine.validate_backup(b1["id"], ORG, "valid")
        engine.validate_backup(b2["id"], ORG, "valid")
        summary = engine.get_summary(ORG)
        # 2 valid / 3 total = 66.67%
        assert summary["backup_coverage_pct"] == pytest.approx(66.67, abs=0.01)

    def test_summary_by_severity(self, engine):
        engine.register_detection(ORG, "C1", severity="critical")
        engine.register_detection(ORG, "C2", severity="critical")
        engine.register_detection(ORG, "H1", severity="high")
        summary = engine.get_summary(ORG)
        assert summary["by_severity"]["critical"] == 2
        assert summary["by_severity"]["high"] == 1

    def test_summary_by_status(self, engine):
        d = engine.register_detection(ORG, "Active")
        engine.update_containment(d["id"], ORG, "contained")
        engine.register_detection(ORG, "Active2")
        summary = engine.get_summary(ORG)
        assert summary["by_status"]["contained"] == 1
        assert summary["by_status"]["active"] == 1


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

class TestOrgIsolation:
    def test_detections_isolated(self, engine):
        engine.register_detection(ORG, "OrgA_detect")
        engine.register_detection(ORG2, "OrgB_detect")
        assert len(engine.list_detections(ORG)) == 1
        assert len(engine.list_detections(ORG2)) == 1

    def test_backups_isolated(self, engine):
        engine.register_backup(ORG, "sys_a")
        engine.register_backup(ORG2, "sys_b")
        unval_a = engine.get_unvalidated_backups(ORG)
        unval_b = engine.get_unvalidated_backups(ORG2)
        assert len(unval_a) == 1
        assert len(unval_b) == 1

    def test_status_isolated(self, engine):
        engine.register_detection(ORG, "d1")
        status_a = engine.get_protection_status(ORG)
        status_b = engine.get_protection_status(ORG2)
        assert status_a["active_detections"] == 1
        assert status_b["active_detections"] == 0

    def test_summary_isolated(self, engine):
        engine.register_detection(ORG, "da")
        engine.register_detection(ORG, "db")
        s = engine.get_summary(ORG2)
        assert s["total_detections"] == 0
