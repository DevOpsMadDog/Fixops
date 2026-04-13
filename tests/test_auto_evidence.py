"""
Tests for AutoEvidenceCollector and auto_evidence_router.

35+ tests covering:
- EvidenceSource enum
- AutoEvidence Pydantic model
- AutoEvidenceCollector all collection methods
- auto_collect_all bulk collection
- verify_evidence hash verification
- get_evidence_coverage coverage report
- Framework control mapping
- FastAPI router endpoints (8 endpoints)
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core is on the path
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

# Configure environment for testing
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.auto_evidence import (
    AutoEvidence,
    AutoEvidenceCollector,
    EvidenceCoverage,
    EvidenceSource,
    FRAMEWORK_CONTROL_MAP,
    SOURCE_TTL_DAYS,
    _sha256,
    get_collector,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_collector(tmp_path):
    """AutoEvidenceCollector backed by a temp SQLite DB."""
    return AutoEvidenceCollector(db_path=str(tmp_path / "test_evidence.db"))


ORG = "test-org-001"
CONTROL = "CC6.1"
FRAMEWORK = "SOC2"


# ===========================================================================
# 1. EvidenceSource enum
# ===========================================================================


class TestEvidenceSourceEnum:
    def test_all_sources_exist(self):
        expected = {
            "api_logs",
            "audit_trail",
            "scan_results",
            "config_snapshots",
            "access_reviews",
            "encryption_status",
            "backup_records",
            "incident_reports",
        }
        actual = {s.value for s in EvidenceSource}
        assert actual == expected

    def test_eight_sources(self):
        assert len(list(EvidenceSource)) == 8

    def test_str_enum_values(self):
        for src in EvidenceSource:
            assert isinstance(src.value, str)
            assert src.value  # non-empty


# ===========================================================================
# 2. AutoEvidence Pydantic model
# ===========================================================================


class TestAutoEvidenceModel:
    def test_default_id_generated(self):
        ev = AutoEvidence(
            source=EvidenceSource.AUDIT_TRAIL,
            control_id=CONTROL,
            framework=FRAMEWORK,
            content_hash="abc123",
            org_id=ORG,
        )
        assert ev.id
        assert len(ev.id) == 36  # UUID4 format

    def test_required_fields(self):
        with pytest.raises(Exception):
            AutoEvidence()  # missing required fields

    def test_defaults(self):
        ev = AutoEvidence(
            source=EvidenceSource.SCAN_RESULTS,
            control_id="CC7.2",
            framework="SOC2",
            content_hash="deadbeef",
            org_id=ORG,
        )
        assert ev.verified is False
        assert ev.expires_at is None
        assert ev.summary == ""
        assert ev.raw_content == "{}"

    def test_collected_at_is_utc(self):
        ev = AutoEvidence(
            source=EvidenceSource.CONFIG_SNAPSHOTS,
            control_id=CONTROL,
            framework=FRAMEWORK,
            content_hash="x",
            org_id=ORG,
        )
        assert ev.collected_at.tzinfo is not None


# ===========================================================================
# 3. Framework control mapping
# ===========================================================================


class TestFrameworkControlMap:
    def test_soc2_exists(self):
        assert "SOC2" in FRAMEWORK_CONTROL_MAP

    def test_pci_exists(self):
        assert "PCI" in FRAMEWORK_CONTROL_MAP

    def test_hipaa_exists(self):
        assert "HIPAA" in FRAMEWORK_CONTROL_MAP

    def test_soc2_has_ten_controls(self):
        assert len(FRAMEWORK_CONTROL_MAP["SOC2"]) == 10

    def test_pci_has_ten_controls(self):
        assert len(FRAMEWORK_CONTROL_MAP["PCI"]) == 10

    def test_hipaa_has_ten_controls(self):
        assert len(FRAMEWORK_CONTROL_MAP["HIPAA"]) == 10

    def test_each_control_maps_to_evidence_sources(self):
        for fw, controls in FRAMEWORK_CONTROL_MAP.items():
            for cid, sources in controls.items():
                assert isinstance(sources, list)
                assert len(sources) >= 1
                for src in sources:
                    assert isinstance(src, EvidenceSource)

    def test_source_ttl_defined_for_all_sources(self):
        for src in EvidenceSource:
            assert src in SOURCE_TTL_DAYS


# ===========================================================================
# 4. AutoEvidenceCollector — persistence
# ===========================================================================


class TestAutoEvidenceCollectorPersistence:
    def test_db_created(self, tmp_collector, tmp_path):
        assert (tmp_path / "test_evidence.db").exists()

    def test_save_and_retrieve(self, tmp_collector):
        ev = tmp_collector.collect_from_audit_logs(ORG, CONTROL, FRAMEWORK)
        retrieved = tmp_collector.get_evidence(ev.id)
        assert retrieved is not None
        assert retrieved.id == ev.id

    def test_get_nonexistent_returns_none(self, tmp_collector):
        result = tmp_collector.get_evidence(str(uuid.uuid4()))
        assert result is None

    def test_list_evidence_filtered_by_org(self, tmp_collector):
        tmp_collector.collect_from_audit_logs(ORG, CONTROL, FRAMEWORK)
        tmp_collector.collect_from_audit_logs("other-org", CONTROL, FRAMEWORK)
        results = tmp_collector.list_evidence(org_id=ORG)
        assert all(r.org_id == ORG for r in results)

    def test_list_evidence_filtered_by_framework(self, tmp_collector):
        tmp_collector.collect_from_audit_logs(ORG, CONTROL, "SOC2")
        tmp_collector.collect_from_audit_logs(ORG, "10.1", "PCI")
        soc2 = tmp_collector.list_evidence(org_id=ORG, framework="SOC2")
        assert all(r.framework == "SOC2" for r in soc2)

    def test_list_evidence_filtered_by_source(self, tmp_collector):
        tmp_collector.collect_from_audit_logs(ORG, CONTROL, FRAMEWORK)
        tmp_collector.collect_from_config(ORG, CONTROL, FRAMEWORK)
        audit = tmp_collector.list_evidence(org_id=ORG, source=EvidenceSource.AUDIT_TRAIL)
        assert all(r.source == EvidenceSource.AUDIT_TRAIL for r in audit)


# ===========================================================================
# 5. Collection methods
# ===========================================================================


class TestCollectionMethods:
    def test_collect_from_audit_logs_returns_evidence(self, tmp_collector):
        ev = tmp_collector.collect_from_audit_logs(ORG, CONTROL, FRAMEWORK)
        assert isinstance(ev, AutoEvidence)
        assert ev.source == EvidenceSource.AUDIT_TRAIL
        assert ev.org_id == ORG
        assert ev.control_id == CONTROL
        assert ev.content_hash

    def test_collect_from_scan_results_returns_evidence(self, tmp_collector):
        ev = tmp_collector.collect_from_scan_results(ORG, CONTROL, FRAMEWORK)
        assert isinstance(ev, AutoEvidence)
        assert ev.source == EvidenceSource.SCAN_RESULTS

    def test_collect_from_config_returns_evidence(self, tmp_collector):
        ev = tmp_collector.collect_from_config(ORG, CONTROL, FRAMEWORK)
        assert isinstance(ev, AutoEvidence)
        assert ev.source == EvidenceSource.CONFIG_SNAPSHOTS
        payload = json.loads(ev.raw_content)
        assert "env_config" in payload

    def test_collect_from_access_matrix_returns_evidence(self, tmp_collector):
        ev = tmp_collector.collect_from_access_matrix(ORG, CONTROL, FRAMEWORK)
        assert isinstance(ev, AutoEvidence)
        assert ev.source == EvidenceSource.ACCESS_REVIEWS

    def test_collect_from_encryption_status_returns_evidence(self, tmp_collector):
        ev = tmp_collector.collect_from_encryption_status(ORG, FRAMEWORK)
        assert isinstance(ev, AutoEvidence)
        assert ev.source == EvidenceSource.ENCRYPTION_STATUS
        payload = json.loads(ev.raw_content)
        assert "ssl_version" in payload
        assert "sha256_available" in payload
        assert payload["sha256_available"] is True

    def test_collect_from_backup_records_returns_evidence(self, tmp_collector):
        ev = tmp_collector.collect_from_backup_records(ORG, FRAMEWORK)
        assert isinstance(ev, AutoEvidence)
        assert ev.source == EvidenceSource.BACKUP_RECORDS

    def test_collect_from_incidents_returns_evidence(self, tmp_collector):
        ev = tmp_collector.collect_from_incidents(ORG, CONTROL, FRAMEWORK)
        assert isinstance(ev, AutoEvidence)
        assert ev.source == EvidenceSource.INCIDENT_REPORTS

    def test_evidence_has_expires_at(self, tmp_collector):
        ev = tmp_collector.collect_from_audit_logs(ORG, CONTROL, FRAMEWORK)
        assert ev.expires_at is not None
        assert ev.expires_at > ev.collected_at

    def test_evidence_has_non_empty_summary(self, tmp_collector):
        ev = tmp_collector.collect_from_audit_logs(ORG, CONTROL, FRAMEWORK)
        assert ev.summary
        assert len(ev.summary) > 0

    def test_evidence_content_hash_is_hex(self, tmp_collector):
        ev = tmp_collector.collect_from_config(ORG, CONTROL, FRAMEWORK)
        assert len(ev.content_hash) == 64  # SHA-256 hex = 64 chars
        int(ev.content_hash, 16)  # raises ValueError if not hex


# ===========================================================================
# 6. Bulk collection
# ===========================================================================


class TestAutoCollectAll:
    def test_auto_collect_all_soc2_returns_results(self, tmp_collector):
        results = tmp_collector.auto_collect_all(ORG, "SOC2")
        assert len(results) > 0
        assert all(isinstance(r, AutoEvidence) for r in results)

    def test_auto_collect_all_pci_returns_results(self, tmp_collector):
        results = tmp_collector.auto_collect_all(ORG, "PCI")
        assert len(results) > 0

    def test_auto_collect_all_hipaa_returns_results(self, tmp_collector):
        results = tmp_collector.auto_collect_all(ORG, "HIPAA")
        assert len(results) > 0

    def test_auto_collect_all_unknown_framework_returns_empty(self, tmp_collector):
        results = tmp_collector.auto_collect_all(ORG, "UNKNOWN_FW_XYZ")
        assert results == []

    def test_auto_collect_all_covers_framework_controls(self, tmp_collector):
        results = tmp_collector.auto_collect_all(ORG, "SOC2")
        collected_controls = {r.control_id for r in results}
        expected_controls = set(FRAMEWORK_CONTROL_MAP["SOC2"].keys())
        # At least some controls should be covered
        assert len(collected_controls & expected_controls) > 0


# ===========================================================================
# 7. Hash verification
# ===========================================================================


class TestVerifyEvidence:
    def test_verify_valid_evidence(self, tmp_collector):
        ev = tmp_collector.collect_from_audit_logs(ORG, CONTROL, FRAMEWORK)
        valid, msg = tmp_collector.verify_evidence(ev.id)
        assert valid is True
        assert "OK" in msg

    def test_verify_nonexistent_evidence(self, tmp_collector):
        valid, msg = tmp_collector.verify_evidence(str(uuid.uuid4()))
        assert valid is False
        assert "not found" in msg

    def test_verify_sets_verified_flag(self, tmp_collector):
        ev = tmp_collector.collect_from_audit_logs(ORG, CONTROL, FRAMEWORK)
        assert ev.verified is False
        tmp_collector.verify_evidence(ev.id)
        updated = tmp_collector.get_evidence(ev.id)
        assert updated is not None
        assert updated.verified is True

    def test_verify_tampered_evidence_fails(self, tmp_collector):
        ev = tmp_collector.collect_from_config(ORG, CONTROL, FRAMEWORK)
        # Tamper with the hash directly in DB
        import sqlite3
        conn = sqlite3.connect(str(tmp_collector.db_path))
        conn.execute(
            "UPDATE auto_evidence SET content_hash = 'tampered000' WHERE id = ?", (ev.id,)
        )
        conn.commit()
        conn.close()
        valid, msg = tmp_collector.verify_evidence(ev.id)
        assert valid is False
        assert "mismatch" in msg.lower()


# ===========================================================================
# 8. Coverage report
# ===========================================================================


class TestEvidenceCoverage:
    def test_coverage_zero_initially(self, tmp_collector):
        cov = tmp_collector.get_evidence_coverage("brand-new-org", "SOC2")
        assert cov.covered_controls == 0
        assert cov.coverage_pct == 0.0
        assert len(cov.missing_controls) == len(FRAMEWORK_CONTROL_MAP["SOC2"])

    def test_coverage_increases_after_collection(self, tmp_collector):
        tmp_collector.collect_from_audit_logs(ORG, "CC6.1", "SOC2")
        cov = tmp_collector.get_evidence_coverage(ORG, "SOC2")
        assert cov.covered_controls >= 1
        assert "CC6.1" in cov.fresh_controls

    def test_coverage_model_fields(self, tmp_collector):
        cov = tmp_collector.get_evidence_coverage(ORG, "SOC2")
        assert isinstance(cov, EvidenceCoverage)
        assert cov.framework == "SOC2"
        assert cov.org_id == ORG
        assert isinstance(cov.total_controls, int)
        assert isinstance(cov.coverage_pct, float)

    def test_full_coverage_after_bulk_collect(self, tmp_collector):
        tmp_collector.auto_collect_all(ORG, "SOC2")
        cov = tmp_collector.get_evidence_coverage(ORG, "SOC2")
        assert cov.covered_controls == cov.total_controls
        assert cov.coverage_pct == 100.0


# ===========================================================================
# 9. _sha256 helper
# ===========================================================================


class TestSha256Helper:
    def test_deterministic(self):
        data = {"key": "value", "num": 42}
        assert _sha256(data) == _sha256(data)

    def test_different_data_different_hash(self):
        assert _sha256({"a": 1}) != _sha256({"a": 2})

    def test_returns_64_char_hex(self):
        h = _sha256({"x": "y"})
        assert len(h) == 64
        int(h, 16)


# ===========================================================================
# 10. Router endpoints (FastAPI TestClient)
# ===========================================================================


class TestAutoEvidenceRouter:
    @pytest.fixture(autouse=True)
    def setup_app(self, tmp_path):
        """Set up a minimal FastAPI app with the auto_evidence_router mounted."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from apps.api.auto_evidence_router import router

        # Patch get_collector to use a temp DB
        collector = AutoEvidenceCollector(db_path=str(tmp_path / "router_test.db"))

        import core.auto_evidence as ae_mod
        self._orig = ae_mod._collector
        ae_mod._collector = collector

        app = FastAPI()
        app.include_router(router)
        self.client = TestClient(app)
        yield
        ae_mod._collector = self._orig

    def test_list_frameworks(self):
        resp = self.client.get("/api/v1/auto-evidence/frameworks")
        assert resp.status_code == 200
        data = resp.json()
        fw_names = [d["framework"] for d in data]
        assert "SOC2" in fw_names
        assert "PCI" in fw_names
        assert "HIPAA" in fw_names

    def test_collect_audit_logs(self):
        resp = self.client.post(
            "/api/v1/auto-evidence/collect/audit-logs",
            json={"org_id": ORG, "control_id": CONTROL, "framework": "SOC2"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["source"] == "audit_trail"
        assert data["org_id"] == ORG

    def test_collect_scan_results(self):
        resp = self.client.post(
            "/api/v1/auto-evidence/collect/scan-results",
            json={"org_id": ORG, "control_id": CONTROL, "framework": "SOC2"},
        )
        assert resp.status_code == 200
        assert resp.json()["source"] == "scan_results"

    def test_collect_config(self):
        resp = self.client.post(
            "/api/v1/auto-evidence/collect/config",
            json={"org_id": ORG, "control_id": CONTROL, "framework": "SOC2"},
        )
        assert resp.status_code == 200
        assert resp.json()["source"] == "config_snapshots"

    def test_collect_access_matrix(self):
        resp = self.client.post(
            "/api/v1/auto-evidence/collect/access-matrix",
            json={"org_id": ORG, "control_id": CONTROL, "framework": "SOC2"},
        )
        assert resp.status_code == 200
        assert resp.json()["source"] == "access_reviews"

    def test_collect_encryption_status(self):
        resp = self.client.post(
            "/api/v1/auto-evidence/collect/encryption-status",
            params={"org_id": ORG, "framework": "SOC2"},
        )
        assert resp.status_code == 200
        assert resp.json()["source"] == "encryption_status"

    def test_collect_backup_records(self):
        resp = self.client.post(
            "/api/v1/auto-evidence/collect/backup-records",
            params={"org_id": ORG, "framework": "SOC2"},
        )
        assert resp.status_code == 200
        assert resp.json()["source"] == "backup_records"

    def test_collect_incidents(self):
        resp = self.client.post(
            "/api/v1/auto-evidence/collect/incidents",
            json={"org_id": ORG, "control_id": CONTROL, "framework": "SOC2"},
        )
        assert resp.status_code == 200
        assert resp.json()["source"] == "incident_reports"

    def test_collect_all_bulk(self):
        resp = self.client.post(
            "/api/v1/auto-evidence/collect/all",
            json={"org_id": ORG, "framework": "SOC2"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_collect_all_unknown_framework_returns_400(self):
        resp = self.client.post(
            "/api/v1/auto-evidence/collect/all",
            json={"org_id": ORG, "framework": "UNKNOWN_XYZ"},
        )
        assert resp.status_code == 400

    def test_verify_evidence(self):
        # First collect
        ev_resp = self.client.post(
            "/api/v1/auto-evidence/collect/config",
            json={"org_id": ORG, "control_id": CONTROL, "framework": "SOC2"},
        )
        ev_id = ev_resp.json()["id"]
        # Now verify
        resp = self.client.post(f"/api/v1/auto-evidence/verify/{ev_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["evidence_id"] == ev_id

    def test_verify_nonexistent_returns_200_invalid(self):
        resp = self.client.post(f"/api/v1/auto-evidence/verify/{uuid.uuid4()}")
        assert resp.status_code == 200
        assert resp.json()["valid"] is False

    def test_coverage_endpoint(self):
        # Collect some evidence first
        self.client.post(
            "/api/v1/auto-evidence/collect/audit-logs",
            json={"org_id": ORG, "control_id": CONTROL, "framework": "SOC2"},
        )
        resp = self.client.get(
            "/api/v1/auto-evidence/coverage",
            params={"org_id": ORG, "framework": "SOC2"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "SOC2"
        assert data["org_id"] == ORG
        assert data["covered_controls"] >= 1

    def test_list_evidence_endpoint(self):
        self.client.post(
            "/api/v1/auto-evidence/collect/config",
            json={"org_id": ORG, "control_id": CONTROL, "framework": "SOC2"},
        )
        resp = self.client.get(
            "/api/v1/auto-evidence/",
            params={"org_id": ORG},
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)
        assert len(resp.json()) >= 1

    def test_get_evidence_by_id(self):
        ev_resp = self.client.post(
            "/api/v1/auto-evidence/collect/incidents",
            json={"org_id": ORG, "control_id": CONTROL, "framework": "SOC2"},
        )
        ev_id = ev_resp.json()["id"]
        resp = self.client.get(f"/api/v1/auto-evidence/{ev_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == ev_id

    def test_get_nonexistent_evidence_returns_404(self):
        resp = self.client.get(f"/api/v1/auto-evidence/{uuid.uuid4()}")
        assert resp.status_code == 404
