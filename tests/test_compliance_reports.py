"""
Tests for Compliance Reports module and router.

Covers:
- ComplianceReport Pydantic model
- ComplianceReportGenerator: generate, export (all formats), list, get, delete
- Router endpoints via FastAPI TestClient
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).parent.parent
for _p in [str(_ROOT), str(_ROOT / "suite-core"), str(_ROOT / "suite-api")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-minimum-32-chars-long")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.compliance_reports import (  # noqa: E402
    SUPPORTED_FRAMEWORKS,
    ComplianceReport,
    ComplianceReportGenerator,
)


# ===========================================================================
# Helpers
# ===========================================================================


def _gen(tmp_path) -> ComplianceReportGenerator:
    return ComplianceReportGenerator(db_path=str(tmp_path / "test_cr.db"))


# ===========================================================================
# MODEL TESTS (7)
# ===========================================================================


class TestComplianceReportModel:
    def test_default_id_is_uuid(self):
        r = ComplianceReport(framework="SOC2", title="Test")
        assert len(r.id) == 36

    def test_unique_ids(self):
        a = ComplianceReport(framework="PCI", title="A")
        b = ComplianceReport(framework="PCI", title="B")
        assert a.id != b.id

    def test_default_timestamp(self):
        r = ComplianceReport(framework="NIST", title="T")
        assert r.generated_at.tzinfo is not None

    def test_score_default_zero(self):
        r = ComplianceReport(framework="GDPR", title="T")
        assert r.score == 0.0

    def test_gaps_count_default_zero(self):
        r = ComplianceReport(framework="CIS", title="T")
        assert r.gaps_count == 0

    def test_sections_default_empty(self):
        r = ComplianceReport(framework="HIPAA", title="T")
        assert r.sections == []

    def test_org_id_optional(self):
        r = ComplianceReport(framework="ISO27001", title="T")
        assert r.org_id is None


# ===========================================================================
# GENERATOR TESTS (28)
# ===========================================================================


class TestComplianceReportGenerator:

    # --- generate_report ---

    def test_generate_soc2(self, tmp_path):
        gen = _gen(tmp_path)
        r = gen.generate_report("SOC2", org_id="org-1")
        assert r.framework == "SOC2"
        assert r.score >= 0.0
        assert len(r.sections) > 0

    def test_generate_pci(self, tmp_path):
        r = _gen(tmp_path).generate_report("PCI")
        assert r.framework == "PCI"
        assert len(r.sections) == 12

    def test_generate_hipaa(self, tmp_path):
        r = _gen(tmp_path).generate_report("HIPAA")
        assert r.framework == "HIPAA"
        assert len(r.sections) == 5

    def test_generate_iso27001(self, tmp_path):
        r = _gen(tmp_path).generate_report("ISO27001")
        assert r.framework == "ISO27001"
        assert len(r.sections) == 14

    def test_generate_nist(self, tmp_path):
        r = _gen(tmp_path).generate_report("NIST")
        assert r.framework == "NIST"
        assert len(r.sections) == 5

    def test_generate_gdpr(self, tmp_path):
        r = _gen(tmp_path).generate_report("GDPR")
        assert r.framework == "GDPR"
        assert len(r.sections) == 10

    def test_generate_cis(self, tmp_path):
        r = _gen(tmp_path).generate_report("CIS")
        assert r.framework == "CIS"
        assert len(r.sections) == 18

    def test_generate_case_insensitive(self, tmp_path):
        r = _gen(tmp_path).generate_report("soc2")
        assert r.framework == "SOC2"

    def test_generate_invalid_framework_raises(self, tmp_path):
        with pytest.raises(ValueError, match="Unsupported"):
            _gen(tmp_path).generate_report("UNKNOWN")

    def test_generate_persists_report(self, tmp_path):
        gen = _gen(tmp_path)
        r = gen.generate_report("NIST")
        fetched = gen.get_report(r.id)
        assert fetched is not None
        assert fetched.id == r.id

    def test_generate_score_between_0_and_100(self, tmp_path):
        r = _gen(tmp_path).generate_report("SOC2")
        assert 0.0 <= r.score <= 100.0

    def test_generate_with_findings_context(self, tmp_path):
        ctx = {"open_findings": 10, "critical_findings": 5}
        r = _gen(tmp_path).generate_report("PCI", findings_context=ctx)
        assert r.gaps_count >= 0

    def test_generate_custom_title(self, tmp_path):
        r = _gen(tmp_path).generate_report("SOC2", title="Q1 2026 SOC2 Audit")
        assert r.title == "Q1 2026 SOC2 Audit"

    def test_generate_default_title(self, tmp_path):
        r = _gen(tmp_path).generate_report("GDPR")
        assert "GDPR" in r.title

    def test_generate_org_id_stored(self, tmp_path):
        r = _gen(tmp_path).generate_report("CIS", org_id="acme-corp")
        assert r.org_id == "acme-corp"

    # --- get_report / list_reports / delete ---

    def test_get_report_not_found_returns_none(self, tmp_path):
        result = _gen(tmp_path).get_report("nonexistent-id")
        assert result is None

    def test_list_reports_empty(self, tmp_path):
        result = _gen(tmp_path).list_reports()
        assert result == []

    def test_list_reports_returns_all(self, tmp_path):
        gen = _gen(tmp_path)
        gen.generate_report("SOC2")
        gen.generate_report("PCI")
        reports = gen.list_reports()
        assert len(reports) == 2

    def test_list_reports_framework_filter(self, tmp_path):
        gen = _gen(tmp_path)
        gen.generate_report("SOC2")
        gen.generate_report("PCI")
        soc2_only = gen.list_reports(framework="SOC2")
        assert len(soc2_only) == 1
        assert soc2_only[0].framework == "SOC2"

    def test_list_reports_org_filter(self, tmp_path):
        gen = _gen(tmp_path)
        gen.generate_report("NIST", org_id="org-A")
        gen.generate_report("NIST", org_id="org-B")
        result = gen.list_reports(org_id="org-A")
        assert all(r.org_id == "org-A" for r in result)

    def test_delete_report_returns_true(self, tmp_path):
        gen = _gen(tmp_path)
        r = gen.generate_report("SOC2")
        assert gen.delete_report(r.id) is True

    def test_delete_report_removes_it(self, tmp_path):
        gen = _gen(tmp_path)
        r = gen.generate_report("SOC2")
        gen.delete_report(r.id)
        assert gen.get_report(r.id) is None

    def test_delete_nonexistent_returns_false(self, tmp_path):
        assert _gen(tmp_path).delete_report("bad-id") is False

    # --- export ---

    def test_export_json(self, tmp_path):
        gen = _gen(tmp_path)
        r = gen.generate_report("SOC2")
        out = gen.export_report(r.id, fmt="json")
        import json
        data = json.loads(out)
        assert data["framework"] == "SOC2"

    def test_export_html(self, tmp_path):
        gen = _gen(tmp_path)
        r = gen.generate_report("PCI")
        out = gen.export_report(r.id, fmt="html")
        assert "<html>" in out.lower() or "<!doctype" in out.lower()
        assert "PCI" in out

    def test_export_csv(self, tmp_path):
        gen = _gen(tmp_path)
        r = gen.generate_report("NIST")
        out = gen.export_report(r.id, fmt="csv")
        assert "control_id" in out
        assert "status" in out

    def test_export_markdown(self, tmp_path):
        gen = _gen(tmp_path)
        r = gen.generate_report("GDPR")
        out = gen.export_report(r.id, fmt="markdown")
        assert "# " in out
        assert "GDPR" in out

    def test_export_invalid_format_raises(self, tmp_path):
        gen = _gen(tmp_path)
        r = gen.generate_report("CIS")
        with pytest.raises(ValueError, match="Unsupported export format"):
            gen.export_report(r.id, fmt="pdf")

    def test_export_not_found_raises(self, tmp_path):
        with pytest.raises(ValueError, match="not found"):
            _gen(tmp_path).export_report("no-such-id", fmt="json")


# ===========================================================================
# ROUTER TESTS (via TestClient)
# ===========================================================================


class TestComplianceReportsRouter:
    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        # Replace module-level generator in router
        import apps.api.compliance_reports_router as _router_mod
        mock_gen = _gen(tmp_path)
        _router_mod._generator = mock_gen
        self._gen = mock_gen

        from apps.api.compliance_reports_router import router
        app = FastAPI()
        app.include_router(router)
        self.client = TestClient(app, raise_server_exceptions=True)

    def test_list_frameworks(self):
        resp = self.client.get("/api/v1/compliance-reports/frameworks")
        assert resp.status_code == 200
        data = resp.json()
        assert "SOC2" in data
        assert "PCI" in data

    def test_generate_report_201(self):
        resp = self.client.post(
            "/api/v1/compliance-reports/generate",
            json={"framework": "SOC2"},
        )
        assert resp.status_code == 201

    def test_generate_returns_id(self):
        resp = self.client.post(
            "/api/v1/compliance-reports/generate",
            json={"framework": "NIST"},
        )
        assert "id" in resp.json()

    def test_generate_invalid_framework(self):
        resp = self.client.post(
            "/api/v1/compliance-reports/generate",
            json={"framework": "FAKE"},
        )
        assert resp.status_code == 400

    def test_list_reports_empty(self):
        resp = self.client.get("/api/v1/compliance-reports/")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_reports_after_generate(self):
        self._gen.generate_report("SOC2", org_id="default")
        resp = self.client.get("/api/v1/compliance-reports/")
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    def test_get_report_not_found(self):
        resp = self.client.get("/api/v1/compliance-reports/no-such-id")
        assert resp.status_code == 404

    def test_get_report_found(self):
        r = self._gen.generate_report("PCI", org_id="default")
        resp = self.client.get(f"/api/v1/compliance-reports/{r.id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == r.id

    def test_delete_report_204(self):
        r = self._gen.generate_report("GDPR", org_id="default")
        resp = self.client.delete(f"/api/v1/compliance-reports/{r.id}")
        assert resp.status_code == 204

    def test_delete_report_not_found(self):
        resp = self.client.delete("/api/v1/compliance-reports/no-such-id")
        assert resp.status_code == 404

    def test_export_json(self):
        r = self._gen.generate_report("CIS", org_id="default")
        resp = self.client.get(f"/api/v1/compliance-reports/{r.id}/export/json")
        assert resp.status_code == 200
        assert "CIS" in resp.text

    def test_export_html(self):
        r = self._gen.generate_report("SOC2", org_id="default")
        resp = self.client.get(f"/api/v1/compliance-reports/{r.id}/export/html")
        assert resp.status_code == 200
        assert "<" in resp.text

    def test_export_csv(self):
        r = self._gen.generate_report("HIPAA", org_id="default")
        resp = self.client.get(f"/api/v1/compliance-reports/{r.id}/export/csv")
        assert resp.status_code == 200
        assert "control_id" in resp.text

    def test_export_markdown(self):
        r = self._gen.generate_report("ISO27001", org_id="default")
        resp = self.client.get(f"/api/v1/compliance-reports/{r.id}/export/markdown")
        assert resp.status_code == 200
        assert "#" in resp.text

    def test_get_gaps(self):
        r = self._gen.generate_report(
            "PCI",
            org_id="default",
            findings_context={"open_findings": 5, "critical_findings": 3},
        )
        resp = self.client.get(f"/api/v1/compliance-reports/{r.id}/gaps")
        assert resp.status_code == 200
        data = resp.json()
        assert "gaps" in data
        assert data["framework"] == "PCI"

    def test_get_gaps_not_found(self):
        resp = self.client.get("/api/v1/compliance-reports/bad-id/gaps")
        assert resp.status_code == 404

    def test_generate_all_frameworks(self):
        for fw in SUPPORTED_FRAMEWORKS:
            resp = self.client.post(
                "/api/v1/compliance-reports/generate",
                json={"framework": fw},
            )
            assert resp.status_code == 201, f"Failed for {fw}: {resp.text}"

    def test_list_framework_filter(self):
        self._gen.generate_report("SOC2", org_id="default")
        self._gen.generate_report("PCI", org_id="default")
        resp = self.client.get("/api/v1/compliance-reports/?framework=SOC2")
        assert resp.status_code == 200
        data = resp.json()
        assert all(r["framework"] == "SOC2" for r in data)
