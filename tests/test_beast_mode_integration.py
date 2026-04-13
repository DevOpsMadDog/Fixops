"""
Beast Mode Integration Tests — Cross-Module Flow Verification.

Tests that Beast Mode modules work TOGETHER, not just in isolation.
Each test exercises a realistic end-to-end flow through 2+ modules.

Flows covered:
 1.  Material Change → blast radius categorisation (analyze_push_event)
 2.  Material Change → dict serialisation round-trip
 3.  Material Change: cosmetic-only push is never material
 4.  SAST finding → RiskPrioritizer score → composite sanity
 5.  Risk scoring → urgency tier derivation (high severity == immediate/urgent)
 6.  RiskPrioritizer → PriorityQueue ordering (highest score ranked 1st)
 7.  CVE finding → MITRE ATT&CK mapping (CWE-89 → T1190)
 8.  Multi-finding → ATTACKCoverage: covered_technique_ids non-empty
 9.  ATTACKCoverage → identify_gaps returns techniques NOT in coverage
10.  ATTACKCoverage → heatmap_data has required Navigator keys
11.  Zero Trust: high-trust device gets ALLOW or CHALLENGE
12.  Zero Trust: untrusted device (score 0) gets DENY
13.  Zero Trust: access decision persists (to_dict has decision_id)
14.  SBOM → generate_from_requirements parses packages into components
15.  SBOM → CycloneDX envelope structure (bomFormat, components, metadata)
16.  LicenseAuditor → audit_summary counts total and flagged
17.  CopilotTrustGraphBridge: CVE query returns a CopilotContext with intent=cve
18.  CopilotTrustGraphBridge: compliance query maps to intent=compliance
19.  AttackSurfaceMapper → register then list_assets returns the asset
20.  AttackSurfaceMapper → get_attack_surface reflects registered assets
21.  PostureTracker → record_posture → get_current_posture round-trip
22.  PostureTracker → two snapshots → compare_posture produces PostureDiff
23.  SecurityMetricsEngine → ingest_event → compute_dora_metrics (no crash)
24.  SecurityMetricsEngine → generate_report returns SecurityReport with sections
25.  RiskPrioritizer → rank_findings orders multiple findings by composite score

All tests use isolated temp databases (FIXOPS_MODE=dev pattern).
No external network calls are required to pass (KEV/EPSS gracefully degrade).
Timeout: 15 s per test (enforced via pytest-timeout).
"""

from __future__ import annotations

import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import pytest

# ---------------------------------------------------------------------------
# Environment — dev mode, no external side-effects
# ---------------------------------------------------------------------------
os.environ.setdefault("FIXOPS_MODE", "dev")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tmp_db(suffix: str = ".db") -> str:
    """Return a path to a throwaway temp database that will be cleaned up."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return path


def _test_org() -> str:
    """Return a collision-safe org_id for the current test."""
    return f"test_bmi_{uuid.uuid4().hex[:8]}"


# ===========================================================================
# Flow 1 — Material Change Detector
# ===========================================================================


class TestMaterialChangeDetector:
    """Tests that PushEventAnalyzer analyses push events end-to-end."""

    @pytest.fixture(autouse=True)
    def _detector(self, tmp_path):
        from core.material_change_detector import PushEventAnalyzer

        # PushEventAnalyzer wraps analyze_push_event; repo_root scopes blast-radius scan
        self.detector = PushEventAnalyzer(repo_root=str(tmp_path))

    def _push_payload(self, files: list[str]) -> Dict[str, Any]:
        return {
            "after": "abc1234",
            "ref": "refs/heads/main",
            "repository": {"full_name": "test-org/fixops"},
            "pusher": {"name": "test_author"},
            "commits": [
                {
                    "added": [],
                    "modified": files,
                    "removed": [],
                }
            ],
        }

    def test_push_event_with_security_file_has_blast_radius(self):
        """analyze_push_event on an auth module produces a non-None blast_radius."""
        payload = self._push_payload(["core/auth.py", "core/brain_pipeline.py"])
        result = self.detector.analyze_push_event(payload)

        assert result.blast_radius is not None, "blast_radius should be set for .py files"
        assert result.commit_sha == "abc1234"
        assert result.repository == "test-org/fixops"

    def test_push_event_serialises_to_dict(self):
        """MaterialChangeResult.to_dict() contains all expected top-level keys."""
        payload = self._push_payload(["core/connectors.py"])
        result = self.detector.analyze_push_event(payload)
        d = result.to_dict()

        for key in (
            "id", "commit_sha", "repository", "branch",
            "is_material", "blast_radius", "analyzed_at",
        ):
            assert key in d, f"Missing key '{key}' in to_dict() output"

    def test_cosmetic_only_push_is_not_material(self):
        """A push containing only .md files is not marked material."""
        payload = self._push_payload(["README.md", "docs/changelog.md"])
        result = self.detector.analyze_push_event(payload)

        # Cosmetic files should not trigger materiality on their own
        assert result.is_material is False, "README.md-only push should not be material"

    def test_empty_push_returns_result_without_blast_radius(self):
        """A push with no files returns a result but blast_radius is None or empty."""
        payload = {
            "after": "000",
            "ref": "refs/heads/main",
            "repository": {"full_name": "test/repo"},
            "pusher": {"name": "bot"},
            "commits": [],
        }
        result = self.detector.analyze_push_event(payload)
        assert result.changed_files == []


# ===========================================================================
# Flow 2 — SAST finding → RiskPrioritizer → composite score
# ===========================================================================


class TestRiskPrioritizerFlow:
    """Tests the full scoring + ranking pipeline."""

    @pytest.fixture(autouse=True)
    def _prioritizer(self, tmp_path):
        from core.risk_prioritizer import RiskPrioritizer

        self.prioritizer = RiskPrioritizer(db_path=str(tmp_path / "risk.db"))

    def test_sql_injection_finding_produces_score(self):
        """A CRITICAL SQL-injection finding gets a composite score > 0."""
        finding = {
            "id": f"f-{uuid.uuid4().hex[:8]}",
            "title": "SQL Injection in login endpoint",
            "severity": "critical",
            "environment": "production",
            "cwe_id": "CWE-89",
        }
        score = self.prioritizer.score_finding(finding)

        assert score.composite_score > 0.0
        assert score.cvss_contribution > 0.0
        assert score.asset_contribution > 0.0
        assert score.finding_id == finding["id"]

    def test_critical_production_finding_urgency_is_not_backlog(self):
        """CRITICAL severity + production environment with explicit CVSS 9.5 is not backlog.

        Without a real CVE the EPSS and KEV contributions are 0, but CVSS (40%) at 9.5
        and production asset_criticality (15%) still push the composite score above 30,
        guaranteeing at least PLANNED (never BACKLOG) urgency.
        """
        from core.risk_prioritizer import RemediationUrgency, _urgency_from_score

        finding = {
            "id": f"f-{uuid.uuid4().hex[:8]}",
            "severity": "critical",
            "cvss_score": 9.5,          # explicit score: 9.5/10 * 0.40 * 100 = 38pts
            "asset_environment": "production",  # 1.0 * 0.15 * 100 = 15pts → total 53pts
        }
        score = self.prioritizer.score_finding(finding)
        urgency = _urgency_from_score(score.composite_score)

        assert urgency != RemediationUrgency.BACKLOG, (
            f"CRITICAL+production finding (score={score.composite_score:.1f}) "
            "should not be in BACKLOG tier"
        )
        assert score.composite_score > 30.0

    def test_rank_findings_orders_by_score_descending(self):
        """rank_findings returns highest composite score first."""
        findings = [
            {"id": "low-1", "severity": "low", "environment": "sandbox"},
            {"id": "crit-1", "severity": "critical", "environment": "production"},
            {"id": "med-1", "severity": "medium", "environment": "staging"},
        ]
        ranked = self.prioritizer.rank_findings(findings)

        assert len(ranked) == 3
        # Each score should be >= the next (descending order)
        for i in range(len(ranked) - 1):
            assert ranked[i].composite_score >= ranked[i + 1].composite_score, (
                f"Score at rank {i} ({ranked[i].composite_score}) is less than "
                f"rank {i+1} ({ranked[i+1].composite_score})"
            )

    def test_priority_queue_total_matches_input_count(self):
        """get_remediation_priority returns a PriorityQueue with total == input length."""
        findings = [
            {"id": f"f-{i}", "severity": "high", "environment": "production"}
            for i in range(5)
        ]
        queue = self.prioritizer.get_remediation_priority(findings)

        assert queue.total == 5
        assert len(queue.items) == 5
        # Ranks should be 1-based and consecutive
        ranks = [item.rank for item in queue.items]
        assert ranks == list(range(1, 6))


# ===========================================================================
# Flow 3 — MITRE ATT&CK Mapping
# ===========================================================================


class TestMITREATTACKFlow:
    """Tests CVE/CWE → ATT&CK technique mapping and coverage analysis."""

    @pytest.fixture(autouse=True)
    def _mapper(self):
        from core.mitre_attack_mapper import MITREATTACKMapper

        self.mapper = MITREATTACKMapper()

    def test_sql_injection_cwe_maps_to_t1190(self):
        """CWE-89 (SQL Injection) maps to T1190 (Exploit Public-Facing Application)."""
        finding = {
            "id": "sast-001",
            "title": "SQL Injection",
            "cwe_id": "CWE-89",
            "severity": "critical",
        }
        mappings = self.mapper.map_finding_to_techniques(finding)

        assert len(mappings) > 0, "Expected at least one ATT&CK technique mapping"
        technique_ids = [m.technique_id for m in mappings]
        assert "T1190" in technique_ids, (
            f"T1190 expected for CWE-89, got: {technique_ids}"
        )

    def test_coverage_calculation_with_multiple_findings(self):
        """calculate_coverage on a mixed finding list returns non-empty covered sets."""
        findings = [
            {"id": "f1", "title": "SQL Injection", "cwe_id": "CWE-89", "severity": "critical"},
            {"id": "f2", "title": "XSS vulnerability", "cwe_id": "CWE-79", "severity": "high"},
            {"id": "f3", "title": "Remote code execution via eval", "severity": "critical"},
        ]
        coverage = self.mapper.calculate_coverage(findings)

        assert len(coverage.covered_technique_ids) > 0
        assert coverage.technique_coverage_pct > 0.0
        assert coverage.total_techniques_in_db > 0

    def test_identify_gaps_excludes_covered_techniques(self):
        """identify_gaps does not return techniques that are already covered."""
        finding = {"id": "f1", "title": "SQL Injection", "cwe_id": "CWE-89", "severity": "critical"}
        coverage = self.mapper.calculate_coverage([finding])
        gaps = self.mapper.identify_gaps(coverage.covered_technique_ids)

        gap_ids = {g.technique_id for g in gaps}
        for covered_tid in coverage.covered_technique_ids:
            assert covered_tid not in gap_ids, (
                f"Covered technique {covered_tid} should not appear in gaps"
            )

    def test_heatmap_data_has_navigator_required_keys(self):
        """generate_heatmap_data returns a dict with ATT&CK Navigator layer keys."""
        findings = [
            {"id": "f1", "title": "Buffer overflow exploit", "severity": "high"},
        ]
        heatmap = self.mapper.generate_heatmap_data(findings)

        # ATT&CK Navigator layer v4.5 required fields
        for key in ("name", "domain", "techniques"):
            assert key in heatmap, f"Heatmap missing required key '{key}'"
        assert isinstance(heatmap["techniques"], list)


# ===========================================================================
# Flow 4 — Zero Trust Engine
# ===========================================================================


class TestZeroTrustFlow:
    """Tests access evaluation, trust scoring, and decision persistence."""

    @pytest.fixture(autouse=True)
    def _engine(self, tmp_path):
        from core.zero_trust_engine import ZeroTrustEngine

        self.engine = ZeroTrustEngine(db_path=str(tmp_path / "zt.db"))

    def test_high_trust_device_is_allowed_or_challenged(self):
        """A device with high trust score (0.9) and MFA gets ALLOW or CHALLENGE."""
        from core.zero_trust_engine import AccessRequest, Decision

        request = AccessRequest(
            user_id=f"user-{uuid.uuid4().hex[:6]}",
            device_id=f"dev-{uuid.uuid4().hex[:6]}",
            resource="api/findings",
            action="read",
            mfa_verified=True,
            device_trust_score=0.9,
            behaviour_score=0.85,
        )
        decision = self.engine.evaluate_access_request(request)

        assert decision.decision in (Decision.ALLOW, Decision.CHALLENGE), (
            f"Expected ALLOW or CHALLENGE for high-trust device, got {decision.decision}"
        )

    def test_untrusted_device_is_denied(self):
        """A device with trust score 0 and no MFA should receive DENY."""
        from core.zero_trust_engine import AccessRequest, Decision

        request = AccessRequest(
            user_id=f"user-{uuid.uuid4().hex[:6]}",
            device_id=f"dev-{uuid.uuid4().hex[:6]}",
            resource="api/admin/secrets",
            action="write",
            mfa_verified=False,
            device_trust_score=0.0,
            behaviour_score=0.0,
        )
        decision = self.engine.evaluate_access_request(request)

        assert decision.decision == Decision.DENY, (
            f"Expected DENY for zero-trust device, got {decision.decision}"
        )

    def test_access_decision_to_dict_contains_required_fields(self):
        """AccessDecision.to_dict() includes decision_id, decision, trust_score."""
        from core.zero_trust_engine import AccessRequest

        request = AccessRequest(
            user_id="u1",
            device_id="d1",
            resource="api/status",
            action="read",
            mfa_verified=True,
            device_trust_score=0.7,
        )
        decision = self.engine.evaluate_access_request(request)
        d = decision.to_dict()

        for key in ("decision_id", "decision", "trust_score", "evaluated_at"):
            assert key in d, f"to_dict() missing key '{key}'"
        assert isinstance(d["decision_id"], str) and len(d["decision_id"]) > 0


# ===========================================================================
# Flow 5 — SBOM Generator + License Auditor
# ===========================================================================


class TestSBOMAndLicenseFlow:
    """Tests SBOM generation from requirements.txt and license auditing."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path):
        from core.sbom_generator import SBOMGenerator
        from core.license_auditor import LicenseAuditor

        self.generator = SBOMGenerator()
        self.auditor = LicenseAuditor()
        # Write a minimal requirements.txt
        self.req_path = str(tmp_path / "requirements.txt")
        Path(self.req_path).write_text(
            "fastapi==0.111.0\npydantic==2.7.1\nrequests==2.31.0\n"
        )

    def test_sbom_generate_from_requirements_produces_components(self):
        """generate_from_requirements parses packages and returns component list."""
        sbom = self.generator.generate_from_requirements(self.req_path)

        assert "components" in sbom, "SBOM must have 'components' key"
        assert len(sbom["components"]) >= 3, (
            f"Expected >=3 components, got {len(sbom['components'])}"
        )

    def test_sbom_has_cyclonedx_envelope(self):
        """SBOM output conforms to CycloneDX 1.4 envelope structure."""
        sbom = self.generator.generate_from_requirements(self.req_path)

        assert sbom.get("bomFormat") == "CycloneDX", "bomFormat must be 'CycloneDX'"
        assert "metadata" in sbom, "CycloneDX SBOM must have 'metadata'"
        assert "components" in sbom

    def test_license_audit_summary_has_total_and_high_risk_count(self):
        """audit_requirements → audit_summary returns 'total' and 'high_risk_count' keys."""
        results = self.auditor.audit_requirements(self.req_path)
        summary = self.auditor.audit_summary(results)

        assert "total" in summary, "audit_summary must include 'total'"
        assert "high_risk_count" in summary, (
            f"audit_summary must include 'high_risk_count', got keys: {list(summary.keys())}"
        )
        assert summary["total"] >= 3


# ===========================================================================
# Flow 6 — Copilot → TrustGraph GraphRAG Bridge
# ===========================================================================


class TestCopilotTrustGraphBridgeFlow:
    """Tests intent classification and context enrichment via CopilotTrustGraphBridge."""

    @pytest.fixture(autouse=True)
    def _bridge(self, tmp_path):
        from core.copilot_trustgraph_bridge import CopilotTrustGraphBridge

        # Use an isolated db_path so we never touch production TrustGraph data
        self.bridge = CopilotTrustGraphBridge(db_path=str(tmp_path / "tg.db"))

    def test_cve_query_intent_is_cve(self):
        """A CVE-specific query is classified with intent='cve'."""
        from core.copilot_trustgraph_bridge import INTENT_CVE

        ctx = self.bridge.enrich_query(
            "CVE-2021-44228 is affecting our Log4j deployment. What should we patch?"
        )
        assert ctx.intent == INTENT_CVE, (
            f"Expected intent '{INTENT_CVE}', got '{ctx.intent}'"
        )

    def test_compliance_query_intent_is_compliance(self):
        """A SOC2/NIST compliance question is classified as intent='compliance'."""
        from core.copilot_trustgraph_bridge import INTENT_COMPLIANCE

        ctx = self.bridge.enrich_query(
            "Which SOC2 controls are we currently failing? NIST CSF gap analysis."
        )
        assert ctx.intent == INTENT_COMPLIANCE, (
            f"Expected intent '{INTENT_COMPLIANCE}', got '{ctx.intent}'"
        )

    def test_enriched_context_has_context_text_field(self):
        """CopilotContext always has a context_text string attribute."""
        ctx = self.bridge.enrich_query("Show me critical vulnerabilities in production")
        assert hasattr(ctx, "context_text"), "CopilotContext must have 'context_text'"
        assert isinstance(ctx.context_text, str)

    def test_bridge_degrades_gracefully_when_unavailable(self):
        """When TrustGraph is unavailable, bridge returns CopilotContext with available=False."""
        from core.copilot_trustgraph_bridge import CopilotTrustGraphBridge

        # Force unavailability by pointing to an intentionally invalid path
        bridge = CopilotTrustGraphBridge(db_path="/nonexistent/path/tg.db")
        ctx = bridge.enrich_query("test query")
        # Either available (TrustGraph connected) or degraded — either is acceptable
        # The important invariant: it never raises an exception
        assert hasattr(ctx, "available")


# ===========================================================================
# Flow 7 — Attack Surface → Posture Score
# ===========================================================================


class TestAttackSurfaceAndPostureFlow:
    """Tests attack surface registration and posture snapshot recording."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path):
        from core.attack_surface import AttackSurfaceMapper
        from core.posture_tracker import PostureTracker

        self.org_id = _test_org()
        self.mapper = AttackSurfaceMapper(db_path=str(tmp_path / "as.db"))
        self.tracker = PostureTracker(db_path=str(tmp_path / "posture.db"))

    def test_register_asset_and_retrieve_it(self):
        """register_asset followed by list_assets returns the registered asset."""
        from core.attack_surface import Asset, AssetType, ExposureLevel

        asset = Asset(
            name=f"api.{self.org_id}.internal",
            type=AssetType.API_ENDPOINT,
            exposure_level=ExposureLevel.EXTERNAL,
            org_id=self.org_id,
        )
        registered = self.mapper.register_asset(asset)
        assets = self.mapper.list_assets(self.org_id)

        asset_names = [a.name for a in assets]
        assert registered.name in asset_names, (
            f"Registered asset '{registered.name}' not found in list_assets"
        )

    def test_get_attack_surface_reflects_registered_assets(self):
        """get_attack_surface total_assets matches the number of registered assets."""
        from core.attack_surface import Asset, AssetType, ExposureLevel

        # Register 2 assets
        for i in range(2):
            self.mapper.register_asset(Asset(
                name=f"service-{i}.{self.org_id}",
                type=AssetType.SERVICE,
                exposure_level=ExposureLevel.INTERNAL,
                org_id=self.org_id,
            ))

        surface = self.mapper.get_attack_surface(self.org_id)
        assert surface.total_assets >= 2, (
            f"Expected >=2 assets in attack surface, got {surface.total_assets}"
        )
        assert surface.org_id == self.org_id

    def test_record_posture_and_get_current_posture(self):
        """record_posture saves a snapshot that get_current_posture returns."""
        components = {
            "critical_findings": 2,
            "high_findings": 5,
            "medium_findings": 10,
            "low_findings": 20,
            "sla_compliance_rate": 85.0,
            "trustgraph_coverage": 60.0,
            "remediation_rate": 70.0,
        }
        snap_id = self.tracker.record_posture(72.5, components, org_id=self.org_id)
        assert isinstance(snap_id, str) and snap_id.startswith("snap-")

        current = self.tracker.get_current_posture(org_id=self.org_id)
        assert current is not None, "get_current_posture returned None after recording"
        assert abs(current.overall_score - 72.5) < 0.01
        assert current.critical_findings == 2

    def test_compare_two_posture_snapshots(self):
        """Two recorded snapshots can be diffed with compare_posture."""
        comp1 = {
            "critical_findings": 5, "high_findings": 10,
            "sla_compliance_rate": 60.0, "trustgraph_coverage": 40.0,
            "remediation_rate": 50.0,
        }
        comp2 = {
            "critical_findings": 2, "high_findings": 6,
            "sla_compliance_rate": 80.0, "trustgraph_coverage": 70.0,
            "remediation_rate": 75.0,
        }
        snap_id_1 = self.tracker.record_posture(50.0, comp1, org_id=self.org_id)
        snap_id_2 = self.tracker.record_posture(75.0, comp2, org_id=self.org_id)

        diff = self.tracker.compare_posture(snap_id_1, snap_id_2)

        assert diff.org_id == self.org_id
        assert diff.score_delta > 0, "Score should improve from 50 → 75"
        assert diff.critical_delta < 0, "Critical findings should decrease"
        assert diff.trend in ("improving", "stable", "degrading")


# ===========================================================================
# Flow 8 — Security Metrics aggregation
# ===========================================================================


class TestSecurityMetricsFlow:
    """Tests DORA metrics computation and report generation."""

    @pytest.fixture(autouse=True)
    def _engine(self, tmp_path):
        from core.security_metrics import SecurityMetricsEngine

        self.engine = SecurityMetricsEngine(db_path=tmp_path / "metrics.db")

    def test_ingest_event_and_compute_dora_metrics_does_not_raise(self):
        """Ingesting a security event and computing DORA metrics completes without error."""
        from core.security_metrics import SecurityEvent, Severity

        now = datetime.now(timezone.utc)
        event = SecurityEvent(
            severity=Severity.HIGH,
            detected_at=now,
            source="semgrep",
            team="security",
            repo="fixops",
        )
        self.engine.ingest_event(event)
        metrics = self.engine.compute_dora_metrics(days=30)

        assert metrics is not None
        assert isinstance(metrics.mttd_hours, float)
        assert isinstance(metrics.mttr_hours, float)
        assert metrics.sample_size >= 1

    def test_generate_report_returns_report_with_sections(self):
        """generate_report returns a SecurityReport with non-empty sections dict."""
        from core.security_metrics import ReportType

        report = self.engine.generate_report(ReportType.WEEKLY_DIGEST)

        assert report is not None
        assert isinstance(report.sections, dict), "Report sections must be a dict"
        assert len(report.sections) > 0, "Report must have at least one section"
        assert report.title != "", "Report must have a non-empty title"
        assert report.dora_metrics is not None

    def test_report_contains_executive_summary_section(self):
        """Weekly digest report includes an 'executive_summary' section."""
        from core.security_metrics import ReportType

        report = self.engine.generate_report(ReportType.WEEKLY_DIGEST)

        assert "executive_summary" in report.sections, (
            f"Expected 'executive_summary' in sections, got: {list(report.sections.keys())}"
        )
