"""Unit tests for decision tree orchestrator."""

from __future__ import annotations

from compliance.mapping import ComplianceMappingResult

from apps.api.normalizers import CVERecordSummary, NormalizedCVEFeed
from core.decision_tree import DecisionTreeOrchestrator, DecisionTreeResult
from risk.enrichment import EnrichmentEvidence
from risk.forecasting import ForecastResult
from risk.threat_model import ThreatModelResult


class TestDecisionTreeResult:
    """Test DecisionTreeResult dataclass."""

    def test_create_decision_tree_result(self):
        """Test creating decision tree result."""
        result = DecisionTreeResult(
            cve_id="CVE-2023-1234",
            verdict="exploitable",
            verdict_confidence=0.85,
            verdict_reasoning=["High exploitation probability", "Attack path found"],
            legacy_verdict="block",
        )

        assert result.cve_id == "CVE-2023-1234"
        assert result.verdict == "exploitable"
        assert result.verdict_confidence == 0.85
        assert len(result.verdict_reasoning) == 2
        assert result.legacy_verdict == "block"

    def test_to_dict(self):
        """Test converting decision tree result to dictionary."""
        result = DecisionTreeResult(
            cve_id="CVE-2023-1234",
            verdict="exploitable",
            verdict_confidence=0.85,
        )

        output = result.to_dict()

        assert isinstance(output, dict)
        assert output["cve_id"] == "CVE-2023-1234"
        assert output["verdict"] == "exploitable"
        assert output["verdict_confidence"] == 0.85


class TestDecisionTreeOrchestrator:
    """Test DecisionTreeOrchestrator class."""

    def test_init_default_config(self):
        """Test initializing orchestrator with default config."""
        orchestrator = DecisionTreeOrchestrator()

        assert orchestrator.not_exploitable_max == 0.15
        assert orchestrator.exploitable_min == 0.70
        assert orchestrator.require_attack_path is True
        assert orchestrator.min_confidence == 0.60

    def test_init_custom_config(self):
        """Test initializing orchestrator with custom config."""
        overlay = {
            "decision_tree": {
                "thresholds": {
                    "not_exploitable_max": 0.10,
                    "exploitable_min": 0.80,
                    "require_attack_path": False,
                    "min_confidence": 0.70,
                }
            }
        }
        orchestrator = DecisionTreeOrchestrator(overlay=overlay)

        assert orchestrator.not_exploitable_max == 0.10
        assert orchestrator.exploitable_min == 0.80
        assert orchestrator.require_attack_path is False
        assert orchestrator.min_confidence == 0.70

    def test_analyze_basic(self):
        """Test basic analysis with minimal data."""
        orchestrator = DecisionTreeOrchestrator()
        raw_data = {
            "cve": {
                "id": "CVE-2023-1234",
                "published": "2023-01-01T00:00:00.000Z",
            },
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8,
                        }
                    }
                ]
            },
        }
        cve_feed = NormalizedCVEFeed(
            records=[
                CVERecordSummary(
                    cve_id="CVE-2023-1234",
                    title="Test CVE",
                    severity="CRITICAL",
                    exploited=False,
                    raw=raw_data,
                )
            ],
            errors=[],
            metadata={},
        )

        results = orchestrator.analyze(cve_feed)

        assert len(results) == 1
        assert "CVE-2023-1234" in results

        result = results["CVE-2023-1234"]
        assert result.cve_id == "CVE-2023-1234"
        assert result.enrichment is not None
        assert result.forecast is not None
        assert result.threat_model is not None
        assert result.compliance is not None
        assert result.verdict in ("exploitable", "not_exploitable", "needs_review")

    def test_analyze_with_kev(self):
        """Test analysis with KEV-listed vulnerability."""
        orchestrator = DecisionTreeOrchestrator()
        cve_feed = NormalizedCVEFeed(
            records=[
                CVERecordSummary(
                    cve_id="CVE-2023-1234",
                    title="Test CVE",
                    severity="HIGH",
                    exploited=False,
                    raw={
                        "cve": {
                            "id": "CVE-2023-1234",
                            "published": "2023-01-01T00:00:00.000Z",
                        }
                    },
                )
            ],
            errors=[],
            metadata={},
        )
        exploit_signals = {"kev": {"vulnerabilities": [{"cveID": "CVE-2023-1234"}]}}

        results = orchestrator.analyze(cve_feed, exploit_signals=exploit_signals)

        result = results["CVE-2023-1234"]
        assert result.enrichment.kev_listed is True
        assert result.forecast.p_exploit_now > 0.5

    def test_analyze_with_graph(self):
        """Test analysis with knowledge graph."""
        orchestrator = DecisionTreeOrchestrator()
        cve_feed = NormalizedCVEFeed(
            records=[
                CVERecordSummary(
                    cve_id="CVE-2023-1234",
                    title="Test CVE",
                    severity="HIGH",
                    exploited=False,
                    raw={
                        "cve": {
                            "id": "CVE-2023-1234",
                            "published": "2023-01-01T00:00:00.000Z",
                        }
                    },
                )
            ],
            errors=[],
            metadata={},
        )
        graph = {
            "nodes": [
                {"id": "vuln:CVE-2023-1234", "type": "vulnerability"},
                {"id": "comp:log4j", "type": "component", "name": "log4j-core"},
            ],
            "edges": [
                {"source": "comp:log4j", "target": "vuln:CVE-2023-1234"},
            ],
        }

        results = orchestrator.analyze(cve_feed, graph=graph)

        result = results["CVE-2023-1234"]
        assert result.threat_model is not None

    def test_analyze_with_llm_results(self):
        """Test analysis with LLM results."""
        orchestrator = DecisionTreeOrchestrator()
        cve_feed = NormalizedCVEFeed(
            records=[
                CVERecordSummary(
                    cve_id="CVE-2023-1234",
                    title="Test CVE",
                    severity="HIGH",
                    exploited=False,
                    raw={
                        "cve": {
                            "id": "CVE-2023-1234",
                            "published": "2023-01-01T00:00:00.000Z",
                        }
                    },
                )
            ],
            errors=[],
            metadata={},
        )
        llm_results = {
            "CVE-2023-1234": {
                "explanation": "High risk vulnerability",
                "confidence": 0.90,
                "consensus": {"action": "block"},
            }
        }

        results = orchestrator.analyze(cve_feed, llm_results=llm_results)

        result = results["CVE-2023-1234"]
        assert result.llm_explanation == "High risk vulnerability"
        assert result.llm_confidence == 0.90

    def test_compute_verdict_exploitable(self):
        """Test verdict computation for exploitable CVE."""
        orchestrator = DecisionTreeOrchestrator()
        enrichment = EnrichmentEvidence(
            cve_id="CVE-2023-1234",
            kev_listed=True,
            cvss_score=9.8,
        )
        forecast = ForecastResult(
            cve_id="CVE-2023-1234",
            p_exploit_now=0.85,
            p_exploit_30d=0.90,
            confidence=0.80,
        )
        threat_model = ThreatModelResult(
            cve_id="CVE-2023-1234",
            attack_path_found=True,
            reachability_score=0.90,
        )
        compliance = ComplianceMappingResult(
            cve_id="CVE-2023-1234",
            cwe_ids=["CWE-89"],
        )

        verdict, confidence, reasoning = orchestrator._compute_verdict(
            enrichment, forecast, threat_model, compliance, 0.85
        )

        assert verdict == "exploitable"
        assert confidence > 0.6
        assert len(reasoning) > 0

    def test_compute_verdict_not_exploitable(self):
        """Test verdict computation for not exploitable CVE."""
        orchestrator = DecisionTreeOrchestrator()
        enrichment = EnrichmentEvidence(
            cve_id="CVE-2023-1234",
            has_vendor_advisory=True,
            cvss_score=3.0,
        )
        forecast = ForecastResult(
            cve_id="CVE-2023-1234",
            p_exploit_now=0.05,
            p_exploit_30d=0.08,
            confidence=0.70,
        )
        threat_model = ThreatModelResult(
            cve_id="CVE-2023-1234",
            attack_path_found=False,
            reachability_score=0.20,
        )
        compliance = ComplianceMappingResult(
            cve_id="CVE-2023-1234",
            cwe_ids=[],
        )

        verdict, confidence, reasoning = orchestrator._compute_verdict(
            enrichment, forecast, threat_model, compliance, 0.75
        )

        assert verdict == "not_exploitable"
        assert len(reasoning) > 0

    def test_compute_verdict_needs_review(self):
        """Test verdict computation for needs review CVE."""
        orchestrator = DecisionTreeOrchestrator()
        enrichment = EnrichmentEvidence(
            cve_id="CVE-2023-1234",
            cvss_score=6.5,
        )
        forecast = ForecastResult(
            cve_id="CVE-2023-1234",
            p_exploit_now=0.40,
            p_exploit_30d=0.50,
            confidence=0.60,
        )
        threat_model = ThreatModelResult(
            cve_id="CVE-2023-1234",
            attack_path_found=False,
            reachability_score=0.50,
        )
        compliance = ComplianceMappingResult(
            cve_id="CVE-2023-1234",
            cwe_ids=["CWE-89"],
        )

        verdict, confidence, reasoning = orchestrator._compute_verdict(
            enrichment, forecast, threat_model, compliance, 0.65
        )

        assert verdict == "needs_review"
        assert len(reasoning) > 0

    def test_compute_verdict_low_confidence_override(self):
        """Test that low confidence overrides to needs_review."""
        orchestrator = DecisionTreeOrchestrator()
        enrichment = EnrichmentEvidence(
            cve_id="CVE-2023-1234",
            kev_listed=True,
        )
        forecast = ForecastResult(
            cve_id="CVE-2023-1234",
            p_exploit_now=0.80,
            p_exploit_30d=0.85,
            confidence=0.40,  # Low confidence
        )
        threat_model = ThreatModelResult(
            cve_id="CVE-2023-1234",
            attack_path_found=True,
        )
        compliance = ComplianceMappingResult(
            cve_id="CVE-2023-1234",
            cwe_ids=[],
        )

        verdict, confidence, reasoning = orchestrator._compute_verdict(
            enrichment, forecast, threat_model, compliance, 0.40  # Low LLM confidence
        )

        assert verdict == "needs_review"

    def test_map_to_legacy_verdict(self):
        """Test mapping new verdict to legacy verdict."""
        orchestrator = DecisionTreeOrchestrator()

        assert orchestrator._map_to_legacy_verdict("exploitable") == "block"
        assert orchestrator._map_to_legacy_verdict("not_exploitable") == "allow"
        assert orchestrator._map_to_legacy_verdict("needs_review") == "defer"

    def test_analyze_multiple_cves(self):
        """Test analyzing multiple CVEs."""
        orchestrator = DecisionTreeOrchestrator()
        cve_feed = NormalizedCVEFeed(
            records=[
                CVERecordSummary(
                    cve_id="CVE-2023-1234",
                    title="Test CVE 1",
                    severity="HIGH",
                    exploited=False,
                    raw={
                        "cve": {
                            "id": "CVE-2023-1234",
                            "published": "2023-01-01T00:00:00.000Z",
                        }
                    },
                ),
                CVERecordSummary(
                    cve_id="CVE-2023-5678",
                    title="Test CVE 2",
                    severity="MEDIUM",
                    exploited=False,
                    raw={
                        "cve": {
                            "id": "CVE-2023-5678",
                            "published": "2023-02-01T00:00:00.000Z",
                        }
                    },
                ),
            ],
            errors=[],
            metadata={},
        )

        results = orchestrator.analyze(cve_feed)

        assert len(results) == 2
        assert "CVE-2023-1234" in results
        assert "CVE-2023-5678" in results

    def test_analyze_empty_feed(self):
        """Test analyzing empty CVE feed."""
        orchestrator = DecisionTreeOrchestrator()
        cve_feed = NormalizedCVEFeed(records=[], errors=[], metadata={})

        results = orchestrator.analyze(cve_feed)

        assert len(results) == 0

    def test_verdict_reasoning_includes_factors(self):
        """Test that verdict reasoning includes key factors."""
        orchestrator = DecisionTreeOrchestrator()
        enrichment = EnrichmentEvidence(
            cve_id="CVE-2023-1234",
            kev_listed=True,
            has_vendor_advisory=True,
        )
        forecast = ForecastResult(
            cve_id="CVE-2023-1234",
            p_exploit_now=0.75,
            p_exploit_30d=0.80,
            confidence=0.80,
        )
        threat_model = ThreatModelResult(
            cve_id="CVE-2023-1234",
            attack_path_found=True,
            reachability_score=0.85,
        )
        compliance = ComplianceMappingResult(
            cve_id="CVE-2023-1234",
            cwe_ids=["CWE-89"],
            compliance_gaps=["No controls for SOC2"],
        )

        verdict, confidence, reasoning = orchestrator._compute_verdict(
            enrichment, forecast, threat_model, compliance, 0.85
        )

        reasoning_text = " ".join(reasoning)
        assert "KEV" in reasoning_text or "exploitation probability" in reasoning_text
        assert len(reasoning) >= 3  # Should have multiple factors
