from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from re import Pattern
from typing import Any, Dict, Iterable, List, Optional

from fixops.ai_agents import AIAgentAdvisor
from fixops.analytics import ROIDashboard
from fixops.configuration import OverlayConfig
from fixops.context_engine import ContextEngine
from fixops.evidence import EvidenceHub
from fixops.compliance import ComplianceEvaluator
from fixops.onboarding import OnboardingGuide
from fixops.policy import PolicyAutomation
from fixops.probabilistic import ProbabilisticForecastEngine
from fixops.ssdlc import SSDLCEvaluator
from fixops.exploit_signals import ExploitFeedRefresher, ExploitSignalEvaluator
from fixops.iac import IaCPostureEvaluator
from fixops.feature_matrix import build_feature_matrix
from fixops.modules import PipelineContext, execute_custom_modules
from fixops.tenancy import TenantLifecycleManager
from fixops.performance import PerformanceSimulator

from .normalizers import (
    CVERecordSummary,
    NormalizedCVEFeed,
    NormalizedSARIF,
    NormalizedSBOM,
    SBOMComponent,
    SarifFinding,
)


def _lower(value: Optional[str]) -> Optional[str]:
    return value.lower() if isinstance(value, str) else None


_SEVERITY_ORDER = ("low", "medium", "high", "critical")
_SARIF_LEVEL_MAP = {
    None: "low",
    "": "low",
    "none": "low",
    "note": "low",
    "info": "low",
    "warning": "medium",
    "error": "high",
}
_CVE_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
}


class PipelineOrchestrator:
    """Derive intermediate insights from the uploaded artefacts."""

    @staticmethod
    def _extract_component_name(row: Dict[str, Any]) -> Optional[str]:
        """Return the first non-empty component identifier in a design row."""

        for key in ("component", "Component", "service", "name"):
            value = row.get(key)
            if isinstance(value, str):
                stripped = value.strip()
                if stripped:
                    return stripped
        return None

    @staticmethod
    def _build_finding_search_text(finding: SarifFinding) -> str:
        """Concatenate searchable portions of a SARIF finding once."""

        parts: List[str] = []
        if finding.file:
            parts.append(finding.file)
        if finding.message:
            parts.append(finding.message)
        if finding.rule_id:
            parts.append(finding.rule_id)
        analysis_target = finding.raw.get("analysisTarget") if finding.raw else None
        if analysis_target:
            try:
                parts.append(
                    json.dumps(
                        analysis_target,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
            except TypeError:
                parts.append(str(analysis_target))
        return " ".join(parts)

    @staticmethod
    def _build_record_search_text(record: CVERecordSummary) -> str:
        parts: List[str] = []
        if record.cve_id:
            parts.append(record.cve_id)
        if record.title:
            parts.append(record.title)
        if record.severity:
            parts.append(record.severity)
        try:
            parts.append(
                json.dumps(record.raw, sort_keys=True, separators=(",", ":"))
            )
        except TypeError:
            parts.append(str(record.raw))
        return " ".join(parts)

    def _match_components(
        self,
        sbom_components: Iterable[SBOMComponent],
    ) -> Dict[str, SBOMComponent]:
        lookup: Dict[str, SBOMComponent] = {}
        for component in sbom_components:
            key = _lower(component.name)
            if key:
                lookup[key] = component
        return lookup

    @staticmethod
    def _compile_token_pattern(tokens: Iterable[str]) -> Optional[Pattern[str]]:
        """Build a compiled regex for substring lookups across artefacts."""

        cleaned = [token for token in tokens if token]
        if not cleaned:
            return None
        # Sort by length (descending) so the regex prefers longer tokens over
        # substrings. Escaping protects special characters in component names.
        sorted_tokens = sorted(cleaned, key=len, reverse=True)
        pattern = "|".join(re.escape(token) for token in sorted_tokens)
        return re.compile(pattern)

    @staticmethod
    def _normalise_sarif_severity(level: Optional[str]) -> str:
        if level is None:
            return "low"
        normalised = _SARIF_LEVEL_MAP.get(level.lower()) if isinstance(level, str) else None
        if normalised:
            return normalised
        return "medium"

    @staticmethod
    def _severity_index(severity: str) -> int:
        try:
            return _SEVERITY_ORDER.index(severity)
        except ValueError:
            return _SEVERITY_ORDER.index("medium")

    @staticmethod
    def _normalise_cve_severity(record: CVERecordSummary) -> str:
        candidates = [record.severity]
        raw = record.raw
        if isinstance(raw, dict):
            candidates.append(raw.get("cvssV3Severity"))
            impact = raw.get("impact")
            if isinstance(impact, dict):
                metric = impact.get("baseMetricV3")
                if isinstance(metric, dict):
                    candidates.append(metric.get("baseSeverity"))
            candidates.append(raw.get("severity"))
        for candidate in candidates:
            if not candidate:
                continue
            normalised = _CVE_SEVERITY_MAP.get(str(candidate).lower())
            if normalised:
                return normalised
        return "medium"

    def _evaluate_guardrails(
        self,
        overlay: OverlayConfig,
        severity_counts: Counter,
        highest_severity: str,
        trigger: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        policy = overlay.guardrail_policy
        fail_rank = self._severity_index(policy["fail_on"])
        warn_rank = self._severity_index(policy["warn_on"])
        highest_rank = self._severity_index(highest_severity)

        status = "pass"
        rationale: List[str] = []
        if highest_rank >= fail_rank:
            status = "fail"
            rationale.append(
                f"highest severity '{highest_severity}' meets fail threshold '{policy['fail_on']}'"
            )
        elif highest_rank >= warn_rank:
            status = "warn"
            rationale.append(
                f"highest severity '{highest_severity}' meets warn threshold '{policy['warn_on']}'"
            )
        else:
            rationale.append(
                f"highest severity '{highest_severity}' is below warn threshold '{policy['warn_on']}'"
            )

        evaluation: Dict[str, Any] = {
            "maturity": policy["maturity"],
            "policy": {"fail_on": policy["fail_on"], "warn_on": policy["warn_on"]},
            "highest_detected": highest_severity,
            "status": status,
            "severity_counts": dict(severity_counts),
            "rationale": rationale,
        }
        if trigger:
            evaluation["trigger"] = trigger
        return evaluation

    def run(
        self,
        design_dataset: Dict[str, Any],
        sbom: NormalizedSBOM,
        sarif: NormalizedSARIF,
        cve: NormalizedCVEFeed,
        overlay: Optional[OverlayConfig] = None,
    ) -> Dict[str, Any]:
        rows = [
            row for row in design_dataset.get("rows", []) if isinstance(row, dict)
        ]

        design_components: List[str] = []
        token_by_index: Dict[int, str] = {}
        for index, row in enumerate(rows):
            name = self._extract_component_name(row)
            if not name:
                continue
            normalised = _lower(name)
            if not normalised:
                continue
            design_components.append(name)
            token_by_index[index] = normalised

        lookup_tokens = set(token_by_index.values())
        sbom_lookup = self._match_components(sbom.components)

        findings_by_level = Counter(
            finding.level or "none" for finding in sarif.findings
        )
        exploited_count = sum(1 for record in cve.records if record.exploited)

        severity_counts: Counter[str] = Counter()
        source_breakdown: Dict[str, Counter[str]] = {
            "sarif": Counter(),
            "cve": Counter(),
        }
        highest_severity = "low"
        highest_trigger: Optional[Dict[str, Any]] = None

        for finding in sarif.findings:
            severity = self._normalise_sarif_severity(finding.level)
            severity_counts[severity] += 1
            source_breakdown["sarif"][severity] += 1
            if self._severity_index(severity) > self._severity_index(highest_severity):
                highest_severity = severity
                highest_trigger = {
                    "source": "sarif",
                    "rule_id": finding.rule_id,
                    "level": finding.level,
                    "file": finding.file,
                }

        for record in cve.records:
            severity = self._normalise_cve_severity(record)
            severity_counts[severity] += 1
            source_breakdown["cve"][severity] += 1
            if self._severity_index(severity) > self._severity_index(highest_severity):
                highest_severity = severity
                highest_trigger = {
                    "source": "cve",
                    "cve_id": record.cve_id,
                    "severity": record.severity,
                    "exploited": record.exploited,
                }

        finding_matches: Dict[str, List[dict[str, Any]]] = defaultdict(list)
        token_pattern = self._compile_token_pattern(lookup_tokens)

        if token_pattern:
            for finding in sarif.findings:
                haystack = self._build_finding_search_text(finding)
                if not haystack:
                    continue
                haystack = haystack.lower()
                payload = finding.to_dict()
                for token in set(token_pattern.findall(haystack)):
                    finding_matches[token].append(dict(payload))

        cve_matches: Dict[str, List[dict[str, Any]]] = defaultdict(list)
        if token_pattern:
            for record in cve.records:
                haystack = self._build_record_search_text(record)
                if not haystack:
                    continue
                haystack = haystack.lower()
                payload = record.to_dict()
                for token in set(token_pattern.findall(haystack)):
                    cve_matches[token].append(dict(payload))

        crosswalk: List[dict[str, Any]] = []
        for index, row in enumerate(rows):
            token = token_by_index.get(index)
            match = sbom_lookup.get(token) if token else None

            crosswalk.append(
                {
                    "design_row": row,
                    "sbom_component": match.to_dict() if match else None,
                    "findings": list(finding_matches.get(token, [])),
                    "cves": list(cve_matches.get(token, [])),
                    "design_index": index,
                }
            )

        result: Dict[str, Any] = {
            "status": "ok",
            "design_summary": {
                "row_count": len(rows),
                "unique_components": sorted(set(design_components)),
            },
            "sbom_summary": {
                **sbom.metadata,
                "format": sbom.format,
                "document_name": sbom.document.get("name"),
            },
            "sarif_summary": {
                **sarif.metadata,
                "severity_breakdown": dict(findings_by_level),
                "tools": sarif.tool_names,
            },
            "cve_summary": {
                **cve.metadata,
                "exploited_count": exploited_count,
            },
            "severity_overview": {
                "highest": highest_severity,
                "counts": dict(severity_counts),
                "sources": {
                    source: dict(counter) for source, counter in source_breakdown.items()
                },
            },
            "crosswalk": crosswalk,
        }

        if overlay is not None:
            modules_status: Dict[str, str] = {}
            executed_modules: List[str] = []
            custom_outcomes: List[Dict[str, Any]] = []

            context_summary: Optional[Dict[str, Any]] = None
            compliance_status: Optional[Dict[str, Any]] = None
            policy_summary: Optional[Dict[str, Any]] = None
            ssdlc_assessment: Optional[Dict[str, Any]] = None
            analytics_summary: Optional[Dict[str, Any]] = None
            tenant_overview: Optional[Dict[str, Any]] = None
            performance_profile: Optional[Dict[str, Any]] = None

            if overlay.is_module_enabled("guardrails"):
                result["guardrail_evaluation"] = self._evaluate_guardrails(
                    overlay, severity_counts, highest_severity, highest_trigger
                )
                modules_status["guardrails"] = "executed"
                executed_modules.append("guardrails")
            else:
                modules_status["guardrails"] = "disabled"

            if overlay.is_module_enabled("context_engine"):
                context_engine = ContextEngine(overlay.context_engine_settings)
                context_summary = context_engine.evaluate(rows, crosswalk)
                result["context_summary"] = context_summary
                modules_status["context_engine"] = "executed"
                executed_modules.append("context_engine")
            else:
                modules_status["context_engine"] = "disabled"

            if overlay.is_module_enabled("onboarding"):
                onboarding = OnboardingGuide(overlay)
                result["onboarding"] = onboarding.build(overlay.required_inputs)
                modules_status["onboarding"] = "executed"
                executed_modules.append("onboarding")
            else:
                modules_status["onboarding"] = "disabled"

            if overlay.is_module_enabled("evidence"):
                # Placeholder so compliance checks recognise evidence availability before persistence.
                result["evidence_bundle"] = {"status": "pending"}

            if overlay.is_module_enabled("compliance"):
                compliance_evaluator = ComplianceEvaluator(overlay.compliance_settings)
                compliance_status = compliance_evaluator.evaluate(result, context_summary)
                result["compliance_status"] = compliance_status
                modules_status["compliance"] = "executed"
                executed_modules.append("compliance")
            else:
                modules_status["compliance"] = "disabled"

            if overlay.is_module_enabled("policy_automation"):
                policy_automation = PolicyAutomation(overlay)
                policy_plan = policy_automation.plan(result, context_summary, compliance_status)
                execution_summary = policy_automation.execute(policy_plan["actions"])
                policy_summary = dict(policy_plan)
                policy_summary["execution"] = execution_summary
                result["policy_automation"] = policy_summary
                modules_status["policy_automation"] = "executed"
                executed_modules.append("policy_automation")
            else:
                modules_status["policy_automation"] = "disabled"

            if overlay.is_module_enabled("ssdlc"):
                ssdlc_evaluator = SSDLCEvaluator(overlay.ssdlc_settings)
                ssdlc_assessment = ssdlc_evaluator.evaluate(
                    design_rows=rows,
                    sbom=sbom,
                    sarif=sarif,
                    cve=cve,
                    pipeline_result=result,
                    context_summary=context_summary,
                    compliance_status=compliance_status,
                    policy_summary=policy_summary,
                    overlay=overlay,
                )
                result["ssdlc_assessment"] = ssdlc_assessment
                modules_status["ssdlc"] = "executed"
                executed_modules.append("ssdlc")
            else:
                modules_status["ssdlc"] = "disabled"

            if overlay.is_module_enabled("ai_agents"):
                ai_advisor = AIAgentAdvisor(overlay.ai_agents)
                ai_analysis = ai_advisor.analyse(rows, crosswalk)
                if ai_analysis:
                    result["ai_agent_analysis"] = ai_analysis
                modules_status["ai_agents"] = "executed"
                executed_modules.append("ai_agents")
            else:
                modules_status["ai_agents"] = "disabled"

            if overlay.is_module_enabled("exploit_signals"):
                exploit_evaluator = ExploitSignalEvaluator(overlay.exploit_settings)
                refresher = ExploitFeedRefresher(overlay)
                refresh_summary = refresher.refresh(cve, exploit_evaluator.last_refreshed)
                if refresh_summary:
                    result["exploit_feed_refresh"] = refresh_summary
                    if refresh_summary.get("status") == "refreshed":
                        exploit_evaluator = ExploitSignalEvaluator(overlay.exploit_settings)
                exploit_summary = exploit_evaluator.evaluate(cve)
                if exploit_summary:
                    result["exploitability_insights"] = exploit_summary
                modules_status["exploit_signals"] = "executed"
                executed_modules.append("exploit_signals")
            else:
                modules_status["exploit_signals"] = "disabled"

            if overlay.is_module_enabled("probabilistic"):
                probabilistic = ProbabilisticForecastEngine(overlay.probabilistic_settings)
                forecast = probabilistic.evaluate(
                    severity_counts=result["severity_overview"]["counts"],
                    crosswalk=crosswalk,
                    exploited_records=[record.to_dict() for record in cve.records],
                )
                result["probabilistic_forecast"] = forecast
                modules_status["probabilistic"] = "executed"
                executed_modules.append("probabilistic")
            else:
                modules_status["probabilistic"] = "disabled"

            if overlay.is_module_enabled("analytics"):
                analytics_engine = ROIDashboard(overlay.analytics_settings)
                analytics_summary = analytics_engine.evaluate(
                    result,
                    overlay,
                    context_summary=context_summary,
                    compliance_status=compliance_status,
                    policy_summary=policy_summary,
                )
                result["analytics"] = analytics_summary
                modules_status["analytics"] = "executed"
                executed_modules.append("analytics")
            else:
                modules_status["analytics"] = "disabled"

            if overlay.is_module_enabled("tenancy"):
                tenancy_manager = TenantLifecycleManager(overlay.tenancy_settings)
                tenant_overview = tenancy_manager.evaluate(result, overlay)
                result["tenant_lifecycle"] = tenant_overview
                modules_status["tenancy"] = "executed"
                executed_modules.append("tenancy")
            else:
                modules_status["tenancy"] = "disabled"

            if overlay.is_module_enabled("performance"):
                performance_simulator = PerformanceSimulator(overlay.performance_settings)
                performance_profile = performance_simulator.simulate(result, overlay)
                result["performance_profile"] = performance_profile
                modules_status["performance"] = "executed"
                executed_modules.append("performance")
            else:
                modules_status["performance"] = "disabled"

            if overlay.is_module_enabled("iac_posture"):
                iac_settings = dict(overlay.iac_settings)
                module_overrides = overlay.module_config("iac_posture")
                if module_overrides:
                    iac_settings.update(module_overrides)
                iac_evaluator = IaCPostureEvaluator(iac_settings)
                iac_posture = iac_evaluator.evaluate(rows, crosswalk, result)
                if iac_posture:
                    result["iac_posture"] = iac_posture
                modules_status["iac_posture"] = "executed"
                executed_modules.append("iac_posture")
            else:
                modules_status["iac_posture"] = "disabled"

            if overlay.is_module_enabled("evidence"):
                evidence_hub = EvidenceHub(overlay)
                evidence_bundle = evidence_hub.persist(
                    result, context_summary, compliance_status, policy_summary
                )
                result["evidence_bundle"] = evidence_bundle
                modules_status["evidence"] = "executed"
                executed_modules.append("evidence")
            else:
                modules_status["evidence"] = "disabled"

            if overlay.is_module_enabled("pricing", default=True):
                result["pricing_summary"] = overlay.pricing_summary
                modules_status["pricing"] = "executed"
                executed_modules.append("pricing")
            else:
                modules_status["pricing"] = "disabled"

            if overlay.custom_module_specs:
                context = PipelineContext(
                    design_rows=rows,
                    crosswalk=crosswalk,
                    sbom=sbom,
                    sarif=sarif,
                    cve=cve,
                    overlay=overlay,
                    result=result,
                    context_summary=context_summary,
                    compliance_status=compliance_status,
                    policy_summary=policy_summary,
                    ssdlc_assessment=ssdlc_assessment,
                )
                custom_outcomes = execute_custom_modules(overlay.custom_module_specs, context)
                custom_executed = any(
                    outcome.get("status") == "executed" for outcome in custom_outcomes
                )
                modules_status["custom"] = "executed" if custom_executed else "skipped"
            result["modules"] = {
                "configured": overlay.module_matrix,
                "enabled": overlay.enabled_modules,
                "status": modules_status,
                "executed": executed_modules,
                "custom": custom_outcomes,
            }
            result["feature_matrix"] = build_feature_matrix(result)

        return result
