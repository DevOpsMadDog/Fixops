from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from core.ai_agents import AIAgentAdvisor
from core.analytics import ROIDashboard
from core.configuration import OverlayConfig
from core.context_engine import ContextEngine
from core.evidence import EvidenceHub
from core.enhanced_decision import EnhancedDecisionEngine
from core.compliance import ComplianceEvaluator
from core.onboarding import OnboardingGuide
from core.policy import PolicyAutomation
from core.probabilistic import ProbabilisticForecastEngine
from core.ssdlc import SSDLCEvaluator
from core.exploit_signals import ExploitFeedRefresher, ExploitSignalEvaluator
from core.iac import IaCPostureEvaluator
from core.feature_matrix import build_feature_matrix
from core.modules import PipelineContext, execute_custom_modules
from core.tenancy import TenantLifecycleManager
from core.performance import PerformanceSimulator
from core.processing_layer import ProcessingLayer
from core.vector_store import SecurityPatternMatcher

from .knowledge_graph import KnowledgeGraphService

from domain import CrosswalkRow
from services.match.indexes import build_component_index, build_cve_index, build_finding_index
from services.match.join import build_crosswalk
from services.match.utils import build_lookup_tokens, extract_component_name

from .normalizers import (
    CVERecordSummary,
    NormalizedBusinessContext,
    NormalizedCNAPP,
    NormalizedCVEFeed,
    NormalizedSARIF,
    NormalizedSBOM,
    NormalizedVEX,
)
_SEVERITY_ORDER = ("low", "medium", "high", "critical")
_SEVERITY_INDEX_MAP = {severity: idx for idx, severity in enumerate(_SEVERITY_ORDER)}
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

_CNAPP_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "low",
}


def evaluate_compliance(
    guardrails: Mapping[str, Any] | None,
    policies: Mapping[str, Any] | None,
    overlay: OverlayConfig | Mapping[str, Any] | None,
) -> List[Dict[str, Any]]:
    """Map guardrail and policy results to compliance control coverage."""

    mapping: Mapping[str, Iterable[str]] = {}
    if isinstance(overlay, OverlayConfig):
        mapping = (
            overlay.compliance.get("control_map", {})
            if isinstance(overlay.compliance, Mapping)
            else {}
        )
    elif isinstance(overlay, Mapping):
        mapping = (
            overlay.get("compliance", {}).get("control_map", {})
            if isinstance(overlay.get("compliance"), Mapping)
            else {}
        )

    if not isinstance(mapping, Mapping):
        return []

    def _resolve_status(source: Mapping[str, Any] | None, path: str) -> Optional[Any]:
        if not source:
            return None
        current: Any = source
        for segment in path.split("."):
            if not isinstance(current, Mapping):
                return None
            current = current.get(segment)
            if current is None:
                return None
        return current

    def _status_passed(value: Any) -> Optional[bool]:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.lower()
            if lowered in {"pass", "passed", "satisfied", "completed", "ok", "success"}:
                return True
            if lowered in {"fail", "failed", "gap", "error", "blocked"}:
                return False
        return None

    results: List[Dict[str, Any]] = []
    for control_id, rule_ids in mapping.items():
        passed = 0
        failed = 0
        rules = list(rule_ids) if isinstance(rule_ids, Iterable) else []
        for rule_id in rules:
            if not isinstance(rule_id, str):
                continue
            target = rule_id
            namespace = "guardrails"
            if ":" in rule_id:
                prefix, remainder = rule_id.split(":", 1)
                namespace = prefix or namespace
                target = remainder
            elif rule_id.startswith("policy."):
                namespace = "policies"
                target = rule_id[len("policy.") :]
            elif rule_id.startswith("policies."):
                namespace = "policies"
                target = rule_id[len("policies.") :]
            elif rule_id.startswith("guardrails."):
                target = rule_id[len("guardrails.") :]
            source = guardrails if namespace == "guardrails" else policies
            status_value = _resolve_status(
                source if isinstance(source, Mapping) else None, target
            )
            outcome = _status_passed(status_value)
            if outcome is True:
                passed += 1
            elif outcome is False:
                failed += 1
        total = max(len(rules), 1)
        coverage = passed / total
        results.append(
            {
                "control_id": control_id,
                "coverage": coverage,
                "passed": passed,
                "failed": failed,
            }
        )
    return results


class PipelineOrchestrator:
    """Derive intermediate insights from the uploaded artefacts."""

    def __init__(self) -> None:
        self._vector_matcher: Optional[SecurityPatternMatcher] = None
        self._vector_signature: Optional[str] = None
        self._repo_root = Path(__file__).resolve().parents[2]

    @staticmethod
    def _determine_highest_severity(counts: Mapping[str, int]) -> str:
        for level in reversed(_SEVERITY_ORDER):
            if counts.get(level, 0) > 0:
                return level
        return _SEVERITY_ORDER[0]

    @staticmethod
    def _normalise_sarif_severity(level: Optional[str]) -> str:
        if level is None:
            return "low"
        normalised = (
            _SARIF_LEVEL_MAP.get(level.lower()) if isinstance(level, str) else None
        )
        if normalised:
            return normalised
        return "medium"

    @staticmethod
    def _severity_index(severity: str) -> int:
        return _SEVERITY_INDEX_MAP.get(severity, _SEVERITY_INDEX_MAP["medium"])

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

    def _ensure_vector_matcher(self, overlay: OverlayConfig) -> SecurityPatternMatcher:
        config = overlay.module_config("vector_store")
        signature = json.dumps(config, sort_keys=True, default=str)
        if self._vector_matcher is None or self._vector_signature != signature:
            matcher = SecurityPatternMatcher(config, root=self._repo_root)
            self._vector_matcher = matcher
            self._vector_signature = signature
        assert self._vector_matcher is not None
        return self._vector_matcher

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

    def _derive_marketplace_recommendations(
        self,
        compliance_status: Optional[Mapping[str, Any]],
        guardrail_evaluation: Optional[Mapping[str, Any]],
        policy_summary: Optional[Mapping[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Return marketplace recommendation payloads aligned with stage runner semantics."""

        matches: List[str] = []

        if isinstance(compliance_status, Mapping):
            frameworks = compliance_status.get("frameworks", [])
            if isinstance(frameworks, Iterable) and not isinstance(frameworks, (str, bytes)):
                iterable_frameworks = frameworks
            else:
                iterable_frameworks = []
            for framework in iterable_frameworks:
                if not isinstance(framework, Mapping):
                    continue
                framework_name = framework.get("name")
                controls = framework.get("controls", [])
                if not (isinstance(controls, Iterable) and not isinstance(controls, (str, bytes))):
                    controls = []
                for control in controls or []:
                    if not isinstance(control, Mapping):
                        continue
                    status = str(control.get("status") or "").lower()
                    if status and status not in {"satisfied", "pass", "ok"}:
                        control_id = control.get("id") or control.get("control_id")
                        if control_id:
                            if framework_name:
                                matches.append(f"{framework_name}:{control_id}")
                            else:
                                matches.append(str(control_id))
            for gap in compliance_status.get("gaps", []) or []:
                if isinstance(gap, str) and gap.strip():
                    matches.append(gap.strip())

        if isinstance(policy_summary, Mapping):
            actions = policy_summary.get("actions", [])
            if isinstance(actions, Iterable) and not isinstance(actions, (str, bytes)):
                iterable_actions = actions
            else:
                iterable_actions = []
            for action in iterable_actions:
                if not isinstance(action, Mapping):
                    continue
                context = action.get("context")
                if isinstance(context, Mapping):
                    highest = context.get("highest")
                    if highest:
                        matches.append(f"guardrail:{highest}")
            execution = policy_summary.get("execution")
            if isinstance(execution, Mapping):
                results = execution.get("results", [])
                if isinstance(results, Iterable) and not isinstance(results, (str, bytes)):
                    iterable_results = results
                else:
                    iterable_results = []
                for result in iterable_results:
                    if not isinstance(result, Mapping):
                        continue
                    status = str(result.get("status") or "").lower()
                    if status == "failed":
                        identifier = result.get("id") or result.get("type")
                        if identifier:
                            matches.append(f"policy:{identifier}")

        if isinstance(guardrail_evaluation, Mapping):
            status = str(guardrail_evaluation.get("status") or "").lower()
            if status in {"fail", "warn"}:
                matches.append(f"guardrail:{status}")
                highest = guardrail_evaluation.get("highest_detected")
                if highest:
                    matches.append(f"guardrail:{highest}")

        unique_matches = sorted({match.strip() for match in matches if isinstance(match, str) and match.strip()})
        if not unique_matches:
            return []
        return [
            {
                "id": "guardrail-remediation",
                "title": "Enable auto-remediation playbooks",
                "match": unique_matches,
            }
        ]

    def run(
        self,
        design_dataset: Dict[str, Any],
        sbom: NormalizedSBOM,
        sarif: NormalizedSARIF,
        cve: NormalizedCVEFeed,
        overlay: Optional[OverlayConfig] = None,
        *,
        vex: Optional[NormalizedVEX] = None,
        cnapp: Optional[NormalizedCNAPP] = None,
        context: Optional[NormalizedBusinessContext] = None,
    ) -> Dict[str, Any]:
        rows: List[Mapping[str, Any]] = [
            row for row in design_dataset.get("rows", []) if isinstance(row, Mapping)
        ]

        lookup_tokens = build_lookup_tokens(rows)
        design_components = lookup_tokens.components
        component_index = build_component_index(sbom.components)
        finding_matches = build_finding_index(sarif.findings, lookup_tokens)
        cve_matches = build_cve_index(cve.records, lookup_tokens)
        crosswalk_rows = build_crosswalk(
            rows,
            lookup_tokens,
            component_index=component_index,
            finding_index=finding_matches,
            cve_index=cve_matches,
        )

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


        if context is not None:
            context_map: Dict[str, Mapping[str, Any]] = {}
            for component in context.components:
                if not isinstance(component, Mapping):
                    continue
                name = str(component.get("name") or component.get("component") or "").strip()
                if not name:
                    continue
                context_map[name.lower()] = component
            updated_rows: List[CrosswalkRow] = []
            for entry in crosswalk_rows:
                candidate = extract_component_name(entry.design_row)
                if not candidate:
                    updated_rows.append(entry)
                    continue
                key = candidate.lower()
                if key in context_map:
                    updated_rows.append(entry.with_business_context(context_map[key]))
                else:
                    updated_rows.append(entry)
            crosswalk_rows = updated_rows

        original_counts = dict(severity_counts)
        noise_reduction: Optional[Dict[str, Any]] = None

        if vex is not None:
            suppressed_counts: Counter[str] = Counter()
            suppressed_refs = vex.suppressed_refs
            if suppressed_refs:
                updated_rows: List[CrosswalkRow] = []
                for entry in crosswalk_rows:
                    component = entry.sbom_component or {}
                    component_ref: Optional[str] = None
                    if isinstance(component, Mapping):
                        component_ref = component.get("purl") or component.get("name")
                    if component_ref and str(component_ref) in suppressed_refs:
                        findings = [dict(item) for item in entry.findings]
                        if findings:
                            for finding in findings:
                                severity = self._normalise_sarif_severity(
                                    finding.get("level")
                                )
                                suppressed_counts[severity] += 1
                            updated_rows.append(
                                entry.with_filtered_findings([]).with_suppressed(
                                    "vex", findings
                                )
                            )
                        else:
                            updated_rows.append(entry)
                    else:
                        updated_rows.append(entry)
                crosswalk_rows = updated_rows
                if suppressed_counts:
                    for severity, count in suppressed_counts.items():
                        severity_counts[severity] = max(
                            0, severity_counts.get(severity, 0) - count
                        )
                        source_breakdown["sarif"][severity] = max(
                            0, source_breakdown["sarif"].get(severity, 0) - count
                        )
                    highest_severity = self._determine_highest_severity(severity_counts)
                    highest_trigger = None
            noise_reduction = {
                "initial": original_counts,
                "suppressed": dict(suppressed_counts),
                "final": dict(severity_counts),
                "suppressed_total": sum(suppressed_counts.values()),
            }

        crosswalk: List[dict[str, Any]] = [entry.to_dict() for entry in crosswalk_rows]

        cnapp_counts: Counter[str] = Counter()
        cnapp_exposures: List[Dict[str, Any]] = []
        if cnapp is not None:
            cnapp_sources = source_breakdown.setdefault("cnapp", Counter())
            for finding in cnapp.findings:
                mapped_severity = _CNAPP_SEVERITY_MAP.get(finding.severity, "low")
                cnapp_counts[mapped_severity] += 1
                severity_counts[mapped_severity] += 1
                cnapp_sources[mapped_severity] += 1
                if self._severity_index(mapped_severity) > self._severity_index(highest_severity):
                    highest_severity = mapped_severity
                    highest_trigger = {
                        "source": "cnapp",
                        "asset": finding.asset,
                        "severity": mapped_severity,
                        "type": finding.finding_type,
                    }
            for asset in cnapp.assets:
                traits: List[str] = []
                if asset.attributes.get("internet_exposed"):
                    traits.append("internet_exposed")
                if asset.attributes.get("partner_connected"):
                    traits.append("partner_connected")
                sensitivity = asset.attributes.get("data_sensitivity")
                if sensitivity:
                    traits.append(f"data:{sensitivity}")
                if traits:
                    cnapp_exposures.append({"asset": asset.asset_id, "traits": traits})

        severity_overview = {
            "highest": highest_severity,
            "counts": dict(severity_counts),
            "sources": {
                source: dict(counter) for source, counter in source_breakdown.items()
            },
        }
        if highest_trigger:
            severity_overview["trigger"] = highest_trigger

        processing_layer = ProcessingLayer()
        processing_result = processing_layer.evaluate(
            sbom_components=[component.to_dict() for component in sbom.components],
            sarif_findings=[finding.to_dict() for finding in sarif.findings],
            cve_records=[record.to_dict() for record in cve.records],
            context=(context.ssvc if context else {}),
            cnapp_exposures=cnapp_exposures,
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
            "severity_overview": severity_overview,
            "crosswalk": crosswalk,
            "processing_layer": processing_result.to_dict(),
        }

        if context is not None:
            result["business_context"] = context.to_dict()

        if vex is not None:
            result["vex_summary"] = vex.to_dict()
            if noise_reduction is not None:
                result["noise_reduction"] = noise_reduction

        if cnapp is not None:
            cnapp_summary: Dict[str, Any] = {
                "metadata": cnapp.metadata,
                "assets": [asset.to_dict() for asset in cnapp.assets],
                "findings": [finding.to_dict() for finding in cnapp.findings],
                "added_severity": dict(cnapp_counts),
            }
            if cnapp_exposures:
                cnapp_summary["exposures"] = cnapp_exposures
            if cnapp_counts:
                cnapp_summary["risk_multiplier"] = round(1.0 + 0.1 * sum(cnapp_counts.values()), 2)
            result["cnapp_summary"] = cnapp_summary

        if overlay is not None:
            modules_status: Dict[str, str] = {}
            executed_modules: List[str] = []
            custom_outcomes: List[Dict[str, Any]] = []
            knowledge_graph_builder = KnowledgeGraphService()

            overlay_metadata = dict(getattr(overlay, "metadata", {}) or {})
            runtime_warnings = list(overlay_metadata.get("runtime_warnings") or [])
            automation_requirements = overlay_metadata.get("automation_requirements")
            automation_ready = bool(overlay_metadata.get("automation_ready", not runtime_warnings))
            if runtime_warnings:
                result["runtime_warnings"] = runtime_warnings
            if automation_requirements:
                result["automation_requirements"] = automation_requirements

            context_summary: Optional[Dict[str, Any]] = None
            compliance_status: Optional[Dict[str, Any]] = None
            compliance_results: Optional[List[Dict[str, Any]]] = None
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
                if context is not None:
                    if isinstance(context_summary, Mapping):
                        summary = dict(context_summary)
                    else:
                        summary = {"summary": context_summary}
                    summary.setdefault("ssvc", context.ssvc)
                    summary.setdefault("components", context.components)
                    summary.setdefault("format", context.format)
                    context_summary = summary
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
                compliance_status = compliance_evaluator.evaluate(
                    result, context_summary
                )
                result["compliance_status"] = compliance_status
                modules_status["compliance"] = "executed"
                executed_modules.append("compliance")
            else:
                modules_status["compliance"] = "disabled"

            if overlay.is_module_enabled("policy_automation"):
                if automation_ready:
                    policy_automation = PolicyAutomation(overlay)
                    policy_plan = policy_automation.plan(
                        result, context_summary, compliance_status
                    )
                    execution_summary = policy_automation.execute(policy_plan["actions"])
                    policy_summary = dict(policy_plan)
                    policy_summary["execution"] = execution_summary
                    result["policy_automation"] = policy_summary
                    modules_status["policy_automation"] = "executed"
                    executed_modules.append("policy_automation")
                else:
                    reason = "automation prerequisites missing"
                    policy_summary = {
                        "status": "unavailable",
                        "actions": [],
                        "skipped": [],
                        "warnings": runtime_warnings,
                        "execution": {
                            "status": "skipped",
                            "reason": reason,
                            "warnings": runtime_warnings,
                        },
                    }
                    result["policy_automation"] = policy_summary
                    modules_status["policy_automation"] = "warning"
            else:
                modules_status["policy_automation"] = "disabled"

            compliance_results = evaluate_compliance(
                result.get("guardrail_evaluation"),
                policy_summary,
                overlay,
            )
            if compliance_results:
                result["compliance_results"] = compliance_results

            marketplace_recommendations = self._derive_marketplace_recommendations(
                compliance_status,
                result.get("guardrail_evaluation"),
                policy_summary,
            )
            result["marketplace_recommendations"] = marketplace_recommendations

            if overlay.is_module_enabled("vector_store"):
                try:
                    matcher = self._ensure_vector_matcher(overlay)
                    vector_matches = matcher.recommend_for_crosswalk(crosswalk)
                except Exception as exc:  # pragma: no cover - defensive guard
                    modules_status["vector_store"] = "error"
                    result["vector_similarity"] = {"error": str(exc)}
                else:
                    result["vector_similarity"] = {
                        "provider": matcher.provider_metadata,
                        "matches": vector_matches,
                    }
                    modules_status["vector_store"] = "executed"
                    executed_modules.append("vector_store")
            else:
                modules_status["vector_store"] = "disabled"

            knowledge_graph = knowledge_graph_builder.build(
                design_rows=rows,
                crosswalk=crosswalk,
                context_summary=context_summary,
                compliance_status=compliance_status,
                guardrail_evaluation=result.get("guardrail_evaluation"),
                marketplace_recommendations=marketplace_recommendations,
                severity_overview=severity_overview,
            )
            result["knowledge_graph"] = knowledge_graph

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
                refresh_summary = refresher.refresh(
                    cve, exploit_evaluator.last_refreshed
                )
                if refresh_summary:
                    result["exploit_feed_refresh"] = refresh_summary
                    if refresh_summary.get("status") == "refreshed":
                        exploit_evaluator = ExploitSignalEvaluator(
                            overlay.exploit_settings
                        )
                exploit_summary = exploit_evaluator.evaluate(cve)
                if exploit_summary:
                    result["exploitability_insights"] = exploit_summary
                modules_status["exploit_signals"] = "executed"
                executed_modules.append("exploit_signals")
            else:
                modules_status["exploit_signals"] = "disabled"

            if overlay.is_module_enabled("probabilistic"):
                probabilistic = ProbabilisticForecastEngine(
                    overlay.probabilistic_settings
                )
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
                performance_simulator = PerformanceSimulator(
                    overlay.performance_settings
                )
                performance_profile = performance_simulator.simulate(result, overlay)
                result["performance_profile"] = performance_profile
                modules_status["performance"] = "executed"
                executed_modules.append("performance")
            else:
                modules_status["performance"] = "disabled"

            if overlay.is_module_enabled("enhanced_decision"):
                enhanced_settings = dict(overlay.enhanced_decision_settings)
                if knowledge_graph:
                    enhanced_settings["knowledge_graph"] = knowledge_graph.get(
                        "graph", knowledge_graph
                    )
                enhanced_engine = EnhancedDecisionEngine(enhanced_settings)
                enhanced_payload = enhanced_engine.evaluate_pipeline(
                    result,
                    context_summary=context_summary,
                    compliance_status=compliance_status,
                    knowledge_graph=knowledge_graph,
                )
                result["enhanced_decision"] = enhanced_payload
                modules_status["enhanced_decision"] = "executed"
                executed_modules.append("enhanced_decision")
            else:
                modules_status["enhanced_decision"] = "disabled"

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
                    compliance_results=compliance_results,
                    vex=vex,
                    cnapp=cnapp,
                )
                custom_outcomes = execute_custom_modules(
                    overlay.custom_module_specs, context
                )
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
