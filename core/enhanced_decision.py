"""Multi-LLM consensus helpers powering the enhanced decision endpoints."""

from __future__ import annotations

import hashlib
import statistics
from dataclasses import dataclass, field
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
)

from core.llm_providers import (
    AnthropicMessagesProvider,
    BaseLLMProvider,
    DeterministicLLMProvider,
    GeminiProvider,
    LLMResponse,
    OpenAIChatProvider,
    SentinelCyberProvider,
)

_SEVERITY_ORDER = ("low", "medium", "high", "critical")
_MITRE_LIBRARY: Dict[str, Dict[str, Any]] = {
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "initial_access",
        "description": "Adversaries exploit internet exposed surfaces to gain footholds.",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "execution",
        "description": "Remote code execution paths leveraged via SQLi/RCE defects.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "defense_evasion",
        "description": "Credential reuse or stolen keys enabling privilege escalation.",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "credential_access",
        "description": "Persistence following exploitation of sensitive runtime services.",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "discovery",
        "description": "Reconnaissance activity against partner or internet exposed assets.",
    },
}


@dataclass
class ProviderSpec:
    name: str
    weight: float = 1.0
    style: str = "consensus"
    focus: List[str] = field(default_factory=list)


@dataclass
class ModelAnalysis:
    provider: str
    recommended_action: str
    confidence: float
    reasoning: str
    mitre_techniques: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    compliance_concerns: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    processing_time_ms: int = 0
    cost_usd: float = 0.0
    risk_assessment: str = "moderate"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "recommended_action": self.recommended_action,
            "confidence": round(self.confidence, 3),
            "reasoning": self.reasoning,
            "mitre_techniques": list(self.mitre_techniques),
            "attack_vectors": list(self.attack_vectors),
            "compliance_concerns": list(self.compliance_concerns),
            "evidence": list(self.evidence),
            "processing_time_ms": self.processing_time_ms,
            "cost_usd": round(self.cost_usd, 4),
            "risk_assessment": self.risk_assessment,
        }


@dataclass
class MultiLLMResult:
    final_decision: str
    consensus_confidence: float
    method: str
    individual_analyses: List[ModelAnalysis]
    disagreement_areas: List[str] = field(default_factory=list)
    expert_validation_required: bool = False
    summary: str = ""
    telemetry: Dict[str, Any] = field(default_factory=dict)
    signals: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "final_decision": self.final_decision,
            "consensus_confidence": round(self.consensus_confidence, 3),
            "method": self.method,
            "summary": self.summary,
            "individual_analyses": [
                analysis.to_dict() for analysis in self.individual_analyses
            ],
            "disagreement_areas": list(self.disagreement_areas),
            "expert_validation_required": self.expert_validation_required,
            "telemetry": dict(self.telemetry),
            "signals": dict(self.signals),
        }


class MultiLLMConsensusEngine:
    """Derive deterministic consensus verdicts for enhanced decisions."""

    DEFAULT_PROVIDERS = (
        ProviderSpec(
            "gpt-5", weight=1.0, style="strategist", focus=["mitre", "context"]
        ),
        ProviderSpec(
            "claude-3", weight=0.95, style="analyst", focus=["compliance", "guardrails"]
        ),
        ProviderSpec(
            "gemini-2", weight=0.9, style="signals", focus=["exploit", "cnapp"]
        ),
        ProviderSpec(
            "sentinel-cyber",
            weight=0.85,
            style="threat",
            focus=["marketplace", "agents"],
        ),
    )

    def __init__(self, settings: Optional[Mapping[str, Any]] = None) -> None:
        settings = dict(settings or {})
        providers: List[ProviderSpec] = []
        for entry in settings.get("providers", []):
            if not isinstance(entry, Mapping):
                continue
            name = str(entry.get("name") or "").strip()
            if not name:
                continue
            weight = float(entry.get("weight", 1.0) or 1.0)
            style = str(entry.get("style") or "consensus")
            focus = [
                str(value).strip().lower()
                for value in entry.get("focus", [])
                if isinstance(value, str) and value.strip()
            ]
            providers.append(
                ProviderSpec(name=name, weight=weight, style=style, focus=focus)
            )
        self.providers: List[ProviderSpec] = providers or list(self.DEFAULT_PROVIDERS)
        self.knowledge_graph = settings.get(
            "knowledge_graph",
            {
                "nodes": [
                    {"id": "service", "type": "asset"},
                    {"id": "finding", "type": "vulnerability"},
                    {"id": "control", "type": "compliance"},
                ],
                "edges": [
                    {"source": "service", "target": "finding", "type": "impacted_by"},
                    {"source": "finding", "target": "control", "type": "mitigated_by"},
                ],
            },
        )
        self.baseline_confidence = float(settings.get("baseline_confidence", 0.78))
        self.provider_clients = self._build_provider_clients(settings)

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------
    def evaluate(
        self,
        *,
        severity_overview: Mapping[str, Any],
        guardrail: Optional[Mapping[str, Any]] = None,
        context_summary: Optional[Mapping[str, Any]] = None,
        compliance_status: Optional[Mapping[str, Any]] = None,
        cnapp_summary: Optional[Mapping[str, Any]] = None,
        exploitability: Optional[Mapping[str, Any]] = None,
        noise_reduction: Optional[Mapping[str, Any]] = None,
        ai_agent_analysis: Optional[Mapping[str, Any]] = None,
        marketplace_recommendations: Optional[Iterable[Mapping[str, Any]]] = None,
        knowledge_graph: Optional[Mapping[str, Any]] = None,
    ) -> MultiLLMResult:
        if knowledge_graph is not None:
            self.knowledge_graph = knowledge_graph
        highest = _normalise_severity(severity_overview.get("highest"))
        counts = _as_counter(severity_overview.get("counts"))
        total_findings = sum(counts.values())
        base_action, base_confidence, mitre_candidates = self._base_profile(
            highest, total_findings
        )
        guardrail_status = (guardrail or {}).get("status", "pass")
        compliance_gaps = _extract_compliance_gaps(compliance_status)
        exposures = _extract_exposures(cnapp_summary)
        exploit_stats = _extract_exploit_stats(exploitability)
        agent_components = _extract_agent_components(ai_agent_analysis)
        suppressed = int((noise_reduction or {}).get("suppressed_total", 0))
        marketplace_focus = [
            item.get("id")
            for item in marketplace_recommendations or []
            if isinstance(item, Mapping)
        ]
        context_details = dict(context_summary or {})
        analysis_context = self._analysis_context(
            context_details,
            counts,
            highest,
            guardrail_status,
            compliance_gaps,
            exposures,
            exploit_stats,
            agent_components,
            suppressed,
            marketplace_focus,
        )
        prompt = self._build_prompt(analysis_context)

        analyses: List[ModelAnalysis] = []
        actions: List[str] = []
        confidences: List[float] = []
        provider_metadata: List[Dict[str, Any]] = []
        max_processing: int = 0
        for index, provider in enumerate(self.providers):
            action = base_action
            confidence = base_confidence * provider.weight
            if provider.style == "analyst" and compliance_gaps:
                action = _promote(action)
                confidence += 0.04
            if provider.style == "signals" and exploit_stats["kev_count"]:
                action = _promote(action)
                confidence += 0.05
            if provider.style == "threat" and exposures:
                confidence += 0.03
            if guardrail_status in {"warn", "fail"} and "guardrails" in provider.focus:
                action = _promote(action)
                confidence += 0.02
            if suppressed and "context" in provider.focus:
                confidence -= 0.03

            jitter = self._jitter(provider.name, highest, index)
            confidence = max(0.42, min(0.99, confidence + jitter))
            confidences.append(confidence)
            actions.append(action)

            mitre = list({*mitre_candidates, *_mitre_for_focus(provider.focus)})[:4]
            attack_vectors = _attack_vectors(exposures, exploit_stats)
            compliance_concerns = compliance_gaps[:2]
            reasoning = self._reasoning(
                provider,
                action,
                highest,
                counts,
                guardrail_status,
                exploit_stats,
                exposures,
                compliance_concerns,
                agent_components,
                suppressed,
            )
            mitigation_hints = {
                "mitre_candidates": mitre,
                "compliance": compliance_concerns,
                "attack_vectors": attack_vectors,
            }
            provider_client = (
                self.provider_clients[index]
                if index < len(self.provider_clients)
                else self.provider_clients[-1]
            )
            llm_result: LLMResponse = provider_client.analyse(
                prompt=prompt,
                context=analysis_context,
                default_action=action,
                default_confidence=confidence,
                default_reasoning=reasoning,
                mitigation_hints=mitigation_hints,
            )
            if llm_result.recommended_action:
                action = str(llm_result.recommended_action).lower()
            confidence = max(0.42, min(0.99, llm_result.confidence or confidence))
            reasoning = llm_result.reasoning or reasoning
            mitre = list({*mitre, *llm_result.mitre_techniques})[:4]
            attack_vectors = list(llm_result.attack_vectors or attack_vectors)
            compliance_concerns = list(
                llm_result.compliance_concerns or compliance_concerns
            )
            metadata = dict(llm_result.metadata or {})
            provider_metadata.append({"provider": provider.name, **metadata})

            processing_time = int(320 + abs(jitter) * 120 + index * 40)
            max_processing = max(max_processing, processing_time)
            cost = 0.18 + 0.02 * index
            analyses.append(
                ModelAnalysis(
                    provider=provider.name,
                    recommended_action=action,
                    confidence=confidence,
                    reasoning=reasoning,
                    mitre_techniques=mitre,
                    attack_vectors=attack_vectors,
                    compliance_concerns=compliance_concerns,
                    evidence=[
                        {"type": "severity", "value": counts},
                        {"type": "guardrail", "value": guardrail_status},
                        {"type": "llm_metadata", "value": metadata},
                    ],
                    processing_time_ms=processing_time,
                    cost_usd=cost,
                    risk_assessment=self._risk_bucket(confidence, exploit_stats),
                )
            )

        final_decision = _majority(actions, base_action)
        consensus_confidence = (
            statistics.fmean(confidences) if confidences else self.baseline_confidence
        )
        if exploit_stats["kev_count"]:
            consensus_confidence += 0.05
        if exposures:
            consensus_confidence += 0.03
        if suppressed:
            consensus_confidence -= 0.02
        consensus_confidence = max(0.45, min(0.99, consensus_confidence))
        expert_validation = (
            consensus_confidence < 0.7 or len(set(actions)) > 1 or bool(compliance_gaps)
        )

        disagreement = []
        if len(set(actions)) > 1:
            disagreement.append("model_action_split")
        if compliance_gaps:
            disagreement.append("compliance_gaps_present")
        if agent_components:
            disagreement.append("ai_agent_components")

        summary = _build_summary(
            final_decision, consensus_confidence, counts, exposures, exploit_stats
        )
        signals = self._signals(final_decision, consensus_confidence, exploit_stats)

        telemetry = {
            "models_consulted": len(analyses),
            "providers": [analysis.provider for analysis in analyses],
            "provider_modes": provider_metadata,
            "mean_confidence": (
                round(statistics.fmean(confidences), 3) if confidences else None
            ),
            "max_processing_time_ms": max_processing,
            "knowledge_graph": self.knowledge_graph_summary,
            "marketplace_references": marketplace_focus,
        }

        return MultiLLMResult(
            final_decision=final_decision,
            consensus_confidence=consensus_confidence,
            method="multi-llm-weighted-consensus",
            individual_analyses=analyses,
            disagreement_areas=disagreement,
            expert_validation_required=expert_validation,
            summary=summary,
            telemetry=telemetry,
            signals=signals,
        )

    def _build_provider_clients(
        self, settings: Mapping[str, Any]
    ) -> List[BaseLLMProvider]:
        llm_settings = settings.get("llm", {}) if isinstance(settings, Mapping) else {}
        clients: List[BaseLLMProvider] = []
        for spec in self.providers:
            config: Mapping[str, Any]
            if isinstance(llm_settings, Mapping):
                config = (
                    llm_settings.get(spec.name)
                    or llm_settings.get(spec.name.lower())
                    or {}
                )
            else:
                config = {}
            clients.append(self._provider_from_spec(spec, config))
        return clients or [
            DeterministicLLMProvider(spec.name, style=spec.style, focus=spec.focus)
            for spec in self.providers
        ]

    def _provider_from_spec(
        self, spec: ProviderSpec, config: Mapping[str, Any]
    ) -> BaseLLMProvider:
        config = dict(config or {})
        timeout = float(config.get("timeout", 30.0))
        focus = spec.focus
        style = spec.style
        name = spec.name.lower()
        if "gpt" in name or "openai" in name:
            return OpenAIChatProvider(
                spec.name,
                model=str(config.get("model", config.get("model_name", "gpt-4o-mini"))),
                api_key_envs=config.get("api_key_envs"),
                timeout=timeout,
                focus=focus,
                style=style,
            )
        if "claude" in name or "anthropic" in name:
            return AnthropicMessagesProvider(
                spec.name,
                model=str(config.get("model", "claude-3-5-sonnet-20240620")),
                api_key_envs=config.get("api_key_envs"),
                timeout=timeout,
                focus=focus,
                style=style,
            )
        if "gemini" in name or "google" in name:
            return GeminiProvider(
                spec.name,
                model=str(config.get("model", "gemini-1.5-pro")),
                api_key_envs=config.get("api_key_envs"),
                timeout=timeout,
                focus=focus,
                style=style,
            )
        if "sentinel" in name or "cyber" in name:
            return SentinelCyberProvider(spec.name, style=style, focus=focus)
        return DeterministicLLMProvider(spec.name, style=style, focus=focus)

    def _analysis_context(
        self,
        context_details: Mapping[str, Any],
        counts: Mapping[str, int],
        highest: str,
        guardrail_status: str,
        compliance_gaps: Sequence[str],
        exposures: Sequence[Mapping[str, Any]],
        exploit_stats: Mapping[str, Any],
        agent_components: Sequence[str],
        suppressed: int,
        marketplace_focus: Sequence[Any],
    ) -> Dict[str, Any]:
        service_name = (
            context_details.get("service")
            or context_details.get("service_name")
            or context_details.get("application")
            or "unknown-service"
        )
        environment = context_details.get("environment", "production")
        business_impact = context_details.get("business_impact") or context_details.get(
            "business_context"
        )
        return {
            "service_name": service_name,
            "environment": environment,
            "business_context": business_impact or {},
            "severity_counts": dict(counts),
            "highest_severity": highest,
            "guardrail_status": guardrail_status,
            "compliance_gaps": list(compliance_gaps),
            "exposures": [dict(item) for item in exposures],
            "exploitability": dict(exploit_stats),
            "ai_agents": list(agent_components),
            "noise_suppressed": suppressed,
            "marketplace": list(marketplace_focus),
        }

    def _build_prompt(self, analysis_context: Mapping[str, Any]) -> str:
        severity_counts = analysis_context.get("severity_counts", {})
        severity_section = (
            ", ".join(f"{key}:{value}" for key, value in severity_counts.items())
            or "none"
        )
        compliance = analysis_context.get("compliance_gaps", [])
        compliance_text = ", ".join(compliance) if compliance else "none"
        exposures = analysis_context.get("exposures", [])
        exposure_text = (
            ", ".join(
                f"{item.get('asset')}:{item.get('type')}"
                for item in exposures
                if isinstance(item, Mapping)
            )
            or "none"
        )
        exploit = analysis_context.get("exploitability", {})
        exploit_text = (
            ", ".join(f"{key}:{value}" for key, value in exploit.items()) or "none"
        )
        agents = analysis_context.get("ai_agents", [])
        agent_text = ", ".join(str(value) for value in agents) or "none"
        return (
            "Security decision context\n"
            f"Service: {analysis_context.get('service_name')}\n"
            f"Environment: {analysis_context.get('environment')}\n"
            f"Highest severity: {analysis_context.get('highest_severity')}\n"
            f"Severity counts: {severity_section}\n"
            f"Guardrail status: {analysis_context.get('guardrail_status')}\n"
            f"Compliance gaps: {compliance_text}\n"
            f"Exposures: {exposure_text}\n"
            f"Exploit signals: {exploit_text}\n"
            f"AI agent components: {agent_text}\n"
            f"Noise suppressed: {analysis_context.get('noise_suppressed')}\n"
            f"Marketplace focus: {', '.join(analysis_context.get('marketplace', [])) or 'none'}"
        )

    def evaluate_from_payload(self, payload: Mapping[str, Any]) -> MultiLLMResult:
        findings = [
            item
            for item in payload.get("security_findings", [])
            if isinstance(item, Mapping)
        ]
        counts: MutableMapping[str, int] = {severity: 0 for severity in _SEVERITY_ORDER}
        for finding in findings:
            severity = _normalise_severity(
                finding.get("severity") or finding.get("level")
            )
            counts[severity] = counts.get(severity, 0) + 1
        highest = _determine_highest(counts)
        severity_overview = {
            "highest": highest,
            "counts": dict(counts),
            "sources": {"payload": dict(counts)},
        }
        guardrail = {
            "status": (
                "fail"
                if _SEVERITY_ORDER.index(highest) >= _SEVERITY_ORDER.index("high")
                else "warn"
                if highest == "medium"
                else "pass"
            )
        }
        context_summary = {
            "service": payload.get("service_name"),
            "environment": payload.get("environment", "production"),
            "business_impact": payload.get("business_context", {}),
        }
        compliance = {
            "requirements": payload.get("compliance_requirements", []),
        }
        return self.evaluate(
            severity_overview=severity_overview,
            guardrail=guardrail,
            context_summary=context_summary,
            compliance_status=compliance,
            cnapp_summary=payload.get("cnapp"),
            exploitability=payload.get("exploitability"),
            noise_reduction=None,
            ai_agent_analysis=payload.get("ai_agent_analysis"),
            marketplace_recommendations=payload.get("marketplace_recommendations"),
            knowledge_graph=payload.get("knowledge_graph"),
        )

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------
    @property
    def provider_names(self) -> List[str]:
        return [provider.name for provider in self.providers]

    @property
    def knowledge_graph_summary(self) -> Dict[str, Any]:
        nodes = (
            self.knowledge_graph.get("nodes", [])
            if isinstance(self.knowledge_graph, Mapping)
            else []
        )
        edges = (
            self.knowledge_graph.get("edges", [])
            if isinstance(self.knowledge_graph, Mapping)
            else []
        )
        return {
            "nodes": len(list(nodes)),
            "edges": len(list(edges)),
            "description": "Context-to-control knowledge graph for consensus telemetry",
        }

    @staticmethod
    def ssvc_label(decision: str, confidence: Optional[float] = None) -> str:
        decision = str(decision or "track").lower()
        if decision in {"block", "deny", "stop"}:
            return "Act"
        if decision in {"review", "hold"}:
            return "Attend"
        if confidence is not None and confidence < 0.55:
            return "Attend"
        return "Track"

    # internal helpers -------------------------------------------------
    def _base_profile(
        self, highest: str, total_findings: int
    ) -> tuple[str, float, List[str]]:
        index = _SEVERITY_ORDER.index(highest) if highest in _SEVERITY_ORDER else 0
        if index >= 3:
            return (
                "block",
                max(self.baseline_confidence, 0.9),
                ["T1190", "T1059", "T1078"],
            )
        if index == 2:
            return (
                "review",
                max(self.baseline_confidence - 0.05, 0.78),
                ["T1059", "T1046", "T1078"],
            )
        if index == 1:
            return (
                "review",
                max(self.baseline_confidence - 0.12, 0.7),
                ["T1046", "T1190"],
            )
        if total_findings == 0:
            return "allow", 0.6, ["T1046"]
        return "allow", max(self.baseline_confidence - 0.18, 0.65), ["T1046"]

    @staticmethod
    def _risk_bucket(confidence: float, exploit_stats: Mapping[str, Any]) -> str:
        if exploit_stats.get("kev_count"):
            return "critical"
        if confidence >= 0.85:
            return "high"
        if confidence >= 0.7:
            return "elevated"
        return "moderate"

    @staticmethod
    def _jitter(provider: str, highest: str, index: int) -> float:
        seed = f"{provider}:{highest}:{index}"
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
        raw = int(digest[:8], 16) / 0xFFFFFFFF
        return (raw - 0.5) * 0.06

    def _reasoning(
        self,
        provider: ProviderSpec,
        action: str,
        highest: str,
        counts: Mapping[str, int],
        guardrail_status: str,
        exploit_stats: Mapping[str, Any],
        exposures: Sequence[Mapping[str, Any]],
        compliance_concerns: Sequence[str],
        agent_components: Sequence[str],
        suppressed: int,
    ) -> str:
        phrases: List[str] = []
        total = sum(counts.values())
        phrases.append(
            f"Detected {total} findings with peak severity {highest.upper()}"
        )
        if guardrail_status in {"warn", "fail"}:
            phrases.append(f"Guardrail status '{guardrail_status}' requires escalation")
        if exploit_stats.get("kev_count"):
            phrases.append("Known exploited vulnerabilities present")
        if exploit_stats.get("epss_max"):
            phrases.append(
                f"EPSS probability peaked at {exploit_stats['epss_max']:.2f}"
            )
        if exposures:
            assets = ", ".join(
                sorted(
                    {
                        exposure.get("asset")
                        for exposure in exposures
                        if exposure.get("asset")
                    }
                )
            )
            phrases.append(f"CNAPP exposure detected on {assets}")
        if compliance_concerns:
            phrases.append("Compliance gaps open: " + ", ".join(compliance_concerns))
        if agent_components and "agents" in provider.focus:
            phrases.append("AI-agent surfaces require sentinel oversight")
        if suppressed:
            phrases.append(f"VEX suppressed {suppressed} noisy findings")
        phrases.append(
            f"Recommended action: {action.upper()} based on multi-signal weighting"
        )
        return ". ".join(phrases)

    def _signals(
        self,
        decision: str,
        confidence: float,
        exploit_stats: Mapping[str, Any],
    ) -> Dict[str, Any]:
        return {
            "kev_count": exploit_stats.get("kev_count", 0),
            "epss_count": exploit_stats.get("epss_count", 0),
            "epss_max": exploit_stats.get("epss_max"),
            "last_updated_epss": exploit_stats.get("last_updated_epss"),
            "last_updated_kev": exploit_stats.get("last_updated_kev"),
            "ssvc_label": self.ssvc_label(decision, confidence),
        }


# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------


def _normalise_severity(value: Any) -> str:
    text = str(value or "low").strip().lower()
    if text not in _SEVERITY_ORDER:
        return "low"
    return text


def _as_counter(payload: Any) -> Dict[str, int]:
    if isinstance(payload, Mapping):
        return {
            key: int(value) for key, value in payload.items() if isinstance(value, int)
        }
    return {severity: 0 for severity in _SEVERITY_ORDER}


def _determine_highest(counts: Mapping[str, int]) -> str:
    highest = "low"
    for severity in _SEVERITY_ORDER:
        if counts.get(severity):
            highest = severity
    return highest


def _promote(action: str) -> str:
    if action == "allow":
        return "review"
    if action == "review":
        return "block"
    return action


def _mitre_for_focus(focus: Iterable[str]) -> List[str]:
    techniques: List[str] = []
    for token in focus:
        if token == "exploit":
            techniques.extend(["T1190", "T1059"])
        if token == "cnapp":
            techniques.extend(["T1046"])
        if token == "guardrails":
            techniques.extend(["T1078"])
    return techniques


def _attack_vectors(
    exposures: Sequence[Mapping[str, Any]],
    exploit_stats: Mapping[str, Any],
) -> List[str]:
    vectors: List[str] = []
    for exposure in exposures:
        traits = exposure.get("traits") if isinstance(exposure, Mapping) else None
        if not traits:
            continue
        vectors.extend(str(trait) for trait in traits if trait)
    if exploit_stats.get("kev_count"):
        vectors.append("kev")
    if exploit_stats.get("epss_count"):
        vectors.append("epss")
    return sorted(set(vectors))


def _extract_exposures(summary: Optional[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(summary, Mapping):
        return []
    exposures = summary.get("exposures")
    if isinstance(exposures, list):
        return [exposure for exposure in exposures if isinstance(exposure, Mapping)]
    return []


def _extract_compliance_gaps(status: Optional[Mapping[str, Any]]) -> List[str]:
    if not isinstance(status, Mapping):
        return []
    gaps: List[str] = []
    frameworks = status.get("frameworks")
    if isinstance(frameworks, Iterable):
        for framework in frameworks:
            if not isinstance(framework, Mapping):
                continue
            coverage = framework.get("coverage")
            if isinstance(coverage, (int, float)) and coverage < 1.0:
                identifier = framework.get("id") or framework.get("name")
                if identifier:
                    gaps.append(str(identifier))
    return gaps


def _extract_exploit_stats(summary: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if not isinstance(summary, Mapping):
        return {
            "kev_count": 0,
            "epss_count": 0,
            "epss_max": None,
            "last_updated_epss": None,
            "last_updated_kev": None,
        }
    overview = (
        summary.get("overview")
        if isinstance(summary.get("overview"), Mapping)
        else summary
    )
    kev_count = int(
        overview.get("kev_matches")
        or overview.get("kev_hits")
        or overview.get("kev_count")
        or 0
    )
    epss_records = overview.get("epss_scores") or overview.get("epss") or []
    if isinstance(epss_records, Mapping):
        epss_values = [
            float(value)
            for value in epss_records.values()
            if isinstance(value, (int, float))
        ]
    elif isinstance(epss_records, Iterable):
        epss_values = [
            float(value) for value in epss_records if isinstance(value, (int, float))
        ]
    else:
        epss_values = []
    epss_count = len(epss_values)
    epss_max = max(epss_values) if epss_values else overview.get("max_epss")
    return {
        "kev_count": kev_count,
        "epss_count": epss_count,
        "epss_max": float(epss_max) if isinstance(epss_max, (int, float)) else None,
        "last_updated_epss": overview.get("last_updated_epss"),
        "last_updated_kev": overview.get("last_updated_kev"),
    }


def _extract_agent_components(summary: Optional[Mapping[str, Any]]) -> List[str]:
    if not isinstance(summary, Mapping):
        return []
    analysis = summary.get("analysis")
    if isinstance(analysis, Mapping):
        components = analysis.get("components")
        if isinstance(components, Iterable):
            return [
                str(component) for component in components if isinstance(component, str)
            ]
    summary_section = (
        summary.get("summary") if isinstance(summary.get("summary"), Mapping) else {}
    )
    components = summary_section.get("components_with_agents")
    if isinstance(components, Iterable):
        return [
            str(component) for component in components if isinstance(component, str)
        ]
    if isinstance(components, int) and components > 0:
        return ["detected"]
    return []


def _build_summary(
    decision: str,
    confidence: float,
    counts: Mapping[str, int],
    exposures: Sequence[Mapping[str, Any]],
    exploit_stats: Mapping[str, Any],
) -> str:
    total = sum(counts.values())
    exposure_assets = ", ".join(
        sorted(
            {exposure.get("asset") for exposure in exposures if exposure.get("asset")}
        )
    )
    exposure_text = f" Exposure across {exposure_assets}." if exposure_assets else ""
    exploit_text = (
        " Known exploited vulnerabilities detected."
        if exploit_stats.get("kev_count")
        else ""
    )
    return (
        f"Consensus {decision.upper()} at {confidence * 100:.1f}% confidence across {total} findings."
        + exposure_text
        + exploit_text
    )


def _majority(actions: Sequence[str], fallback: str) -> str:
    counts: Dict[str, int] = {}
    for action in actions:
        counts[action] = counts.get(action, 0) + 1
    if not counts:
        return fallback
    sorted_actions = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    top_action, top_count = sorted_actions[0]
    if len(sorted_actions) > 1 and sorted_actions[1][1] == top_count:
        return fallback
    return top_action


# ----------------------------------------------------------------------
# Enhanced decision facade combining consensus with metrics
# ----------------------------------------------------------------------


class EnhancedDecisionEngine:
    """High-level facade consumed by the API and pipeline."""

    def __init__(self, settings: Optional[Mapping[str, Any]] = None) -> None:
        self.settings = dict(settings or {})
        self.consensus = MultiLLMConsensusEngine(self.settings)
        self._metrics: Dict[str, Any] = {"total_runs": 0}
        self._last_signals: Dict[str, Any] = {
            "kev_count": 0,
            "epss_count": 0,
            "last_updated_epss": None,
            "last_updated_kev": None,
            "ssvc_label": "Track",
        }

    def evaluate_pipeline(
        self,
        pipeline_result: Mapping[str, Any],
        *,
        context_summary: Optional[Mapping[str, Any]] = None,
        compliance_status: Optional[Mapping[str, Any]] = None,
        knowledge_graph: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        result = self.consensus.evaluate(
            severity_overview=pipeline_result.get("severity_overview", {}),
            guardrail=pipeline_result.get("guardrail_evaluation"),
            context_summary=context_summary or pipeline_result.get("context_summary"),
            compliance_status=compliance_status
            or pipeline_result.get("compliance_status"),
            cnapp_summary=pipeline_result.get("cnapp_summary"),
            exploitability=pipeline_result.get("exploitability_insights"),
            noise_reduction=pipeline_result.get("noise_reduction"),
            ai_agent_analysis=pipeline_result.get("ai_agent_analysis"),
            marketplace_recommendations=pipeline_result.get(
                "marketplace_recommendations"
            ),
            knowledge_graph=knowledge_graph or pipeline_result.get("knowledge_graph"),
        )
        return self._record(result)

    def analyse_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        result = self.consensus.evaluate_from_payload(payload)
        return self._record(result)

    def capabilities(self) -> Dict[str, Any]:
        return {
            "status": "ready",
            "api_version": "enhanced_v1",
            "supported_llms": self.consensus.provider_names,
            "runs": self._metrics.get("total_runs", 0),
            "knowledge_graph": self.consensus.knowledge_graph_summary,
            "last_decision": self._metrics.get("last_decision"),
            "mean_confidence": self._metrics.get("mean_confidence"),
        }

    def signals(
        self, *, verdict: Optional[str] = None, confidence: Optional[float] = None
    ) -> Dict[str, Any]:
        payload = dict(self._last_signals)
        if verdict is not None:
            payload["ssvc_label"] = self.consensus.ssvc_label(verdict, confidence)
        if confidence is not None:
            payload["confidence"] = round(confidence, 3)
        else:
            payload["confidence"] = self._metrics.get("last_confidence")
        payload["models_consulted"] = self._metrics.get(
            "last_models", len(self.consensus.provider_names)
        )
        return payload

    # internal ---------------------------------------------------------
    def _record(self, result: MultiLLMResult) -> Dict[str, Any]:
        payload = result.to_dict()
        signals = payload.get("signals", {})
        self._last_signals = signals
        self._metrics["total_runs"] = int(self._metrics.get("total_runs", 0)) + 1
        self._metrics["last_decision"] = payload.get("final_decision")
        self._metrics["last_confidence"] = payload.get("consensus_confidence")
        self._metrics["last_models"] = len(payload.get("individual_analyses", []))
        confidences = [
            analysis["confidence"]
            for analysis in payload.get("individual_analyses", [])
            if isinstance(analysis, Mapping)
        ]
        if confidences:
            self._metrics["mean_confidence"] = round(statistics.fmean(confidences), 3)
        return payload


__all__ = [
    "EnhancedDecisionEngine",
    "MultiLLMConsensusEngine",
    "MultiLLMResult",
    "ModelAnalysis",
]
