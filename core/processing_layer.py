"""Advanced processing layer implementing Bayesian, Markov, and graph analytics."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence

try:  # networkx is optional but preferred for rich graph metrics
    import networkx as nx  # type: ignore[import]
except Exception:  # pragma: no cover - optional dependency
    nx = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

try:  # pgmpy is declared in requirements and provides Bayesian inference
    from pgmpy.factors.discrete import TabularCPD
    from pgmpy.inference import VariableElimination
    from pgmpy.models import BayesianNetwork
except Exception:  # pragma: no cover - defensive guard for environments without pgmpy
    BayesianNetwork = None  # type: ignore[assignment]
    VariableElimination = None  # type: ignore[assignment]
    TabularCPD = None  # type: ignore[assignment]

try:  # optional dependency for probabilistic modelling
    from pomegranate import BayesianNetwork as PomegranateBayes  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    PomegranateBayes = None  # type: ignore[assignment]

try:  # optional dependency for Markov modelling
    import mchmm  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    mchmm = None  # type: ignore[assignment]


@dataclass
class ProcessingLayerResult:
    """Structured response returned by the advanced processing layer."""

    bayesian_priors: Dict[str, float]
    markov_projection: Dict[str, Any]
    non_cve_findings: List[Dict[str, Any]]
    knowledge_graph: Dict[str, Any]
    library_status: Dict[str, bool]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bayesian_priors": self.bayesian_priors,
            "markov_projection": self.markov_projection,
            "non_cve_findings": self.non_cve_findings,
            "knowledge_graph": self.knowledge_graph,
            "library_status": self.library_status,
        }


class ProcessingLayer:
    """Combine Bayesian inference, Markov projections, and knowledge graph analytics."""

    def __init__(self) -> None:
        self.pgmpy_available = (
            BayesianNetwork is not None and VariableElimination is not None
        )
        self.pomegranate_available = PomegranateBayes is not None
        self.mchmm_available = mchmm is not None
        self.networkx_available = nx is not None
        if not self.networkx_available:
            logger.warning(
                "networkx not available; knowledge graph metrics will use simplified fallbacks"
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def evaluate(
        self,
        *,
        sbom_components: Sequence[Mapping[str, Any]],
        sarif_findings: Sequence[Mapping[str, Any]],
        cve_records: Sequence[Mapping[str, Any]],
        context: Optional[Mapping[str, Any]] = None,
        cnapp_exposures: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> ProcessingLayerResult:
        priors = self._compute_bayesian_priors(context or {})
        markov_projection = self._build_markov_projection(cve_records)
        non_cve = self._summarise_non_cve_findings(sarif_findings)
        graph_snapshot = self._build_knowledge_graph(
            sbom_components,
            sarif_findings,
            cve_records,
            cnapp_exposures or (),
        )
        status = {
            "pgmpy": self.pgmpy_available,
            "pomegranate": self.pomegranate_available,
            "mchmm": self.mchmm_available,
            "networkx": self.networkx_available,
        }
        return ProcessingLayerResult(
            bayesian_priors=priors,
            markov_projection=markov_projection,
            non_cve_findings=non_cve,
            knowledge_graph=graph_snapshot,
            library_status=status,
        )

    # ------------------------------------------------------------------
    # Bayesian inference helpers
    # ------------------------------------------------------------------
    def _compute_bayesian_priors(self, context: Mapping[str, Any]) -> Dict[str, float]:
        defaults = {
            "exploitation": str(context.get("exploitation") or "none").lower(),
            "exposure": str(context.get("exposure") or "controlled").lower(),
            "utility": str(context.get("utility") or "efficient").lower(),
            "safety_impact": str(context.get("safety_impact") or "negligible").lower(),
            "mission_impact": str(context.get("mission_impact") or "degraded").lower(),
        }
        if not self.pgmpy_available:
            return {**defaults, "risk": "medium", "confidence": 0.5}  # type: ignore[dict-item]

        assert (
            BayesianNetwork is not None
            and VariableElimination is not None
            and TabularCPD is not None
        )
        model = BayesianNetwork(
            [
                ("exploitation", "risk"),
                ("exposure", "risk"),
                ("utility", "risk"),
                ("safety_impact", "risk"),
                ("mission_impact", "risk"),
            ]
        )
        exploitation_cpd = TabularCPD(
            variable="exploitation",
            variable_card=3,
            values=[[0.6], [0.3], [0.1]],
            state_names={"exploitation": ["none", "poc", "active"]},
        )
        exposure_cpd = TabularCPD(
            variable="exposure",
            variable_card=3,
            values=[[0.5], [0.3], [0.2]],
            state_names={"exposure": ["controlled", "limited", "open"]},
        )
        risk_cpd = TabularCPD(
            variable="risk",
            variable_card=4,
            values=[[0.35] * 324, [0.3] * 324, [0.2] * 324, [0.15] * 324],
            evidence=[
                "exploitation",
                "exposure",
                "utility",
                "safety_impact",
                "mission_impact",
            ],
            evidence_card=[3, 3, 3, 4, 3],
            state_names={
                "risk": ["low", "medium", "high", "critical"],
                "utility": ["laborious", "efficient", "super_effective"],
                "safety_impact": ["negligible", "marginal", "major", "hazardous"],
                "mission_impact": ["degraded", "crippled", "mev"],
            },
        )
        try:
            model.add_cpds(exploitation_cpd, exposure_cpd, risk_cpd)
            inference = VariableElimination(model)
            evidence = {key: value for key, value in defaults.items() if value}
            result = inference.query(["risk"], evidence=evidence)
            distribution = {
                state: float(prob)
                for state, prob in zip(result.state_names["risk"], result.values)
            }
        except Exception:  # pragma: no cover - pgmpy misconfiguration
            return {**defaults, "risk": "medium", "confidence": 0.5}  # type: ignore[dict-item]
        risk_level = max(distribution, key=distribution.get)  # type: ignore[arg-type]
        return {  # type: ignore[arg-type]
            **defaults,  # type: ignore[arg-type]
            "risk": risk_level,  # type: ignore[arg-type]
            "confidence": round(distribution[risk_level], 3),  # type: ignore[arg-type]
            "distribution": distribution,  # type: ignore[arg-type]
        }  # type: ignore[arg-type]

    # type: ignore[arg-type]
    # ------------------------------------------------------------------  # type: ignore[arg-type]
    # Markov modelling helpers
    # ------------------------------------------------------------------
    def _build_markov_projection(
        self, cve_records: Sequence[Mapping[str, Any]]
    ) -> Dict[str, Any]:
        if not cve_records:
            return {"transitions": [], "library": "fallback"}

        if self.mchmm_available:
            try:
                chain = mchmm.MarkovChain()
                states = [
                    record.get("severity", "medium").lower() for record in cve_records
                ]
                chain.fit([states])
                forecast = chain.predict(states[-1], n_steps=3)
                return {
                    "transitions": list(chain.transition_matrix.tolist()),
                    "forecast": list(forecast),
                    "library": "mchmm",
                }
            except Exception:  # pragma: no cover - handle modelling error
                pass

        severities = [
            record.get("severity", "medium").lower() for record in cve_records
        ]
        severity_counts = {level: severities.count(level) for level in set(severities)}
        ordered = sorted(
            severity_counts.items(), key=lambda item: item[1], reverse=True
        )
        projection = [level for level, _ in ordered[:3]]
        return {
            "transitions": severity_counts,
            "forecast": projection,
            "library": "heuristic",
        }

    # ------------------------------------------------------------------
    # SARIF helpers
    # ------------------------------------------------------------------
    def _summarise_non_cve_findings(
        self, sarif_findings: Sequence[Mapping[str, Any]]
    ) -> List[Dict[str, Any]]:
        catalogue: List[Dict[str, Any]] = []
        for finding in sarif_findings:
            if not isinstance(finding, Mapping):
                continue
            related = finding.get("raw", {}).get("properties", {})
            cve = related.get("cve") or related.get("CVE")
            if cve:
                continue
            entry = {
                "rule_id": finding.get("rule_id") or finding.get("ruleId"),
                "message": finding.get("message"),
                "severity": finding.get("level"),
                "file": finding.get("file"),
            }
            catalogue.append({k: v for k, v in entry.items() if v is not None})
        return catalogue[:10]

    # ------------------------------------------------------------------
    # Graph helpers
    # ------------------------------------------------------------------
    def _build_knowledge_graph(
        self,
        sbom_components: Sequence[Mapping[str, Any]],
        sarif_findings: Sequence[Mapping[str, Any]],
        cve_records: Sequence[Mapping[str, Any]],
        cnapp_exposures: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        if nx is None:
            return self._build_knowledge_graph_fallback(
                sbom_components, sarif_findings, cve_records, cnapp_exposures
            )

        graph = nx.DiGraph()
        for component in sbom_components:
            if not isinstance(component, Mapping):
                continue
            name = component.get("name") or component.get("component")
            if not name:
                continue
            graph.add_node(
                str(name),
                type="component",
                severity=component.get("severity"),
                version=component.get("version"),
            )
        for finding in sarif_findings:
            if not isinstance(finding, Mapping):
                continue
            rule_id = finding.get("rule_id") or finding.get("ruleId") or "finding"
            node_id = f"finding:{rule_id}"
            graph.add_node(node_id, type="finding", severity=finding.get("level"))
            target = finding.get("raw", {}).get("locations", [{}])[0]
            component_ref = None
            if isinstance(target, Mapping):
                physical = target.get("physicalLocation")
                if isinstance(physical, Mapping):
                    artifact = physical.get("artifactLocation", {})
                    if isinstance(artifact, Mapping):
                        component_ref = artifact.get("uri")
            if component_ref:
                graph.add_edge(component_ref, node_id, relation="affected_by")
        for record in cve_records:
            if not isinstance(record, Mapping):
                continue
            cve_id = record.get("cve_id") or record.get("cveID")
            if not cve_id:
                continue
            node_id = f"cve:{cve_id}"
            graph.add_node(node_id, type="cve", severity=record.get("severity"))
            affected = record.get("components") or []
            for component in affected:
                if component and graph.has_node(component):
                    graph.add_edge(component, node_id, relation="referenced_by")
        for exposure in cnapp_exposures:
            if not isinstance(exposure, Mapping):
                continue
            asset = exposure.get("asset") or exposure.get("id")
            if asset and graph.has_node(asset):
                traits = exposure.get("traits") or []
                graph.nodes[asset].setdefault("traits", list(traits))
        metrics = {
            "nodes": graph.number_of_nodes(),
            "edges": graph.number_of_edges(),
            "density": (
                round(nx.density(graph), 3) if graph.number_of_nodes() > 1 else 0.0
            ),
        }
        try:
            centrality = nx.degree_centrality(graph)
        except Exception:
            centrality = {}
        top_nodes = sorted(centrality.items(), key=lambda item: item[1], reverse=True)[
            :5
        ]
        return {
            "metrics": metrics,
            "top_centrality": top_nodes,
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }

    def _build_knowledge_graph_fallback(
        self,
        sbom_components: Sequence[Mapping[str, Any]],
        sarif_findings: Sequence[Mapping[str, Any]],
        cve_records: Sequence[Mapping[str, Any]],
        cnapp_exposures: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        nodes: Dict[str, Dict[str, Any]] = {}
        edges: list[tuple[str, str, str]] = []

        def _ensure_node(node_id: str, **attrs: Any) -> None:
            payload = nodes.setdefault(node_id, {})
            for key, value in attrs.items():
                if value is not None:
                    payload[key] = value

        def _add_edge(source: str, target: str, relation: str) -> None:
            edges.append((source, target, relation))

        for component in sbom_components:
            if not isinstance(component, Mapping):
                continue
            name = component.get("name") or component.get("component")
            if not name:
                continue
            _ensure_node(
                str(name),
                type="component",
                severity=component.get("severity"),
                version=component.get("version"),
            )
        for finding in sarif_findings:
            if not isinstance(finding, Mapping):
                continue
            rule_id = finding.get("rule_id") or finding.get("ruleId") or "finding"
            node_id = f"finding:{rule_id}"
            _ensure_node(node_id, type="finding", severity=finding.get("level"))
            target = finding.get("raw", {}).get("locations", [{}])[0]
            component_ref = None
            if isinstance(target, Mapping):
                physical = target.get("physicalLocation")
                if isinstance(physical, Mapping):
                    artifact = physical.get("artifactLocation", {})
                    if isinstance(artifact, Mapping):
                        component_ref = artifact.get("uri")
            if component_ref and component_ref in nodes:
                _add_edge(component_ref, node_id, "affected_by")
        for record in cve_records:
            if not isinstance(record, Mapping):
                continue
            cve_id = record.get("cve_id") or record.get("cveID")
            if not cve_id:
                continue
            node_id = f"cve:{cve_id}"
            _ensure_node(node_id, type="cve", severity=record.get("severity"))
            affected = record.get("components") or []
            for component in affected:
                if component and component in nodes:
                    _add_edge(component, node_id, "referenced_by")
        for exposure in cnapp_exposures:
            if not isinstance(exposure, Mapping):
                continue
            asset = exposure.get("asset") or exposure.get("id")
            if asset and asset in nodes:
                traits = exposure.get("traits") or []
                node_traits = nodes[asset].setdefault("traits", [])
                for trait in traits:
                    if trait not in node_traits:
                        node_traits.append(trait)

        node_count = len(nodes)
        edge_count = len(edges)
        density = 0.0
        if node_count > 1:
            density = round(edge_count / (node_count * (node_count - 1)), 3)

        degree: Dict[str, int] = {key: 0 for key in nodes}
        for source, target, _ in edges:
            degree[source] = degree.get(source, 0) + 1
            degree[target] = degree.get(target, 0) + 1
        normaliser = max(1, node_count - 1)
        centrality = {
            node: round(weight / normaliser, 3) for node, weight in degree.items()
        }
        top_nodes = sorted(centrality.items(), key=lambda item: item[1], reverse=True)[
            :5
        ]
        return {
            "metrics": {"nodes": node_count, "edges": edge_count, "density": density},
            "top_centrality": top_nodes,
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }


__all__ = ["ProcessingLayer", "ProcessingLayerResult"]
