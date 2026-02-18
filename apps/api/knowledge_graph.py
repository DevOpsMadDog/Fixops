"""Knowledge graph builder wiring contextual insights to the enhanced engine."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, Mapping, Optional

from new_apps.api.processing import KnowledgeGraphProcessor


class KnowledgeGraphService:
    """Assemble a CTINexus-compatible payload from pipeline artefacts."""

    def __init__(self) -> None:
        self._processor = KnowledgeGraphProcessor()

    def build(
        self,
        *,
        design_rows: Iterable[Mapping[str, Any]],
        crosswalk: Iterable[Mapping[str, Any]],
        context_summary: Optional[Mapping[str, Any]] = None,
        compliance_status: Optional[Mapping[str, Any]] = None,
        guardrail_evaluation: Optional[Mapping[str, Any]] = None,
        marketplace_recommendations: Optional[Iterable[Mapping[str, Any]]] = None,
        severity_overview: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        entities: Dict[str, Dict[str, Any]] = {}
        relationships: list[Dict[str, Any]] = []

        def _ensure_entity(
            entity_id: str,
            entity_type: str,
            properties: Optional[Mapping[str, Any]] = None,
        ) -> Dict[str, Any]:
            if not entity_id:
                return {}
            if entity_id in entities:
                if properties:
                    current_props = entities[entity_id].setdefault("properties", {})
                    for key, value in properties.items():
                        if value is not None:
                            current_props.setdefault(key, value)
                return entities[entity_id]
            payload = {
                "id": entity_id,
                "type": entity_type,
                "properties": {
                    k: v for k, v in (properties or {}).items() if v is not None
                },
            }
            entities[entity_id] = payload
            return payload

        def _extract_name(entry: Mapping[str, Any]) -> Optional[str]:
            for key in ("component", "Component", "service", "name"):
                value = entry.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
            return None

        context_components = {}
        for component in (context_summary or {}).get("components", []) or []:
            if not isinstance(component, Mapping):
                continue
            name = _extract_name(component)
            if name:
                context_components[name] = component

        crosswalk_by_token: Dict[str, Mapping[str, Any]] = {}
        for entry in crosswalk:
            if not isinstance(entry, Mapping):
                continue
            design_row = entry.get("design_row")
            if isinstance(design_row, Mapping):
                token = _extract_name(design_row)
                if token:
                    crosswalk_by_token[token] = entry

        for row in design_rows:
            if not isinstance(row, Mapping):
                continue
            name = _extract_name(row)
            if not name:
                continue
            context = context_components.get(name, {})
            properties = {
                "severity": context.get("severity"),
                "context_score": context.get("context_score"),
                "criticality": context.get("criticality"),
                "data": context.get("data_classification"),
                "exposure": context.get("exposure"),
            }
            _ensure_entity(name, "service", properties)

        finding_nodes: Dict[str, Dict[str, Any]] = {}
        advisory_nodes: Dict[str, Dict[str, Any]] = {}

        for component, entry in crosswalk_by_token.items():
            findings = (
                entry.get("findings", [])
                if isinstance(entry.get("findings"), Iterable)
                else []
            )
            for finding in findings:
                if not isinstance(finding, Mapping):
                    continue
                finding_id = str(
                    finding.get("rule_id")
                    or finding.get("id")
                    or finding.get("ruleId")
                    or f"finding:{component}:{len(finding_nodes)}"
                )
                node = _ensure_entity(
                    finding_id,
                    "finding",
                    {
                        "severity": finding.get("level"),
                        "message": finding.get("message"),
                        "file": finding.get("file"),
                    },
                )
                finding_nodes[finding_id] = node
                relationships.append(
                    {
                        "id": f"impact:{component}:{finding_id}",
                        "source": component,
                        "target": finding_id,
                        "type": "impacted_by",
                        "metadata": {"source": "sarif"},
                    }
                )
            advisories = (
                entry.get("cves", []) if isinstance(entry.get("cves"), Iterable) else []
            )
            for advisory in advisories:
                if not isinstance(advisory, Mapping):
                    continue
                advisory_id = str(
                    advisory.get("cve_id")
                    or advisory.get("id")
                    or f"cve:{component}:{len(advisory_nodes)}"
                )
                node = _ensure_entity(
                    advisory_id,
                    "advisory",
                    {
                        "severity": advisory.get("severity"),
                        "exploited": advisory.get("exploited"),
                        "description": advisory.get("description")
                        or advisory.get("summary"),
                    },
                )
                advisory_nodes[advisory_id] = node
                relationships.append(
                    {
                        "id": f"advisory:{component}:{advisory_id}",
                        "source": component,
                        "target": advisory_id,
                        "type": "impacted_by",
                        "metadata": {"source": "cve"},
                    }
                )

        controls_map: Dict[str, Dict[str, Any]] = {}
        service_ids = [
            entity_id
            for entity_id, entity in entities.items()
            if entity.get("type") == "service"
        ]

        for framework in (compliance_status or {}).get("frameworks", []) or []:
            if not isinstance(framework, Mapping):
                continue
            framework_name = str(framework.get("name") or "framework")
            for control in framework.get("controls", []) or []:
                if not isinstance(control, Mapping):
                    continue
                control_id = str(
                    control.get("id") or control.get("title") or len(controls_map)
                )
                node_id = f"{framework_name}:{control_id}"
                node = _ensure_entity(
                    node_id,
                    "control",
                    {
                        "title": control.get("title"),
                        "status": control.get("status"),
                        "missing": control.get("missing"),
                        "framework": framework_name,
                    },
                )
                controls_map[node_id] = node
                edge_type = "requires" if control.get("missing") else "satisfies"
                metadata = {
                    "status": control.get("status"),
                    "missing": control.get("missing"),
                }
                for service_id in service_ids:
                    relationships.append(
                        {
                            "id": f"control:{service_id}:{node_id}",
                            "source": service_id,
                            "target": node_id,
                            "type": edge_type,
                            "metadata": metadata,
                        }
                    )

        rec_targets: Dict[str, list[str]] = defaultdict(list)
        for recommendation in marketplace_recommendations or []:
            if not isinstance(recommendation, Mapping):
                continue
            rec_id = str(
                recommendation.get("id")
                or recommendation.get("title")
                or len(rec_targets)
            )
            _ensure_entity(
                rec_id,
                "mitigation",
                {
                    "title": recommendation.get("title"),
                    "match": recommendation.get("match"),
                },
            )
            for match in recommendation.get("match", []) or []:
                if not isinstance(match, str):
                    continue
                rec_targets[rec_id].append(match)

        for rec_id, matches in rec_targets.items():
            for match in matches:
                if match.startswith("guardrail:") and guardrail_evaluation:
                    relationships.append(
                        {
                            "id": f"mitigation:{rec_id}:{match}",
                            "source": rec_id,
                            "target": "guardrail",
                            "type": "remediated_by",
                            "metadata": {"match": match},
                        }
                    )
                elif match.startswith("policy:"):
                    _ensure_entity(match, "policy", {"source": "automation"})
                    relationships.append(
                        {
                            "id": f"mitigation:{rec_id}:{match}",
                            "source": rec_id,
                            "target": match,
                            "type": "remediated_by",
                            "metadata": {"match": match},
                        }
                    )

        if guardrail_evaluation:
            _ensure_entity(
                "guardrail",
                "policy",
                {
                    "status": guardrail_evaluation.get("status"),
                    "highest_detected": guardrail_evaluation.get("highest_detected"),
                    "maturity": guardrail_evaluation.get("maturity"),
                },
            )

        if severity_overview:
            _ensure_entity(
                "severity-overview",
                "telemetry",
                {
                    "highest": severity_overview.get("highest"),
                    "counts": severity_overview.get("counts"),
                },
            )
            for service_id in service_ids:
                relationships.append(
                    {
                        "id": f"severity:{service_id}",
                        "source": service_id,
                        "target": "severity-overview",
                        "type": "tracked_by",
                        "metadata": {},
                    }
                )

        snapshot = {
            "entities": list(entities.values()),
            "relationships": relationships,
            "metadata": {
                "services": sum(
                    1 for item in entities.values() if item.get("type") == "service"
                ),
                "findings": len(finding_nodes),
                "advisories": len(advisory_nodes),
                "controls": len(controls_map),
            },
        }
        return self._processor.build_graph(snapshot)


__all__ = ["KnowledgeGraphService"]
