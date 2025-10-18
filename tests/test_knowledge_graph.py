from __future__ import annotations

from apps.api.knowledge_graph import KnowledgeGraphService


def test_knowledge_graph_service_builds_snapshot() -> None:
    service = KnowledgeGraphService()
    graph = service.build(
        design_rows=[{"component": "customer-api"}],
        crosswalk=[
            {
                "design_row": {"component": "customer-api"},
                "findings": [
                    {"rule_id": "SQLi", "level": "error", "message": "SQL injection"},
                ],
                "cves": [
                    {
                        "cve_id": "CVE-2024-1234",
                        "severity": "critical",
                        "exploited": True,
                    }
                ],
            }
        ],
        context_summary={
            "components": [
                {
                    "name": "customer-api",
                    "severity": "critical",
                    "context_score": 15,
                    "criticality": "mission_critical",
                    "data_classification": ["pii"],
                    "exposure": "internet",
                }
            ]
        },
        compliance_status={
            "frameworks": [
                {
                    "name": "SOC2",
                    "controls": [
                        {"id": "CC7.1", "status": "satisfied", "title": "Vuln Mgmt"},
                    ],
                }
            ]
        },
        guardrail_evaluation={
            "status": "fail",
            "highest_detected": "critical",
            "maturity": "scaling",
        },
        marketplace_recommendations=[
            {
                "id": "guardrail-remediation",
                "title": "Enable playbooks",
                "match": ["guardrail:fail"],
            }
        ],
        severity_overview={"highest": "critical", "counts": {"critical": 1}},
    )

    analytics = graph.get("analytics", {})
    assert analytics.get("entity_count", 0) >= 4
    structure = graph.get("graph", {})
    nodes = structure.get("nodes", [])
    edges = structure.get("edges", [])
    assert any(node.get("type") == "service" for node in nodes)
    assert any(edge.get("type") == "impacted_by" for edge in edges)
    assert any(edge.get("type") == "satisfies" for edge in edges)
