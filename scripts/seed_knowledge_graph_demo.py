#!/usr/bin/env python3
"""DEMO-010: Knowledge Graph Demo Data Seeder [V3 — Decision Intelligence]

Seeds the Knowledge Graph with realistic enterprise demo data:
- 5 applications (ACME Banking ecosystem)
- 20 vulnerabilities (4 Critical, 6 High, 6 Medium, 4 Low)
- 13 components with dependency chains
- 10+ discoverable attack paths
- Blast radius analysis from Log4Shell (CVE-2021-44228)

Usage:
    # Direct seeding (no server required)
    python scripts/seed_knowledge_graph_demo.py

    # Via API (requires running server)
    curl -X POST http://localhost:8000/api/v1/knowledge-graph/seed-demo

    # Verify
    curl http://localhost:8000/api/v1/knowledge-graph/analytics
    curl http://localhost:8000/api/v1/knowledge-graph/export?format=mermaid
"""

import json
import sys
import os

# Ensure suite paths are available
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))


def seed_knowledge_graph():
    """Seed the knowledge graph with demo data, returning analytics."""
    from core.falkordb_client import (
        EdgeType,
        GraphEdge,
        GraphNode,
        KnowledgeGraphEngine,
        NodeType,
    )

    engine = KnowledgeGraphEngine()
    engine.clear()

    # ── Applications ──────────────────────────────────────────────
    apps = [
        {"id": "acme-banking-portal", "name": "ACME Banking Portal", "tier": "Tier-1"},
        {"id": "acme-customer-api", "name": "ACME Customer API", "tier": "Tier-1"},
        {"id": "acme-payment-gateway", "name": "ACME Payment Gateway", "tier": "Tier-1"},
        {"id": "acme-internal-tools", "name": "ACME Internal Admin Tools", "tier": "Tier-2"},
        {"id": "acme-mobile-bff", "name": "ACME Mobile BFF", "tier": "Tier-1"},
    ]
    for app in apps:
        engine._backend.add_node(GraphNode(id=f"app:{app['id']}", type=NodeType.APP, properties=app))

    # ── Components ────────────────────────────────────────────────
    components = [
        ("comp:auth-service", "Authentication Service", "acme-banking-portal"),
        ("comp:session-mgr", "Session Manager", "acme-banking-portal"),
        ("comp:react-frontend", "React Frontend", "acme-banking-portal"),
        ("comp:user-api", "User Management API", "acme-customer-api"),
        ("comp:data-layer", "Data Access Layer", "acme-customer-api"),
        ("comp:cache-layer", "Redis Cache Layer", "acme-customer-api"),
        ("comp:payment-processor", "Payment Processor", "acme-payment-gateway"),
        ("comp:card-vault", "Card Vault (HSM)", "acme-payment-gateway"),
        ("comp:webhook-handler", "Webhook Handler", "acme-payment-gateway"),
        ("comp:admin-panel", "Admin Panel", "acme-internal-tools"),
        ("comp:log-aggregator", "Log Aggregator", "acme-internal-tools"),
        ("comp:mobile-gateway", "Mobile API Gateway", "acme-mobile-bff"),
        ("comp:graphql-layer", "GraphQL Federation", "acme-mobile-bff"),
    ]
    for cid, name, app_id in components:
        engine._backend.add_node(GraphNode(id=cid, type=NodeType.COMPONENT, properties={"name": name}))
        engine._backend.add_edge(GraphEdge(f"app:{app_id}", cid, EdgeType.HAS_COMPONENT))

    # ── Vulnerabilities ───────────────────────────────────────────
    vulns = [
        ("VULN-001", "SQL Injection in User Search", "critical", "CWE-89", "CVE-2025-44123", 9.8, "comp:user-api"),
        ("VULN-002", "Hardcoded API Key in Payment Processor", "critical", "CWE-798", "", 9.1, "comp:payment-processor"),
        ("VULN-003", "Remote Code Execution via Log4Shell", "critical", "CWE-917", "CVE-2021-44228", 10.0, "comp:auth-service"),
        ("VULN-004", "Insecure Deserialization in Session Manager", "critical", "CWE-502", "CVE-2024-29025", 9.6, "comp:session-mgr"),
        ("VULN-005", "Broken Authentication - JWT None Algorithm", "high", "CWE-287", "", 8.2, "comp:auth-service"),
        ("VULN-006", "SSRF via Webhook URL Validation Bypass", "high", "CWE-918", "CVE-2025-31001", 8.6, "comp:webhook-handler"),
        ("VULN-007", "Privilege Escalation in Admin Panel", "high", "CWE-269", "", 8.0, "comp:admin-panel"),
        ("VULN-008", "XSS Stored in User Comments", "high", "CWE-79", "", 7.5, "comp:react-frontend"),
        ("VULN-009", "GraphQL Introspection Enabled in Production", "high", "CWE-200", "", 7.2, "comp:graphql-layer"),
        ("VULN-010", "Weak TLS Configuration (TLS 1.0 Enabled)", "high", "CWE-326", "", 7.4, "comp:mobile-gateway"),
        ("VULN-011", "Missing Rate Limiting on Login", "medium", "CWE-307", "", 6.5, "comp:auth-service"),
        ("VULN-012", "Verbose Error Messages Expose Stack Traces", "medium", "CWE-209", "", 5.3, "comp:user-api"),
        ("VULN-013", "Outdated Redis Client (Known DoS)", "medium", "CWE-400", "CVE-2024-31449", 6.2, "comp:cache-layer"),
        ("VULN-014", "CORS Wildcard in Customer API", "medium", "CWE-942", "", 5.8, "comp:user-api"),
        ("VULN-015", "Dependency Confusion Risk — Internal Package", "medium", "CWE-427", "", 6.8, "comp:mobile-gateway"),
        ("VULN-016", "Insufficient Logging of Payment Transactions", "medium", "CWE-778", "", 5.5, "comp:payment-processor"),
        ("VULN-017", "Missing Security Headers (X-Frame-Options)", "low", "CWE-1021", "", 3.7, "comp:react-frontend"),
        ("VULN-018", "Debug Mode Enabled in Django Settings", "low", "CWE-489", "", 3.3, "comp:admin-panel"),
        ("VULN-019", "Outdated ESLint Configuration", "low", "CWE-1104", "", 2.1, "comp:graphql-layer"),
        ("VULN-020", "Log File Contains PII (Email Addresses)", "low", "CWE-532", "", 3.9, "comp:log-aggregator"),
    ]

    weight_map = {"critical": 0.1, "high": 0.3, "medium": 0.6, "low": 0.8}

    for vid, title, severity, cwe, cve, cvss, comp_id in vulns:
        engine._backend.add_node(GraphNode(
            id=f"finding:{vid}", type=NodeType.FINDING,
            properties={"title": title, "severity": severity, "cwe": cwe, "cvss": cvss, "status": "open"},
        ))
        engine._backend.add_edge(GraphEdge(comp_id, f"finding:{vid}", EdgeType.HAS_FINDING, weight=weight_map.get(severity, 0.5)))
        if cwe:
            engine._backend.add_node(GraphNode(id=f"cwe:{cwe}", type=NodeType.CWE, properties={"cwe_id": cwe}))
            engine._backend.add_edge(GraphEdge(f"finding:{vid}", f"cwe:{cwe}", EdgeType.MAPS_TO))
        if cve:
            engine._backend.add_node(GraphNode(id=f"cve:{cve}", type=NodeType.CVE, properties={"cve_id": cve, "cvss": cvss}))
            engine._backend.add_edge(GraphEdge(f"finding:{vid}", f"cve:{cve}", EdgeType.EXPLOITS, weight=weight_map.get(severity, 0.5)))

    # ── Dependencies ──────────────────────────────────────────────
    deps = [
        ("comp:auth-service", "comp:session-mgr"), ("comp:session-mgr", "comp:data-layer"),
        ("comp:react-frontend", "comp:auth-service"), ("comp:auth-service", "comp:user-api"),
        ("comp:user-api", "comp:data-layer"), ("comp:user-api", "comp:cache-layer"),
        ("comp:payment-processor", "comp:card-vault"), ("comp:payment-processor", "comp:user-api"),
        ("comp:webhook-handler", "comp:payment-processor"),
        ("comp:mobile-gateway", "comp:graphql-layer"), ("comp:graphql-layer", "comp:user-api"),
        ("comp:graphql-layer", "comp:payment-processor"),
        ("comp:admin-panel", "comp:data-layer"), ("comp:admin-panel", "comp:log-aggregator"),
        ("comp:log-aggregator", "comp:cache-layer"),
    ]
    for src, tgt in deps:
        engine._backend.add_edge(GraphEdge(src, tgt, EdgeType.DEPENDS_ON))

    # ── Attack chains ─────────────────────────────────────────────
    chains = [
        ("finding:VULN-003", "comp:auth-service"), ("comp:auth-service", "finding:VULN-005"),
        ("finding:VULN-005", "comp:session-mgr"), ("comp:session-mgr", "finding:VULN-004"),
        ("finding:VULN-004", "comp:data-layer"),
        ("finding:VULN-001", "comp:data-layer"), ("comp:data-layer", "comp:payment-processor"),
        ("comp:payment-processor", "finding:VULN-002"), ("finding:VULN-002", "comp:card-vault"),
        ("finding:VULN-008", "comp:react-frontend"), ("comp:react-frontend", "comp:auth-service"),
        ("comp:auth-service", "comp:admin-panel"), ("comp:admin-panel", "finding:VULN-007"),
        ("finding:VULN-006", "comp:webhook-handler"), ("comp:webhook-handler", "comp:admin-panel"),
        ("comp:admin-panel", "comp:log-aggregator"), ("comp:log-aggregator", "finding:VULN-020"),
        ("finding:VULN-009", "comp:graphql-layer"), ("comp:graphql-layer", "comp:user-api"),
        ("comp:user-api", "finding:VULN-001"),
        ("finding:VULN-010", "comp:mobile-gateway"), ("comp:mobile-gateway", "comp:graphql-layer"),
        ("finding:VULN-015", "comp:mobile-gateway"),
        ("comp:mobile-gateway", "comp:graphql-layer"),
    ]
    for src, tgt in chains:
        engine._backend.add_edge(GraphEdge(src, tgt, EdgeType.ATTACK_STEP, weight=0.2))

    # ── Analytics & demo paths ────────────────────────────────────
    analytics = engine.get_graph_analytics()
    blast = engine.calculate_blast_radius("finding:VULN-003", max_depth=5)

    print("✅ Knowledge Graph seeded successfully!")
    print(f"   Nodes: {analytics['node_count']}")
    print(f"   Edges: {analytics['edge_count']}")
    print(f"   Applications: {len(apps)}")
    print(f"   Vulnerabilities: {len(vulns)}")
    print(f"   Backend: {analytics['backend']}")
    print("\n🔥 Blast Radius from Log4Shell (VULN-003):")
    print(f"   Affected nodes: {len(blast.affected_nodes)}")
    print(f"   Affected components: {blast.affected_components}")
    print(f"   Chained findings: {blast.affected_findings}")
    print(f"   Risk multiplier: {blast.risk_multiplier}x")

    # Demo attack paths
    path_pairs = [
        ("finding:VULN-003", "comp:data-layer", "Log4Shell → Data Layer"),
        ("finding:VULN-001", "comp:card-vault", "SQLi → Card Vault"),
        ("finding:VULN-008", "finding:VULN-007", "XSS → Admin Escalation"),
        ("finding:VULN-006", "finding:VULN-020", "SSRF → PII Exposure"),
        ("finding:VULN-009", "finding:VULN-001", "GraphQL → SQLi Chain"),
    ]
    print("\n🛡️ Attack Paths Discovered:")
    for src, tgt, label in path_pairs:
        paths = engine.find_attack_paths(src, tgt, max_depth=8)
        if paths:
            top = paths[0]
            print(f"   {label}: {top.risk_score}/10 risk ({top.exploitability}), {len(top.nodes)} hops")

    # Export mermaid for visualization
    mermaid = engine.export_mermaid(max_nodes=60)
    output_path = os.path.join(os.path.dirname(__file__), "..", "data", "analysis", "knowledge_graph_demo.mmd")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(mermaid)
    print(f"\n📊 Mermaid diagram exported to: {output_path}")

    # Export JSON
    graph_json = engine.export_json()
    json_path = os.path.join(os.path.dirname(__file__), "..", "data", "analysis", "knowledge_graph_demo.json")
    with open(json_path, "w") as f:
        json.dump(graph_json, f, indent=2, default=str)
    print(f"📊 JSON export saved to: {json_path}")

    return analytics


if __name__ == "__main__":
    seed_knowledge_graph()
