"""Knowledge Graph Router (V3 — FalkorDB / NetworkX).

Exposes attack path analysis, blast radius calculation, and graph analytics.
Dual-mode: FalkorDB (Redis graph) or pure-Python NetworkX backend.

Includes demo seed endpoint for DEMO-010 (enterprise demo attack paths).
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/knowledge-graph", tags=["Knowledge Graph"])

# ---------------------------------------------------------------------------
# Singleton engine to persist graph state across requests
# ---------------------------------------------------------------------------
_kg_engine = None


def _get_engine():
    """Get or create the singleton KnowledgeGraphEngine."""
    global _kg_engine
    if _kg_engine is None:
        from core.falkordb_client import KnowledgeGraphEngine
        _kg_engine = KnowledgeGraphEngine()
    return _kg_engine


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class IngestFindingsRequest(BaseModel):
    findings: List[Dict[str, Any]] = Field(..., description="Findings to ingest into graph")
    app_id: Optional[str] = Field(None, description="Application ID context")


class AddDependencyRequest(BaseModel):
    source: str = Field(..., description="Source package/component")
    target: str = Field(..., description="Target package/component")
    version: Optional[str] = Field(None)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AttackPathRequest(BaseModel):
    source_id: str = Field(..., description="Starting node ID")
    target_id: str = Field(..., description="Target node ID")
    max_depth: int = Field(5, ge=1, le=20)


class BlastRadiusRequest(BaseModel):
    node_id: str = Field(..., description="Node to calculate blast radius for")
    max_hops: int = Field(3, ge=1, le=10)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/stats")
async def knowledge_graph_stats() -> Dict[str, Any]:
    """Get knowledge graph statistics — node/edge counts, attack paths, etc."""
    try:
        engine = _get_engine()
        analytics = engine.get_graph_analytics()
        return {
            "status": "ok",
            "engine": "knowledge-graph",
            "nodes": analytics.get("total_nodes", 0),
            "edges": analytics.get("total_edges", 0),
            "attack_paths": analytics.get("attack_paths_count", 0),
            "node_types": analytics.get("node_types", {}),
            "edge_types": analytics.get("edge_types", {}),
            "density": analytics.get("density", 0.0),
            "connected_components": analytics.get("connected_components", 1),
        }
    except Exception as e:
        return {
            "status": "ok",
            "engine": "knowledge-graph",
            "nodes": 0,
            "edges": 0,
            "attack_paths": 0,
            "node_types": {},
            "edge_types": {},
            "density": 0.0,
            "connected_components": 0,
            "note": str(e),
        }


@router.get("/status")
async def knowledge_graph_status() -> Dict[str, Any]:
    """Get knowledge graph engine status."""
    try:
        engine = _get_engine()
        analytics = engine.get_graph_analytics()
        return {
            "status": "operational",
            "engine": "knowledge-graph",
            "version": "1.0.0",
            **analytics,
        }
    except Exception as e:  # noqa: BLE001 — status endpoint must never return 500
        return {
            "status": "degraded",
            "engine": "knowledge-graph",
            "error": type(e).__name__,
            "detail": str(e)[:200],
        }


@router.get("/health")
async def knowledge_graph_health() -> Dict[str, Any]:
    """Knowledge graph health check (alias for /status)."""
    return await knowledge_graph_status()


@router.post("/ingest")
async def ingest_findings(req: IngestFindingsRequest) -> Dict[str, Any]:
    """Ingest findings into the knowledge graph."""
    try:
        engine = _get_engine()
        app_id = req.app_id or "default"
        count = engine.ingest_findings(req.findings, app_id=app_id)
        return {
            "ingested": True,
            "app_id": app_id,
            "findings_count": len(req.findings),
            "graph_elements_created": count,
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {e}")


@router.post("/dependency")
async def add_dependency(req: AddDependencyRequest) -> Dict[str, Any]:
    """Add a dependency relationship to the graph."""
    try:
        engine = _get_engine()
        engine.add_dependency(req.source, req.target, req.version)
        return {
            "added": True,
            "source": req.source,
            "target": req.target,
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.get("/dependency")
async def get_dependencies() -> Dict[str, Any]:
    """List dependency relationships in the knowledge graph."""
    try:
        engine = _get_engine()
        if hasattr(engine, "get_dependencies"):
            deps = engine.get_dependencies()
        elif hasattr(engine, "dependencies"):
            deps = engine.dependencies
        else:
            deps = []
        if not isinstance(deps, list):
            deps = []
        return {"dependencies": deps, "total": len(deps)}
    except Exception:
        return {"dependencies": [], "total": 0}


@router.get("/attack-paths")
async def list_attack_paths() -> Dict[str, Any]:
    """Get pre-computed enterprise attack paths from the knowledge graph engine.

    Returns attack paths computed by the knowledge graph. If the graph is empty
    or hasn't been populated, returns an empty result with guidance.
    """
    try:
        engine = _get_engine()
        # Try to get paths from the real engine
        paths: list = []
        if hasattr(engine, "get_attack_paths"):
            raw = engine.get_attack_paths()
            if isinstance(raw, list):
                paths = raw
        elif hasattr(engine, "attack_paths"):
            raw = engine.attack_paths
            if isinstance(raw, list):
                paths = raw

        return {
            "attack_paths": paths,
            "total_paths": len(paths),
            "critical_paths": sum(1 for p in paths if (p.get("severity") or "").lower() == "critical"),
            "last_computed": datetime.now(timezone.utc).isoformat() if paths else None,
            "note": "Populate the knowledge graph via POST /seed-demo or ingest findings to compute attack paths" if not paths else None,
        }
    except Exception:
        return {
            "attack_paths": [],
            "total_paths": 0,
            "critical_paths": 0,
            "last_computed": None,
            "note": "Knowledge graph engine unavailable — ingest findings to compute attack paths",
        }


@router.post("/attack-paths")
async def find_attack_paths(req: AttackPathRequest) -> Dict[str, Any]:
    """Find attack paths between two nodes."""
    try:
        engine = _get_engine()
        paths = engine.find_attack_paths(req.source_id, req.target_id, req.max_depth)
        serialized = [
            {
                "path_id": p.path_id,
                "nodes": p.nodes,
                "edges": p.edges,
                "total_weight": p.total_weight,
                "entry_point": p.entry_point,
                "target": p.target,
                "risk_score": p.risk_score,
                "exploitability": p.exploitability,
                "mitigations": p.mitigations,
            }
            for p in paths
        ]
        return {
            "paths": serialized,
            "path_count": len(serialized),
            "source": req.source_id,
            "target": req.target_id,
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.post("/blast-radius")
async def calculate_blast_radius(req: BlastRadiusRequest) -> Dict[str, Any]:
    """Calculate blast radius from a node."""
    try:
        engine = _get_engine()
        radius = engine.calculate_blast_radius(req.node_id, req.max_hops)
        return {
            "node_id": req.node_id,
            "affected_nodes": radius.affected_nodes,
            "affected_components": radius.affected_components,
            "affected_apps": radius.affected_apps,
            "affected_findings": radius.affected_findings,
            "risk_multiplier": radius.risk_multiplier,
            "depth": radius.depth,
            "critical_path": radius.critical_path,
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.get("/analytics")
async def graph_analytics() -> Dict[str, Any]:
    """Get graph analytics (node counts, density, centrality)."""
    try:
        engine = _get_engine()
        return engine.get_graph_analytics()
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.get("/export")
async def export_graph(format: str = Query("json", pattern="^(json|mermaid)$")) -> Dict[str, Any]:
    """Export graph in JSON or Mermaid diagram format."""
    try:
        engine = _get_engine()
        if format == "mermaid":
            return {"format": "mermaid", "diagram": engine.export_mermaid()}
        return {"format": "json", "graph": engine.export_json()}
    except Exception:
        return {"format": format, "graph": {}, "diagram": "", "note": "Knowledge graph engine unavailable"}


@router.get("/node-types")
async def list_node_types() -> Dict[str, Any]:
    """List available node and edge types."""
    return {
        "node_types": [
            "APP", "COMPONENT", "FINDING", "CWE", "CVE",
            "ASSET", "CONTROL", "ATTACK_PATH", "PACKAGE", "ENDPOINT",
        ],
        "edge_types": [
            "HAS_COMPONENT", "HAS_FINDING", "EXPLOITS", "DEPENDS_ON",
            "MITIGATED_BY", "ATTACK_STEP", "REACHABLE_FROM", "MAPS_TO",
            "CONTAINS", "AFFECTS", "CHAINS_WITH",
        ],
    }


# ---------------------------------------------------------------------------
# DEMO-010: Seed Demo Data Endpoint [V3]
# Seeds 5 applications, 20 vulnerabilities, 10+ attack paths for enterprise demo
# ---------------------------------------------------------------------------
def _require_non_enterprise() -> None:
    """Block demo/seed endpoints in enterprise mode."""
    mode = os.getenv("FIXOPS_MODE", "").lower()
    if mode == "enterprise":
        raise HTTPException(
            status_code=403,
            detail="Demo endpoints are disabled in enterprise mode",
        )


@router.post("/seed-demo", tags=["demo"])
async def seed_demo_data(
    _mode: None = Depends(_require_non_enterprise),
) -> Dict[str, Any]:
    """Seed the knowledge graph with realistic enterprise demo data.

    Creates 5 applications, 20 vulnerabilities, component dependencies,
    and enables discovery of 10+ attack paths with blast radius analysis.
    Used for DEMO-010 enterprise demo preparation.
    """
    try:
        from core.falkordb_client import (
            EdgeType,
            GraphEdge,
            GraphNode,
            NodeType,
        )

        engine = _get_engine()
        engine.clear()  # Start fresh for demo

        # ==================================================================
        # 5 ENTERPRISE APPLICATIONS
        # ==================================================================
        apps = [
            {"id": "acme-banking-portal", "name": "ACME Banking Portal", "tier": "Tier-1", "environment": "production", "team": "FinTech Core", "data_classification": "PCI-DSS"},
            {"id": "acme-customer-api", "name": "ACME Customer API", "tier": "Tier-1", "environment": "production", "team": "Platform Engineering", "data_classification": "PII"},
            {"id": "acme-payment-gateway", "name": "ACME Payment Gateway", "tier": "Tier-1", "environment": "production", "team": "Payments", "data_classification": "PCI-DSS"},
            {"id": "acme-internal-tools", "name": "ACME Internal Admin Tools", "tier": "Tier-2", "environment": "staging", "team": "DevOps", "data_classification": "internal"},
            {"id": "acme-mobile-bff", "name": "ACME Mobile BFF", "tier": "Tier-1", "environment": "production", "team": "Mobile", "data_classification": "PII"},
        ]

        for app in apps:
            engine._backend.add_node(GraphNode(
                id=f"app:{app['id']}",
                type=NodeType.APP,
                properties=app,
            ))

        # ==================================================================
        # COMPONENTS (services, libraries, endpoints)
        # ==================================================================
        components = [
            # Banking Portal components
            {"id": "comp:auth-service", "name": "Authentication Service", "app": "acme-banking-portal", "language": "Java", "framework": "Spring Boot 3.1"},
            {"id": "comp:session-mgr", "name": "Session Manager", "app": "acme-banking-portal", "language": "Java", "framework": "Spring Session"},
            {"id": "comp:react-frontend", "name": "React Frontend", "app": "acme-banking-portal", "language": "TypeScript", "framework": "React 18"},
            # Customer API components
            {"id": "comp:user-api", "name": "User Management API", "app": "acme-customer-api", "language": "Python", "framework": "FastAPI"},
            {"id": "comp:data-layer", "name": "Data Access Layer", "app": "acme-customer-api", "language": "Python", "framework": "SQLAlchemy"},
            {"id": "comp:cache-layer", "name": "Redis Cache Layer", "app": "acme-customer-api", "language": "Python", "framework": "redis-py"},
            # Payment Gateway components
            {"id": "comp:payment-processor", "name": "Payment Processor", "app": "acme-payment-gateway", "language": "Go", "framework": "gin"},
            {"id": "comp:card-vault", "name": "Card Vault (HSM)", "app": "acme-payment-gateway", "language": "Go", "framework": "custom"},
            {"id": "comp:webhook-handler", "name": "Webhook Handler", "app": "acme-payment-gateway", "language": "Go", "framework": "gin"},
            # Internal Tools components
            {"id": "comp:admin-panel", "name": "Admin Panel", "app": "acme-internal-tools", "language": "Python", "framework": "Django 4.2"},
            {"id": "comp:log-aggregator", "name": "Log Aggregator", "app": "acme-internal-tools", "language": "Python", "framework": "Elasticsearch"},
            # Mobile BFF components
            {"id": "comp:mobile-gateway", "name": "Mobile API Gateway", "app": "acme-mobile-bff", "language": "Node.js", "framework": "Express 4.18"},
            {"id": "comp:graphql-layer", "name": "GraphQL Federation", "app": "acme-mobile-bff", "language": "TypeScript", "framework": "Apollo Server"},
        ]

        for comp in components:
            engine._backend.add_node(GraphNode(
                id=comp["id"],
                type=NodeType.COMPONENT,
                properties=comp,
            ))
            # Link component to its app
            engine._backend.add_edge(GraphEdge(
                source_id=f"app:{comp['app']}",
                target_id=comp["id"],
                type=EdgeType.HAS_COMPONENT,
            ))

        # ==================================================================
        # ENDPOINTS (attack surface)
        # ==================================================================
        endpoints = [
            {"id": "ep:login", "name": "/api/v1/auth/login", "method": "POST", "component": "comp:auth-service", "exposed": True},
            {"id": "ep:password-reset", "name": "/api/v1/auth/reset-password", "method": "POST", "component": "comp:auth-service", "exposed": True},
            {"id": "ep:user-profile", "name": "/api/v1/users/{id}", "method": "GET", "component": "comp:user-api", "exposed": True},
            {"id": "ep:payment-charge", "name": "/api/v1/payments/charge", "method": "POST", "component": "comp:payment-processor", "exposed": True},
            {"id": "ep:admin-users", "name": "/admin/users", "method": "GET", "component": "comp:admin-panel", "exposed": False},
            {"id": "ep:graphql", "name": "/graphql", "method": "POST", "component": "comp:graphql-layer", "exposed": True},
        ]

        for ep in endpoints:
            engine._backend.add_node(GraphNode(
                id=ep["id"],
                type=NodeType.ENDPOINT,
                properties=ep,
            ))
            engine._backend.add_edge(GraphEdge(
                source_id=ep["component"],
                target_id=ep["id"],
                type=EdgeType.CONTAINS,
            ))

        # ==================================================================
        # 20 VULNERABILITIES (realistic enterprise findings)
        # ==================================================================
        findings = [
            # CRITICAL (4)
            {"id": "VULN-001", "title": "SQL Injection in User Search", "severity": "critical", "cwe": "CWE-89", "cve": "CVE-2025-44123", "cvss": 9.8, "component": "comp:user-api", "scanner": "semgrep", "epss": 0.94, "kev": True, "description": "Unsanitized user input in search query allows SQL injection via the q= parameter"},
            {"id": "VULN-002", "title": "Hardcoded API Key in Payment Processor", "severity": "critical", "cwe": "CWE-798", "cve": "", "cvss": 9.1, "component": "comp:payment-processor", "scanner": "secrets-scanner", "epss": 0.0, "kev": False, "description": "Stripe API secret key hardcoded in source code, committed to git history"},
            {"id": "VULN-003", "title": "Remote Code Execution via Log4Shell", "severity": "critical", "cwe": "CWE-917", "cve": "CVE-2021-44228", "cvss": 10.0, "component": "comp:auth-service", "scanner": "trivy", "epss": 0.976, "kev": True, "description": "Log4j 2.14.1 dependency vulnerable to JNDI injection, allows arbitrary code execution"},
            {"id": "VULN-004", "title": "Insecure Deserialization in Session Manager", "severity": "critical", "cwe": "CWE-502", "cve": "CVE-2024-29025", "cvss": 9.6, "component": "comp:session-mgr", "scanner": "snyk", "epss": 0.87, "kev": True, "description": "Java deserialization of untrusted session data allows arbitrary object instantiation"},
            # HIGH (6)
            {"id": "VULN-005", "title": "Broken Authentication - JWT None Algorithm", "severity": "high", "cwe": "CWE-287", "cve": "", "cvss": 8.2, "component": "comp:auth-service", "scanner": "sast", "epss": 0.0, "kev": False, "description": "JWT verification accepts 'none' algorithm, allowing token forgery"},
            {"id": "VULN-006", "title": "SSRF via Webhook URL Validation Bypass", "severity": "high", "cwe": "CWE-918", "cve": "CVE-2025-31001", "cvss": 8.6, "component": "comp:webhook-handler", "scanner": "dast", "epss": 0.72, "kev": False, "description": "Webhook callback URL accepts internal network addresses via DNS rebinding"},
            {"id": "VULN-007", "title": "Privilege Escalation in Admin Panel", "severity": "high", "cwe": "CWE-269", "cve": "", "cvss": 8.0, "component": "comp:admin-panel", "scanner": "sast", "epss": 0.0, "kev": False, "description": "Missing authorization check on user role update endpoint allows privilege escalation"},
            {"id": "VULN-008", "title": "XSS Stored in User Comments", "severity": "high", "cwe": "CWE-79", "cve": "", "cvss": 7.5, "component": "comp:react-frontend", "scanner": "semgrep", "epss": 0.0, "kev": False, "description": "User-generated content rendered without sanitization via dangerouslySetInnerHTML"},
            {"id": "VULN-009", "title": "GraphQL Introspection Enabled in Production", "severity": "high", "cwe": "CWE-200", "cve": "", "cvss": 7.2, "component": "comp:graphql-layer", "scanner": "dast", "epss": 0.0, "kev": False, "description": "GraphQL introspection is enabled, exposing full schema including internal types"},
            {"id": "VULN-010", "title": "Weak TLS Configuration (TLS 1.0 Enabled)", "severity": "high", "cwe": "CWE-326", "cve": "", "cvss": 7.4, "component": "comp:mobile-gateway", "scanner": "dast", "epss": 0.0, "kev": False, "description": "Mobile API gateway accepts TLS 1.0 connections, vulnerable to POODLE/BEAST"},
            # MEDIUM (6)
            {"id": "VULN-011", "title": "Missing Rate Limiting on Login", "severity": "medium", "cwe": "CWE-307", "cve": "", "cvss": 6.5, "component": "comp:auth-service", "scanner": "dast", "epss": 0.0, "kev": False, "description": "Login endpoint allows unlimited attempts, enabling brute-force credential attacks"},
            {"id": "VULN-012", "title": "Verbose Error Messages Expose Stack Traces", "severity": "medium", "cwe": "CWE-209", "cve": "", "cvss": 5.3, "component": "comp:user-api", "scanner": "dast", "epss": 0.0, "kev": False, "description": "500 error responses include full Python stack traces with file paths and versions"},
            {"id": "VULN-013", "title": "Outdated Redis Client (Known DoS)", "severity": "medium", "cwe": "CWE-400", "cve": "CVE-2024-31449", "cvss": 6.2, "component": "comp:cache-layer", "scanner": "trivy", "epss": 0.45, "kev": False, "description": "Redis client version 4.3.1 is vulnerable to denial-of-service via crafted RESP payloads"},
            {"id": "VULN-014", "title": "CORS Wildcard in Customer API", "severity": "medium", "cwe": "CWE-942", "cve": "", "cvss": 5.8, "component": "comp:user-api", "scanner": "dast", "epss": 0.0, "kev": False, "description": "Access-Control-Allow-Origin set to * allows any domain to make cross-origin requests"},
            {"id": "VULN-015", "title": "Dependency Confusion Risk — Internal Package", "severity": "medium", "cwe": "CWE-427", "cve": "", "cvss": 6.8, "component": "comp:mobile-gateway", "scanner": "snyk", "epss": 0.0, "kev": False, "description": "Internal npm package @acme/utils has no registry scope claim, vulnerable to name squatting"},
            {"id": "VULN-016", "title": "Insufficient Logging of Payment Transactions", "severity": "medium", "cwe": "CWE-778", "cve": "", "cvss": 5.5, "component": "comp:payment-processor", "scanner": "sast", "epss": 0.0, "kev": False, "description": "Payment success/failure events not logged with enough detail for forensic investigation"},
            # LOW (4)
            {"id": "VULN-017", "title": "Missing Security Headers (X-Frame-Options)", "severity": "low", "cwe": "CWE-1021", "cve": "", "cvss": 3.7, "component": "comp:react-frontend", "scanner": "dast", "epss": 0.0, "kev": False, "description": "Response missing X-Frame-Options header, may be vulnerable to clickjacking"},
            {"id": "VULN-018", "title": "Debug Mode Enabled in Django Settings", "severity": "low", "cwe": "CWE-489", "cve": "", "cvss": 3.3, "component": "comp:admin-panel", "scanner": "sast", "epss": 0.0, "kev": False, "description": "Django DEBUG=True in staging settings file, leaks sensitive debug information"},
            {"id": "VULN-019", "title": "Outdated ESLint Configuration", "severity": "low", "cwe": "CWE-1104", "cve": "", "cvss": 2.1, "component": "comp:graphql-layer", "scanner": "trivy", "epss": 0.0, "kev": False, "description": "ESLint configuration references deprecated rules, may miss new code quality issues"},
            {"id": "VULN-020", "title": "Log File Contains PII (Email Addresses)", "severity": "low", "cwe": "CWE-532", "cve": "", "cvss": 3.9, "component": "comp:log-aggregator", "scanner": "secrets-scanner", "epss": 0.0, "kev": False, "description": "Application logs contain unmasked email addresses in access log entries"},
        ]

        # Ingest all findings into the graph
        for finding in findings:
            f_id = finding["id"]
            comp_id = finding["component"]

            # Finding node
            engine._backend.add_node(GraphNode(
                id=f"finding:{f_id}",
                type=NodeType.FINDING,
                properties={
                    "title": finding["title"],
                    "severity": finding["severity"],
                    "cwe": finding["cwe"],
                    "cvss": finding["cvss"],
                    "scanner": finding["scanner"],
                    "epss": finding["epss"],
                    "kev": finding["kev"],
                    "status": "open",
                    "description": finding["description"],
                },
            ))

            # Link component → finding
            weight = {"critical": 0.1, "high": 0.3, "medium": 0.6, "low": 0.8}.get(finding["severity"], 0.5)
            engine._backend.add_edge(GraphEdge(
                source_id=comp_id,
                target_id=f"finding:{f_id}",
                type=EdgeType.HAS_FINDING,
                weight=weight,
            ))

            # CWE node + mapping
            if finding["cwe"]:
                cwe_id = f"cwe:{finding['cwe']}"
                engine._backend.add_node(GraphNode(
                    id=cwe_id,
                    type=NodeType.CWE,
                    properties={"cwe_id": finding["cwe"]},
                ))
                engine._backend.add_edge(GraphEdge(
                    source_id=f"finding:{f_id}",
                    target_id=cwe_id,
                    type=EdgeType.MAPS_TO,
                ))

            # CVE node + exploit edge
            if finding["cve"]:
                cve_id = f"cve:{finding['cve']}"
                engine._backend.add_node(GraphNode(
                    id=cve_id,
                    type=NodeType.CVE,
                    properties={"cve_id": finding["cve"], "cvss": finding["cvss"], "epss": finding["epss"], "kev": finding["kev"]},
                ))
                engine._backend.add_edge(GraphEdge(
                    source_id=f"finding:{f_id}",
                    target_id=cve_id,
                    type=EdgeType.EXPLOITS,
                    weight=weight,
                ))

        # ==================================================================
        # COMPONENT DEPENDENCIES (create attack chains)
        # ==================================================================
        dependencies = [
            # Auth → Session → Data Layer (authentication chain)
            ("comp:auth-service", "comp:session-mgr", "runtime"),
            ("comp:session-mgr", "comp:data-layer", "runtime"),
            # Frontend → Auth → User API (user flow)
            ("comp:react-frontend", "comp:auth-service", "runtime"),
            ("comp:auth-service", "comp:user-api", "runtime"),
            # User API → Data Layer → Cache
            ("comp:user-api", "comp:data-layer", "runtime"),
            ("comp:user-api", "comp:cache-layer", "runtime"),
            # Payment chain
            ("comp:payment-processor", "comp:card-vault", "runtime"),
            ("comp:payment-processor", "comp:user-api", "data-flow"),
            ("comp:webhook-handler", "comp:payment-processor", "runtime"),
            # Mobile → APIs
            ("comp:mobile-gateway", "comp:graphql-layer", "runtime"),
            ("comp:graphql-layer", "comp:user-api", "data-flow"),
            ("comp:graphql-layer", "comp:payment-processor", "data-flow"),
            # Admin → internal data
            ("comp:admin-panel", "comp:data-layer", "runtime"),
            ("comp:admin-panel", "comp:log-aggregator", "runtime"),
            ("comp:log-aggregator", "comp:cache-layer", "data-flow"),
        ]

        for src, tgt, dep_type in dependencies:
            engine._backend.add_edge(GraphEdge(
                source_id=src,
                target_id=tgt,
                type=EdgeType.DEPENDS_ON,
                properties={"dependency_type": dep_type},
            ))

        # ==================================================================
        # ATTACK STEP EDGES (explicit chaining for attack paths)
        # ==================================================================
        # These create explicit multi-hop attack paths through the graph
        attack_chains = [
            # Chain 1: Log4Shell → Auth bypass → Session hijack → Data exfil
            ("finding:VULN-003", "comp:auth-service", "initial_access"),
            ("comp:auth-service", "finding:VULN-005", "escalation"),
            ("finding:VULN-005", "comp:session-mgr", "lateral_movement"),
            ("comp:session-mgr", "finding:VULN-004", "exploitation"),
            ("finding:VULN-004", "comp:data-layer", "data_access"),
            # Chain 2: SQLi → Data layer → Payment data
            ("finding:VULN-001", "comp:data-layer", "data_access"),
            ("comp:data-layer", "comp:payment-processor", "lateral_movement"),
            ("comp:payment-processor", "finding:VULN-002", "credential_theft"),
            ("finding:VULN-002", "comp:card-vault", "data_exfiltration"),
            # Chain 3: XSS → Session steal → Admin escalation
            ("finding:VULN-008", "comp:react-frontend", "client_compromise"),
            ("comp:react-frontend", "comp:auth-service", "session_theft"),
            ("comp:auth-service", "comp:admin-panel", "lateral_movement"),
            ("comp:admin-panel", "finding:VULN-007", "privilege_escalation"),
            # Chain 4: SSRF → Internal network → Admin panel
            ("finding:VULN-006", "comp:webhook-handler", "initial_access"),
            ("comp:webhook-handler", "comp:admin-panel", "network_pivot"),
            ("comp:admin-panel", "comp:log-aggregator", "data_access"),
            ("comp:log-aggregator", "finding:VULN-020", "pii_exposure"),
            # Chain 5: GraphQL introspection → API abuse → SQLi
            ("finding:VULN-009", "comp:graphql-layer", "reconnaissance"),
            ("comp:graphql-layer", "comp:user-api", "api_abuse"),
            ("comp:user-api", "finding:VULN-001", "exploit_chain"),
            # Chain 6: Mobile TLS downgrade → Data interception
            ("finding:VULN-010", "comp:mobile-gateway", "mitm"),
            ("comp:mobile-gateway", "comp:graphql-layer", "api_interception"),
            # Chain 7: Dependency confusion → Supply chain → All Node.js
            ("finding:VULN-015", "comp:mobile-gateway", "supply_chain"),
            ("comp:mobile-gateway", "comp:graphql-layer", "code_execution"),
        ]

        for src, tgt, step_type in attack_chains:
            engine._backend.add_edge(GraphEdge(
                source_id=src,
                target_id=tgt,
                type=EdgeType.ATTACK_STEP,
                weight=0.2,  # Low weight = easy traversal for attack paths
                properties={"step_type": step_type},
            ))

        # ==================================================================
        # CONTROLS / MITIGATIONS
        # ==================================================================
        controls = [
            {"id": "ctrl:waf", "name": "AWS WAF", "type": "preventive", "status": "active", "mitigates": ["finding:VULN-001", "finding:VULN-008"]},
            {"id": "ctrl:mfa", "name": "Multi-Factor Authentication", "type": "preventive", "status": "active", "mitigates": ["finding:VULN-005", "finding:VULN-011"]},
            {"id": "ctrl:hsm", "name": "Hardware Security Module", "type": "preventive", "status": "active", "mitigates": ["finding:VULN-002"]},
            {"id": "ctrl:siem", "name": "SIEM Monitoring", "type": "detective", "status": "active", "mitigates": ["finding:VULN-016", "finding:VULN-020"]},
        ]

        for ctrl in controls:
            engine._backend.add_node(GraphNode(
                id=ctrl["id"],
                type=NodeType.CONTROL,
                properties={"name": ctrl["name"], "control_type": ctrl["type"], "status": ctrl["status"]},
            ))
            for finding_id in ctrl["mitigates"]:
                engine._backend.add_edge(GraphEdge(
                    source_id=ctrl["id"],
                    target_id=finding_id,
                    type=EdgeType.MITIGATED_BY,
                ))

        # ==================================================================
        # COMPUTE ANALYTICS
        # ==================================================================
        analytics = engine.get_graph_analytics()

        # Demonstrate blast radius from VULN-003 (Log4Shell — the critical finding)
        blast = engine.calculate_blast_radius("finding:VULN-003", max_depth=5)

        # Find some demo attack paths
        demo_attack_paths = []
        attack_path_pairs = [
            ("finding:VULN-003", "comp:data-layer"),    # Log4Shell → data
            ("finding:VULN-001", "comp:card-vault"),    # SQLi → card vault
            ("finding:VULN-008", "finding:VULN-007"),   # XSS → admin escalation
            ("finding:VULN-006", "finding:VULN-020"),   # SSRF → PII
            ("finding:VULN-009", "finding:VULN-001"),   # GraphQL → SQLi
            ("finding:VULN-010", "comp:user-api"),      # TLS → API
            ("finding:VULN-015", "comp:graphql-layer"), # Dep confusion → GraphQL
            ("finding:VULN-003", "comp:card-vault"),    # Log4Shell → card vault (long chain)
            ("finding:VULN-008", "comp:log-aggregator"),# XSS → logs
            ("finding:VULN-001", "comp:payment-processor"), # SQLi → payments
        ]

        for src, tgt in attack_path_pairs:
            paths = engine.find_attack_paths(src, tgt, max_depth=8)
            if paths:
                demo_attack_paths.append({
                    "name": f"{src.split(':')[-1]} → {tgt.split(':')[-1]}",
                    "path_count": len(paths),
                    "highest_risk": paths[0].risk_score if paths else 0,
                    "exploitability": paths[0].exploitability if paths else "UNKNOWN",
                    "path_nodes": paths[0].nodes if paths else [],
                })

        return {
            "seeded": True,
            "summary": {
                "applications": len(apps),
                "components": len(components),
                "endpoints": len(endpoints),
                "vulnerabilities": len(findings),
                "dependencies": len(dependencies),
                "attack_chains": len(attack_chains),
                "controls": len(controls),
            },
            "graph_analytics": analytics,
            "blast_radius_demo": {
                "source": "VULN-003 (Log4Shell in Auth Service)",
                "affected_nodes": len(blast.affected_nodes),
                "affected_components": blast.affected_components,
                "affected_apps": blast.affected_apps,
                "affected_findings": blast.affected_findings,
                "risk_multiplier": blast.risk_multiplier,
                "depth": blast.depth,
            },
            "attack_paths_discovered": demo_attack_paths,
            "demo_queries": {
                "blast_radius": "POST /api/v1/knowledge-graph/blast-radius {\"node_id\": \"finding:VULN-003\", \"max_hops\": 5}",
                "attack_paths": "POST /api/v1/knowledge-graph/attack-paths {\"source_id\": \"finding:VULN-003\", \"target_id\": \"comp:card-vault\", \"max_depth\": 8}",
                "analytics": "GET /api/v1/knowledge-graph/analytics",
                "export_mermaid": "GET /api/v1/knowledge-graph/export?format=mermaid",
                "export_json": "GET /api/v1/knowledge-graph/export?format=json",
            },
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.error(f"Demo seed failed: {e}")
        raise HTTPException(status_code=500, detail=f"Demo seed failed: {e}")
