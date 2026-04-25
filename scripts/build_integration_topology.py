"""
Build the TrustGraph "integration topology" meta-graph.

Federation across 8+ integration waves landing in this surge:
  Snyk-OSS, CSPM, EDR/XDR, SIEM, Container, IAM, ThreatIntel, DAST

For each of 15 tenants emit:
  Tenant -> 8 connector nodes -> OSS tool -> Fixops engine -> finding-source category

Uses the real TrustGraph KnowledgeStore (sqlite-backed) — not synthetic.
After ingest, dumps a markdown summary to raw/competitive/integration_topology.md
so graphify can pick it up alongside the existing competitive corpus.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Ensure project on sys.path
ROOT = Path(__file__).resolve().parents[1]
for sub in ("suite-core", "suite-api", "suite-evidence-risk", "suite-feeds", "suite-attack", "suite-integrations"):
    p = ROOT / sub
    if p.exists():
        sys.path.insert(0, str(p))

# Use a dedicated DB so we never trample the production graph,
# but co-located so the existing TrustGraph routers can query it
# (set TRUSTGRAPH_DB env to point existing services at it).
TG_DB = ROOT / ".aldeci" / "integration_topology.db"
TG_DB.parent.mkdir(parents=True, exist_ok=True)

from trustgraph.knowledge_store import KnowledgeEntity, KnowledgeRelationship, KnowledgeStore  # noqa: E402

# ---------------------------------------------------------------------------
# Federation taxonomy (real Fixops engines, real OSS tools)
# ---------------------------------------------------------------------------

# 8 integration families landing in this surge.
# Each: (family_label, oss_tool, oss_replacement_for, fixops_engine, finding_source)
INTEGRATION_FAMILIES: List[Dict[str, str]] = [
    {
        "family": "snyk_oss",
        "label": "Open-Source Vuln (Snyk-OSS)",
        "tool": "Trivy",
        "tool_label": "Trivy",
        "oss_replacement_for": "Snyk Open Source",
        "engine": "software_composition_analysis_engine",
        "engine_label": "SCA Engine",
        "finding_source": "cve",
    },
    {
        "family": "cspm",
        "label": "Cloud Security Posture (CSPM)",
        "tool": "Prowler",
        "tool_label": "Prowler",
        "oss_replacement_for": "Wiz / Lacework CSPM",
        "engine": "cspm_analyzer",
        "engine_label": "CSPM Analyzer",
        "finding_source": "misconfig",
    },
    {
        "family": "edr_xdr",
        "label": "Endpoint / Extended Detection (EDR/XDR)",
        "tool": "Wazuh",
        "tool_label": "Wazuh",
        "oss_replacement_for": "CrowdStrike Falcon / SentinelOne",
        "engine": "edr_engine",
        "engine_label": "EDR Engine",
        "finding_source": "endpoint_alert",
    },
    {
        "family": "siem",
        "label": "SIEM",
        "tool": "OpenSearch+Wazuh",
        "tool_label": "OpenSearch + Wazuh SIEM",
        "oss_replacement_for": "Splunk / Sentinel",
        "engine": "siem_integration_engine",
        "engine_label": "SIEM Integration",
        "finding_source": "log_event",
    },
    {
        "family": "container",
        "label": "Container Runtime + Image",
        "tool": "Falco+Trivy",
        "tool_label": "Falco + Trivy",
        "oss_replacement_for": "Sysdig Secure / Aqua",
        "engine": "container_runtime_security_engine",
        "engine_label": "Container Runtime Security",
        "finding_source": "runtime_violation",
    },
    {
        "family": "iam",
        "label": "Identity / IAM",
        "tool": "Keycloak+ScoutSuite",
        "tool_label": "Keycloak + ScoutSuite IAM",
        "oss_replacement_for": "Okta / Sailpoint",
        "engine": "iam_policy_analyzer",
        "engine_label": "IAM Policy Analyzer",
        "finding_source": "iam_drift",
    },
    {
        "family": "threat_intel",
        "label": "Threat Intelligence",
        "tool": "MISP+OpenCTI",
        "tool_label": "MISP + OpenCTI",
        "oss_replacement_for": "Recorded Future / Mandiant",
        "engine": "threat_intel_fusion_engine",
        "engine_label": "Threat Intel Fusion",
        "finding_source": "ioc",
    },
    {
        "family": "dast",
        "label": "Dynamic App Security (DAST)",
        "tool": "OWASP ZAP",
        "tool_label": "OWASP ZAP",
        "oss_replacement_for": "Veracode DAST / Invicti",
        "engine": "dast_engine",
        "engine_label": "DAST Engine",
        "finding_source": "dast",
    },
]

# 15 tenants — mix of recognizable apps + persona-tagged corp names
TENANTS: List[Dict[str, str]] = [
    {"id": "juice-shop-corp",       "vertical": "fintech",     "tier": "enterprise"},
    {"id": "dvwa-mfg",              "vertical": "manufacturing","tier": "enterprise"},
    {"id": "webgoat-health",        "vertical": "healthcare",  "tier": "enterprise"},
    {"id": "petclinic-saas",        "vertical": "saas",        "tier": "growth"},
    {"id": "nodegoat-retail",       "vertical": "retail",      "tier": "growth"},
    {"id": "bodgeit-edu",           "vertical": "education",   "tier": "starter"},
    {"id": "vampi-gov",             "vertical": "government",  "tier": "enterprise"},
    {"id": "altoro-bank",           "vertical": "fintech",     "tier": "enterprise"},
    {"id": "hackazon-ecom",         "vertical": "retail",      "tier": "growth"},
    {"id": "vulnado-airlines",      "vertical": "transport",   "tier": "enterprise"},
    {"id": "railsgoat-media",       "vertical": "media",       "tier": "growth"},
    {"id": "django-vuln-energy",    "vertical": "energy",      "tier": "enterprise"},
    {"id": "graphql-pwn-telecom",   "vertical": "telecom",     "tier": "enterprise"},
    {"id": "ssrf-lab-biotech",      "vertical": "biotech",     "tier": "growth"},
    {"id": "log4shell-pos-grocery", "vertical": "retail",      "tier": "starter"},
]

# Knowledge Core mapping (matches trustgraph_backbone.py)
CORE_CUSTOMER_ENV = 1   # tenant + connector
CORE_THREAT_INTEL = 2   # finding-source taxonomy + engines
CORE_COMPLIANCE = 3
CORE_DECISION_MEMORY = 4
CORE_EXTERNAL = 5       # OSS tools (third-party software)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _entity(eid: str, core: int, etype: str, name: str, **props: Any) -> KnowledgeEntity:
    return KnowledgeEntity(
        entity_id=eid,
        core_id=core,
        entity_type=etype,
        name=name,
        properties={**props, "indexed_at": _now()},
        org_id="aldeci-meta",  # synthetic meta-tenant scope for the topology view
    )


def _rel(src: str, tgt: str, rel_type: str, **props: Any) -> KnowledgeRelationship:
    return KnowledgeRelationship(
        rel_id=f"rel_{src}__{rel_type}__{tgt}"[:128],
        source_id=src,
        target_id=tgt,
        rel_type=rel_type,
        properties=props,
        confidence=1.0,
    )


def build_topology(store: KnowledgeStore) -> Dict[str, Any]:
    """Emit nodes + edges. Returns counts + sample shortest path."""
    counts = {"nodes": 0, "edges": 0, "by_type": {}}
    nodes_emitted: List[Tuple[str, str]] = []
    edges_emitted: List[Tuple[str, str, str]] = []

    def ingest_entity(ent: KnowledgeEntity) -> None:
        store.ingest(ent)
        counts["nodes"] += 1
        counts["by_type"][ent.entity_type] = counts["by_type"].get(ent.entity_type, 0) + 1
        nodes_emitted.append((ent.entity_id, ent.entity_type))

    def ingest_rel(rel: KnowledgeRelationship) -> None:
        try:
            store.add_relationship(rel)
            counts["edges"] += 1
            edges_emitted.append((rel.source_id, rel.target_id, rel.rel_type))
        except Exception as exc:
            # Ignore duplicates on rerun — KnowledgeStore enforces unique rel_id
            if "UNIQUE" not in str(exc) and "unique" not in str(exc).lower():
                raise

    # --- 1. OSS tools (Core 5: external) — global, shared across tenants ---
    for fam in INTEGRATION_FAMILIES:
        tool_id = f"tool_{fam['tool'].lower().replace('+', '_').replace(' ', '_')}"
        ingest_entity(_entity(
            tool_id,
            CORE_EXTERNAL,
            "OSSTool",
            fam["tool_label"],
            family=fam["family"],
            oss_replacement_for=fam["oss_replacement_for"],
            license="Apache-2.0",
            self_hosted=True,
        ))

    # --- 2. Fixops engines (Core 2: threat_intel) — global ---
    for fam in INTEGRATION_FAMILIES:
        engine_id = f"engine_{fam['engine']}"
        ingest_entity(_entity(
            engine_id,
            CORE_THREAT_INTEL,
            "FixopsEngine",
            fam["engine_label"],
            module=f"core/{fam['engine']}.py",
            family=fam["family"],
        ))
        # tool -feeds_engine-> engine
        tool_id = f"tool_{fam['tool'].lower().replace('+', '_').replace(' ', '_')}"
        ingest_rel(_rel(tool_id, engine_id, "FEEDS_ENGINE",
                        oss_replacement_for=fam["oss_replacement_for"]))

    # --- 3. Finding-source taxonomy (Core 2) — global badges ---
    finding_sources = sorted({fam["finding_source"] for fam in INTEGRATION_FAMILIES})
    for src in finding_sources:
        ingest_entity(_entity(
            f"findsrc_{src}",
            CORE_THREAT_INTEL,
            "FindingSource",
            src,
            category=src,
            badge=True,
        ))
    # engine -emits_to-> finding-source
    for fam in INTEGRATION_FAMILIES:
        engine_id = f"engine_{fam['engine']}"
        ingest_rel(_rel(engine_id, f"findsrc_{fam['finding_source']}", "EMITS_TO"))

    # --- 4. Tenants (Core 1: customer_env) ---
    for t in TENANTS:
        tenant_id = f"tenant_{t['id']}"
        ingest_entity(_entity(
            tenant_id,
            CORE_CUSTOMER_ENV,
            "Tenant",
            t["id"],
            vertical=t["vertical"],
            tier=t["tier"],
        ))

        # 8 connector nodes per tenant
        for fam in INTEGRATION_FAMILIES:
            connector_id = f"conn_{t['id']}__{fam['family']}"
            ingest_entity(_entity(
                connector_id,
                CORE_CUSTOMER_ENV,
                "Connector",
                f"{t['id']}/{fam['family']}",
                tenant=t["id"],
                family=fam["family"],
                status="active",
            ))
            # tenant -has_connector-> connector
            ingest_rel(_rel(tenant_id, connector_id, "HAS_CONNECTOR", family=fam["family"]))
            # connector -uses_tool-> tool (with metadata: oss_replacement_for)
            tool_id = f"tool_{fam['tool'].lower().replace('+', '_').replace(' ', '_')}"
            ingest_rel(_rel(connector_id, tool_id, "USES_TOOL",
                            oss_replacement_for=fam["oss_replacement_for"],
                            tenant=t["id"]))

    # --- 5. Sample shortest path: juice-shop-corp -> Wazuh -> security_event_correlation_engine ---
    # Verify our edges produce a real path. Add the bonus correlation engine link.
    correlation_engine_id = "engine_security_event_correlation_engine"
    if not any(eid == correlation_engine_id for eid, _ in nodes_emitted):
        ingest_entity(_entity(
            correlation_engine_id,
            CORE_THREAT_INTEL,
            "FixopsEngine",
            "Security Event Correlation",
            module="core/security_event_correlation_engine.py",
            family="siem",
        ))
        # Wazuh feeds the correlation engine too (cross-link)
        ingest_rel(_rel("tool_wazuh", correlation_engine_id, "FEEDS_ENGINE",
                        oss_replacement_for="Splunk Enterprise Security"))
        ingest_rel(_rel("tool_opensearch_wazuh", correlation_engine_id, "FEEDS_ENGINE",
                        oss_replacement_for="Splunk ES"))
        ingest_rel(_rel(correlation_engine_id, "findsrc_log_event", "EMITS_TO"))

    return {"counts": counts, "nodes": nodes_emitted, "edges": edges_emitted}


def shortest_path_demo(store: KnowledgeStore, src: str, tgt: str, max_depth: int = 5) -> List[str]:
    """BFS shortest-path through the graph using KnowledgeStore.get_relationships."""
    queue: List[List[str]] = [[src]]
    visited = {src}
    while queue:
        path = queue.pop(0)
        if len(path) > max_depth:
            continue
        cur = path[-1]
        if cur == tgt:
            return path
        try:
            rels = store.get_relationships(entity_id=cur)
        except Exception:
            rels = []
        for r in rels:
            nxt = r.target_id if r.source_id == cur else r.source_id
            if nxt not in visited:
                visited.add(nxt)
                queue.append(path + [nxt])
    return []


def dump_markdown(result: Dict[str, Any], path_demo: List[str]) -> str:
    """Write a markdown summary into raw/competitive/ so graphify picks it up."""
    out_path = ROOT / "raw" / "competitive" / "integration_topology.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    counts = result["counts"]
    lines: List[str] = []
    lines.append("# Integration Topology — TrustGraph Meta-Graph")
    lines.append("")
    lines.append(f"_Generated: {_now()}_")
    lines.append("")
    lines.append(f"- **Tenants**: {len(TENANTS)}")
    lines.append(f"- **Integration families**: {len(INTEGRATION_FAMILIES)}")
    lines.append(f"- **Total nodes ingested**: {counts['nodes']}")
    lines.append(f"- **Total edges ingested**: {counts['edges']}")
    lines.append("")
    lines.append("## Nodes by type")
    for t, n in sorted(counts["by_type"].items()):
        lines.append(f"- `{t}`: {n}")
    lines.append("")
    lines.append("## Integration families")
    lines.append("| Family | OSS Tool | Replaces | Fixops Engine | Finding Source |")
    lines.append("|---|---|---|---|---|")
    for fam in INTEGRATION_FAMILIES:
        lines.append(
            f"| {fam['family']} | {fam['tool_label']} | {fam['oss_replacement_for']} | "
            f"`{fam['engine']}` | `{fam['finding_source']}` |"
        )
    lines.append("")
    lines.append("## Tenants")
    lines.append("| Tenant | Vertical | Tier | Connectors |")
    lines.append("|---|---|---|---|")
    for t in TENANTS:
        lines.append(f"| `{t['id']}` | {t['vertical']} | {t['tier']} | {len(INTEGRATION_FAMILIES)} |")
    lines.append("")
    lines.append("## Sample shortest path (BFS over real TrustGraph edges)")
    lines.append("")
    lines.append("Query: `tenant_juice-shop-corp` → `engine_security_event_correlation_engine`")
    lines.append("")
    if path_demo:
        lines.append("```")
        for i, eid in enumerate(path_demo):
            arrow = "  -> " if i > 0 else "  "
            lines.append(f"{arrow}{eid}")
        lines.append("```")
        lines.append(f"_{len(path_demo) - 1} hops_")
    else:
        lines.append("_no path found_")
    lines.append("")
    lines.append("## Edge vocabulary")
    lines.append("- `HAS_CONNECTOR` — tenant owns a connector instance")
    lines.append("- `USES_TOOL` — connector binds to an OSS tool (replaces a paid SaaS)")
    lines.append("- `FEEDS_ENGINE` — OSS tool emits findings into a Fixops engine")
    lines.append("- `EMITS_TO` — Fixops engine produces a finding-source category")
    lines.append("")
    lines.append("## Cross-link to Fixops research graph")
    lines.append("Engines listed here are the same nodes already present in `graphify-out/graph-filtered.html` ")
    lines.append("(the Fixops + research graph). When the new `graphify-out-integrations/graph.html` is overlaid, ")
    lines.append("the engine nodes act as joins linking the two corpora into one federation map.")
    lines.append("")
    out_path.write_text("\n".join(lines))
    return str(out_path)


def main() -> int:
    print(f"[topology] using TrustGraph DB: {TG_DB}")
    store = KnowledgeStore(db_path=str(TG_DB))

    result = build_topology(store)
    counts = result["counts"]
    print(f"[topology] ingested {counts['nodes']} nodes, {counts['edges']} edges")
    print(f"[topology] node types: {counts['by_type']}")

    # Sample path query — proves graph is queryable
    path = shortest_path_demo(
        store,
        "tenant_juice-shop-corp",
        "engine_security_event_correlation_engine",
        max_depth=5,
    )
    if path:
        print(f"[topology] sample shortest path ({len(path) - 1} hops):")
        for eid in path:
            print(f"   -> {eid}")
    else:
        print("[topology] WARNING: no path found juice-shop-corp -> security_event_correlation")

    md_path = dump_markdown(result, path)
    print(f"[topology] markdown summary written: {md_path}")

    # Also dump a graph.json compatible blob so graphify can consume it directly if needed
    dump_path = ROOT / ".aldeci" / "integration_topology_dump.json"
    dump_path.write_text(json.dumps({
        "nodes": [
            {"id": eid, "type": etype}
            for eid, etype in result["nodes"]
        ],
        "edges": [
            {"source": s, "target": t, "rel": rt}
            for s, t, rt in result["edges"]
        ],
        "counts": counts,
        "sample_path": path,
        "generated_at": _now(),
    }, indent=2))
    print(f"[topology] dump JSON: {dump_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
