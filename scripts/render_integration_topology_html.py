"""
Render the integration topology meta-graph to interactive HTML using
the graphify library directly (no LLM, no subagent dispatch — purely
deterministic build from the TrustGraph dump JSON).

Outputs:
  graphify-out-integrations/graph.html      — interactive meta-graph
  graphify-out-integrations/graph.json      — graphify-format graph
  graphify-out-integrations/GRAPH_REPORT.md — audit report
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DUMP_PATH = ROOT / ".aldeci" / "integration_topology_dump.json"
OUT_DIR = ROOT / "graphify-out-integrations"
OUT_DIR.mkdir(parents=True, exist_ok=True)

if not DUMP_PATH.exists():
    print(f"ERROR: missing {DUMP_PATH} — run scripts/build_integration_topology.py first")
    sys.exit(1)

dump = json.loads(DUMP_PATH.read_text())

# ---------------------------------------------------------------------------
# Convert the TrustGraph dump into the graphify extraction format.
# Schema: {nodes:[{id,label,file_type,source_file,...}], edges:[{source,target,relation,confidence,confidence_score,weight}]}
# ---------------------------------------------------------------------------

# Pretty labels per type
TYPE_FILE = {
    "Tenant": "document",
    "Connector": "document",
    "OSSTool": "document",
    "FixopsEngine": "code",
    "FindingSource": "document",
}

REL_RELATION = {
    "HAS_CONNECTOR": "has_connector",
    "USES_TOOL": "uses_tool",
    "FEEDS_ENGINE": "feeds_engine",
    "EMITS_TO": "emits_to",
}


def label_for(node_id: str, node_type: str) -> str:
    # Strip prefix
    base = node_id
    for prefix in ("tenant_", "conn_", "tool_", "engine_", "findsrc_"):
        if base.startswith(prefix):
            base = base[len(prefix):]
            break
    return base.replace("_", " ").replace("__", " / ")


nodes_out = []
seen = set()
for n in dump["nodes"]:
    if n["id"] in seen:
        continue
    seen.add(n["id"])
    nodes_out.append({
        "id": n["id"],
        "label": label_for(n["id"], n["type"]),
        "file_type": TYPE_FILE.get(n["type"], "document"),
        "source_file": f"trustgraph/{n['type']}",
        "source_location": None,
        "source_url": None,
        "captured_at": dump["generated_at"],
        "author": "trustgraph_event_bus",
        "contributor": "data-scientist",
        "node_type": n["type"],
    })

edges_out = []
for e in dump["edges"]:
    edges_out.append({
        "source": e["source"],
        "target": e["target"],
        "relation": REL_RELATION.get(e["rel"], e["rel"].lower()),
        "confidence": "EXTRACTED",
        "confidence_score": 1.0,
        "source_file": "trustgraph/integration_topology",
        "source_location": None,
        "weight": 1.0,
    })

extraction = {
    "nodes": nodes_out,
    "edges": edges_out,
    "hyperedges": [],
    "input_tokens": 0,
    "output_tokens": 0,
}

(OUT_DIR / ".graphify_extract.json").write_text(json.dumps(extraction, indent=2))

# ---------------------------------------------------------------------------
# Build, cluster, render via graphify library
# ---------------------------------------------------------------------------

from graphify.build import build_from_json
from graphify.cluster import cluster, score_all
from graphify.analyze import god_nodes, surprising_connections
from graphify.export import to_html, to_json

G = build_from_json(extraction)
print(f"[render] built graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

communities = cluster(G)
cohesion = score_all(G, communities)
print(f"[render] communities: {len(communities)}")

# Smart community labelling — name the cluster after its anchor tenant if any,
# otherwise after its OSS tool / engine / taxonomy hub.
labels = {}
for cid, members in communities.items():
    type_counts = {}
    tenant_name = None
    tool_name = None
    for nid in members:
        nd = G.nodes[nid]
        nt = nd.get("node_type") or nd.get("file_type", "node")
        type_counts[nt] = type_counts.get(nt, 0) + 1
        if nt == "Tenant" and tenant_name is None:
            tenant_name = nd.get("label", nid)
        elif nt == "OSSTool" and tool_name is None:
            tool_name = nd.get("label", nid)
    if tenant_name:
        labels[cid] = f"Tenant: {tenant_name}"
    elif tool_name:
        labels[cid] = f"OSS Hub: {tool_name}"
    else:
        top = sorted(type_counts.items(), key=lambda kv: -kv[1])[0][0]
        pretty = {
            "Tenant": "Tenant Cluster",
            "Connector": "Connector Mesh",
            "OSSTool": "OSS Tool Federation",
            "FixopsEngine": "Fixops Engine Layer",
            "FindingSource": "Finding Taxonomy",
        }.get(top, f"{top} Cluster")
        labels[cid] = f"{pretty} #{cid}"

# Render
to_json(G, communities, str(OUT_DIR / "graph.json"))
print(f"[render] wrote graph.json")

to_html(G, communities, str(OUT_DIR / "graph.html"), community_labels=labels)
print(f"[render] wrote graph.html")

# Audit report
gods = god_nodes(G)
surprises = surprising_connections(G, communities)
report_lines = [
    "# Integration Topology — graph audit report",
    "",
    f"- Nodes: {G.number_of_nodes()}",
    f"- Edges: {G.number_of_edges()}",
    f"- Communities: {len(communities)}",
    "",
    "## Community labels",
]
for cid, lbl in labels.items():
    members = communities[cid]
    cohe = cohesion.get(cid, 0.0)
    report_lines.append(f"- **{lbl}** — {len(members)} nodes, cohesion {cohe:.3f}")

report_lines.extend(["", "## God nodes (highest degree)"])
for g in gods[:10]:
    report_lines.append(f"- `{g['id']}` ({g.get('label','')}) — degree {g['degree']}")

report_lines.extend(["", "## Surprising bridges (cross-community connectors)"])
for s in surprises[:10]:
    report_lines.append(f"- `{s['source']}` <-> `{s['target']}` (relation: {s.get('relation','?')})")

report_lines.extend([
    "", "## Sample shortest path (from TrustGraph BFS)", "",
    "Query: `tenant_juice-shop-corp` -> `engine_security_event_correlation_engine`", "",
    "```",
])
for eid in dump["sample_path"]:
    report_lines.append(f"  -> {eid}")
report_lines.append("```")
report_lines.append(f"_{len(dump['sample_path'])-1} hops via the EDR/XDR connector + Wazuh OSS tool_")

(OUT_DIR / "GRAPH_REPORT.md").write_text("\n".join(report_lines))
print(f"[render] wrote GRAPH_REPORT.md")

print()
print(f"Outputs in {OUT_DIR}/")
print(f"  graph.html         — interactive viz")
print(f"  graph.json         — graphify-format graph data")
print(f"  GRAPH_REPORT.md    — audit + community labels")
