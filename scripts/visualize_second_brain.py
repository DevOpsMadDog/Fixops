"""
Second-Brain Visualization — TrustGraph coverage density over the graphify graph.

Reads:
    graphify-out/graph.json                 — full code graph (119k nodes, 408k edges)
    suite-core/core/trustgraph_event_bus.py — event-bus implementation (for middleware
                                              auto-emit detection)
    grep results across suite-core/ + suite-api/ for direct emit-site detection.

Classifies every node by its `source_file` against TrustGraph emission status:
    GREEN  — file directly emits to TrustGraph (uses get_event_bus / _emit_event /
             bus.publish / bus.emit / from core.trustgraph_event_bus)
    AQUA   — file does NOT directly emit but is reachable (within depth 2) from a
             GREEN/wired hub via an inbound import/call edge.  The hub effectively
             pumps these files' state through the bus on its own emit.
    YELLOW — file is a router/middleware-touched file in suite-api/apps/api/ and is
             therefore covered by ResponseInterceptorMiddleware auto-emit
    RED    — file has no known link into TrustGraph (not even via blast-radius)

Outputs:
    graphify-out/second_brain.html       — interactive pyvis force-directed view
                                           with legend, color-coded nodes, % coverage
                                           badge, and node-count breakdown
    graphify-out/SECOND_BRAIN_REPORT.md  — plain-text coverage report

The visualization is sampled (top-N by degree) so the HTML stays openable; the
markdown report uses the FULL node set for stats.

Read-only with respect to source code: this script does NOT modify any engine,
connector, router, or trustgraph_event_bus.py.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
GRAPH_JSON = REPO_ROOT / "graphify-out" / "graph.json"
OUT_HTML = REPO_ROOT / "graphify-out" / "second_brain.html"
OUT_REPORT = REPO_ROOT / "graphify-out" / "SECOND_BRAIN_REPORT.md"

# Regex used to find direct TrustGraph emit-sites in source code.
# Includes the new connectors._emit helper indirection (added 2026-04-26 as
# part of the connector wave — single shared helper publishes to TrustGraph
# event bus + legacy in-process bus, used by all 16+ connectors).
EMIT_PATTERN = re.compile(
    r"(from\s+core\.trustgraph_event_bus|"
    r"from\s+connectors\._emit|"
    r"_emit_event\s*\(|"
    r"emit_connector_event\s*\(|"
    r"bus\.publish\s*\(|"
    r"bus\.emit\s*\(|"
    r"get_event_bus\s*\()"
)

# Roots to scan for emit-sites
SCAN_ROOTS = ["suite-core", "suite-api"]

# Roots considered "middleware auto-emit covered" (ResponseInterceptorMiddleware
# wraps every POST/PUT/PATCH response in the API gateway)
MIDDLEWARE_COVERED_PREFIXES = ("suite-api/apps/api/",)

# Color palette
COLOR_GREEN = "#1ec97a"   # directly wired
COLOR_AQUA = "#3ec5ff"    # reachable via wired hub (blast-radius depth <= 2)
COLOR_YELLOW = "#f5c542"  # likely-wired via middleware
COLOR_RED = "#e34a4a"     # disconnected
COLOR_GREY = "#444"        # docs / non-code (excluded from %)

# How many hops outward from a GREEN file we walk before stopping.
# 1 = files that directly import or are called by the hub.
# 2 = files that import a file that imports the hub.
BLAST_RADIUS_DEPTH = 2


def find_emit_files() -> Set[str]:
    """Return set of repo-relative paths whose source contains a TrustGraph emit call."""
    found: Set[str] = set()
    for root in SCAN_ROOTS:
        root_path = REPO_ROOT / root
        if not root_path.exists():
            continue
        # Walk the tree and grep for emit pattern in .py files
        for path in root_path.rglob("*.py"):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if EMIT_PATTERN.search(text):
                rel = str(path.relative_to(REPO_ROOT))
                found.add(rel)
    return found


def classify_file(source_file: str, emit_files: Set[str]) -> str:
    """Return one of: green, yellow, red, grey."""
    if not source_file:
        return "grey"
    # Non-code files don't participate in TrustGraph wiring
    lower = source_file.lower()
    if lower.endswith((".md", ".rst", ".txt", ".json", ".yaml", ".yml")):
        return "grey"
    if source_file in emit_files:
        return "green"
    if source_file.startswith(MIDDLEWARE_COVERED_PREFIXES):
        return "yellow"
    return "red"


def load_graph() -> dict:
    print(f"Loading graph: {GRAPH_JSON} ({GRAPH_JSON.stat().st_size / 1e6:.1f} MB)...")
    with GRAPH_JSON.open() as fh:
        g = json.load(fh)
    print(f"  nodes={len(g['nodes'])} links={len(g['links'])}")
    return g


def compute_degrees(nodes: List[dict], links: List[dict]) -> Dict[str, int]:
    """Return per-node degree (in + out)."""
    deg: Dict[str, int] = defaultdict(int)
    valid_ids = {n["id"] for n in nodes}
    for e in links:
        s = e.get("_src") or e.get("source")
        t = e.get("_tgt") or e.get("target")
        if s in valid_ids:
            deg[s] += 1
        if t in valid_ids:
            deg[t] += 1
    return deg


def compute_blast_radius(
    nodes: List[dict],
    links: List[dict],
    file_class: Dict[str, str],
    depth: int = BLAST_RADIUS_DEPTH,
) -> Set[str]:
    """Return the set of source files reachable from a GREEN file within `depth` hops.

    Direction:
        We follow edges OUTWARD from the GREEN hub.  An edge `A -> B` (A imports
        or calls B; or A "contains" symbol B) means symbol B is part of the
        hub's surface, so when the hub emits, the hub's outputs reflect B's
        state.  We therefore mark B's *file* as reachable.

    The traversal works on a file-level graph derived from the symbol graph:
        for each (src_node, tgt_node) link, we add a (src_file, tgt_file) edge.

    GREEN files themselves are excluded from the return set (they're already
    GREEN; we only mark *new* files as AQUA).
    """
    # Build node-id -> file map
    node_file: Dict[str, str] = {}
    for n in nodes:
        sf = n.get("source_file", "")
        if sf:
            node_file[n["id"]] = sf

    # Build adjacency at file level (outbound: src_file -> set of tgt_files)
    file_adj: Dict[str, Set[str]] = defaultdict(set)
    for e in links:
        s = e.get("_src") or e.get("source")
        t = e.get("_tgt") or e.get("target")
        sf = node_file.get(s)
        tf = node_file.get(t)
        if sf and tf and sf != tf:
            file_adj[sf].add(tf)

    # BFS from each GREEN seed up to `depth` hops
    green_seeds = {f for f, c in file_class.items() if c == "green"}
    reached: Set[str] = set()

    for seed in green_seeds:
        # frontier per seed
        frontier: Set[str] = {seed}
        for _hop in range(depth):
            next_frontier: Set[str] = set()
            for f in frontier:
                for nbr in file_adj.get(f, ()):
                    if nbr in green_seeds:
                        continue  # already GREEN — don't downgrade to AQUA
                    if nbr not in reached:
                        next_frontier.add(nbr)
                        reached.add(nbr)
            if not next_frontier:
                break
            frontier = next_frontier

    return reached


def write_report(
    nodes: List[dict],
    links: List[dict],
    classification: Dict[str, str],
    degrees: Dict[str, int],
    file_class: Dict[str, str],
    file_node_count: Dict[str, int],
    emit_files: Set[str],
) -> Dict[str, int]:
    """Write SECOND_BRAIN_REPORT.md and return color counts."""
    color_counts = Counter(classification.values())
    total_code = (
        color_counts.get("green", 0)
        + color_counts.get("aqua", 0)
        + color_counts.get("yellow", 0)
        + color_counts.get("red", 0)
    )
    pct_green = 100 * color_counts.get("green", 0) / max(total_code, 1)
    pct_aqua = 100 * color_counts.get("aqua", 0) / max(total_code, 1)
    pct_yellow = 100 * color_counts.get("yellow", 0) / max(total_code, 1)
    pct_red = 100 * color_counts.get("red", 0) / max(total_code, 1)
    pct_reachable = (
        100
        * (color_counts.get("green", 0) + color_counts.get("aqua", 0))
        / max(total_code, 1)
    )
    pct_wired_total = (
        100
        * (
            color_counts.get("green", 0)
            + color_counts.get("aqua", 0)
            + color_counts.get("yellow", 0)
        )
        / max(total_code, 1)
    )

    # Per-file degree (sum of node degrees grouped by source_file)
    file_degree: Dict[str, int] = defaultdict(int)
    for n in nodes:
        sf = n.get("source_file", "")
        if sf:
            file_degree[sf] += degrees.get(n["id"], 0)

    # Top unwired hubs (RED files with highest degree)
    red_hubs = sorted(
        ((f, file_degree[f], file_node_count[f]) for f, c in file_class.items() if c == "red"),
        key=lambda t: t[1],
        reverse=True,
    )[:20]

    # Top well-wired hubs (GREEN files with highest degree)
    green_hubs = sorted(
        ((f, file_degree[f], file_node_count[f]) for f, c in file_class.items() if c == "green"),
        key=lambda t: t[1],
        reverse=True,
    )[:20]

    # Cluster (community) coverage: % wired per community
    community_stats: Dict[int, Counter] = defaultdict(Counter)
    for n in nodes:
        c = n.get("community", -1)
        community_stats[c][classification.get(n["id"], "grey")] += 1

    community_rows = []
    for cid, cnt in community_stats.items():
        cc = cnt.get("green", 0) + cnt.get("yellow", 0) + cnt.get("red", 0)
        if cc < 50:  # ignore tiny communities
            continue
        wired = cnt.get("green", 0) + cnt.get("yellow", 0)
        community_rows.append((cid, cc, wired, 100 * wired / cc))

    most_wired = sorted(community_rows, key=lambda r: (-r[3], -r[1]))[:10]
    least_wired = sorted(community_rows, key=lambda r: (r[3], -r[1]))[:10]

    lines = []
    lines.append("# Second-Brain Coverage Report — TrustGraph wiring density")
    lines.append("")
    lines.append(f"_Generated by `scripts/visualize_second_brain.py` from `graphify-out/graph.json`._")
    lines.append("")
    lines.append("## Headline numbers")
    lines.append("")
    lines.append(f"- **Total nodes**: {len(nodes):,}")
    lines.append(f"- **Total edges**: {len(links):,}")
    lines.append(f"- **Code nodes (excluding docs/configs)**: {total_code:,}")
    lines.append(f"- **GREEN — direct TrustGraph emit**: {color_counts.get('green', 0):,} ({pct_green:.1f}%)")
    lines.append(
        f"- **AQUA — reachable via wired hub (depth ≤ {BLAST_RADIUS_DEPTH})**: "
        f"{color_counts.get('aqua', 0):,} ({pct_aqua:.1f}%)"
    )
    lines.append(f"- **YELLOW — middleware auto-emit (suite-api routers)**: {color_counts.get('yellow', 0):,} ({pct_yellow:.1f}%)")
    lines.append(f"- **RED — disconnected from TrustGraph**: {color_counts.get('red', 0):,} ({pct_red:.1f}%)")
    lines.append(f"- **GREY — docs / non-code**: {color_counts.get('grey', 0):,}")
    lines.append("")
    lines.append(
        f"- **Reachable via wired hubs (GREEN + AQUA)**: {pct_reachable:.1f}%  "
        f"← *true second-brain coverage including blast-radius*"
    )
    lines.append(
        f"- **Total wired (GREEN + AQUA + YELLOW)**: {pct_wired_total:.1f}%  "
        f"← *includes middleware-covered routers*"
    )
    lines.append("")
    lines.append(f"- **Files emitting directly**: {len(emit_files):,}")
    lines.append(f"- **Source files in graph**: {len(file_class):,}")
    lines.append("")
    lines.append("## Top 20 unwired hubs (RED, highest in/out-degree) — priority next-wires")
    lines.append("")
    lines.append("| # | Source file | Total degree | Node count |")
    lines.append("|---|-------------|--------------|------------|")
    for i, (f, d, nc) in enumerate(red_hubs, 1):
        lines.append(f"| {i} | `{f}` | {d:,} | {nc:,} |")
    lines.append("")
    lines.append("## Top 20 well-wired hubs (GREEN, highest in/out-degree)")
    lines.append("")
    lines.append("| # | Source file | Total degree | Node count |")
    lines.append("|---|-------------|--------------|------------|")
    for i, (f, d, nc) in enumerate(green_hubs, 1):
        lines.append(f"| {i} | `{f}` | {d:,} | {nc:,} |")
    lines.append("")
    lines.append("## Most-wired communities (top 10 by % wired, communities >= 50 nodes)")
    lines.append("")
    lines.append("| Community | Code nodes | Wired (green+yellow) | % wired |")
    lines.append("|-----------|------------|---------------------|---------|")
    for cid, cc, wired, pct in most_wired:
        lines.append(f"| {cid} | {cc:,} | {wired:,} | {pct:.1f}% |")
    lines.append("")
    lines.append("## Least-wired communities (bottom 10 by % wired, communities >= 50 nodes)")
    lines.append("")
    lines.append("| Community | Code nodes | Wired (green+yellow) | % wired |")
    lines.append("|-----------|------------|---------------------|---------|")
    for cid, cc, wired, pct in least_wired:
        lines.append(f"| {cid} | {cc:,} | {wired:,} | {pct:.1f}% |")
    lines.append("")
    lines.append("## How to read this")
    lines.append("")
    lines.append(
        "- A **node** is one symbol (function, class, module) extracted by graphify."
        " The color reflects the *file* the symbol belongs to, since TrustGraph wiring"
        " is a file-level property (one `from core.trustgraph_event_bus import ...` covers"
        " all symbols in that file)."
    )
    lines.append(
        "- **GREEN** = the file directly imports `core.trustgraph_event_bus` or calls"
        " `get_event_bus()`, `bus.emit()`, `bus.publish()`, or `_emit_event()` somewhere."
    )
    lines.append(
        f"- **AQUA** = the file does not directly emit, but it is reached within"
        f" {BLAST_RADIUS_DEPTH} hop(s) outward from a GREEN hub via the call/import"
        f" graph.  When the hub fires its emit on a public method, the AQUA file's"
        f" state is part of the hub's surface — so it is effectively second-brain"
        f" reachable without needing its own emit."
    )
    lines.append(
        "- **YELLOW** = the file lives under `suite-api/apps/api/` and is therefore"
        " auto-covered by `ResponseInterceptorMiddleware`, which sniffs every POST/PUT/PATCH"
        " response for entity IDs and emits an event without the router needing to know."
    )
    lines.append(
        "- **RED** = no known wire into TrustGraph (not even via blast-radius from a"
        " wired hub). These are the next-priority files to either wire directly or to"
        " surface through an existing hub."
    )
    lines.append(
        "- **GREY** = documentation / config / non-Python — excluded from the % coverage."
    )

    OUT_REPORT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote report: {OUT_REPORT}")
    return color_counts


def write_html(
    nodes: List[dict],
    links: List[dict],
    classification: Dict[str, str],
    degrees: Dict[str, int],
    color_counts: Counter,
    sample_n: int = 1500,
) -> None:
    """Write the interactive pyvis HTML."""
    from pyvis.network import Network  # local import; pyvis 0.3.2 verified available

    # Sample top-N nodes by degree so the HTML stays openable
    ranked = sorted(nodes, key=lambda n: degrees.get(n["id"], 0), reverse=True)
    keep_ids = {n["id"] for n in ranked[:sample_n]}
    keep_nodes = [n for n in nodes if n["id"] in keep_ids]

    net = Network(
        height="900px",
        width="100%",
        bgcolor="#0d1117",
        font_color="#e6edf3",
        directed=True,
        notebook=False,
    )
    # Force-directed layout
    net.barnes_hut(
        gravity=-8000,
        central_gravity=0.3,
        spring_length=120,
        spring_strength=0.04,
        damping=0.4,
        overlap=0,
    )

    color_map = {
        "green": COLOR_GREEN,
        "aqua": COLOR_AQUA,
        "yellow": COLOR_YELLOW,
        "red": COLOR_RED,
        "grey": COLOR_GREY,
    }

    for n in keep_nodes:
        cls = classification.get(n["id"], "grey")
        deg = degrees.get(n["id"], 0)
        size = max(8, min(40, 8 + deg ** 0.5 * 1.5))
        title_lines = [
            f"<b>{n.get('label', '?')}</b>",
            f"file: {n.get('source_file', '?')}",
            f"degree: {deg}",
            f"community: {n.get('community', '?')}",
            f"trustgraph: <b style='color:{color_map[cls]}'>{cls.upper()}</b>",
        ]
        net.add_node(
            n["id"],
            label=n.get("label", n["id"])[:30],
            color=color_map[cls],
            size=size,
            title="<br>".join(title_lines),
            borderWidth=1,
        )

    edge_count = 0
    for e in links:
        s = e.get("_src") or e.get("source")
        t = e.get("_tgt") or e.get("target")
        if s in keep_ids and t in keep_ids:
            cs = classification.get(s, "grey")
            ct = classification.get(t, "grey")
            # Heavier edge if both endpoints are reachable into TrustGraph
            wired = cs in ("green", "aqua", "yellow") and ct in ("green", "aqua", "yellow")
            net.add_edge(
                s,
                t,
                width=2.5 if wired else 0.6,
                color="#5fa8d3" if wired else "#2a2a2a",
            )
            edge_count += 1

    print(f"  HTML: kept {len(keep_nodes)} nodes (top by degree), {edge_count} edges")

    total_code = (
        color_counts.get("green", 0)
        + color_counts.get("aqua", 0)
        + color_counts.get("yellow", 0)
        + color_counts.get("red", 0)
    )
    pct_reachable = (
        100
        * (color_counts.get("green", 0) + color_counts.get("aqua", 0))
        / max(total_code, 1)
    )
    pct_wired = (
        100
        * (
            color_counts.get("green", 0)
            + color_counts.get("aqua", 0)
            + color_counts.get("yellow", 0)
        )
        / max(total_code, 1)
    )

    # pyvis writes an HTML file we then post-process to inject overlays
    tmp_html = OUT_HTML.with_suffix(".tmp.html")
    net.write_html(str(tmp_html), open_browser=False, notebook=False)
    raw = tmp_html.read_text(encoding="utf-8")

    badge = f"""
<style>
  body {{ background: #0d1117 !important; }}
  #sb-overlay {{
    position: fixed; top: 14px; right: 14px; z-index: 999;
    background: rgba(13,17,23,0.92); border: 1px solid #30363d;
    border-radius: 8px; padding: 14px 18px; color: #e6edf3;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    box-shadow: 0 4px 12px rgba(0,0,0,0.4); min-width: 280px;
  }}
  #sb-overlay h2 {{ margin: 0 0 8px 0; font-size: 16px; color: #58a6ff; }}
  #sb-overlay .pct {{ font-size: 32px; font-weight: 700; color: {COLOR_GREEN}; }}
  #sb-overlay .legend-row {{ display: flex; align-items: center; gap: 8px; margin-top: 6px; font-size: 13px; }}
  #sb-overlay .swatch {{ width: 14px; height: 14px; border-radius: 3px; display: inline-block; }}
  #sb-overlay .small {{ font-size: 11px; opacity: 0.7; margin-top: 8px; }}
</style>
<div id="sb-overlay">
  <h2>TrustGraph Coverage</h2>
  <div class="pct">{pct_reachable:.1f}%</div>
  <div style="font-size:12px;opacity:0.8;margin-bottom:4px;">reachable via wired hubs (GREEN + AQUA, depth ≤ {BLAST_RADIUS_DEPTH})</div>
  <div style="font-size:12px;opacity:0.8;margin-bottom:8px;">{pct_wired:.1f}% total wired (incl. middleware) of {total_code:,} code nodes</div>
  <div class="legend-row"><span class="swatch" style="background:{COLOR_GREEN}"></span>
    GREEN direct emit ({color_counts.get('green', 0):,})</div>
  <div class="legend-row"><span class="swatch" style="background:{COLOR_AQUA}"></span>
    AQUA blast-radius ({color_counts.get('aqua', 0):,})</div>
  <div class="legend-row"><span class="swatch" style="background:{COLOR_YELLOW}"></span>
    YELLOW middleware ({color_counts.get('yellow', 0):,})</div>
  <div class="legend-row"><span class="swatch" style="background:{COLOR_RED}"></span>
    RED disconnected ({color_counts.get('red', 0):,})</div>
  <div class="legend-row"><span class="swatch" style="background:{COLOR_GREY}"></span>
    GREY non-code ({color_counts.get('grey', 0):,})</div>
  <div class="small">Showing top-{len(keep_nodes)} nodes by degree.<br>Hover any node for file + class.</div>
</div>
"""
    if "</body>" in raw:
        raw = raw.replace("</body>", badge + "</body>")
    else:
        raw = raw + badge
    OUT_HTML.write_text(raw, encoding="utf-8")
    tmp_html.unlink(missing_ok=True)
    print(f"Wrote HTML: {OUT_HTML}")


def main() -> int:
    if not GRAPH_JSON.exists():
        print(f"ERROR: graph.json not found at {GRAPH_JSON}", file=sys.stderr)
        return 1

    print("Step 1/4: scanning emit-sites...")
    emit_files = find_emit_files()
    print(f"  found {len(emit_files)} files with direct TrustGraph emit calls")

    print("Step 2/4: loading graph...")
    g = load_graph()
    nodes = g["nodes"]
    links = g["links"]

    print("Step 3/5: classifying nodes + computing degrees...")
    # File-level classification (initial pass: green/yellow/red/grey)
    file_class: Dict[str, str] = {}
    file_node_count: Dict[str, int] = Counter()
    for n in nodes:
        sf = n.get("source_file", "")
        file_node_count[sf] += 1
        if sf not in file_class:
            file_class[sf] = classify_file(sf, emit_files)
    degrees = compute_degrees(nodes, links)

    print(
        f"Step 4/5: computing blast-radius (depth {BLAST_RADIUS_DEPTH}) "
        f"from {sum(1 for c in file_class.values() if c == 'green')} GREEN seeds..."
    )
    aqua_files = compute_blast_radius(nodes, links, file_class, depth=BLAST_RADIUS_DEPTH)
    # Promote RED -> AQUA where reachable.  Do NOT touch GREEN, YELLOW, or GREY.
    promoted = 0
    for f in aqua_files:
        if file_class.get(f) == "red":
            file_class[f] = "aqua"
            promoted += 1
    print(f"  promoted {promoted} files RED -> AQUA via blast radius")

    # Per-node classification (inherits from file, post-promotion)
    classification: Dict[str, str] = {}
    for n in nodes:
        sf = n.get("source_file", "")
        classification[n["id"]] = file_class.get(sf, "grey")

    print("Step 5/5: writing report + HTML...")
    color_counts = write_report(
        nodes, links, classification, degrees, file_class, file_node_count, emit_files
    )
    write_html(nodes, links, classification, degrees, color_counts)

    total_code = (
        color_counts.get("green", 0)
        + color_counts.get("aqua", 0)
        + color_counts.get("yellow", 0)
        + color_counts.get("red", 0)
    )
    pct_reachable = (
        100
        * (color_counts.get("green", 0) + color_counts.get("aqua", 0))
        / max(total_code, 1)
    )
    pct_wired = (
        100
        * (
            color_counts.get("green", 0)
            + color_counts.get("aqua", 0)
            + color_counts.get("yellow", 0)
        )
        / max(total_code, 1)
    )
    print()
    print("=" * 60)
    print(f"Reachable via wired hubs (GREEN+AQUA): {pct_reachable:.1f}% of {total_code:,} code nodes")
    print(f"Total wired (GREEN+AQUA+YELLOW):      {pct_wired:.1f}%")
    print(f"  GREEN  {color_counts.get('green', 0):>7,}  (direct emit)")
    print(f"  AQUA   {color_counts.get('aqua', 0):>7,}  (blast-radius depth {BLAST_RADIUS_DEPTH})")
    print(f"  YELLOW {color_counts.get('yellow', 0):>7,}  (middleware auto-emit)")
    print(f"  RED    {color_counts.get('red', 0):>7,}  (disconnected)")
    print(f"  GREY   {color_counts.get('grey', 0):>7,}  (non-code)")
    print("=" * 60)
    print(f"Open: {OUT_HTML}")
    print(f"Read: {OUT_REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
