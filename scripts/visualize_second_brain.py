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
    YELLOW — file is a router/middleware-touched file in suite-api/apps/api/ and is
             therefore covered by ResponseInterceptorMiddleware auto-emit
    RED    — file has no known link into TrustGraph

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

# Regex used to find direct TrustGraph emit-sites in source code
EMIT_PATTERN = re.compile(
    r"(from\s+core\.trustgraph_event_bus|"
    r"_emit_event\s*\(|"
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
COLOR_YELLOW = "#f5c542"  # likely-wired via middleware
COLOR_RED = "#e34a4a"     # disconnected
COLOR_GREY = "#444"        # docs / non-code (excluded from %)


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
        + color_counts.get("yellow", 0)
        + color_counts.get("red", 0)
    )
    pct_green = 100 * color_counts.get("green", 0) / max(total_code, 1)
    pct_yellow = 100 * color_counts.get("yellow", 0) / max(total_code, 1)
    pct_red = 100 * color_counts.get("red", 0) / max(total_code, 1)

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
    lines.append(f"- **YELLOW — middleware auto-emit (suite-api routers)**: {color_counts.get('yellow', 0):,} ({pct_yellow:.1f}%)")
    lines.append(f"- **RED — disconnected from TrustGraph**: {color_counts.get('red', 0):,} ({pct_red:.1f}%)")
    lines.append(f"- **GREY — docs / non-code**: {color_counts.get('grey', 0):,}")
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
        "- **YELLOW** = the file lives under `suite-api/apps/api/` and is therefore"
        " auto-covered by `ResponseInterceptorMiddleware`, which sniffs every POST/PUT/PATCH"
        " response for entity IDs and emits an event without the router needing to know."
    )
    lines.append(
        "- **RED** = no known wire into TrustGraph. These are the next-priority files to"
        " add explicit emits to."
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
            # Heavier edge if both endpoints are wired into TrustGraph
            wired = cs in ("green", "yellow") and ct in ("green", "yellow")
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
        + color_counts.get("yellow", 0)
        + color_counts.get("red", 0)
    )
    pct_wired = (
        100 * (color_counts.get("green", 0) + color_counts.get("yellow", 0)) / max(total_code, 1)
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
  <div class="pct">{pct_wired:.1f}%</div>
  <div style="font-size:12px;opacity:0.8;margin-bottom:8px;">of {total_code:,} code nodes wired</div>
  <div class="legend-row"><span class="swatch" style="background:{COLOR_GREEN}"></span>
    GREEN direct emit ({color_counts.get('green', 0):,})</div>
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

    print("Step 3/4: classifying nodes + computing degrees...")
    # File-level classification
    file_class: Dict[str, str] = {}
    file_node_count: Dict[str, int] = Counter()
    for n in nodes:
        sf = n.get("source_file", "")
        file_node_count[sf] += 1
        if sf not in file_class:
            file_class[sf] = classify_file(sf, emit_files)
    # Per-node classification (inherits from file)
    classification: Dict[str, str] = {}
    for n in nodes:
        sf = n.get("source_file", "")
        classification[n["id"]] = file_class.get(sf, "grey")
    degrees = compute_degrees(nodes, links)

    print("Step 4/4: writing report + HTML...")
    color_counts = write_report(
        nodes, links, classification, degrees, file_class, file_node_count, emit_files
    )
    write_html(nodes, links, classification, degrees, color_counts)

    total_code = (
        color_counts.get("green", 0)
        + color_counts.get("yellow", 0)
        + color_counts.get("red", 0)
    )
    pct_wired = (
        100 * (color_counts.get("green", 0) + color_counts.get("yellow", 0)) / max(total_code, 1)
    )
    print()
    print("=" * 60)
    print(f"Second-brain coverage: {pct_wired:.1f}% of {total_code:,} code nodes wired")
    print(f"  GREEN  {color_counts.get('green', 0):>7,}")
    print(f"  YELLOW {color_counts.get('yellow', 0):>7,}")
    print(f"  RED    {color_counts.get('red', 0):>7,}")
    print(f"  GREY   {color_counts.get('grey', 0):>7,}")
    print("=" * 60)
    print(f"Open: {OUT_HTML}")
    print(f"Read: {OUT_REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
