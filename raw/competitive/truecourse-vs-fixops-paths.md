# TrueCourse ↔ Fixops — Graphify Architectural Path Trace

**Date:** 2026-04-22
**Graph:** `graphify-out/graph.json` (2620 nodes / 2433 links / 454 communities)
**Method:** `graphify path "A" "B"` — shortest BFS path in the merged competitive-research + UI graph

---

## Findings summary

| # | Pair | Hops | Verdict |
|---|------|-----:|---------|
| 1 | TrueCourse Tiered LLM Router ↔ Fixops Karpathy Consensus | 1 | **Direct competitor-primitive match** — `semantically_similar_to` INFERRED edge; different primitives, same problem (multi-LLM spend/quality optimisation). Confirms comparison-doc row 2 (TRUECOURSE_WINS on per-rule tiering). |
| 2 | TrueCourse Violation Lifecycle ↔ Fixops findings table | 1 | **1-hop but only semantic** — Fixops has `correlation_key` column but no `previousViolationId` chain. Confirms comparison-doc row 5 biggest TRUECOURSE_WIN + NEW-G070 dependency. |
| 3 | Apiiro Risk Graph → Fixops TrustGraph | 2 | Routes through central "TrustGraph (event-driven graph)" hub node. Apiiro has patented primitive; Fixops has tri-layer (code+risk+threat, 1941 nodes/7324 edges). |
| 4 | Wiz Security Graph → Fixops TrustGraph | 2 | **Same hub as Path 3** — proves `TrustGraph (event-driven graph)` is the cross-competitor anchor in our community #0. Confirms `fixops.trustgraph` positions against BOTH Wiz and Apiiro simultaneously — the strongest single-asset competitive moat. |
| 5 | Endor callgraph ↔ Fixops security_dependency_mapping | 1 | Direct INFERRED similarity. Endor operates at function granularity (moat), Fixops at dependency granularity (GAP-010). |
| 6 | TrueCourse Files tab ↔ Fixops useFindings | — | **No path.** TrueCourse IDE-UX concept nodes are in community #2 (TrueCourse Absorb); Fixops UI-hook nodes are in community #15+ (use-api.ts). Research docs were merged but not cross-linked to the 2258 UI code nodes — this is exactly the `NEW-G071` IDE-in-browser gap surfacing structurally. |
| 7 | TrueCourse hooks.yaml ↔ GitHub Actions | — | **No path.** "GitHub Actions" isn't a node in this graph at all (neither TrueCourse nor Fixops research docs name it directly). Signal: this axis isn't modelled yet — needs either a fresh doc or a backend-code ingest pass. |

### Cross-graph takeaway

The **TrustGraph hub** in community #0 is the single highest-leverage node in the merged graph — every competing "security graph" (Wiz, Apiiro, Lacework Polygraph, Arnica) routes through it via INFERRED `semantically_similar_to`. That's the narrative for the investor demo.

The **two dead paths (6, 7)** are honest: they show where the graphify merge stopped. To get IDE-UX trace (Files tab ↔ actual UI code modules) we need the thread-#1 deferred backend + UI-code ingest pass to land.

---

## Path 1 — TrueCourse tiered LLM router ↔ Fixops Karpathy consensus
```
Shortest path (1 hops):
  Tiered LLM context router (metadata|targeted|full-file) --semantically_similar_to [INFERRED]--> Karpathy LLM Consensus (multi-LLM agreement)
```

## Path 2 — TrueCourse violation lifecycle ↔ Fixops findings table
```
Shortest path (1 hops):
  Violation lifecycle: new|unchanged|resolved chain via previousViolationId --semantically_similar_to [INFERRED]--> findings table (UUID, org_id, severity, correlation_key)
```

## Path 3 — Apiiro Risk Graph ↔ Fixops TrustGraph
```
Shortest path (2 hops):
  Apiiro Risk Graph (patented) --semantically_similar_to [INFERRED]--> TrustGraph (event-driven graph) --references [EXTRACTED]--> Fixops TrustGraph tri-layer (code+risk+threat) — 1941 nodes/7324 edges
```

## Path 4 — Wiz Security Graph ↔ Fixops TrustGraph
```
Shortest path (2 hops):
  Wiz Security Graph (toxic combinations) --semantically_similar_to [INFERRED]--> TrustGraph (event-driven graph) --references [EXTRACTED]--> Fixops TrustGraph tri-layer (code+risk+threat) — 1941 nodes/7324 edges
```

## Path 5 — Endor callgraph ↔ Fixops security_dependency_mapping
```
Shortest path (1 hops):
  Endor pre-computed call graphs --semantically_similar_to [INFERRED]--> security_dependency_mapping engine
```

## Path 6 — TrueCourse Files tab (IDE UX) ↔ Fixops UI
```
No path found between 'Files tab' and 'useFindings'.
```

## Path 7 — TrueCourse hooks.yaml policy ↔ Fixops pre-commit / GitHub Actions
```
No path found between 'hooks.yaml' and 'GitHub Actions'.
```

## Explain — TrueCourse root node
```
Node: TrueCourse (npm v0.5.5)
  ID:        truecourse_analysis_truecourse
  Source:    raw/competitive/truecourse-analysis.md pitch
  Type:      document
  Community: 2
  Degree:    1

Connections (1):
  --> TrueCourse monorepo (pnpm + turbo) [contains] [EXTRACTED]
```

## Explain — Fixops TrustGraph tri-layer
```
Node: Fixops TrustGraph tri-layer (code+risk+threat) — 1941 nodes/7324 edges
  ID:        competitor_emerging_fixops_trustgraph_tri_layer
  Source:    raw/competitive/competitor-emerging.md §final
  Type:      document
  Community: 0
  Degree:    1

Connections (1):
  --> TrustGraph (event-driven graph) [references] [EXTRACTED]
```
