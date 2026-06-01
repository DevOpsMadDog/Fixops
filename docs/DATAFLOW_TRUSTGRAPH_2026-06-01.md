# TrustGraph Data-Flow Audit — 2026-06-01

Chief-Architect audit. Every claim is grounded in a file:line reference or a live
database query executed during this session. Nothing is inferred from intent or
comments alone.

---

## ASCII Data-Flow Diagram

```
  SCANNERS / ENGINES                API LAYER                STORES
  ─────────────────                 ─────────                ──────

  brain_pipeline.py                app.py:5765
  _step_ingest_findings             init_event_bus(app)
         │                               │
         │ ctx["findings"]               │  ResponseInterceptorMiddleware
         ▼                               │  (POST/PUT/PATCH responses)
  _step_enrich_findings                  │
  (CVE,EPSS,CVSS,SLA,                    │  ┌─ RESPONSE_KEY_MAP ─────────────┐
   attack-paths,                         │  │  finding_id, asset_id,         │
   compliance mapping)                   │  │  incident_id, cve_id, ...      │
         │                               │  │  → emit(event_type, payload)  │
         │                               │  └────────────────────────────────┘
         ▼                               │
  _step_correlate_findings               │
  (FindingCorrelator.build_exposure_cases│  trustgraph_event_bus.py
   → exposure_cases[]                    ▼  EventBus.emit()
   stored in finding_correlator.db)  ┌───────────────────────────┐
         │                           │  In-process EventBus       │
         ▼                           │  + SQLite offline queue    │
  _step_build_graph ──────────────►  │  (.aldeci/event_bus_queue) │
  (brain_pipeline.py:2407)           └───────────────────────────┘
         │  direct KnowledgeBrain          │
         │  upsert_node / add_edge    ┌────┴──────────────────────┐
         │                           │  Handlers dispatch to:    │
         ▼                           │  finding.created →        │
  ┌──────────────────────────┐       │    UniversalFindingIndexer │
  │  STORE B                 │       │    → backbone._safe_ingest │
  │  KnowledgeBrain          │       │  asset.discovered →       │
  │  data/fixops_brain.db    │       │    TrustGraphBackbone      │
  │  (NetworkX + SQLite WAL) │       │    .index_asset()         │
  │                          │       │  cve.discovered →         │
  │  brain_nodes (13,397)    │       │    UniversalFindingIndexer │
  │  brain_edges (17,651)    │◄──────┘  incident.created →       │
  │                          │          TrustGraphBackbone        │
  │  Node types:             │          .index_incident()         │
  │   finding:    9,915      │                                    │
  │   exposure_case: 2,374   │       ┌────────────────────────────┘
  │   component:    337      │       │
  │   cve:          312      │       ▼
  │   file:         266      │  ┌──────────────────────────┐
  │   rule:          82      │  │  STORE A                 │
  │   attack:        36      │  │  KnowledgeStore          │
  │   asset:         59      │  │  /tmp/trustgraph.db      │
  └──────────────────────────┘  │  (SQLite + FTS5)         │
             │                  │                          │
             │                  │  entities:    3,980      │
             ▼                  │  relationships: 9,496    │
  ┌──────────────────────────┐  │                          │
  │  CONSUMPTION             │  │  Entity types:           │
  │                          │  │   Finding:    3,718      │
  │  llm_council.py:363      │  │   Asset:        221      │
  │  _enrich_with_trustgraph │  │   Scanner:       21      │
  │  → BrainCorrelator       │  │   Incident:      17      │
  │    (reads Store B)       │  │   CVE:            3      │
  │  → enriched_finding      │  │                          │
  │    ["trustgraph"] block  │  │  Rel types:              │
  │    into council prompt   │  │  FINDING_AFFECTS_ASSET: 4,329 │
  │                          │  │  found_by_scanner:  5,150│
  │  brain_router.py         │  │  FINDING_EXPLOITS_CVE: 4 │
  │  /api/v1/brain/*         │  │  CONTROL_MITIGATES:   13 │
  │  (CRUD + query on        │  └──────────────────────────┘
  │   Store B directly)      │
  │                          │
  │  GraphRAGQueries         │
  │  (reads Store A via      │
  │   TrustGraphBackbone)    │
  │  — DISCONNECTED from     │
  │    pipeline writes       │
  └──────────────────────────┘
```

---

## Stage 1 — INGRESS: How a Finding Enters

### Path A: Brain Pipeline (primary, bulk)

File: `suite-core/core/brain_pipeline.py`

1. `BrainPipeline.run()` is called with a `PipelineInput` (org_id, repo_url, etc.).
2. `_step_ingest_findings` (line ~591) calls `_mirror_to_security_findings_engine()` which
   routes raw connector output through `SecurityFindingsEngine` → normalised finding dicts
   are placed into `ctx["findings"]`.
3. `_step_enrich_findings` adds CVSS/EPSS, CVE lookups, SLA deadlines, attack-path counts,
   and compliance-control mappings. At line ~1152 it calls `TrustGraphBackbone.link_entities()`
   to write `CONTROL_MITIGATES_FINDING` edges into **Store A** (best-effort, wrapped in a
   bare `except`).
4. `_step_correlate_findings` calls `FindingCorrelator.build_exposure_cases()` which runs
   five correlation strategies (CVE-match, component-match, file-match, attack-chain,
   scanner-overlap), groups findings into `ExposureCase` objects via union-find, and
   persists them to `suite-core/core/finding_correlator.db` (4,509 cases live).
5. `_step_build_graph` (line 2407) writes directly to **Store B** (`data/fixops_brain.db`)
   via `KnowledgeBrain` calls:
   - `brain.upsert_node(GraphNode(node_type=EntityType.ASSET, ...))` for each asset in `ctx["assets"]`
   - `brain.upsert_node(GraphNode(node_type=EntityType.FINDING, ...))` for each finding
   - `brain.upsert_node(GraphNode(node_type=EntityType.CVE, ...))` — deduplicated set
   - `brain.upsert_node(GraphNode(node_type=EntityType.EXPOSURE_CASE, ...))` for each case id
   - `brain.add_edge(GraphEdge(edge_type=EdgeType.AFFECTS))` — finding → asset
   - `brain.add_edge(GraphEdge(edge_type=EdgeType.REFERENCES))` — finding → CVE
   - Then calls `_populate_attack_graph()` which also writes to `AttackPathEngine`.

### Path B: ResponseInterceptorMiddleware (automatic, every POST/PUT/PATCH)

File: `suite-core/core/trustgraph_event_bus.py:1037`

- Mounted in `suite-api/apps/api/app.py:5765` via `init_event_bus(app)`.
- On every POST/PUT/PATCH with a 200/201/202 JSON response, the middleware reads the
  body (up to 64 KB), walks it up to 3 wrapper levels deep (`data`, `result`, `items`, etc.),
  and matches any key from `_RESPONSE_KEY_MAP` (50+ keys: `finding_id`, `asset_id`,
  `cve_id`, `scan_id`, etc.).
- On a match, it calls `EventBus.emit(event_type, {**payload, "org_id": request_org_id})`.
- `org_id` is resolved from `request.state.org_id` (set by `OrgIdMiddleware` from JWT),
  then from the `_org_id_var` contextvar, then from the `X-Org-ID` header, then falls
  back to `"default"`. This is the SPEC-005 fix — org comes from the request, not the body.
- The emit is dispatched as a background task (`asyncio.ensure_future`) so the API
  response is never blocked.

### Path C: Direct engine emit

Any engine can call `get_event_bus().emit("finding.created", {...})` directly
(e.g. `knowledge_store.py:314` emits `trustgraph.entity.ingested` after every
`ingest()` call; `knowledge_brain.py:70` emits `engine.loaded` on import).

---

## Stage 2 — THE TWO STORES (honest split)

### Store A — KnowledgeStore (`/tmp/trustgraph.db`)

File: `suite-core/trustgraph/knowledge_store.py:191`

- SQLite with FTS5 full-text search and a `relationships` table.
- Schema: `entities(entity_id, core_id, entity_type, name, properties, org_id)` +
  `relationships(rel_id, source_id, target_id, rel_type, confidence)`.
- Written to by:
  - `UniversalFindingIndexer.index()` (`trustgraph_integrations.py:307`) — called
    from the EventBus `_handle_finding_created` handler.
  - `TrustGraphBackbone._safe_ingest()` — called from the same indexer and from
    `AttackPathEnricher`, `CrossDomainCorrelator`, etc.
  - `_step_enrich_findings` compliance-mapping sub-step via `backbone.link_entities()`
    for `CONTROL_MITIGATES_FINDING` edges (best-effort).
- **Live state (verified 2026-06-01):** 3,980 entities, 9,496 relationships.
  - Finding: 3,718 | Asset: 221 | Scanner: 21 | Incident: 17 | CVE: 3
  - FINDING_AFFECTS_ASSET: 4,329 | found_by_scanner: 5,150 | FINDING_EXPLOITS_CVE: 4
  - The scif org (`org-5f4bcda1-e979-4490-85be-2575ccc8e552`) has 1,236 Finding entities
    and 34 Asset entities here. Only 5 FINDING_AFFECTS_ASSET and 3 found_by_scanner
    rels are present for this org, with 0 FINDING_EXPLOITS_CVE edges — the pipeline
    did not write CVE edges into Store A for this org.
- Read by: `CrossDomainCorrelator`, `ImpactAnalyzer`, `AttackPathEnricher`,
  `GraphRAGQueries` (all via `TrustGraphBackbone._store`).

### Store B — KnowledgeBrain (`data/fixops_brain.db`)

File: `suite-core/core/knowledge_brain.py:221`

- SQLite WAL + in-memory NetworkX `MultiDiGraph`. Thread-safe with background
  60-second WAL checkpoint thread.
- Schema: `brain_nodes(node_id, node_type, org_id, properties)` +
  `brain_edges(source_id, target_id, edge_type, properties, confidence)` +
  `brain_events(event_type, source, data)`.
- Written to exclusively by `_step_build_graph` in the Brain Pipeline (direct calls,
  not via the event bus). Also written by the `_handle_risk_assessed` event handler
  (`trustgraph_event_bus.py:589`) which calls `KnowledgeBrain.add_node()`.
- **Live state (verified 2026-06-01):** 13,397 nodes, 17,651 edges.
  - finding: 9,915 | exposure_case: 2,374 | component: 337 | cve: 312
  - affects: 8,307 | groups: 1,284 | CLUSTERS_WITH: 1,195 | references: 782
  - The scif org has **zero nodes** in Store B — the pipeline run that produced
    1,236 findings in Store A did not also run `_step_build_graph` for this org,
    or ran against a different DB path.
- Read by: `BrainCorrelator` (council enrichment), `brain_router.py` (`/api/v1/brain/*`).

### Why two stores exist

The split was not by design. `KnowledgeStore` was the original TrustGraph storage
class. `KnowledgeBrain` was added as a "second brain" with richer NetworkX support.
The Brain Pipeline's `_step_build_graph` writes to Store B because it imports
`get_brain()` directly. The EventBus handlers call `UniversalFindingIndexer` which
calls `TrustGraphBackbone` which opens Store A. This means findings ingested through
the API layer (ResponseInterceptorMiddleware → EventBus → `UniversalFindingIndexer`)
go to Store A, while findings processed through the full pipeline go to Store B.

---

## Stage 3 — CORRELATION: How Edges Are Created

### A. finding → CVE (`references` / `REFERENCES`)

- **Store B path** (`brain_pipeline.py:2587`): `brain.add_edge(GraphEdge(edge_type=EdgeType.REFERENCES))`
  where `EdgeType.REFERENCES = "references"` (`knowledge_brain.py:145`). Written for
  every finding where `f.get("cve_id")` is non-null.
  Live count: 782 `references` edges + 31 `REFERENCES` edges (uppercase variant from
  an older code path) = 813 total finding→CVE edges in Store B.

- **Store A path** (`trustgraph_integrations.py:380`): `backbone._safe_relate(
  backbone._make_rel(finding_id, cve_entity_id, "FINDING_EXPLOITS_CVE"))`.
  Live count: only 4 `FINDING_EXPLOITS_CVE` edges in Store A (very sparse).

### B. finding → asset (`affects` / `FINDING_AFFECTS_ASSET`)

- **Store B path** (`brain_pipeline.py:2567`): `brain.add_edge(GraphEdge(edge_type=EdgeType.AFFECTS))`
  where `EdgeType.AFFECTS = "affects"`. Written when `f.get("canonical_asset_id")` or
  `f.get("asset_name")` is non-null. Live count: 8,307 `affects` edges in Store B.
  However the `affects` direction in Store B is inverted in some corpus data: the query
  showed `cve:CVE-2022-24999 --[AFFECTS]--> finding:...` (CVE→finding direction),
  meaning some edges were written by a different path with reversed source/target.

- **Store A path** (`trustgraph_integrations.py:417`): `backbone._safe_relate(
  "FINDING_AFFECTS_ASSET")`. Live count: 4,329 in Store A for all orgs.

### C. CLUSTERS_WITH (finding ↔ finding via correlator)

File: `brain_pipeline.py` (correlation step) + `knowledge_brain.py:131`
(`EdgeType.CORRELATES_WITH = "correlates_with"`).
Live Store B count: 1,195 `CLUSTERS_WITH` + 110 `CORRELATES_WITH` edges. These link
findings grouped by the same exposure case or correlated by `FindingCorrelator`.
`BrainCorrelator.enrich_finding()` traverses these at `trustgraph_integrations.py:1710`
(Step 4a, looking for `edge_type.lower() == "correlates_with"`).

### D. CONTROL_MITIGATES_FINDING (brain_pipeline.py:1152)

Written to **Store A** via `TrustGraphBackbone.link_entities()` during
`_step_enrich_findings`. Live count: 13 in Store A. Best-effort; failures silently
swallowed.

### E. asset ↔ asset via shared CVE (AFFECTS_SAME_CVE in Store B)

`brain_pipeline.py:_populate_attack_graph()` (line 2660): after upserting finding
nodes, it also writes `asset→asset` edges when two findings share the same CVE, using
`AttackPathEngine.add_edge()`. This is separate from `KnowledgeBrain` edges but feeds
the blast-radius calculation. Live Store B count: 11 `AFFECTS_SAME_CVE` edges.

### F. BrainCorrelator traversal (council reads)

`trustgraph_integrations.py:BrainCorrelator.enrich_finding()` (line 1586):
- Step 2: traverses `out` edges of type `"references"` (lowercase, matching Store B
  edge type) from the finding node → builds `correlated_cves` list.
- Step 3: traverses `out` edges of type `"affects"` (lowercase) → builds blast_radius.
- Step 4a: traverses `both`-direction edges of type `"correlates_with"` → builds
  `related_findings`.
- Step 4b: traverses inbound `"references"` edges on each CVE node to find sibling
  findings that share the same CVE → extends `related_findings`.

**Live verification:** `BrainCorrelator.enrich_finding("finding:github:juice-shop/juice-shop:CVE-2022-24999:0", org="aldeci")` returned:
- `enriched: True`
- `correlated_cves: [{"cve": "CVE-2022-24999", "via": "references"}, ...]`
- `related_findings count: 3` (sibling findings sharing the same CVE node)
- `blast_radius: {"affected_assets": 0, ...}` — zero because the `affects` edges in
  this corpus run CVE→finding (inverted) rather than finding→asset.

---

## Stage 4 — CONSUMPTION: Who Reads the Correlated Graph

### A. LLM Council — `llm_council.py:363` `_enrich_with_trustgraph`

This is the primary consumption path. Called inside `LLMCouncilEngine.convene()` at
line 328 before Stage 1 (Independent Analysis).

Flow:
```
convene(finding, context, org_id)
  → _enrich_with_trustgraph(finding, context, org_id)   [llm_council.py:363]
      → BrainCorrelator(org_id=org_id)                   [trustgraph_integrations.py:1527]
          → get_brain()  →  data/fixops_brain.db          [knowledge_brain.py:1084]
          → brain.get_edges(finding_id, "out")  →  references, affects edges
      → enriched_finding["trustgraph"] = {
            blast_radius, correlated_cves, related_findings,
            dollar_risk_estimate, violated_controls, enriched
        }
  → _stage_independent_analysis(enriched_finding, ...)   [each member sees the block]
  → _stage_peer_review(...)
  → _stage_chairman_synthesis(...)
```

The enrichment block is attached as `finding["trustgraph"]` and passed into every
council stage prompt. When `result.enriched` is True the council prompt includes real
blast-radius and CVE correlation data.

### B. `brain_router.py` — `/api/v1/brain/*`

File: `suite-api/apps/api/brain_router.py`
Provides full CRUD + query over Store B (`KnowledgeBrain`):
- `GET /api/v1/brain/nodes` — `query_nodes()` with type/org/search filters
- `GET /api/v1/brain/stats` — `brain.stats()` (nodes, edges, org counts)
- `POST /api/v1/brain/ingest/cve` — `brain.ingest_cve()`
- `POST /api/v1/brain/ingest/finding` — `brain.ingest_finding()`
- `GET /api/v1/brain/correlate/{id}` — `CrossDomainCorrelator.correlate_finding()`
  (NOTE: this uses Store A via `TrustGraphBackbone`, not Store B)

### C. `GraphRAGQueries` — pre-built templates for dashboards

File: `suite-core/core/trustgraph_integrations.py:1133`
Templates: `top_risks`, `exposure_chain`, `compliance_gaps`, `attack_surface`,
`threat_landscape`.
All use `TrustGraphBackbone._store` which resolves to **Store A** (`/tmp/trustgraph.db`).
Store A has 3,718 Finding entities and real relationships for active orgs.
The `top_risks` template (`line 1173`) queries `store.search(core_id=CORE_SECURITY,
query_text="", filters={"org_id": self.org_id})` — this works when the org's findings
are present in Store A, which they are for the scif org (1,236 findings, 34 assets).

### D. GraphRAG — DEAD for the council path, LIVE for dashboards

`GraphRAGQueries` / `GraphRAGEnhanced` (Store A reads) are wired and functional for
dashboard consumption. They are **not** called from the council path. The council path
reads Store B exclusively via `BrainCorrelator`. Both stores contain real data but for
overlapping (not identical) org populations.

---

## Stage 5 — LIVE EXERCISE

All queries executed against the running DBs on 2026-06-01.

### Store B — KnowledgeBrain (`data/fixops_brain.db`)
| Metric | Value |
|--------|-------|
| Total nodes | 13,397 |
| Total edges | 17,651 |
| finding nodes | 9,915 |
| exposure_case nodes | 2,374 |
| cve nodes | 312 |
| asset nodes | 59 |
| `affects` edges (finding→asset) | 8,307 |
| `references` edges (finding→CVE) | 782 |
| `CLUSTERS_WITH` edges | 1,195 |
| Orgs with data | 68 |
| scif org (`org-5f4bcda1...`) nodes | **0** |

### Store A — KnowledgeStore (`/tmp/trustgraph.db`)
| Metric | Value |
|--------|-------|
| Total entities | 3,980 |
| Total relationships | 9,496 |
| Finding entities | 3,718 |
| Asset entities | 221 |
| `FINDING_AFFECTS_ASSET` rels | 4,329 |
| `found_by_scanner` rels | 5,150 |
| `FINDING_EXPLOITS_CVE` rels | 4 |
| `CONTROL_MITIGATES_FINDING` rels | 13 |
| scif org entities | **1,270** (1,236 Finding + 34 Asset) |

### FindingCorrelator (`suite-core/core/finding_correlator.db`)
| Metric | Value |
|--------|-------|
| Total exposure cases | 4,509 |
| Orgs with cases | default (2,796), test-org (1,366), perf-test-org (190), org (34) |

### Real correlation demo (Store B, org=aldeci)

Finding: `finding:github:juice-shop/juice-shop:CVE-2022-24999:0`

```
BrainCorrelator.enrich_finding() result:
  enriched:            True
  correlated_cves:     [{"cve": "CVE-2022-24999", "via": "references"}, ...]
  related_findings:    3  (CVE-2022-23529, CVE-2022-23540, CVE-2021-26540 siblings)
  blast_radius:        {"affected_assets": 0, "affected_containers": 0, "downstream": []}
  dollar_risk_estimate: None  (0 affected_assets → no heuristic cost)
```

The CVE correlation works: 3 related findings are returned via CVE-sibling traversal.
The blast radius is zero because the `affects` edges in this corpus are written
CVE→finding (reversed) rather than finding→asset, so `BrainCorrelator`'s outbound
`"affects"` traversal from the finding node finds nothing.

### scif org exercise (Store B)

The scif org (`org-5f4bcda1-e979-4490-85be-2575ccc8e552`) has **0 nodes in Store B**.
Its 1,236 findings are in Store A only. Therefore `BrainCorrelator.enrich_finding()`
returns `enriched=False` for any finding from this org because `brain.node_count()`
returns 13,397 (non-zero) but `_get_visible_node()` finds nothing for this org_id.
The council enrichment path produces no signal for this org.

---

## Honest State Assessment

**Is the data REALLY connected and correlated into TrustGraph today?**

**PARTIAL — with significant gaps.**

### What is genuinely wired and working

1. **Brain Pipeline → Store B**: The `_step_build_graph` step correctly writes finding
   nodes, CVE nodes, asset nodes, REFERENCES edges, and AFFECTS edges to Store B via
   direct `KnowledgeBrain` calls. For orgs processed by the full pipeline (e.g.
   `aldeci`, `aldeci-self`, `large-org`, `juice-shop-corp`), the graph has real data
   and the correlation works. Live proof: 13,397 nodes, 17,651 edges, CVE correlation
   returns 3 related findings for the juice-shop finding.

2. **Council reads Store B**: `llm_council.py:363` `_enrich_with_trustgraph` correctly
   calls `BrainCorrelator` which reads Store B. The enrichment block is attached to the
   finding before all three council stages. When the graph contains the relevant org's
   data, the council sees real blast-radius and CVE correlation.

3. **Event Bus wired at app startup**: `ResponseInterceptorMiddleware` is mounted in
   `app.py:5765`. All POST/PUT/PATCH responses are inspected. Default handlers are
   registered for 11 event types. The offline SQLite queue provides durability.

4. **Store A has real findings for the scif org**: 1,236 Finding entities with
   FINDING_AFFECTS_ASSET and found_by_scanner relationships. `GraphRAGQueries.top_risks()`
   and `exposure_chain()` will return real data for this org.

5. **FindingCorrelator is functional**: 4,509 exposure cases across 4 orgs, built by
   5 real correlation strategies (CVE, component, file, attack-chain, scanner-overlap).

### Top gaps

**Gap 1 — Split-store disconnection (highest severity)**
The pipeline writes to Store B; the EventBus and `UniversalFindingIndexer` write to
Store A. `GraphRAGQueries` and `CrossDomainCorrelator` (dashboard paths) read Store A.
`BrainCorrelator` (council path) reads Store B. These are separate SQLite files with
separate org populations. A finding indexed via the API (e.g. from a connector POST)
goes to Store A only. A finding from the Brain Pipeline goes to Store B only. There is
no sync or merge path between them. The council is blind to API-ingested findings; the
dashboards are blind to pipeline-written findings.

**Gap 2 — scif org missing from Store B**
The verified real-customer org (`org-5f4bcda1-e979-4490-85be-2575ccc8e552`) has 0 nodes
in Store B and 1,270 entities in Store A. The council enrichment path returns
`enriched=False` for every finding from this org. The `_step_build_graph` step has not
run for this org, or ran against a different `FIXOPS_BRAIN_DB_PATH`.

**Gap 3 — Inverted AFFECTS edges in Store B for some corpus data**
For the `aldeci` org corpus, CVE→finding `affects` edges exist (reversed direction)
instead of finding→asset. `BrainCorrelator` traverses outbound `"affects"` from
finding nodes and finds nothing, producing `blast_radius.affected_assets = 0`. The
dollar risk estimate is always None for this corpus. The edge direction needs to be
standardised: finding→asset, not CVE→finding.

**Gap 4 — FINDING_EXPLOITS_CVE extremely sparse in Store A (4 records)**
`UniversalFindingIndexer.index()` creates `FINDING_EXPLOITS_CVE` edges in Store A
only when `finding.cve_id` is non-null. For the scif org scan (1,236 findings) there
are 0 such edges, meaning scanner output did not carry populated `cve_id` fields
through the normalisation path. The `CrossDomainCorrelator.correlate_cve()` chain
(Store A path) returns empty for any CVE lookup against this org.

**Gap 5 — GraphRAG not wired to council**
`GraphRAGQueries` (Store A) and `GraphRAGEnhanced` query templates are implemented and
functional but are never called from the council pipeline or from any finding enrichment
path. They are available via REST (`brain_router.py` calls `correlate_finding()` which
uses `CrossDomainCorrelator` on Store A), but the council sees only the `BrainCorrelator`
(Store B) output.

**Gap 6 — CONTROL_MITIGATES_FINDING has 13 entries total**
The compliance mapping step writes this edge to Store A best-effort. With 3,718 Finding
entities in Store A the expected count would be in the hundreds. The 13 entries indicate
most findings did not carry matching CWE→control mappings through the enrichment step.

**Gap 7 — FindingCorrelator exposure cases not cross-referenced into either graph store**
`finding_correlator.db` holds 4,509 exposure cases with full correlation metadata
(CVE-match, component-match, attack-chain groups), but these are not synced into
Store A `relationships` or Store B `brain_edges`. The council and GraphRAG templates
cannot query them as graph edges.

---

## File Reference Index

| Component | File | Key lines |
|-----------|------|-----------|
| TrustGraph EventBus | `suite-core/core/trustgraph_event_bus.py` | 1037 (middleware), 694 (EventBus), 982 (init) |
| ResponseInterceptorMiddleware mount | `suite-api/apps/api/app.py` | 5765 |
| Store A — KnowledgeStore | `suite-core/trustgraph/knowledge_store.py` | 191 (init), 268 (ingest), 425 (add_relationship) |
| Store B — KnowledgeBrain | `suite-core/core/knowledge_brain.py` | 221 (init), 447 (upsert_node), 524 (add_edge) |
| Brain Pipeline — graph step | `suite-core/core/brain_pipeline.py` | 2407 (_step_build_graph), 2491-2604 (upserts+edges) |
| Brain Pipeline — compliance edges | `suite-core/core/brain_pipeline.py` | 1152 (CONTROL_MITIGATES_FINDING to Store A) |
| UniversalFindingIndexer | `suite-core/core/trustgraph_integrations.py` | 280 (class), 307 (index), 366-434 (CVE/asset rels) |
| BrainCorrelator | `suite-core/core/trustgraph_integrations.py` | 1527 (class), 1586 (enrich_finding) |
| Council enrichment | `suite-core/core/llm_council.py` | 328 (call site), 363 (_enrich_with_trustgraph), 396-418 (BrainCorrelator call) |
| FindingCorrelator | `suite-core/core/finding_correlator.py` | 194 (class), 379 (correlate_findings), 407 (build_exposure_cases) |
| GraphRAGQueries | `suite-core/core/trustgraph_integrations.py` | 1133 (class), 1173 (top_risks) |
| brain_router | `suite-api/apps/api/brain_router.py` | 23 (router), direct Store B CRUD |
| EdgeType enum | `suite-core/core/knowledge_brain.py` | 121 (AFFECTS, REFERENCES, CORRELATES_WITH, ...) |
| org_id resolution | `suite-core/core/trustgraph_event_bus.py` | 1116-1141 (request→org_id) |
