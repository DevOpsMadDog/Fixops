# TrustGraph Chief-Architect Audit — 2026-06-01

**Scope:** READ-ONLY audit of the TrustGraph "second brain" implementation.
**Method:** Code as source of truth. All claims verified against actual files and live SQLite data.
**Auditor:** Code Quality Analyzer (Claude Sonnet 4.6)

---

## 1. What IS TrustGraph here?

**Verdict: REAL GRAPH — but split across two overlapping stores with no synchronisation.**

There are two distinct graph implementations that share the "TrustGraph" brand:

### Store A — KnowledgeStore (`/tmp/trustgraph.db`)
- File: `suite-core/trustgraph/knowledge_store.py`
- Backend: SQLite, two tables — `entities` (FTS5 virtual table for text search) and `relationships`
- Schema: `entities(entity_id, core_id, entity_type, name, properties JSON, embeddings, org_id, deleted_at)` and `relationships(rel_id, source_id, target_id, rel_type, properties JSON, confidence, created_at)`
- Features: FTS5 full-text search, soft-delete, per-org filtering, depth-limited BFS traversal
- Live state: **2,456 entities / 6,340 relationships** in `/tmp/trustgraph.db`
- Org distribution: 2,292 under `default` org (93%), rest spread across test/e2e orgs

### Store B — KnowledgeBrain (`data/fixops_brain.db`)
- File: `suite-core/core/knowledge_brain.py`
- Backend: SQLite + in-memory NetworkX `MultiDiGraph`
- Schema: `brain_nodes(node_id, node_type, org_id, properties JSON, created_at, updated_at)` and `brain_edges(source_id, target_id, edge_type, properties JSON, confidence, created_at)` with `UNIQUE(source_id, target_id, edge_type)` constraint
- Features: WAL+checkpoint, 60-second background checkpoint thread, PageRank via NetworkX, BFS path finding, per-org queries, risk scoring
- Live state: **13,359 nodes / 17,625 edges** in `data/fixops_brain.db`
- Three separate DB files found with different row counts: `fixops_brain.db` (0 nodes — empty), `data/fixops_brain.db` (13,359 nodes), `suite-api/data/fixops_brain.db` (174 nodes)

### The "5 Knowledge Cores"
Exist as named constants in `trustgraph_backbone.py` (lines 50-54) and `trustgraph_integrations.py` (lines 115-119): Core 1=customer_env, Core 2=threat_intel, Core 3=compliance, Core 4=decision_memory, Core 5=external. These are enforced only by code convention (a `core_id` field on entities). KnowledgeBrain has no native core_id column — it stores core_id embedded inside the JSON `properties` blob (backbone.py line 188). There is no database-level separation of cores, and `KnowledgeBrainAdapter.core_stats()` (line 234-246) explicitly acknowledges it "cannot filter by JSON-embedded core_id without a full scan" and returns aggregate totals instead.

### The Backbone Layer
`TrustGraphBackbone` (trustgraph_backbone.py lines 332-994) is a facade that tries to load the external `trustgraph.knowledge_store.KnowledgeStore` first, then falls back to `KnowledgeBrainAdapter` wrapping KnowledgeBrain. This means in production — where the external package is always present as an in-repo module — it uses Store A (the `/tmp/trustgraph.db` KnowledgeStore). `KnowledgeBrain` (Store B) is used directly by the brain_pipeline's `_step_build_graph` and by `llm_council._enrich_with_trustgraph` only when it explicitly instantiates `ImpactAnalyzer`/`CrossDomainCorrelator`, which themselves call `TrustGraphBackbone` which resolves back to Store A.

**Bottom line:** Two real graph stores exist, real data in both, but they are not synchronised. The brain_pipeline writes directly to KnowledgeBrain (Store B) while the event bus and backbone write to KnowledgeStore (Store A, `/tmp/trustgraph.db`). A query against one store cannot see data written to the other.

---

## 2. Is it WIRED?

**Verdict: REAL-BUT-PARTIALLY-WIRED — middleware is mounted, brain_pipeline writes to KnowledgeBrain, but the event bus has 5,636 queued + 110 failed events, and 93% of KnowledgeStore entities are under the wrong `default` org.**

### Emit-site inventory

The `_tg_emit` / `emit_event` / `get_event_bus` wiring exists in these locations:

| Location | What it emits | Real? |
|---|---|---|
| `brain_pipeline.py` lines 388, 596 | `brain_pipeline.run_started` / `brain_pipeline.run_completed` | Yes — fires on every pipeline run |
| `brain_pipeline.py` lines 2313-2340 | `finding.created` per correlator exposure case | Yes — fires in Step 4 |
| `knowledge_store.py` lines 314-322, 453-462 | `trustgraph.entity.ingested` / `trustgraph.relationship.added` | Yes — self-referential, fires when backbone writes to store |
| `knowledge_brain.py` lines 69-72 | `engine.loaded` on module import | Fires once per process, payload is just `{"module": "..."}` — low value |
| `ResponseInterceptorMiddleware` (trustgraph_event_bus.py) | Entity events from every POST/PUT/PATCH response body | Wired in app.py line 5702 — yes |
| 529 files in suite-core/core + 25 in suite-api | Various engine-level emits | Patchy — most are copy-paste `_emit_event` boilerplate that calls `get_event_bus().emit()` |

The CLAUDE.md claim of "548 emit-sites" is in the right order of magnitude. The boilerplate `_emit_event` function is pasted into hundreds of engine files. However, "emit-site" != "real event fired": many of these functions exist in the file but are only called from rarely-invoked paths (e.g. `harbor_registry_engine.py`, `deception_engine.py`).

### Event bus queue state (measured live)

From `.aldeci/event_bus_queue.db`:
- **5,636 events in `queued` status** — never processed (no handler registered at time of emit)
- **110 events in `failed` status** — handler ran and returned False or raised
- **43 events in `indexed` status** — successfully processed

The 5,636 queued events are predominantly `scan.completed` and `session.created` event types for which no default handler is registered in `_DEFAULT_HANDLERS` (trustgraph_event_bus.py lines 632-642). The bus has handlers only for: `finding.created`, `finding.updated`, `asset.discovered`, `incident.created`, `control.assessed`, `vendor.updated`, `actor.identified`, `cve.discovered`, `risk.assessed`. Everything else goes to the queue and stays there permanently unless a manual flush is triggered.

The 110 failed events are primarily `cve.discovered` events — failing because `_handle_cve_discovered` calls `UniversalFindingIndexer.index()` which instantiates `TrustGraphBackbone`, which resolves to KnowledgeStore, but the `FindingInput` validation at trustgraph_integrations.py line 321 requires an `engine` field that is absent in the CVE event payload shape.

### Brain pipeline wiring (CLAUDE.md claim: "emits at line 553")

The CLAUDE.md claim is technically correct but misleading. Line 553 is inside the `if all_completed ... else ...` ternary — the actual `_tg_emit("brain_pipeline.run_completed", {...})` is at **line 596** of brain_pipeline.py. It emits a summary dict with `run_id`, `org_id`, `status`, `findings_out`, `exposure_cases`. This is a telemetry event, not a per-finding index operation. The per-finding indexing happens in `_step_build_graph` (line 2349) via direct `KnowledgeBrain.upsert_node()` calls — bypassing the event bus entirely and writing straight to Store B (KnowledgeBrain).

---

## 3. Does it CORRELATE?

**Verdict: REAL-BUT-SHALLOW — edges exist and are created on ingest, but the edge vocabulary is inconsistent between stores and most correlations are within-finding-set rather than cross-source.**

### Edges created in KnowledgeStore (Store A)

`UniversalFindingIndexer.index()` (trustgraph_integrations.py lines 307-450) creates these edges per finding:
- `FINDING_EXPLOITS_CVE` — finding → CVE entity (if cve_id present)
- `FINDING_AFFECTS_ASSET` — finding → Asset entity (if asset_id or asset_name present)
- `caused_by_cwe` — finding → CWE entity (if cwe_id present)
- `found_by_scanner` — finding → Scanner entity (always)
- `violates_control` — finding → Control entity (for each control_id in list)

Live state in `/tmp/trustgraph.db`: 6,340 relationships across 2,456 entities. Entity type breakdown: 2,290 Finding, 147 Asset, 19 Scanner. No CVE entities, no Control entities, no CWE entities. This means in practice the `cve_id`, `asset_id`, and `control_ids` fields are rarely populated when events arrive via the interceptor middleware — the response body scanner picks up a generic `finding_id` key but the payload does not include the enrichment fields needed to build cross-domain edges. Real correlation edges require an enriched payload that currently only the Brain Pipeline produces.

### Edges created in KnowledgeBrain (Store B)

`_step_build_graph` in brain_pipeline.py (lines 2349-2530) creates:
- `EntityType.FINDING` nodes with `affects` edge to `EntityType.ASSET` nodes
- `EntityType.CVE` nodes (deduped) with `references` edge from finding nodes
- `EntityType.EXPOSURE_CASE` nodes

Live state in `data/fixops_brain.db`: 17,625 edges. Top edge types by count:
- `affects`: 8,299
- `groups`: 1,278
- `CLUSTERS_WITH`: 1,195
- `DETECTED_BY`: 1,195
- `FOUND_ON`: 1,165
- `FOUND_IN`: 899
- `references`: 770

These edges are real cross-finding correlations produced by the pipeline's dedup/clustering step. A `CLUSTERS_WITH` edge means two findings share the same CVE or are co-located in the same file/asset — that is genuine cross-source correlation.

### The gap

The two stores have incompatible edge vocabularies. Store A uses `FINDING_EXPLOITS_CVE` / `FINDING_AFFECTS_ASSET`. Store B uses `affects` / `references` / `CLUSTERS_WITH`. A query for "all assets affected by CVE-2024-1234" using `CrossDomainCorrelator.correlate_cve()` (trustgraph_integrations.py line 503) reads from Store A. But Store A has 0 CVE entities and 0 FINDING_EXPLOITS_CVE edges in its live data — so the query always returns empty. The edges that actually encode CVE→finding relationships exist in Store B, which `correlate_cve()` never queries.

---

## 4. Is it QUERIED / used for decisions?

**Verdict: WIRED-FOR-READS — but reads mostly return empty because Store A is sparsely populated and the council enrichment silently degrades to no enrichment.**

### LLM Council integration (the most important consumer)

`LLMCouncil.convene()` calls `self._enrich_with_trustgraph(finding, context, org_id)` at llm_council.py line 328. This enrichment (lines 363-421):

1. If `asset_id` is present in the finding, calls `ImpactAnalyzer(org_id).blast_radius(asset_id)` — which calls `TrustGraphBackbone._store.get_neighbors()` on Store A
2. If `cve_id` is present, calls `CrossDomainCorrelator(org_id).correlate_cve(cve_id)` — which traverses Store A for FINDING_EXPLOITS_CVE relationships

The entire block is wrapped in `except Exception` (line 419) that logs at DEBUG level and returns the original finding unchanged. Given Store A has 147 Asset entities and 0 CVE cross-links in production, the blast_radius call returns `blast_radius=0` and `correlate_cve` returns empty containers/namespaces/controls. The council prompts therefore receive no graph enrichment in the common case — the finding is passed as-is.

### GraphRAGRetriever

`suite-core/trustgraph/graph_rag.py` provides `GraphRAGRetriever.retrieve()` which does keyword search → BFS traversal → LLM context string. This is a real implementation with a real interface. However: (a) it tries to load from `trustgraph.get_knowledge_store()` which does not exist as a top-level export in the in-tree package (`suite-core/trustgraph/__init__.py`), so `self._store` is `None` at construction, (b) when `_store` is None every method returns empty results silently. The retriever is not called from brain_pipeline or llm_council — it is unused code.

### GraphRAGQueries (dashboard templates)

`GraphRAGQueries` in trustgraph_integrations.py provides five templates: `top_risks`, `exposure_chain`, `compliance_gaps`, `attack_surface`, `threat_landscape`. These are real implementations that query Store A. Given Store A only has Finding/Asset/Scanner entity types and no ThreatActor, Control, or CVE entities, `compliance_gaps` and `threat_landscape` always return empty results. `top_risks` will return findings but they are scoped to `org_id` — and 93% of Store A entities are under the `default` org rather than real customer org IDs, so a real tenant query returns nothing.

### KnowledgeBrain direct reads

`KnowledgeBrain.pagerank()`, `most_connected()`, `risk_score_for_node()`, and `find_paths()` are implemented and use the NetworkX in-memory graph. These are called from brain router endpoints. With 13,359 nodes and 17,625 edges in `data/fixops_brain.db` and a NetworkX graph loaded at startup, these queries are functional. This is the strongest "read" path — but it is accessed via separate API routes, not integrated back into LLM council prompts.

---

## 5. Tenant isolation

**Verdict: DESIGN IS CORRECT — but implementation has two active gaps.**

### Design
KnowledgeStore has `org_id` column on every entity row with `idx_entities_org_id` index (knowledge_store.py lines 226, 260). Every search call accepts an `org_id` filter. KnowledgeBrain has `org_id` on `brain_nodes` with index (knowledge_brain.py lines 338, 344). `_migrate_legacy_null_nodes()` runs at startup and assigns `org_id='system'` to any NULL rows (lines 369-392). The `SYSTEM_ORG='system'` concept is correct for shared threat intel.

### Gap 1 — Relationships table has no org_id column
`relationships` in KnowledgeStore has no `org_id` column (knowledge_store.py lines 242-255). An edge from tenant A's finding to a CVE entity is readable by any tenant that can look up either endpoint. Cross-tenant relationship traversal is possible via `get_neighbors()` if entity IDs are guessable. The backbone's `link_entities` / `_safe_relate` never stamps org_id onto the edge.

### Gap 2 — 2,292 entities under `default` org in Store A
In `/tmp/trustgraph.db`, 93% of entities have `org_id='default'`. These were written by the event bus middleware intercepting API responses that did not include an `org_id` field in the response body. `_payload_org_id()` (trustgraph_event_bus.py line 479) defaults to `'default'` when the key is absent. Any real tenant query that uses a real org ID (e.g. `'aldeci-self'`, `'juice-shop-corp'`) will miss 93% of the graph data. The council enrichment uses `org_id` passed into `convene()`, so for real customers the TrustGraph context is effectively empty.

### Gap 3 — Three separate brain.db files
Three `fixops_brain.db` files exist: `./fixops_brain.db` (0 nodes — empty), `./data/fixops_brain.db` (13,359 nodes — main), `./suite-api/data/fixops_brain.db` (174 nodes — populated by API process). The `get_brain()` function (knowledge_brain.py line 1084) resolves to `os.environ.get("FIXOPS_BRAIN_DB_PATH", "data/fixops_brain.db")` — relative path, so which file is used depends on the process working directory. The suite-api process writes to its own copy; direct python scripts write to `data/fixops_brain.db`. These are not the same graph.

---

## Per-Question Verdicts

| Question | Verdict | Key Evidence |
|---|---|---|
| 1. What IS TrustGraph? | REAL GRAPH — two overlapping stores | KnowledgeStore (2,456 entities, `/tmp/trustgraph.db`) + KnowledgeBrain (13,359 nodes, `data/fixops_brain.db`); 5 cores exist as code constants only |
| 2. Is it WIRED? | REAL-BUT-PARTIALLY-WIRED | Event bus mounted in app.py; brain_pipeline writes to KnowledgeBrain per-finding; but 5,636 events are stranded in queue and 110 failed; 93% of KnowledgeStore data under `default` org |
| 3. Does it CORRELATE? | REAL-BUT-SHALLOW | 17,625 edges in KnowledgeBrain with real correlation types (CLUSTERS_WITH, affects, references); KnowledgeStore has 6,340 relationships but 0 CVE cross-links in live data |
| 4. Is it QUERIED? | WIRED-FOR-READS — silent empty in practice | LLM council calls ImpactAnalyzer/CrossDomainCorrelator but returns no enrichment because Store A has no CVE entities and wrong org IDs; GraphRAGRetriever is unused (broken import) |
| 5. Tenant isolation | DESIGN CORRECT — two active implementation gaps | Relationships table has no org_id; 93% entities under wrong `default` org; three separate brain.db files |

---

## TrustGraph Customer-Readiness

TrustGraph is not write-only — it is more correctly described as a write-heavy system where reads exist but are largely silenced by data quality failures upstream of those reads. The graph infrastructure is genuinely well-engineered: two real SQLite stores, a proper backbone adapter with graceful fallback, a real event bus with offline queueing, a response-interceptor middleware, and a LLM council integration that explicitly queries the graph for blast radius before rendering prompts. The architecture is correct for the value proposition. What makes it not customer-ready as a differentiating moat today is: (1) **the split-store problem** — brain_pipeline writes to KnowledgeBrain (Store B) but cross-domain queries (CVE correlation, compliance gaps, blast radius) read from KnowledgeStore (Store A), so they return empty because Store A lacks CVE cross-links; (2) **the org_id defaulting problem** — 5,636 events arrived with no org_id and were stored under `default`, meaning real tenant queries miss 93% of the graph; and (3) **5,636 stranded queue events** that have never been processed. The top three things to make TrustGraph a real moat: **A)** Unify the two stores — either wire brain_pipeline's `_step_build_graph` to also write through `TrustGraphBackbone.index_finding()` into Store A, or route ImpactAnalyzer/CrossDomainCorrelator to read from KnowledgeBrain (Store B) instead; either path eliminates the cross-query dead zone. **B)** Fix the org_id defaulting in the event bus interceptor — the API response body rarely includes `org_id`; instead read it from the request auth header (`X-Org-ID` / JWT claim) which is always present; this turns 93% of misrouted entities into properly tenant-scoped entities. **C)** Add `org_id` to the `relationships` table and stamp it on every edge written through the backbone, closing the cross-tenant traversal gap that the chief-architect sweep flagged as a remaining leak.
