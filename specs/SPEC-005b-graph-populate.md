# SPEC-005b — Auto-populate TrustGraph + Attack-Path from scans (blast_radius ≠ 0)

- **Status**: IMPLEMENTED
- **Owner family**: TrustGraph / Pipeline
- **Engines**: `core/brain_pipeline.py` (_step_build_graph / _correlate_and_emit), `core/attack_path_engine.py`, `core/knowledge_brain.py`, `core/trustgraph_backbone.py`
- **Depends on**: SPEC-001
- **Last updated**: 2026-06-01

## 1. Intent
PM-4 found `get_blast_radius()` returns 0 for every finding because the `AttackPathEngine` graph is
NEVER populated from scan data — nodes/edges only come from explicit API calls. So the council's
blast-radius enrichment (SPEC-001) reads an empty attack graph. This spec auto-populates the
attack-path + cross-entity edges (CONTROL_MITIGATES_FINDING, asset nodes) DURING the pipeline run, so
a customer who ingests a scan gets a real blast_radius — closing the gap between "has a graph" and
"the graph informs verdicts".

## 2. Scope
- During pipeline `_correlate_and_emit` / `_step_build_graph`: for each finding, auto-create
  AttackPathEngine nodes (finding, asset) + edges (finding→asset, asset→asset from topology if present),
  and TrustGraph CONTROL_MITIGATES_FINDING edges from the compliance step's control mapping.
- `get_blast_radius(finding/asset)` returns a real count (>0 when the org has related assets/findings).
Out of scope: merging the two graph stores (separate); network-topology discovery (use what's in ctx).

## 3. Data contracts
- After a pipeline run for an org with ≥2 findings sharing an asset/CVE, `get_blast_radius()` for one
  returns `total_reachable > 0` + the reachable node ids (org-scoped).
- The council enrichment (SPEC-001 trustgraph block) shows `blast_radius.affected_assets > 0` for such findings.
- Empty org / single isolated finding → blast_radius 0 honestly (not fabricated).

## 4. Functional requirements
- **REQ-005b-01**: pipeline auto-creates AttackPathEngine nodes+edges from the run's findings+assets (org-scoped), so the attack graph is non-empty after a real ingest.
- **REQ-005b-02**: CONTROL_MITIGATES_FINDING edges auto-created from the compliance step's finding↔control mapping (the data is already in ctx).
- **REQ-005b-03**: `get_blast_radius()` returns real reachability for a finding whose asset has neighbours; 0 (honest) when genuinely isolated.
- **REQ-005b-04**: org-scoped — blast radius only traverses the caller org's nodes (+ system/global read-only). No cross-org.
- **REQ-005b-05**: a `graph_depth` / `blast_radius` metric is surfaced in the pipeline result so it's visible the graph did real work.
- **REQ-005b-06**: no fabricated edges — only edges derived from real scan/finding/asset/control data.

## 5. Non-functional
- Graph population adds bounded latency to the pipeline (local writes); no network.
- Idempotent: re-running a scan doesn't duplicate nodes/edges.

## 6. Acceptance criteria (executable)
- **AC-005b-01**: ingest 2 findings on the same asset for org A (or run pipeline with 2 findings sharing an asset) → `get_blast_radius()` for one returns total_reachable > 0.
- **AC-005b-02**: SPEC-001 enrichment for that finding → `blast_radius.affected_assets > 0`.
- **AC-005b-03**: org B (no data) → blast_radius 0, no cross-org nodes; org A's nodes not visible to B.
- **AC-005b-04**: single isolated finding → blast_radius 0 (honest, not fabricated).
- **AC-005b-05**: `tests/test_graph_populate.py` covers the above; boot create_app() succeeds; no regression in tests/test_trustgraph.py + tests/test_trustgraph_correlation.py.

## 7. Debate log (internal role-debate)
| Date | Mode | Verdict |
|------|------|---------|

## 8. Implementation notes

### Root cause
`AttackPathEngine.add_edge` always used `uuid4()` as the edge key and bare
`INSERT INTO` (never `INSERT OR REPLACE/IGNORE`), so repeated pipeline runs
silently duplicated edges.  More critically, `_blast_radius_adapter` called
`get_blast_radius(node_id)` without `org_id`, defaulting to `"default"` for
every org — so the engine always queried an empty graph for non-default tenants.
The pipeline's `_step_build_graph` populated `KnowledgeBrain` but never
populated `AttackPathEngine`.

### Changes made

**`suite-core/core/attack_path_engine.py`**
- Added `upsert_edge(from_node, to_node, …, org_id)`: idempotent variant keyed
  on `(from_node, to_node, org_id)` using a deterministic SHA-256 edge_id and
  `INSERT OR IGNORE`.  Existing `add_edge` is unchanged (backward compat).

**`suite-core/core/brain_pipeline.py`**
- `_step_build_graph`: calls new `_populate_attack_graph(ctx)` at the end of
  the existing KnowledgeBrain upsert loop.  Result dict now contains
  `attack_graph`, `blast_radius_nodes`, and `graph_depth` (REQ-005b-05).
- `_populate_attack_graph(ctx)`: new private method.  For every finding in
  `ctx["findings"]` it upserts a `server` node for the finding itself and for
  any named asset, then writes finding→asset edges (`upsert_edge`) and
  asset→asset edges for findings that share a CVE (the CVE is the lateral
  movement vector).  Fully idempotent; only real scan data used (REQ-005b-06).
- `_enrich_post_pipeline` / `_blast_radius_adapter`: fixed `org_id` capture —
  now uses `ctx["org_id"]` instead of the engine default `"default"`, closing
  the cross-tenant scoping gap (REQ-005b-04).
- `_enrich_compliance`: after writing `finding["compliance_impact"]`, emits
  `CONTROL_MITIGATES_FINDING` edges to TrustGraph via `backbone.link_entities`
  for every NIST 800-53, PCI DSS, and ISO 27001 control in the CWE mapping.
  Best-effort; never blocks the pipeline (REQ-005b-02).

### Acceptance criteria results (observed numbers)

| AC | Test | Result |
|----|------|--------|
| AC-005b-01 | `test_ac_005b_01_blast_radius_nonzero_with_shared_asset` | PASS — `total_reachable=1` (finding-1 → asset-web) |
| AC-005b-02 | `test_ac_005b_02_enrichment_blast_radius_nonzero` | PASS — `finding["blast_radius"]=1` after `_enrich_attack_paths` |
| AC-005b-03 | `test_ac_005b_03_org_isolation` | PASS — org B returns `total_reachable=0`; org A unaffected |
| AC-005b-04 | `test_ac_005b_04_isolated_finding_returns_zero` | PASS — `total_reachable=0` for node with no edges |
| AC-005b-05 | `test_upsert_edge_idempotent` | PASS — exactly 1 edge row after 2 upserts |
| AC-005b-05 (pipeline) | `test_populate_attack_graph_via_pipeline` | PASS — `nodes_upserted>0`, `edges_upserted>0`, `blast_radius>0` |
| Regression | `tests/test_trustgraph.py` + `tests/test_trustgraph_correlation.py` | 57/57 PASS |

### Design decisions
- `upsert_edge` uses a deterministic edge_id (`sha256(org:from:to)[:32]`) so
  the same logical edge always maps to the same row — `INSERT OR IGNORE` is
  safe.  `add_edge` (random uuid) is preserved for callers that intentionally
  want parallel edges (e.g. multiple protocols between the same pair).
- Finding nodes are modelled as `server` type (the only VALID_NODE_TYPES
  supertype appropriate for "a host/service with a vulnerability").  Dedicated
  `finding` type would require schema migration; `server` + `vulnerabilities`
  list carries the same semantics for BFS traversal.
- `_populate_attack_graph` is synchronous and local-SQLite only — bounded
  latency, no network (REQ NFR).
