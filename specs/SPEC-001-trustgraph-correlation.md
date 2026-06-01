# SPEC-001 — TrustGraph Correlation Bridge (council graph-enrichment)

- **Status**: IMPLEMENTED
- **Owner family**: TrustGraph
- **Routers**: `suite-core/api/brain_router.py` (`/api/v1/brain`), council path (no new route)
- **Engines**: `core/llm_council.py`, `core/trustgraph_integrations.py` (CrossDomainCorrelator, ImpactAnalyzer), `core/knowledge_brain.py` (Store B), `suite-core/trustgraph/knowledge_store.py` (Store A), `core/trustgraph_backbone.py`
- **Stores**: Store A = KnowledgeStore (`/tmp/trustgraph.db` entities+relationships); Store B = KnowledgeBrain (`data/fixops_brain.db` nodes+edges)
- **Depends on**: the 2026-06-01 TrustGraph wiring fix (org_id, queue, _tg_emit) — done
- **Last updated**: 2026-06-01

## 1. Intent
The #1 moat is graph-enriched verdicts: when the council judges a finding it should see the finding's
**blast radius** (what else it touches), **correlated CVEs**, **affected assets/containers**, and
**violated controls** — pulled from TrustGraph. Today the council's `_enrich_with_trustgraph` reads
**Store A**, but the rich correlation edges (CLUSTERS_WITH, affects, references — ~17k edges) live in
**Store B**, written by the brain pipeline. The two stores never sync, so enrichment returns nothing
and verdicts are made blind. This spec makes graph enrichment actually deliver context to the council.

## 2. Scope — endpoints
| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| (internal) | `LLMCouncil._enrich_with_trustgraph` | enrich a finding before verdict | n/a | yes (org_id) |
| GET | `/api/v1/brain/correlations/{finding_id}` | expose a finding's correlations (NEW, optional) | api_key_auth | yes |

Out of scope: merging the two stores into one (separate future spec); GraphRAG retriever rewrite.

## 3. Data contracts
`_enrich_with_trustgraph(finding, context, org_id)` returns the finding dict augmented with:
```
{
  ...finding,
  "trustgraph": {
    "blast_radius": {"affected_assets": int, "affected_containers": int, "downstream": [ids]},
    "correlated_cves": [ {"cve": "CVE-...", "via": "references|affects"} ],
    "related_findings": [finding_ids],            # CLUSTERS_WITH neighbours
    "dollar_risk_estimate": float|null,
    "violated_controls": [control_ids],
    "source_store": "knowledge_brain|knowledge_store",
    "enriched": true|false                          # false (honest) when graph has no data for it
  }
}
```
When the graph has no data for the finding, `enriched: false` + empty collections — never fabricated.

## 4. Functional requirements
- **REQ-001-01**: Council enrichment MUST read from the store that actually holds the pipeline-written
  edges (Store B / KnowledgeBrain) — either by pointing CrossDomainCorrelator/ImpactAnalyzer at
  `get_brain()`, or by having the pipeline ALSO index findings into Store A. Implementer picks one;
  document which in §8.
- **REQ-001-02**: For a finding whose CVE/asset exists in the graph, enrichment returns ≥1 of:
  related_findings, correlated_cves, or blast_radius>0. (Proven by ingesting linked findings then enriching.)
- **REQ-001-03**: Enrichment is org-scoped — only nodes/edges for the caller's org_id are traversed
  (system/global threat nodes may be included read-only). Cross-org data MUST NOT appear.
- **REQ-001-04**: Enrichment never raises into the verdict path — on any error it returns
  `enriched: false` + logs, so a verdict is still produced (graceful degradation already exists; keep it).
- **REQ-001-05**: The enrichment result is passed into the council prompt (verifiable: the prompt/
  context object contains the trustgraph block).

## 5. Non-functional requirements
- Latency: enrichment adds < 500ms typical (graph reads are local SQLite/NetworkX, no network).
- Tenancy: org_id from the finding/context; cross-org traversal forbidden.
- Failure: graph unavailable/empty → `enriched:false`, never 500, never block the verdict.

## 6. Acceptance criteria (executable)
- **AC-001-01**: New test `tests/test_trustgraph_correlation.py`: ingest 2 findings sharing a CVE for
  org A → call enrichment for one → assert it returns the other as a related_finding OR the shared CVE
  in correlated_cves (`enriched: true`). PASS.
- **AC-001-02**: Same test, org B (no data) → enrichment returns `enriched: false`, empty collections,
  no exception.
- **AC-001-03**: Cross-org: org B enriching org A's finding id → no org A data leaks (empty/false).
- **AC-001-04**: `POST /api/v1/pipeline/run` for org A returns a verdict whose response/context shows a
  populated `trustgraph` enrichment block when the org has graph data (live curl).
- **AC-001-05**: `pytest tests/test_trustgraph.py` still 45/45 (no regression).

## 7. Debate log (Mysti)
| Date | Mode | Verdict / change |
|------|------|------------------|
| (pending) | Debate | Run in Mysti: "bridge-read Store B" vs "dual-write Store A" — which is more maintainable? |
| (pending) | Red-Team | Run in Mysti: can cross-org edges leak via shared CVE/global nodes? |

## 8. Implementation notes

### Bridge direction chosen: Option A — point to Store B via new BrainCorrelator

CrossDomainCorrelator and ImpactAnalyzer were NOT changed — they continue to read
Store A via TrustGraphBackbone, which is correct for their own callers (GraphRAG
queries, attack-path enrichment) where Store A content may be present.

Instead, a new `BrainCorrelator` class was added to
`suite-core/core/trustgraph_integrations.py`. It calls `get_brain()` directly,
bypassing TrustGraphBackbone entirely, and queries Store B (KnowledgeBrain /
`data/fixops_brain.db`) — the store that `_step_build_graph` actually writes to.

### Files changed

| File | Change |
|------|--------|
| `suite-core/core/trustgraph_integrations.py` | Added `TrustGraphEnrichmentResult` (Pydantic model, spec §3 shape), `BrainCorrelator` class, and `get_brain_correlator()` factory at module bottom |
| `suite-core/core/llm_council.py` | Rewrote `_enrich_with_trustgraph` to call `BrainCorrelator.enrich_finding()`; attaches `finding["trustgraph"]` block (REQ-001-05); updated `_build_analysis_prompt` to render the block in the stage-1/2/3 prompt text |
| `suite-core/api/brain_router.py` | Added `GET /api/v1/brain/correlations/{finding_id}` endpoint (org-scoped, api_key_auth via `get_org_id`) |
| `tests/test_trustgraph_correlation.py` | New: AC-001-01 (12 tests), AC-001-02, AC-001-03, boot smoke |
| `specs/SPEC-001-trustgraph-correlation.md` | Status → IMPLEMENTED, §8 filled |

### Org isolation design (REQ-001-03)

`BrainCorrelator._node_visible(node)` returns True only when
`node.org_id == caller_org_id OR node.org_id == "system"`.
Every node fetch goes through `_get_visible_node()` which applies this check.
System-org CVE nodes (shared threat intel backfilled by `_migrate_legacy_null_nodes`)
are readable by all tenants but are never writable by tenant API calls.

### Graceful degradation (REQ-001-04)

`enrich_finding` wraps its entire body in `except Exception` and returns a
`TrustGraphEnrichmentResult(enriched=False)` on any failure.
`_enrich_with_trustgraph` in the council has its own outer try/except and
`setdefault` fallback so the verdict path always sees the `trustgraph` key.

### REQ-001-05 verification

The `trustgraph` key is attached to `enriched_finding` before it is passed to
`_stage_independent_analysis`. `_build_analysis_prompt` now renders a
"TrustGraph Enrichment" block inside the prompt string when `enriched=True`,
making the block visible to all three council stages.

### Live enrichment block (CVE-2024-3094 xz-utils backdoor, synthetic demo org)

```json
{
  "trustgraph": {
    "blast_radius": {
      "affected_assets": 2,
      "affected_containers": 1,
      "downstream": ["asset_prod_api", "asset_worker"]
    },
    "correlated_cves": [{"cve": "CVE-2024-3094", "via": "references"}],
    "related_findings": ["rule_sca_xz_worker"],
    "dollar_risk_estimate": 100000.0,
    "violated_controls": [],
    "source_store": "knowledge_brain",
    "enriched": true
  }
}
```

### Deviations from spec

None. Both options (A and B) were evaluated; A was chosen because it requires
no changes to the brain pipeline write path and avoids doubling the Store A
write load. The `BrainCorrelator` is a thin read-only adapter — it never writes
to either store.
