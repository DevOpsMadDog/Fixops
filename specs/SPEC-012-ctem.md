# SPEC-012 — Continuous Threat Exposure Management (CTEM) Surface

- **Status**: BACKFILL
- **Owner family**: CTEM / ASPM
- **Routers**:
  - `suite-api/apps/api/ctem_router.py` (prefix `/api/v1/ctem`) — CTEM cycle + exposure lifecycle
  - `suite-api/apps/api/ctem_engine_router.py` (prefix `/api/v1/ctem`) — extended cycle/exposure + dashboard
  - `suite-core/api/exposure_case_router.py` (prefix `/api/v1/cases`) — exposure case CRUD + lifecycle
  - `suite-api/apps/api/exposure_case_router.py` (prefix `/api/v1/cases`) — same prefix, suite-api mount
  - `suite-api/apps/api/prioritizer_router.py` (prefix `/api/v1/prioritize`) — ML-based vuln prioritization
  - `suite-api/apps/api/risk_aggregator_router.py` (prefix `/api/v1/risk-aggregator`) — org risk aggregation
  - `suite-api/apps/api/risk_scoring_router.py` (prefix `/api/v1/risk-scoring`) — per-vuln risk scores
  - `suite-core/api/monte_carlo_router.py` (prefix `/api/v1/risk/simulate`) — FAIR Monte Carlo
  - `suite-core/api/gnn_router.py` (prefix `/api/v1/attack-paths/gnn`) — GNN attack surface
  - `suite-api/apps/api/attack_path_router.py` — BFS attack path CRUD + traversal
  - `suite-feeds/api/feeds_router.py` (prefix `/api/v1/feeds`) — threat intel feeds
- **Engines**:
  - `suite-core/core/ctem_engine.py` — CTEM cycle state machine
  - `suite-core/core/exposure_case.py` — ExposureCaseManager (SQLite WAL)
  - `suite-core/core/finding_correlator.py` — FindingCorrelator (union-find + 5 strategies)
  - `suite-core/core/risk_aggregator_engine.py` — RiskAggregatorEngine
  - `suite-core/core/vuln_prioritizer.py` — VulnPrioritizer (GBT scoring)
  - `suite-core/core/ml/risk_scorer.py` — RiskScoringModel (GBT, 9-feature)
  - `suite-core/core/ml/attack_path_gnn.py` — AttackPathGNN (optional overlay)
  - `suite-core/core/attack_path_engine.py` — AttackPathEngine (BFS + choke-point cache)
  - `suite-core/core/monte_carlo.py` — MonteCarloRiskEngine (FAIR, numpy)
  - `suite-core/core/probabilistic.py` — Bayesian/Markov severity forecast utilities
  - `suite-feeds/feeds/epss/importer.py` — EPSS daily feed (FIRST.org CSV)
  - `suite-feeds/feeds/cisa_kev/importer.py` — CISA KEV JSON feed
  - `suite-feeds/feeds_service.py` — FeedsService (EPSS + KEV + 6 more categories)
  - `suite-core/core/threat_intel_enrichment_engine.py` — threat enricher
- **Stores**:
  - `fixops_exposure_cases.db` — exposure_cases table (ExposureCaseManager)
  - `suite-core/core/finding_correlator.db` — exposure_cases table (FindingCorrelator)
  - `.fixops_data/risk_aggregator.db` — risk_scores, risk_thresholds
  - `data/attack_paths.db` — nodes, edges, choke_point_analyses
  - `data/epss.db` — epss_scores
  - `data/cisa_kev.db` — kev_entries
  - `data/feeds/feeds.db` — FeedsService composite store
- **Depends on**: SPEC-001 (TrustGraph correlation), SPEC-002 (Nuclei pen-test connector), SPEC-005 (air-gap enforced default), SPEC-005b (graph-populate from scan)
- **Last updated**: 2026-06-01

---

## 1. Intent (the why)

CTEM is ALDECI's core differentiator: it continuously collapses raw scanner noise into a manageable set
of exposure cases, prioritizes them using real exploitability signals (EPSS, KEV, CVSS, GBT model), maps
blast radius through an attack graph, and drives remediation through a governed lifecycle. Where
competitors give customers a flat list of CVEs, ALDECI gives them an exposure case backlog of ~32 items
from 100+ scanner findings, each ranked by financial impact (FAIR Monte Carlo) and lateral-movement
reach (BFS + GNN). This is the platform's primary $199–$1,499/mo value delivery mechanism.

---

## 2. Scope — endpoints

### 2a. CTEM Cycle lifecycle (`/api/v1/ctem`)

| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| POST | /api/v1/ctem/cycles | Create + start CTEM cycle at SCOPING stage | api_key_auth | yes (org_id query param) |
| GET | /api/v1/ctem/cycles | List all cycles for org, newest first | api_key_auth | yes |
| GET | /api/v1/ctem/cycles/{cycle_id} | Get single cycle | api_key_auth | yes (ValueError→404) |
| DELETE | /api/v1/ctem/cycles/{cycle_id} | Delete cycle | api_key_auth | yes |
| POST | /api/v1/ctem/cycles/{cycle_id}/advance | Advance to next stage | api_key_auth | yes |
| GET | /api/v1/ctem/cycles/{cycle_id}/exposures | List exposures in cycle | api_key_auth | yes |
| POST | /api/v1/ctem/cycles/{cycle_id}/scope | Set asset scope for cycle | api_key_auth | yes |
| POST | /api/v1/ctem/cycles/{cycle_id}/discover | Trigger discovery phase | api_key_auth | yes |
| POST | /api/v1/ctem/cycles/{cycle_id}/prioritize | Trigger prioritization phase | api_key_auth | yes |
| POST | /api/v1/ctem/exposures | Create exposure | api_key_auth | yes |
| PUT | /api/v1/ctem/exposures/{exposure_id} | Update exposure | api_key_auth | yes |
| PATCH | /api/v1/ctem/exposures/{exposure_id} | Partial update (status, risk_score, owner, remediation_plan) | api_key_auth | yes |
| POST | /api/v1/ctem/exposures/{exposure_id}/validate | Mark exposure validated | api_key_auth | yes |
| POST | /api/v1/ctem/exposures/{exposure_id}/mobilize | Trigger mobilization | api_key_auth | yes |
| GET | /api/v1/ctem/dashboard | Dashboard summary | api_key_auth | yes |
| GET | /api/v1/ctem/stats | Cycle + exposure statistics | api_key_auth | yes |
| GET | /api/v1/ctem/ | Root — engine info/health | api_key_auth | no |

### 2b. Exposure Cases (`/api/v1/cases`)

| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| GET | /api/v1/cases/stats/summary | Aggregated stats (total, by_status, by_priority, kev_cases) | api_key_auth | yes (org_id from dependency) |
| POST | /api/v1/cases | Create exposure case | api_key_auth | yes (org_id always from auth, never from body) |
| GET | /api/v1/cases | List cases (filter: status, priority; paginate: limit, offset) | api_key_auth | yes |
| GET | /api/v1/cases/{case_id} | Get single case — 404 if wrong org | api_key_auth | yes |
| PATCH | /api/v1/cases/{case_id} | Update fields (not status) | api_key_auth | yes |
| POST | /api/v1/cases/{case_id}/transition | Lifecycle transition with validation | api_key_auth | yes |
| POST | /api/v1/cases/{case_id}/clusters | Attach dedup cluster IDs | api_key_auth | yes |
| GET | /api/v1/cases/{case_id}/transitions | List valid transitions for current state | api_key_auth | yes |
| GET | /api/v1/cases/health | Engine health check | none | no |

### 2c. Vuln Prioritization (`/api/v1/prioritize`)

| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| POST | /api/v1/prioritize | Score + rank finding list by exploitability | api_key_auth | no (stateless scoring) |
| GET | /api/v1/prioritize/top | Guidance message — submit via POST | api_key_auth | no |
| POST | /api/v1/prioritize/top | Score + return top-N findings | api_key_auth | no |
| POST | /api/v1/prioritize/explain/{finding_id} | Explain single finding rank + factors | api_key_auth | no |
| POST | /api/v1/prioritize/compare | Compare two findings side-by-side | api_key_auth | no |
| GET | /api/v1/prioritize/weights | Current factor weight config | api_key_auth | no |
| PUT | /api/v1/prioritize/weights | Update factor weights | api_key_auth | no |
| POST | /api/v1/prioritize/feedback | Record analyst feedback for model tuning | api_key_auth | no |
| GET | /api/v1/prioritize/stats | Prioritization stats (category distribution, avg score) | api_key_auth | org-filtered |

### 2d. Risk Aggregation (`/api/v1/risk-aggregator`)

| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| POST | /api/v1/risk-aggregator/scores | Record risk score for entity | api_key_auth | yes (org_id from auth) |
| GET | /api/v1/risk-aggregator/scores | List scores (filter: entity_type, severity) | api_key_auth | yes |
| GET | /api/v1/risk-aggregator/scores/entity/{entity_id} | Latest + history for entity | api_key_auth | yes |
| GET | /api/v1/risk-aggregator/heatmap | Counts per entity_type per severity | api_key_auth | yes |
| GET | /api/v1/risk-aggregator/top-risks | Top-N highest risk entities | api_key_auth | yes |
| GET | /api/v1/risk-aggregator/org-score | Composite org risk score (0-100) + grade + trend | api_key_auth | yes |
| POST | /api/v1/risk-aggregator/thresholds | Create threshold rule | api_key_auth | yes |
| GET | /api/v1/risk-aggregator/thresholds | List threshold rules | api_key_auth | yes |
| GET | /api/v1/risk-aggregator/stats | Aggregated risk statistics | api_key_auth | yes |
| POST | /api/v1/risk-aggregator/sync | Sync from brain graph finding nodes | api_key_auth | yes |

### 2e. Monte Carlo Risk Simulation (`/api/v1/risk/simulate`)

| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| POST | /api/v1/risk/simulate/fair | Full FAIR Monte Carlo simulation (custom params) | none (router-level) | no |
| POST | /api/v1/risk/simulate/cvss | Simplified simulation from CVSS score | none | no |
| POST | /api/v1/risk/simulate/cve | CVE-specific risk quantification | none | no |
| POST | /api/v1/risk/simulate/portfolio | Portfolio-level aggregate simulation | none | no |

### 2f. Attack Paths — BFS + GNN

| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| POST | /api/v1/attack-paths/nodes | Add node to attack graph | api_key_auth | yes (org_id) |
| GET | /api/v1/attack-paths/nodes | List nodes | api_key_auth | yes |
| GET | /api/v1/attack-paths/nodes/{node_id} | Get node (org-scoped read guard) | api_key_auth | yes |
| DELETE | /api/v1/attack-paths/nodes/{node_id} | Remove node + org-scoped edges | api_key_auth | yes |
| POST | /api/v1/attack-paths/edges | Add directed edge | api_key_auth | yes |
| POST | /api/v1/attack-paths/analyze | BFS path analysis from entry_point | api_key_auth | yes |
| POST | /api/v1/attack-paths/gnn/analyze | Full GNN attack surface analysis | api_key_auth | no |
| POST | /api/v1/attack-paths/gnn/paths | GNN path finding | api_key_auth | no |
| POST | /api/v1/attack-paths/gnn/propagate | Risk propagation through graph | api_key_auth | no |
| GET | /api/v1/attack-paths/gnn/node-types | List valid node types | none | no |
| GET | /api/v1/attack-paths/gnn/edge-types | List valid edge types | none | no |

### 2f. Threat Intel Feeds (`/api/v1/feeds`)

| Method | Path | Purpose | Auth | Tenant-scoped | Air-gap |
|--------|------|---------|------|---------------|---------|
| POST | /api/v1/feeds/epss/refresh | Fetch + replace EPSS table from FIRST.org | api_key_auth | no | blocked when enforced |
| GET | /api/v1/feeds/epss | List EPSS scores (paginated, filter by cve/epss_min) | api_key_auth | no | read-only OK |
| GET | /api/v1/feeds/epss/{cve_id} | Single CVE EPSS score | api_key_auth | no | read-only OK |
| POST | /api/v1/feeds/kev/refresh | Fetch + upsert CISA KEV from cisa.gov | api_key_auth | no | blocked when enforced |
| GET | /api/v1/feeds/kev | List KEV entries (paginated, ransomware_only filter) | api_key_auth | no | read-only OK |
| POST | /api/v1/feeds/enrich | Enrich findings batch with EPSS + KEV + threat intel | api_key_auth | no | read-only OK |
| GET | /api/v1/feeds/stats | Feed stats (total EPSS/KEV rows, last refresh) | api_key_auth | no | read-only OK |

**Out of scope for this spec**: NVD full CVE import (separate NVD router), MITRE ATT&CK mapping
(mitre_attack_router), compliance-framework mapping (SPEC-006), scanner normalization (connector
framework), LLM council verdict (SPEC-001/003).

---

## 3. Data contracts

### 3a. Exposure Case object

```
ExposureCase {
  case_id: str           // "EC-<12 hex chars>"
  title: str
  description: str
  status: open|triaging|fixing|resolved|closed|accepted_risk|false_positive
  priority: critical|high|medium|low|info
  org_id: str            // always from auth context, never from request body
  root_cve: str|null
  root_cwe: str|null
  root_component: str|null
  affected_assets: [str]
  cluster_ids: [str]     // dedup cluster IDs from FindingCorrelator
  finding_count: int
  risk_score: float      // 0.0 – 10.0 (FindingCorrelator scale) or 0.0 – 100.0 (VulnPrioritizer)
  epss_score: float|null
  in_kev: bool
  blast_radius: int      // reachable node count from AttackPathEngine (0 = isolated)
  assigned_to: str|null
  assigned_team: str|null
  sla_due: str|null      // ISO-8601
  sla_breached: bool
  created_at: str        // ISO-8601 UTC
  updated_at: str
  resolved_at: str|null
  closed_at: str|null
  remediation_plan: str|null
  playbook_id: str|null
  autofix_pr_url: str|null
  tags: [str]
  metadata: {}
}
```

### 3b. Key endpoint contracts

```
GET /api/v1/cases
  → 200 {"cases": [...], "total": N, "limit": 100, "offset": 0}
  Query: ?status=open&priority=critical&limit=50&offset=0

GET /api/v1/cases/stats/summary
  → 200 {"total_cases": N, "by_status": {"open": N, ...},
          "by_priority": {"critical": N, ...},
          "avg_risk_score": 0.0, "kev_cases": N}

POST /api/v1/cases/{case_id}/transition
  Body: {"new_status": "triaging", "actor": "analyst@example.com"}
  → 200 <updated ExposureCase>
  → 400 {"detail": "ValueError"} when transition invalid
         (e.g. open → resolved is not in VALID_TRANSITIONS)
  → 404 when case_id not found or belongs to different org

POST /api/v1/prioritize
  Body: {"findings": [{...}, ...]}
  → 200 {"count": N, "findings": [{"finding_id": ..., "risk_score": 0-100,
          "rank": N, "category": "critical_now|act_soon|monitor|defer",
          "explanation": "...", "factors": [...]}]}
  → 500 {"detail": "..."} on engine failure (not 503 — stateless scoring always available)

GET /api/v1/risk-aggregator/org-score
  → 200 {"org_id": "...", "org_risk_score": 0-100, "grade": "A|B|C|D|F",
          "breakdown": {"asset": 0.0, "user": 0.0, ...},
          "trend": "stable|worsening|improving",
          "entity_count": N}
  → 200 {"org_id": "...", "org_risk_score": 0, "grade": "A", "breakdown": {},
          "trend": "stable", "entity_count": 0}  // honest empty — no 503

POST /api/v1/risk/simulate/fair
  Body: FAIRSimulationRequest (tef_*, vuln_*, primary_loss_*, secondary_loss_*,
                               slef_probability, asset_value, iterations: 100–100000)
  → 200 {"mean_annual_loss": $, "median_annual_loss": $, "var_90": $, "var_95": $,
          "var_99": $, "prob_exceed_100k": 0.0-1.0, ...,
          "breach_probability": 0.0-1.0, "breach_probability_ci_lower": ...,
          "breach_probability_ci_upper": ...}
  // No auth required on monte_carlo_router (direct engine, no tenant data)

POST /api/v1/attack-paths/analyze
  Body: {"entry_point": "node-id", "target": null, "max_hops": 5, "org_id": "..."}
  → 200 {"entry_point": "...", "target_nodes_reached": [...],
          "paths": [{"path": [...], "hops": N, "risk_score": 0-100,
                     "vulnerabilities_required": [...],
                     "gnn_risk_score": 0-100}],    // present only when GNN model available
          "total_paths": N, "max_blast_radius": N}
  → 200 {"paths": [], "total_paths": 0, ...}  // honest empty when org graph is empty

POST /api/v1/feeds/epss/refresh
  → 200 {"scores_imported": N, "high_risk_count": N, "source_url": "..."}
  → 503 {"detail": "<feed_name>: offline — FIXOPS_AIRGAP_MODE=enforced or
                    FIXOPS_FEEDS_OFFLINE=1. Use the offline bundle import path instead."}
         when FIXOPS_AIRGAP_MODE=enforced OR FIXOPS_FEEDS_OFFLINE=1

POST /api/v1/feeds/kev/refresh
  → 200 {"imported": N, "updated": N, "skipped": N, "source_count": N}
  → 503 same offline message as EPSS

GET /api/v1/feeds/epss  (no network, read from local DB)
  → 200 {"scores": [...], "total": N, "page": 1, "page_size": 50}
  → 200 {"scores": [], "total": 0, ...}  // honest empty when feed not yet imported
```

### 3c. CTEM Cycle state machine

```
Stages (in order):
  SCOPING → DISCOVERY → PRIORITIZATION → VALIDATION → MOBILIZATION → MEASUREMENT

CTEMCycle {
  cycle_id: str
  name: str
  org_id: str
  stage: scoping|discovery|prioritization|validation|mobilization|measurement
  scoped_assets: [str]
  exposures: [Exposure]
  created_at: str
  updated_at: str
}

Exposure {
  id: str
  title: str
  description: str
  assets: [str]
  severity: str
  risk_score: float (0-100)
  business_impact: str
  owner: str
  org_id: str
  status: str
  remediation_plan: str|null
}
```

---

## 4. Functional requirements

- **REQ-012-01**: FindingCorrelator runs 5 strategies (CVE match, component match, file match, attack-chain pattern detection, scanner overlap) and uses union-find to collapse findings into ExposureCase clusters. Input: raw finding dicts of any schema. Output: list of ExposureCase objects sorted by risk_score descending.

- **REQ-012-02**: ExposureCaseManager enforces lifecycle state machine via VALID_TRANSITIONS dict. Invalid transition (e.g. OPEN → RESOLVED) raises ValueError mapped to HTTP 400. Status changes outside transition() are rejected (update_case() skips the "status" field).

- **REQ-012-03**: org_id on exposure cases is ALWAYS sourced from the authenticated context (get_org_id dependency), never from the request body. GET /cases/{case_id} returns 404 if case.org_id != caller org_id.

- **REQ-012-04**: VulnPrioritizer scores findings using ScoringConfig with configurable weights for: cvss_score, epss_score, asset_criticality, exposure_level, exploit_available, age_days, has_patch, in_attack_path. Output includes risk_score (0-100), rank, category (critical_now|act_soon|monitor|defer), and per-factor explanation.

- **REQ-012-05**: RiskScoringModel (GBT) accepts 9 features: cvss_score, epss_score, in_kev (bool→int), asset_criticality, network_exposure (categorical→ordinal via EXPOSURE_MAP), exploit_available, exploit_maturity (categorical→ordinal via MATURITY_MAP), reachable, chain_exploit. Returns risk_score 0-100 + confidence_interval [lower, upper].

- **REQ-012-06**: AttackPathEngine BFS traverses the org-scoped graph up to max_hops (default 5). Edge traversal respects requires_vuln (CVE ID that must be present on source node). When AttackPathGNN is available (importable), each path's risk_score is blended: (BFS_score + GNN_score) / 2, and gnn_risk_score is included in the path dict.

- **REQ-012-07**: AttackPathEngine.get_node() and list_nodes() include AND org_id = ? predicate. remove_node() only deletes edges WHERE org_id = ?. No cross-tenant graph read is possible.

- **REQ-012-08**: upsert_edge() is idempotent: same (from_node, to_node, org_id) tuple returns existing edge. edge_id is SHA-256 of "org_id:from_node:to_node" (first 32 hex chars), not random UUID.

- **REQ-012-09**: SPEC-005b — AttackPathEngine graph is auto-populated from pipeline scan results (brain_pipeline._step_build_graph / _correlate_and_emit). blast_radius on an ExposureCase reflects real reachability, not 0. See SPEC-005b.

- **REQ-012-10**: MonteCarloRiskEngine implements FAIR model using numpy triangular distributions. Iterations configurable (100–100000). Produces VaR at 90/95/99 percentile, loss exceedance probabilities for $100K/$500K/$1M/$5M thresholds, and breach probability with 95% confidence interval.

- **REQ-012-11**: EPSS importer fetches FIRST.org daily gzipped CSV (~250K rows). Import is a full REPLACE (DELETE + bulk INSERT in single transaction), not append. Rows with unparseable float fields are skipped with DEBUG log. Air-gap guard called before any HTTP request.

- **REQ-012-12**: CISA KEV importer fetches CISA JSON feed. Idempotent mode (default) skips CVE IDs already present. Force-update mode UPDATE-replaces existing rows. Air-gap guard called before any HTTP request.

- **REQ-012-13**: feeds_egress_allowed() blocks outbound requests when FIXOPS_AIRGAP_MODE=enforced OR FIXOPS_FEEDS_OFFLINE=1. Raises RuntimeError with message "offline — FIXOPS_AIRGAP_MODE=enforced or FIXOPS_FEEDS_OFFLINE=1. Use the offline bundle import path instead." Read operations (list_scores, get_by_cve, list_entries) are not blocked — they query the local SQLite DB.

- **REQ-012-14**: RiskAggregatorEngine.calculate_org_risk_score() returns mean of latest score per entity (not mean of all historical scores). Trend compares current org_score against previous-period average: +2 → "worsening", -2 → "improving", otherwise "stable". Returns grade A–F (A=0-20, B=21-40, C=41-60, D=61-80, F=81-100).

- **REQ-012-15**: RiskAggregatorEngine.sync_from_brain_graph() pulls brain_nodes WHERE node_type = 'finding' AND org_id = ? from the brain SQLite DB. CVSS → risk conversion: >=9.0 → 95, >=7.0 → 70 + scale, >=4.0 → 30 + scale. Exposure multiplier: internet/public/external → 1.2. Emits RISK_ASSESSED to TrustGraph event bus.

- **REQ-012-16**: CTEM cycle advances through SCOPING → DISCOVERY → PRIORITIZATION → VALIDATION → MOBILIZATION → MEASUREMENT in order. advance_stage() on a cycle already at MEASUREMENT raises ValueError. Cycle and exposure records are org-scoped.

- **REQ-012-17**: ExposureCaseManager.purge_empty_cases() deletes cases where finding_count=0 AND risk_score=0.0 AND root_cve/cwe/component all NULL. Supports dry_run=True for inspection without deletion.

- **REQ-012-18**: FindingCorrelator attack-chain detection uses 4 hardcoded patterns (EXPOSED_VULN confidence 0.90, AUTH_BYPASS 0.85, SUPPLY_CHAIN 0.80, DATA_EXPOSURE 0.85). All tag groups in a pattern must have at least one matching finding for the chain to fire. Correlations sorted by confidence descending.

- **REQ-012-19**: On exposure case CREATE, ExposureCaseManager calls _persist_to_brain() (upserts GraphNode + GROUPS edges to clusters + REFERENCES edge to CVE) and _emit_event() (exposure_case.created on event bus). Both calls are non-critical: exceptions are caught and logged, never propagate to the HTTP response.

---

## 5. Non-functional requirements

- **Latency**: GET /cases, GET /risk-aggregator/org-score, GET /cases/stats/summary must return < 2s with up to 10,000 cases per org. SQLite WAL mode on exposure_cases.db and risk_aggregator.db. No synchronous heavy compute on GET paths.

- **Monte Carlo**: POST /risk/simulate/fair with 10,000 iterations must complete < 5s on a single CPU core (numpy vectorized triangular sampling).

- **Attack path BFS**: max_hops=5 on a graph of 1,000 nodes / 5,000 edges must complete < 10s. GNN overlay failure must not block the BFS result (try/except with warning log).

- **Tenancy**: org_id always injected by the get_org_id() dependency (derived from API key). Cross-org read returns 404, never 403 (no information leak on case_id existence). All SQLite queries include AND org_id = ? predicates where applicable.

- **Failure mode (feeds)**: When FIXOPS_AIRGAP_MODE=enforced, POST /feeds/*/refresh → RuntimeError raised by assert_feeds_egress_allowed() before any HTTP call, surfaced as 503. GET read-only feed endpoints remain functional (local DB only). Never 500/hang/fake data.

- **Failure mode (brain graph sync)**: sync_from_brain_graph() returns {"processed":0,"skipped":0,"errors":1} when brain DB is absent or unreadable; never raises. Per-row exceptions are caught and counted, never abort the batch.

- **Failure mode (GNN)**: AttackPathGNN import failure at module load degrades gracefully (_gnn = None). BFS result is returned without gnn_risk_score field. No 500.

- **Feed import idempotency**: Re-running EPSS import replaces the entire table atomically (BEGIN/DELETE/bulk INSERT/COMMIT with ROLLBACK on error). Re-running KEV import in idempotent=True mode skips existing CVE IDs.

- **Exposure case org isolation**: case.org_id is set from the authenticated context in create_case(); the body org_id field is ignored. GET/{case_id} and all mutation endpoints check case.org_id == caller org_id before operating.

---

## 6. Acceptance criteria (executable)

- **AC-012-01**: `pytest tests/test_exposure_case_unit.py -q` — all tests pass. Covers create, get, list, transition, add_clusters, stats, purge_empty_cases.

- **AC-012-02**: Invalid lifecycle transition returns HTTP 400:
  ```
  curl -X POST /api/v1/cases/{case_id}/transition \
    -H "X-API-Key: $KEY" \
    -d '{"new_status":"resolved","actor":"test"}' \
    # case currently OPEN → 400 (OPEN→RESOLVED not in VALID_TRANSITIONS)
  ```

- **AC-012-03**: Cross-org isolation — GET /api/v1/cases/{case_id_from_other_org} → 404 (not 200 or 403).

- **AC-012-04**: `pytest tests/test_risk_aggregator_engine.py -q` — all tests pass. Covers record_risk_score, list_risk_scores, get_entity_risk, get_risk_heatmap, get_top_risks, calculate_org_risk_score, trend detection, score_breakdown.

- **AC-012-05**: `pytest tests/test_attack_path_engine.py tests/test_ml_attack_path_gnn.py -q` — all tests pass.

- **AC-012-06**: BFS returns empty paths honestly for empty graph:
  ```python
  engine = AttackPathEngine(db_path=":memory:")
  result = engine.find_attack_paths("node-1", org_id="test")
  assert result["total_paths"] == 0
  assert result["paths"] == []
  ```

- **AC-012-07**: Air-gap guard blocks EPSS refresh:
  ```python
  import os
  os.environ["FIXOPS_FEEDS_OFFLINE"] = "1"
  from feeds.epss.importer import EpssImporter
  with pytest.raises(RuntimeError, match="offline"):
      EpssImporter().run()
  ```

- **AC-012-08**: `pytest tests/test_vuln_prioritizer.py tests/test_ml_vuln_prioritizer.py -q` — all tests pass.

- **AC-012-09**: FAIR Monte Carlo produces non-trivial output:
  ```python
  from core.monte_carlo import FAIRInputs, MonteCarloRiskEngine
  engine = MonteCarloRiskEngine(iterations=1000)
  result = engine.simulate(FAIRInputs())
  assert result.mean_annual_loss > 0
  assert 0.0 <= result.breach_probability <= 1.0
  assert result.var_99 >= result.var_95 >= result.var_90
  ```

- **AC-012-10**: `pytest tests/test_ctem_engine.py tests/test_ctem_delete.py -q` — all tests pass.

- **AC-012-11**: EPSS read-only list works with empty local DB (no network, no crash):
  ```python
  from feeds.epss.importer import EpssImporter
  imp = EpssImporter(db_path="/tmp/test_epss.db")
  result = imp.list_scores()
  assert result["total"] == 0
  assert result["scores"] == []
  ```

- **AC-012-12**: purge_empty_cases dry_run never deletes:
  ```python
  mgr = ExposureCaseManager(db_path=":memory:")
  mgr.create_case(ExposureCase(case_id="", title="hollow", org_id="test"))
  result = mgr.purge_empty_cases(dry_run=True)
  assert result["purged"] == 1
  assert result["dry_run"] is True
  assert mgr.get_case("EC-...") is not None  # not deleted
  ```

- **AC-012-13**: GBT risk scorer feature vector produces deterministic output for known input:
  ```python
  from core.ml.risk_scorer import RiskScoringModel
  model = RiskScoringModel()
  result = model.predict({"cvss_score": 9.8, "epss_score": 0.95, "in_kev": True,
                          "asset_criticality": 1.0, "network_exposure": "internet",
                          "exploit_available": True, "exploit_maturity": "weaponized",
                          "reachable": True})
  assert result["risk_score"] > 80  # high-risk input should score high
  ```

---

## 7. Debate log (Mysti)

| Date | Mode | Verdict / change |
|------|------|------------------|
| 2026-06-01 | Backfill audit | Two separate ExposureCase implementations exist (core/exposure_case.py with full lifecycle + core/finding_correlator.py with simpler Pydantic model). They are intentionally separate concerns: finding_correlator.py produces transient cases from correlation runs; exposure_case.py is the persistent, lifecycle-managed entity. This duality should be documented. |
| 2026-06-01 | Red-Team | org_id from body ignored in create_case (correct). However CTEM cycle routes use org_id as a Query param (not from auth dependency) — a caller can fabricate org_id=other_org on POST /ctem/cycles. This is an open tenancy gap in ctem_router.py; ctem_engine_router.py does the same. Flagged for SPEC-007 follow-up. |
| 2026-06-01 | Red-Team | Monte Carlo router has no auth dependency on any endpoint — anyone can trigger CPU-intensive simulations. Should add api_key_auth or rate-limit. Open gap. |

---

## 8. Implementation notes

### Files read (source of truth for this spec)

| File | Role |
|------|------|
| `suite-core/core/exposure_case.py` | ExposureCaseManager, CaseStatus enum, VALID_TRANSITIONS, lifecycle, SQLite schema |
| `suite-core/api/exposure_case_router.py` | REST endpoints for /api/v1/cases (suite-core mount) |
| `suite-api/apps/api/exposure_case_router.py` | Same prefix, suite-api mount — same logic |
| `suite-core/core/finding_correlator.py` | FindingCorrelator: 5 strategies, union-find, risk_score formula, attack-chain patterns |
| `suite-core/core/risk_aggregator_engine.py` | RiskAggregatorEngine: org score, heatmap, thresholds, brain graph sync, CVSS→risk formula |
| `suite-api/apps/api/risk_aggregator_router.py` | /api/v1/risk-aggregator endpoints |
| `suite-api/apps/api/prioritizer_router.py` | /api/v1/prioritize endpoints, VulnPrioritizer + VulnerabilityPrioritizationEngine |
| `suite-core/core/ml/risk_scorer.py` | RiskScoringModel GBT, 9 features, EXPOSURE_MAP, MATURITY_MAP |
| `suite-core/core/attack_path_engine.py` | AttackPathEngine: BFS, upsert_edge idempotency, GNN overlay, choke-point cache table |
| `suite-core/core/ml/attack_path_gnn.py` | AttackPathGNN optional overlay |
| `suite-core/api/gnn_router.py` | /api/v1/attack-paths/gnn endpoints |
| `suite-core/core/monte_carlo.py` | MonteCarloRiskEngine, FAIRInputs, MonteCarloResult |
| `suite-core/api/monte_carlo_router.py` | /api/v1/risk/simulate endpoints |
| `suite-core/core/probabilistic.py` | Bayesian/Markov severity forecast utilities |
| `suite-feeds/feeds/__init__.py` | feeds_egress_allowed(), assert_feeds_egress_allowed() — SPEC-005 air-gap guard |
| `suite-feeds/feeds/epss/importer.py` | EpssImporter: FIRST.org CSV, full-replace strategy |
| `suite-feeds/feeds/cisa_kev/importer.py` | CisaKevImporter: CISA JSON, idempotent upsert |
| `suite-feeds/api/feeds_router.py` | /api/v1/feeds endpoints, auto-refresh background thread |
| `suite-api/apps/api/ctem_router.py` | /api/v1/ctem cycle + exposure routes |
| `suite-api/apps/api/ctem_engine_router.py` | /api/v1/ctem extended routes (discover, prioritize, validate, mobilize, dashboard, stats) |

### Dual ExposureCase model — clarification

`core/finding_correlator.py` defines a `ExposureCase` Pydantic model (id, title, severity, findings,
correlations, risk_score 0–10). This is a *correlation result* produced during a correlate run and
persisted in `finding_correlator.db`. It has a simpler 3-state lifecycle (open/investigating/resolved).

`core/exposure_case.py` defines `ExposureCase` (dataclass) + `ExposureCaseManager`. This is the
*persistent entity* with the full 7-state lifecycle, SLA tracking, blast_radius, knowledge-graph
integration, and event emission. This is what the REST API at `/api/v1/cases` operates on.

The intended data flow is: FindingCorrelator produces correlation clusters → those clusters are
attached to ExposureCaseManager cases via cluster_ids + add_clusters().

### Risk score scale mismatch

FindingCorrelator produces risk_score 0–10 (sev_weight * 1.5 + len(fids) * 0.3, capped at 10).
VulnPrioritizer and RiskScoringModel produce risk_score 0–100.
ExposureCaseManager stores risk_score as REAL with no enforced scale.
Callers must normalize when comparing scores across these two subsystems.

### CTEM cycle org_id tenancy gap (open)

`ctem_router.py` and `ctem_engine_router.py` accept `org_id` as a URL query parameter
(`org_id: str = Query(default="default")`), not from an auth-derived dependency. This means an
authenticated caller can fabricate any org_id. Tracked for remediation under SPEC-007.

### Cross-references

- SPEC-001: TrustGraph correlation — ExposureCaseManager._persist_to_brain() writes to knowledge graph; blast_radius enriched via SPEC-001 council block.
- SPEC-002: Nuclei pen-test connector — openclaw campaign results feed exploit evidence into prioritization (in_attack_path, exploit_available factors).
- SPEC-005: Air-gap enforcement — feeds egress guard implemented in suite-feeds/feeds/__init__.py.
- SPEC-005b: Graph populate from scan — AttackPathEngine auto-populated during pipeline run so blast_radius is non-zero after real ingest.
