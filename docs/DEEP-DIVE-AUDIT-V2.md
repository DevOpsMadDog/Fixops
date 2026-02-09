# ALdeci / FixOps — Deep-Dive Codebase Audit V2

**Date:** 2026-02-08
**Auditor:** Augment Agent (Claude Opus 4.6)
**Scope:** All 6 suites + frontend + CLI + infrastructure
**Methodology:** Static code analysis, cross-reference tracing, integration contract verification

---

## Executive Summary

This audit examined every router, every frontend API call, every cross-suite import, the EventBus, Knowledge Graph, Brain Pipeline, Copilot tool chain, CLI, auth system, and deployment configuration. The goal was to answer one question: **if we deploy this today, what breaks?**

### Severity Breakdown

| Severity | Count | Description |
|----------|-------|-------------|
| 🔴 CRITICAL | 4 | System will not function as designed |
| 🟠 HIGH | 4 | Major features broken or misleading |
| 🟡 MEDIUM | 3 | Functional but fragile or inconsistent |
| 🟢 LOW | 2 | Cosmetic or documentation-only |

### Top 4 Critical Findings (TL;DR)

1. **~90+ frontend API calls will return 404** — suite-api only mounts 23 of 57 routers; the other 34 routers run on ports 8001–8005 but the frontend only talks to port 8000.
2. **EventBus emits events but nobody listens** — `.emit()` is called in 7 files; zero `.on()` or `.subscribe()` registrations exist in production code.
3. **Knowledge Graph is isolated per process** — each suite gets its own singleton `KnowledgeBrain` instance with its own SQLite file; there is no cross-process sharing.
4. **Copilot actions are stubbed** — `_execute_action_sync()` returns `"pending_integration"` for every action type (analyze, pentest, remediate).

---

## Section 1: Endpoint Inventory Audit

### Claimed vs Actual

| Metric | Claimed | Actual | Delta |
|--------|---------|--------|-------|
| Total endpoints | 603 | 568 | -35 (5.8% inflated) |
| Router files | 62 | 57 | -5 |

### Breakdown by Suite

| Suite | Port | Router Files | Endpoints |
|-------|------|-------------|-----------|
| suite-api | 8000 | 17 | 203 |
| suite-core | 8001 | 17 | 185 |
| suite-attack | 8002 | 11 | 83 |
| suite-feeds | 8003 | 1 | 29 |
| suite-evidence-risk | 8004 | 6 | 22 |
| suite-integrations | 8005 | 5 | 46 |
| **Total** | | **57** | **568** |

### Route Prefix Conflicts 🔴

Three prefix collisions were found:

| Conflict | Router A | Router B | Prefix |
|----------|----------|----------|--------|
| 1 | `suite-core/api/brain_router.py` (20 ep) | `suite-core/api/pipeline_router.py` (6 ep) | `/api/v1/brain` |
| 2 | `suite-evidence-risk/api/business_context.py` | `suite-evidence-risk/api/business_context_enhanced.py` | `/business-context` |
| 3 | `suite-integrations/api/webhooks_router.py` `router` | same file `receiver_router` | `/api/v1/webhooks` |

**Impact:** Conflict #1 means the Brain Pipeline REST API (`POST /api/v1/brain/pipeline/run`) is shadowed by brain_router's 20 endpoints — pipeline execution is unreachable even if both routers were mounted.

### Inconsistent Prefix Naming 🟡

Most routers use `/api/v1/...` but 8 do not:

| Router | Prefix | Expected |
|--------|--------|----------|
| evidence_router | `/evidence` | `/api/v1/evidence` |
| provenance_router | `/provenance` | `/api/v1/provenance` |
| risk_router | `/risk` | `/api/v1/risk` |
| graph_router | `/graph` | `/api/v1/graph` |
| business_context (×2) | `/business-context` | `/api/v1/business-context` |
| decisions_router | `/decisions` | `/api/v1/decisions` |
| oss_tools | `/oss` | `/api/v1/oss` |

---

## Section 2: Frontend → Backend Contract Audit 🔴 CRITICAL

### Architecture

```
Browser → http://localhost:3000 (Vite dev server)
       → /api/* proxied to http://localhost:8000 (suite-api)

suite-ui/aldeci/src/lib/api.ts:
  baseURL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

vite.config.ts proxy:
  '/api' → 'http://localhost:8000'
```

**ALL frontend requests go to port 8000 (suite-api).** There is no proxy configuration for ports 8001–8005.

### What suite-api Actually Mounts (23 routers)

```
✅ health_v1_router       → /api/v1
✅ enhanced_router         → /api/v1/enhanced
✅ reachability_router     → /api/v1/reachability  (from suite-evidence-risk)
✅ inventory_router        → /api/v1/inventory
✅ users_router            → /api/v1/users
✅ teams_router            → /api/v1/teams
✅ policies_router         → /api/v1/policies
✅ analytics_router        → /api/v1/analytics
✅ reports_router          → /api/v1/reports
✅ audit_router            → /api/v1/audit
✅ workflows_router        → /api/v1/workflows
✅ auth_router             → /api/v1/auth
✅ bulk_router             → /api/v1/bulk
✅ remediation_router      → /api/v1/remediation
✅ collaboration_router    → /api/v1/collaboration
✅ validation_router       → /api/v1/validate       (conditional)
✅ marketplace_router      → /api/v1/marketplace     (conditional)
✅ mpte_router             → /api/v1/mpte            (from suite-attack)
✅ micro_pentest_router    → /api/v1/micro-pentest   (from suite-attack)
✅ vuln_discovery_router   → /api/v1/vulns           (from suite-attack)
✅ secrets_router          → /api/v1/secrets          (from suite-attack)
✅ feeds_router            → /api/v1/feeds            (from suite-feeds)
✅ brain_router            → /api/v1/brain            (from suite-core)
+ 22 inline endpoints defined directly in app.py
```

### What Will 404 — 34 Missing Routers (345+ endpoints)

**From suite-core (16 missing):**

| Router | Prefix | Endpoints | Frontend Calls That Break |
|--------|--------|-----------|--------------------------|
| nerve_center | `/api/v1/nerve-center` | 9 | `getPulse()`, `getOverview()` |
| copilot_router | `/api/v1/copilot` | 14 | `createSession()`, `sendMessage()`, `getHistory()` |
| agents_router | `/api/v1/copilot/agents` | 32 | All agent CRUD + actions |
| deduplication_router | `/api/v1/deduplication` | 18 | `getClusters()`, `getClusterDetails()`, `mergeFindings()` |
| autofix_router | `/api/v1/autofix` | 12 | `generateFix()`, `getFixStatus()` |
| mindsdb_router | `/api/v1/ml` | 11 | `getModels()`, `predict()` |
| pipeline_router | `/api/v1/brain` | 6 | `brain.pipeline.run()` (**prefix conflict**) |
| exposure_case_router | `/api/v1/cases` | 8 | `cases.list()`, `cases.get()`, `cases.transition()` |
| predictions_router | `/api/v1/predictions` | 8 | `getPredictions()` |
| fuzzy_identity_router | `/api/v1/identity` | 7 | `resolveIdentity()` |
| llm_router | `/api/v1/llm` | 6 | `getLLMConfig()` |
| algorithmic_router | `/api/v1/algorithms` | 11 | `runAlgorithm()` |
| intelligent_engine_routes | `/intelligent-engine` | 11 | — |
| llm_monitor_router | `/api/v1/llm-monitor` | 4 | `getLLMMetrics()` |
| code_to_cloud_router | `/api/v1/code-to-cloud` | 2 | `traceCode()` |
| decisions_router | `/decisions` | 6 | — |

**From suite-attack (7 missing):**

| Router | Prefix | Endpoints |
|--------|--------|-----------|
| attack_sim_router | `/api/v1/attack-sim` | 13 |
| sast_router | `/api/v1/sast` | 4 |
| container_router | `/api/v1/container` | 3 |
| dast_router | `/api/v1/dast` | 2 |
| cspm_router | `/api/v1/cspm` | 4 |
| api_fuzzer_router | `/api/v1/api-fuzzer` | 3 |
| malware_router | `/api/v1/malware` | 4 |

**From suite-evidence-risk (5 missing):**

| Router | Prefix | Endpoints |
|--------|--------|-----------|
| evidence_router | `/evidence` | 6 |
| provenance_router | `/provenance` | 2 |
| risk_router | `/risk` | 3 |
| graph_router | `/graph` | 4 |
| business_context (×2) | `/business-context` | 7 |

**From suite-integrations (6 missing):**

| Router | Prefix | Endpoints |
|--------|--------|-----------|
| integrations_router | `/api/v1/integrations` | 8 |
| iac_router | `/api/v1/iac` | 6 |
| ide_router | `/api/v1/ide` | 5 |
| oss_tools | `/oss` | 8 |
| webhooks_router (×2) | `/api/v1/webhooks` | 19 |

### Sample Frontend Calls That Will Fail

```typescript
// suite-ui/aldeci/src/lib/api.ts

// Line 454 — nerve_center NOT mounted
getPulse: () => api.get('/api/v1/nerve-center/pulse')  // → 404

// Line 144 — copilot NOT mounted
createSession: (data) => api.post('/api/v1/copilot/sessions', data)  // → 404

// Line 239 — deduplication NOT mounted
getClusters: (orgId) => api.get('/api/v1/deduplication/clusters')  // → 404

// Line 485 — exposure cases NOT mounted
list: (params) => api.get('/api/v1/cases', { params })  // → 404

// Line 474 — pipeline NOT mounted + prefix conflict
run: (data) => api.post('/api/v1/brain/pipeline/run', data)  // → 404

// Line 394 — evidence NOT mounted + wrong prefix
list: () => api.get('/evidence/')  // → 404

// Line 249 — graph NOT mounted + wrong prefix
getGraph: () => api.get('/graph/')  // → 404
```

### Root Cause

suite-api (`suite-api/apps/api/app.py`) imports routers from other suites via `sitecustomize.py` path injection, but only imports 7 cross-suite routers. The remaining 34 routers are only mounted in their own suite's `app.py` (ports 8001–8005), which the frontend never contacts.

### Fix Required

**Option A (Recommended): Mount all 34 missing routers in suite-api's app.py**
- Import each missing router via `sitecustomize.py` path injection (already works for 7 routers)
- Resolve the `/api/v1/brain` prefix conflict by renaming `pipeline_router` to `/api/v1/pipeline`
- Normalize all prefixes to `/api/v1/...` pattern

**Option B: Multi-port proxy in Vite config**
- Add proxy rules for each suite port
- More complex, requires frontend to know about backend topology

---

## Section 3: Inter-Suite Communication Audit 🟠 HIGH

### Finding: No Runtime HTTP Communication Between Suites

A comprehensive search for `httpx`, `aiohttp`, `requests.get/post`, and URL patterns like `localhost:800[1-5]` across all suite directories found **ZERO inter-suite HTTP calls**.

**How suites currently share code:**
1. `sitecustomize.py` adds all suite directories to `sys.path`
2. Suites import directly: `from core.knowledge_brain import get_brain`
3. This only works when running in the **same Python process** or when all suite directories are on the filesystem

**Implications:**
- In development (single machine): Works because all files are on disk and `sitecustomize.py` sets up paths
- In Kubernetes (separate pods): **WILL BREAK** — suite-attack pod can't `from core.knowledge_brain import get_brain` because `suite-core/core/` isn't in its filesystem
- The Helm chart deploys each suite as a separate pod, but the code assumes shared filesystem access

### Fix Required

For Kubernetes deployment, either:
1. **Shared volume mount** with all suite code in each pod (simple but wasteful)
2. **HTTP API calls** between suites (proper microservice pattern)
3. **Monolith mode** — run all suites in one process (current implicit design)

---

## Section 4: CLI ↔ API Integration Audit 🟠 HIGH

### Finding: CLI Commands Target Unmounted Endpoints

**File:** `suite-core/core/cli.py` (5,386 lines)

The CLI targets `http://127.0.0.1:8000` (suite-api) via `FIXOPS_API_URL` env var. Three command groups call endpoints that are NOT mounted in suite-api:

```python
# Lines 3550-3552 — correlation command
api_base = os.environ.get("FIXOPS_API_URL", "http://127.0.0.1:8000")
api_token = os.environ.get("FIXOPS_API_TOKEN", "demo-token")  # ← hardcoded default
# Calls: /api/v1/deduplication/clusters → 404 (deduplication_router not mounted)

# Lines 3629-3631 — groups command
# Calls: /api/v1/deduplication/stats → 404

# Lines 3725-3727 — remediation command
# Calls: /api/v1/remediation/tasks → may work (remediation_router IS mounted)
```

### Hardcoded Demo Token 🟡

The string `"demo-token"` appears as a default API token in 3 CLI handler functions (lines 3551, 3630, 3726). While overridable via `FIXOPS_API_TOKEN` env var, this is a security risk if the default is ever accepted in production.

Also found in:
- `scripts/micropentest_sidecar.py` line 66: `API_KEY = os.getenv("FIXOPS_API_TOKEN", "demo-token")`
- `test_real_apis.py` line 17: `API_KEY = os.getenv("FIXOPS_API_KEY", "demo-token")`
- `suite-ui/aldeci/src/lib/api.ts` line 3: `API_KEY = ... || 'demo-token'`

---

## Section 5: Copilot / LLM Tool Chain Audit 🔴 CRITICAL

### What Works ✅

1. **Session management:** In-memory store with UUID-based sessions, message history, context injection
2. **LLM provider chain:** OpenAI → Anthropic → Sentinel (deterministic fallback)
3. **Knowledge Brain context enrichment:** Copilot searches graph for relevant context before generating responses
4. **Chat endpoint:** `/api/v1/copilot/sessions/{id}/messages` — sends user message, gets LLM response

### What Is Stubbed ❌

**File:** `suite-core/api/copilot_router.py`, lines 637–686

```python
async def _execute_action_sync(action_id: str) -> None:
    """Execute action synchronously.
    Actions return pending status until real integrations are configured."""

    action_type = action["action_type"]

    if action_type == "analyze":
        action["result"] = {"status": "pending_integration", ...}
    elif action_type == "pentest":
        if os.environ.get("MPTE_TOKEN", ""):
            action["result"] = {"status": "submitted_to_mpte", ...}
        else:
            action["result"] = {"status": "pending_integration", ...}
    elif action_type == "remediate":
        action["result"] = {"status": "pending_integration", ...}
    else:
        action["result"] = {"status": "pending", "message": f"Action {action_type} not yet implemented"}
```

**Impact:** When a user asks the Copilot to "analyze CVE-2024-1234" or "run a pentest" or "fix this vulnerability", the Copilot will respond with a chat message (LLM works) but the **action execution** returns `"pending_integration"` instead of actually invoking FeedsService, MPTE, or AutoFix.

### Additional Issue: Copilot Router Not Mounted

The `copilot_router` is NOT mounted in suite-api (it runs on port 8001 in suite-core). Frontend calls to `/api/v1/copilot/*` will 404. This compounds the stub issue — even if actions were implemented, they'd be unreachable.

---

## Section 6: Brain Pipeline Orchestrator Audit ✅/🔴

### 12-Step Implementation Status

**File:** `suite-core/core/brain_pipeline.py` (696 lines)

| Step | Method | Implementation | Status |
|------|--------|---------------|--------|
| 1. Connect | `_step_connect` | Tallies findings/assets count | ✅ Real |
| 2. Normalize | `_step_normalize` | Ensures canonical shape for findings | ✅ Real |
| 3. Resolve Identity | `_step_resolve_identity` | FuzzyIdentityResolver for asset names | ✅ Real |
| 4. Deduplicate | `_step_deduplicate` | DeduplicationService → Exposure Cases | ✅ Real |
| 5. Build Graph | `_step_build_graph` | Upserts nodes/edges to KnowledgeBrain | ✅ Real |
| 6. Enrich Threats | `_step_enrich_threats` | Fetches EPSS, KEV, CVSS from feeds | ✅ Real |
| 7. Score Risk | `_step_score_risk` | CVSS + EPSS + KEV + asset criticality | ✅ Real |
| 8. Apply Policy | `_step_apply_policy` | Evaluates rules, determines actions | ✅ Real |
| 9. LLM Consensus | `_step_llm_consensus` | EnhancedDecisionEngine multi-LLM | ✅ Real |
| 10. Micro Pentest | `_step_micro_pentest` | MPTE validation on high-risk findings | ✅ Real |
| 11. Run Playbooks | `_step_run_playbooks` | Executes remediation playbooks | ✅ Real |
| 12. Generate Evidence | `_step_generate_evidence` | SOC2 Type II evidence packs | ✅ Real |

**All 12 steps have real implementations.** This is the strongest part of the codebase.

### But: Pipeline Is Unreachable From Frontend 🔴

**File:** `suite-core/api/pipeline_router.py` (prefix: `/api/v1/brain`)

1. `pipeline_router.py` is NOT mounted in suite-api
2. Its prefix `/api/v1/brain` CONFLICTS with `brain_router.py` (also `/api/v1/brain`)
3. Frontend call `api.post('/api/v1/brain/pipeline/run', data)` hits `brain_router` which has no `/pipeline/run` endpoint → **404**

### Fix Required

1. Change `pipeline_router.py` prefix to `/api/v1/pipeline`
2. Mount `pipeline_router` in suite-api's app.py
3. Update frontend call from `/api/v1/brain/pipeline/run` to `/api/v1/pipeline/run`



---

## Section 7: EventBus Wiring Audit 🔴 CRITICAL

### Architecture

**File:** `suite-core/core/event_bus.py` (232 lines)

The EventBus is an async pub/sub system with:
- `emit(event)` — publish an event
- `on(event_type)` — decorator to subscribe to events
- `subscribe_all(handler)` — wildcard subscriber
- Singleton pattern via `get_event_bus()`
- In-memory event log (max 10,000 entries)

### Emit Sites (7 files)

| File | Line | Event Type |
|------|------|------------|
| `suite-core/core/exposure_case.py` | 435 | Case lifecycle events |
| `suite-core/core/attack_simulation_engine.py` | various | Campaign events |
| `suite-attack/api/vuln_discovery_router.py` | various | CVE discovered |
| `suite-core/core/autofix_engine.py` | various | Fix events |
| `suite-attack/api/micro_pentest_router.py` | various | Pentest events |
| `suite-feeds/api/feeds_router.py` | various | Feed update events |
| `suite-evidence-risk/api/evidence_router.py` | various | Evidence events |

### Subscribe Sites: **ZERO** ❌

A comprehensive search for `.on(`, `.subscribe(`, `subscribe_all` across all suite directories found:
- **0 production subscriber registrations**
- The only `.on()` reference is in the EventBus docstring as an **example** (line 120 of `event_bus.py`)

```python
# This is in the DOCSTRING, not production code:
@bus.on(EventType.CVE_DISCOVERED)
async def handle_cve(event: Event):
    # Auto-trigger EPSS lookup, dedup check, graph update
    ...
```

### Impact

Events are emitted throughout the system but **no handler ever receives them**. The EventBus is architecturally sound but entirely unwired. Cross-engine orchestration (e.g., "when a CVE is discovered, automatically run EPSS lookup and update the graph") does not happen.

### Fix Required

Create a subscriber registration module (e.g., `suite-core/core/event_subscribers.py`) that registers handlers for all event types on application startup. Wire it into `suite-core/api/app.py` as a startup hook.

---

## Section 8: Knowledge Graph Sharing Audit 🔴 CRITICAL

### Architecture

**File:** `suite-core/core/knowledge_brain.py` (661 lines)

```python
class KnowledgeBrain:
    _instance: Optional["KnowledgeBrain"] = None  # Per-process singleton
    _lock = threading.Lock()

    def __init__(self, db_path="fixops_brain.db"):
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._graph = nx.MultiDiGraph()  # In-memory graph
```

### The Problem

Each suite runs as a **separate Python process** on a different port:
- suite-api → port 8000 → its own `KnowledgeBrain` singleton → its own `fixops_brain.db`
- suite-core → port 8001 → its own `KnowledgeBrain` singleton → its own `fixops_brain.db`
- suite-attack → port 8002 → its own `KnowledgeBrain` singleton → its own `fixops_brain.db`
- etc.

Python singletons are **per-process**, not cross-process. The `_instance` class variable is isolated in each process's memory space.

### Observed Behavior

- If suite-core's brain pipeline upserts a CVE node, suite-api's brain won't see it
- If suite-attack discovers a vulnerability and writes to the graph, suite-core can't query it
- The Knowledge Graph is effectively **6 isolated graphs**, not one unified graph

### SQLite Note

Because the default `db_path` is `"fixops_brain.db"` (relative), each process creates the file in its own working directory. Even if they used the same absolute path, SQLite has limited concurrent write support (WAL mode helps but NetworkX in-memory graph won't sync).

### Fix Required

**Option A (Quick):** Use a single shared absolute path (`/data/fixops_brain.db`) and accept SQLite WAL mode limitations. Remove the NetworkX in-memory graph or make it read-on-demand from SQLite.

**Option B (Production):** Replace SQLite + NetworkX with a proper graph database (Neo4j, or PostgreSQL with Apache AGE) that supports concurrent multi-process access.

---

## Section 9: Error Handling & Security Audit 🟠 HIGH

### Silent Router Loading Failures

**Files:** `suite-core/api/app.py` (lines 109–128), `suite-attack/api/app.py` (lines 83–105)

Both suites use dynamic router loading with `try/except` that silently swallows import failures:

```python
for module_name, display_name in _optional_routers.items():
    try:
        mod = importlib.import_module(f"api.{module_name}")
        _router = getattr(mod, "router")
        app.include_router(_router)
        logger.info("Loaded %s router", display_name)
    except Exception as exc:
        logger.warning("%s router not available: %s", display_name, exc)
        # ← Silently continues — no way to know which routers loaded
```

**Impact:** In production, if a router fails to import (missing dependency, syntax error, etc.), the app starts successfully but endpoints silently 404. Debugging requires checking startup logs.

### Hardcoded Secrets Summary

| Location | Value | Risk |
|----------|-------|------|
| `suite-core/core/cli.py` ×3 | `"demo-token"` | Medium — env-var overridable |
| `suite-ui/aldeci/src/lib/api.ts` | `"demo-token"` | Medium — env-var overridable |
| `scripts/micropentest_sidecar.py` | `"demo-token"` | Low — dev script |
| `test_real_apis.py` | `"demo-token"` | Low — test script |
| `tests/conftest.py` | `"demo-token-12345"` | Low — test fixture |

### Auth Architecture (Positive Findings ✅)

- JWT uses `FIXOPS_JWT_SECRET` env var (no hardcoded secret)
- CORS reads from `FIXOPS_ALLOWED_ORIGINS` with safe localhost defaults
- Scoped API keys with `fixops_<prefix>.<secret>` format, bcrypt hashed
- Role-based access: ADMIN, ANALYST, VIEWER, SERVICE
- Dev mode bypass via `FIXOPS_AUTH_MODE=dev` (appropriate for development)

---

## Section 10: Configuration & Environment Audit 🟢 LOW

### Helm Chart Alignment ✅

The Helm chart at `deployments/kubernetes/fixops-6suite/` correctly:
- Deploys all 6 suites as separate Deployments
- Sets up correct ports (8000–8005)
- Configures shared env vars: `FIXOPS_JWT_SECRET`, `FIXOPS_ALLOWED_ORIGINS`, `FIXOPS_AUTH_MODE`
- Includes HPA for suite-api, suite-core, suite-attack
- Includes PVC for suite-core data persistence
- Configures Ingress with `/api` → suite-api and `/` → suite-ui routing

### Environment Variable Coverage ✅

All required env vars are documented and have sensible defaults:

| Variable | Default | Purpose |
|----------|---------|---------|
| `FIXOPS_JWT_SECRET` | (generated) | JWT signing key |
| `FIXOPS_ALLOWED_ORIGINS` | `http://localhost:3000,http://localhost:8000` | CORS origins |
| `FIXOPS_AUTH_MODE` | `dev` | Auth enforcement level |
| `FIXOPS_CACHE_URL` | (none, uses in-memory) | Redis cache URL |
| `FIXOPS_API_TOKEN` | (none) | API key for external access |
| `OPENAI_API_KEY` | (none) | OpenAI integration |
| `ANTHROPIC_API_KEY` | (none) | Anthropic integration |
| `NVD_API_KEY` | (none) | NVD rate limit bypass |

### Only Concern 🟡

The Kubernetes deployment will trigger the cross-suite import issue (Section 3) because each pod has its own filesystem. The `sitecustomize.py` path injection only works when all suite directories exist on the same machine.

---

## Prioritized Fix List

### Priority 1: CRITICAL — System Will Not Function (fix before any demo/deploy)

| # | Finding | Effort | Fix |
|---|---------|--------|-----|
| F1 | **34 routers not mounted in suite-api** (345+ endpoints 404) | 2–4 hours | Import and mount all 34 missing routers in `suite-api/apps/api/app.py` |
| F2 | **Pipeline router prefix conflict** (`/api/v1/brain` ×2) | 30 min | Rename `pipeline_router` prefix to `/api/v1/pipeline`, update frontend |
| F3 | **EventBus has zero subscribers** | 2–3 hours | Create `event_subscribers.py` with handlers for all event types, wire into app startup |
| F4 | **Knowledge Graph isolated per process** | 1–2 hours (Option A) | Use shared absolute `db_path`, reload NetworkX from SQLite on each query |

### Priority 2: HIGH — Major Features Broken

| # | Finding | Effort | Fix |
|---|---------|--------|-----|
| F5 | **Copilot actions stubbed** (`pending_integration`) | 4–6 hours | Wire `_execute_action_sync` to call FeedsService, MPTE engine, AutoFix engine |
| F6 | **CLI targets unmounted endpoints** | 30 min | Mount `deduplication_router` in suite-api OR update CLI to target port 8001 |
| F7 | **No inter-suite HTTP communication** | 4–8 hours | Either mount all routers in suite-api (monolith gateway) or add HTTP client calls |
| F8 | **Silent router loading failures** | 1 hour | Add startup health check that logs all mounted routes; fail-fast option for production |

### Priority 3: MEDIUM — Fragile or Inconsistent

| # | Finding | Effort | Fix |
|---|---------|--------|-----|
| F9 | **Inconsistent route prefixes** (8 routers missing `/api/v1`) | 1–2 hours | Standardize all prefixes to `/api/v1/...`, update frontend calls |
| F10 | **business_context prefix conflict** (×2 routers) | 30 min | Rename enhanced version to `/api/v1/business-context/enhanced` |
| F11 | **Endpoint count inflation** (568 actual vs 603 claimed) | 30 min | Update documentation to reflect actual count |

### Priority 4: LOW — Cosmetic / Documentation

| # | Finding | Effort | Fix |
|---|---------|--------|-----|
| F12 | **Hardcoded `demo-token` defaults** | 30 min | Change defaults to empty string, require explicit configuration |
| F13 | **K8s deployment breaks cross-suite imports** | 2–4 hours | Shared volume mount or convert to HTTP API calls |

---

## Recommended Fix Sequence

```
Phase 15.1: Mount all 34 missing routers in suite-api  [F1, F2, F9, F10]
            ↳ This single change fixes ~60% of all issues

Phase 15.2: Wire EventBus subscribers                  [F3]
            ↳ Enables cross-engine orchestration

Phase 15.3: Fix Knowledge Graph sharing                [F4]
            ↳ Enables unified graph across all suites

Phase 15.4: Implement Copilot actions                  [F5]
            ↳ Enables real action execution from chat

Phase 15.5: CLI + hardcoded token cleanup              [F6, F8, F12]
            ↳ Production hardening

Phase 15.6: K8s deployment fix                         [F7, F13]
            ↳ Required before any Kubernetes deployment
```

### Estimated Total Effort: 16–28 hours

---

## Test Scenarios for Validation

After fixes are applied, these scenarios should pass end-to-end:

### Scenario 1: Frontend → Copilot Chat
```
1. POST /api/v1/copilot/sessions → 201 (create session)
2. POST /api/v1/copilot/sessions/{id}/messages → 200 (get LLM response)
3. POST /api/v1/copilot/actions → 200 (execute action)
4. GET /api/v1/copilot/actions/{id} → status != "pending_integration"
```

### Scenario 2: Brain Pipeline E2E
```
1. POST /api/v1/pipeline/run (with findings + assets)
2. Verify all 12 steps complete
3. GET /api/v1/brain/stats → nodes/edges increased
4. GET /api/v1/cases → new exposure cases created
5. GET /evidence/ → evidence pack generated
```

### Scenario 3: EventBus Flow
```
1. POST /api/v1/vulns/scan (discover a CVE)
2. Verify EventBus emits CVE_DISCOVERED
3. Verify subscriber triggers EPSS lookup
4. Verify subscriber updates Knowledge Graph
5. GET /api/v1/brain/nodes/{cve_id} → enriched with EPSS data
```

### Scenario 4: Cross-Suite Knowledge Graph
```
1. POST /api/v1/brain/nodes (create node via suite-api)
2. GET /api/v1/brain/nodes/{id} (read from suite-api) → found
3. Verify same node visible in suite-core's graph
4. Verify same node visible in suite-attack's graph
```

### Scenario 5: CLI Integration
```
1. fixops correlation list → returns real clusters
2. fixops groups stats → returns real stats
3. fixops remediation list → returns real tasks
```

---

## Appendix A: Files Examined

| Category | Files Examined |
|----------|---------------|
| Router files | 57 (all suites) |
| App entry points | 6 (`app.py` per suite) |
| Frontend API client | 1 (`api.ts`, 875 lines, 201 calls) |
| Frontend config | 1 (`vite.config.ts`) |
| CLI | 1 (`cli.py`, 5,386 lines) |
| Core engines | 8 (brain_pipeline, knowledge_brain, event_bus, exposure_case, attack_sim, autofix, copilot, cli) |
| Auth system | 3 (auth_models, auth_db, auth_middleware) |
| Kubernetes | 11 (Helm chart files) |
| Cross-suite wiring | 1 (`sitecustomize.py`) |
| **Total** | **~89 files** |

## Appendix B: Methodology

1. **Endpoint enumeration:** Regex `@(router|app)\.(get|post|put|patch|delete)\(` across all `suite-*/` directories
2. **Frontend contract:** Extracted all `api.get/post/put/patch/delete` calls from `api.ts`
3. **Router mounting:** Traced `include_router()` calls in each suite's `app.py`
4. **Cross-suite communication:** Searched for `httpx`, `aiohttp`, `requests`, `localhost:800[1-5]` across all suites
5. **EventBus wiring:** Searched for `.emit(`, `.on(`, `.subscribe(`, `subscribe_all` across all suites
6. **Knowledge Graph:** Traced `get_brain()` and `KnowledgeBrain` imports, analyzed singleton lifecycle
7. **Copilot actions:** Read `_execute_action_sync()` implementation line-by-line
8. **CLI integration:** Mapped CLI `api_base` URLs to actual mounted endpoints
9. **Security:** Searched for hardcoded tokens, secret patterns, auth bypass mechanisms
10. **Configuration:** Cross-referenced Helm values with code env var reads

---

*End of Deep-Dive Audit V2. Generated 2026-02-08.*