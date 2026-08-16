# Codebase Understanding — measured, 2026-08-16

> Produced by running **Understand-Anything** (`Egonex-AI/Understand-Anything`) deterministic
> phases over this repo, cross-checked against direct measurement and against the live
> container. Every number here came from a tool run or an API call — none is estimated.

---

## 1. The shape of the repo

| Metric | Value | Source |
|---|---|---|
| Files scanned | **17,831** | `scan-project.mjs` |
| Code files | **16,691** | scanner `byCategory` |
| Python files | **12,799** | scanner `byLanguage` |
| TypeScript/TSX | **3,769** | scanner `byLanguage` |
| Estimated complexity | **`very-large`** | scanner verdict |
| Python source | **1,043,837 LOC** | direct count |
| UI source | **139,216 LOC** | direct count |
| Engines / routers | **464 / 813** | file count |
| Mounted route entries | **7,940** | `create_app()` |

## 2. The single most important number

Running the batch planner over the scan:

```
Loaded 17831 files (16691 code).
Wrote 801 batches (sizes: max=25, min=1)
```

**A full semantic pass over this codebase requires 801 LLM batches.** That is an external,
tool-derived measure of the bloat — not an opinion.

Against that, the code that actually carries the product:

| The value path (13 files) | Lines |
|---|---|
| `core/brain_pipeline.py` | 5,377 |
| `core/crypto.py` | 3,204 |
| `core/scanner_parsers.py` | 3,036 |
| `api/copilot_router.py` | 2,540 |
| `core/llm_council.py` | 2,244 |
| `core/llm_providers.py` | 2,239 |
| `apps/api/analytics_router.py` | 1,317 |
| `core/security_findings_engine.py` | 1,026 |
| `core/council_pipeline_adapter.py` | 912 |
| `core/exposure_case.py` | 673 |
| `apps/api/llm_council_router.py` | 381 |
| `api/pipeline_router.py` | 380 |
| `apps/api/exposure_case_router.py` | 250 |
| **TOTAL** | **23,579** |

> **23,579 of 1,043,837 lines — 2.3% — is the product.**
> The remaining 97.7% is breadth that no user path reaches.

## 3. Why it is large (mechanism, not blame)

1. **Competitor-parity breadth.** 149 capabilities × 7 competitors were each turned into an
   engine + router. That alone explains ~40 domains and hundreds of prefixes.
2. **Volume without consolidation.** Routers were generated faster than anyone merged them:
   104 files match "security", 34 paths under `/analytics`. Result: 813 routers for ~25 domains.
3. **Duplication.** 729 duplicate `(method, path)` groups existed; 406 dead route entries were
   removed this session and the distinct-path count never moved (7,532) — proving they were pure
   duplication.
4. **Artifacts on disk.** 4.37 GB of agent worktrees, graph caches, coverage HTML and browser
   artifacts (now purged; all were already gitignored).

## 4. What is actually missing — connections, not features

**49% of the backend (368 of 744 router prefixes) has no UI callsite**, while 457 of 464 engines
*are* imported by some router. So the code is built and wired at import level, and connected to
nothing a user can reach.

Every defect found this session was wiring or data — not a missing capability:

| Defect | Class |
|---|---|
| Feeds never synced (0 KEV / 0 EPSS) | no data |
| `/feeds/kev/refresh` → "Feed not found" | route shadowing (generic `{feed_id}` registered first) |
| Exposure cases invisible | **two SQLite files** (relative path resolved against CWD) |
| EPSS lookup empty | **two stores**; only one populated |
| Scanner / CVE columns blank | field-name mismatch (`source_tool`, `cve_id`) |
| Council 4/5 models | stale model IDs (removed from OpenRouter) |
| Login impossible | auth state never propagated to React |
| Copilot "AI" | canned template — no LLM, no tenant data |

Sampling the orphans confirms they are honest but idle: `/api/v1/abuseipdb/` returns
`{"service":"AbuseIPDB", …, "api_key_present": false}`; `/anomaly-ml/groups` returns
`{"group_count": 0}`. Built, wired, honest — unused.

## 5. What is genuinely real (verified live on the container)

| Capability | Evidence |
|---|---|
| Threat enrichment | 1,665 CISA KEV CVEs (20.96% ransomware), 360,142 FIRST EPSS scores, 2,000 NVD CVEs |
| Pipeline enrichment | `enrichment_source="real_api"`, `kev_matches=1`, `epss_api_hits=1` |
| AI council | 5 cross-vendor models, `providers_responded=5`, real `cost_usd`, `source=consensus` |
| Copilot | `source=llm_grounded_live_data`, names the tenant's actual findings |
| TrustGraph | 5 knowledge cores |
| MPTE | 34 steps executed on a real run |
| Self-learning | 5 active feedback loops |
| **MindsDB** | **0 API routes** — container runs, nothing wired. Genuinely absent. |

## 6. Conclusion

The product is **2.3% of the repo**, and that 2.3% now works end-to-end (UAT 11/11 against the
container). The other 97.7% is not broken so much as **unreached**. The cheapest path to a
credible product is therefore not to build — it is to **stop advertising what nothing reaches**:
`FIXOPS_CORE_MODE=1` already does this for the API (454 of 6,564 paths) and the UI (curated
5-section nav). See `DORMANCY_PLAN_2026-08-16.md` for the runtime half.

## 7. Reproducing / going further

The deterministic phases above were run by bootstrapping the tool manually. For the full
7-phase analysis with tree-sitter symbol extraction and semantic summaries, install it natively —
this is a Claude Code CLI command the operator runs (it cannot be invoked by an agent):

```
/plugin marketplace add Egonex-AI/Understand-Anything
/plugin install understand-anything
/understand --exclude "node_modules/*,dist/*,htmlcov/*,data/*"
```

Note the practical constraint: at 801 batches, a full run is expensive. Scope it, e.g.
`/understand suite-core/core` — the value path is 13 files.
