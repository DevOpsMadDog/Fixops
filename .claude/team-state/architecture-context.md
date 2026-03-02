# ALdeci Architecture Context

> **Generated**: 2026-03-02 (v24.0 scan) by context-engineer
> **Version**: 24.0 (878 files, 366,177 LOC, 759 endpoints, 19.19% coverage)
> **Sprint**: 2 — ENTERPRISE DEMO (4 days to 2026-03-06)
> **Pillars**: V3 (Decision Intelligence), V5 (MPTE), V7 (MCP-Native)

---

## 1. System Architecture Overview [V3/V5/V7]

ALdeci is a **modular monolith** — 6 Python suites mounted on a single FastAPI application process (port 8000). All cross-suite imports work via `sitecustomize.py` which auto-prepends suite directories to `sys.path`.

```
┌─────────────────────────────────────────────────────────────┐
│                    FastAPI Gateway (port 8000)                │
│                  suite-api/apps/api/app.py                   │
│                   2,742 LOC | 34 router mounts               │
│                   759 total endpoints (687+47+25)            │
├─────────┬──────────┬──────────┬──────────┬──────────┬────────┤
│suite-api│suite-core│suite-atk │suite-feed│suite-evid│suite-int│
│ 22.1K   │ 130.2K   │  6.3K    │  4.4K    │ 20.3K    │  6.7K  │
│ 20 rtrs │ 21 rtrs  │ 12 rtrs  │  1 rtr   │  5 rtrs  │  5 rtrs│
└─────────┴──────────┴──────────┴──────────┴──────────┴────────┘
                              │
              sitecustomize.py (sys.path injection)
                              │
┌──────────────────────────────────────────────────────────────┐
│                   SQLite WAL (56 .db files)                   │
│              data/ | .fixops_data/ | suite-api/data/          │
└──────────────────────────────────────────────────────────────┘
```

### Key Characteristics
- **Single process**: No message queue, no microservice boundaries
- **SQLite WAL**: 56 domain-specific `.db` files, no shared schema
- **No migration system**: Schema managed by engine code
- **In-process EventBus**: `core/event_bus.py` for cross-module events
- **Air-gap ready**: Zero mandatory external dependencies (V9)

---

## 2. Data Flow: Ingestion → Analysis → Decision → Remediation [V3]

```
External Sources          Internal Pipeline              Outputs
─────────────────    ──────────────────────────    ──────────────────
NVD/KEV/EPSS/OSV ──→ FeedsService (4,353 LOC) ──→ feeds.db
SAST scan results ──→ sast_engine.py (1,577 LOC)──→ ┐
DAST scan results ──→ dast_engine.py (533 LOC) ──→ ├→ Brain Pipeline (1,161 LOC, 12 steps)
Secrets detection ──→ secrets_scanner (845 LOC) ──→│    ├→ Step 1: Normalize findings
Container scans   ──→ container_scanner (410 LOC)──→│    ├→ Step 2-3: Deduplicate + correlate
CSPM analysis     ──→ cspm_engine.py (586 LOC) ──→ │    ├→ Step 4-5: Enrich + classify
API fuzz results  ──→ api_fuzzer_router (55 LOC)──→│    ├→ Step 6: FAIL scoring (713 LOC)
Malware detection ──→ malware_router (58 LOC) ──→  │    ├→ Step 7: Knowledge graph (836 LOC)
LLM monitor       ──→ llm_monitor_router (64 LOC)─┘    ├→ Step 8: Attack paths (networkx)
3rd-party scanners──→ scanner_parsers (1,088 LOC)──→    ├→ Step 9: Prioritize
                      scanner_ingest_router (387 LOC)    ├→ Step 10: AutoFix (1,259 LOC)
                                                        ├→ Step 11: Evidence bundle
                                                        └→ Step 12: Compliance verification
                                                              │
                                                              ▼
                                    ┌───────────────────────────────────┐
                                    │ MPTE Verification [V5]             │
                                    │ micro_pentest.py (2,054 LOC)       │
                                    │ 19-phase exploitability proof       │
                                    │ sandbox_verifier.py (1,029 LOC)    │
                                    └─────────────┬─────────────────────┘
                                                  ▼
                                    ┌───────────────────────────────────┐
                                    │ Remediation                        │
                                    │ AutoFix Engine (1,259 LOC, 10 types)│
                                    │ Connectors: Jira, GitHub, Slack    │
                                    │ Evidence: crypto-signed bundles    │
                                    └───────────────────────────────────┘
```

---

## 3. Core Pillar Architectures

### V3 — Decision Intelligence (Grade: A, ~6,820 LOC) [V3]

| Component | File | LOC | Purpose |
|-----------|------|-----|---------|
| Brain Pipeline | `core/brain_pipeline.py` | 1,000 | 12-step CTEM decision pipeline (+75 from v7.0) |
| FAIL Engine | `core/fail_engine.py` | 713 | $FACT→$ASSESS→$IMPACT→$LIKELIHOOD scoring |
| AutoFix Engine | `core/autofix_engine.py` | 1,259 | LLM-powered auto-remediation (10 fix types) |
| FalkorDB Client | `core/falkordb_client.py` | 835 | Knowledge graph + attack path analysis |
| Exposure Case | `core/exposure_case.py` | 646 | Triage case management |
| Enhanced Decision | `core/enhanced_decision.py` | 1,279 | Advanced decision engine |
| Scanner Parsers | `core/scanner_parsers.py` | 1,088 | 15 third-party scanner normalizers |
| Feeds Service | `suite-feeds/` | 4,347 | 8-category threat intelligence |

### V5 — MPTE Verification (Grade: A, ~5,235 LOC) [V5]

| Component | File | LOC | Purpose |
|-----------|------|-----|---------|
| Micro Pentest | `core/micro_pentest.py` | 2,054 | Core exploitation proof engine |
| MPTE Router | `attack/api/mpte_router.py` | 1,063 | 21 endpoints including 19-phase verification (+103 from v7.0) |
| MPTE Advanced | `core/mpte_advanced.py` | 1,089 | Advanced exploitation techniques |
| Sandbox Verifier | `core/sandbox_verifier.py` | 1,029 | Docker sandbox PoC verification |
| MPTE Client | `integrations/mpte_client.py` | 386 | MPTE integration client |

### V7 — MCP-Native Platform (Grade: B+, ~2,628 LOC) [V7]

| Component | File | LOC | Purpose |
|-----------|------|-----|---------|
| MCP Server | `core/mcp_server.py` | 979 | Full MCP 2025 JSON-RPC server |
| Auto-Discovery | `apps/api/mcp_router.py` | 977 | Introspects all FastAPI routes → tool catalog |
| Original MCP | `integrations/api/mcp_router.py` | 468 | Original server with 10 endpoints |
| MCP Protocol | `core/api/mcp_protocol_router.py` | — | Protocol-level router, 8 endpoints |

---

## 4. Integration Points

### External Integrations (all optional)
| Integration | Connector | Purpose |
|------------|-----------|---------|
| Jira | `connectors.py` (3,005 LOC) | Ticket creation from findings |
| GitHub | `connectors.py` | Issue/PR creation |
| Slack | `connectors.py` | Alert notifications |
| MindsDB | `mindsdb_router.py` | ML predictions |
| FalkorDB | `falkordb_client.py` | Knowledge graph |
| OpenAI/Anthropic | `llm_router.py` | LLM analysis |
| Trivy/Grype | `oss_tools.py` | SCA scanning |

### Internal Integration Patterns
1. **EventBus** (`core/event_bus.py`): In-process pub/sub for cross-module events
2. **PersistentDict**: SQLite-backed key-value store pattern used by most engines
3. **Router mount**: `app.include_router()` for all 34 router modules
4. **sitecustomize.py**: Auto-import mechanism (fragile but functional)
5. **Scanner Parsers**: `scanner_parsers.py` — 15 normalizers for universal ingestion

---

## 5. Security Model

### Authentication
- **API Key**: `X-API-Key` header → `_verify_api_key()` middleware
- **JWT Tokens**: `FIXOPS_JWT_SECRET` → `auth_router.py` (4 endpoints)
- **RBAC**: Teams/Users/Roles model in `teams_router.py` + `users_router.py`

### Cryptographic Evidence [V10]
- **RSA-SHA256**: `crypto.py` (570 LOC) — evidence bundle signing
- **Quantum-ready**: `quantum_crypto.py` (666 LOC) — FIPS 204 ML-DSA hybrid (V6, deferred)

### Rate Limiting
- Configurable via `FIXOPS_DISABLE_RATE_LIMIT` env var
- Applied at middleware level in `app.py`

---

## 6. Deployment Topology

### Development
```bash
python -m uvicorn apps.api.app:create_app --factory --port 8000
cd suite-ui/aldeci && npm run dev  # Port 3001
```

### Docker
```bash
docker compose -f docker/docker-compose.yml up
# Services: fixops (API :8000), aldeci-ui (:3001), fixops-feeds (cron)
```

### Kubernetes
- Helm chart: `docker/kubernetes/fixops-6suite/`
- Templates: 7 (one per suite + ingress)
- Values: `values.yaml` for all configuration

### Air-Gapped [V9]
- Zero external dependencies required
- All 8 scanners are built-in fallback engines
- SQLite for all storage (no PostgreSQL/Redis required)
- Zero-Gravity data aging: `zero_gravity.py` (857 LOC)

---

## 7. Key Metrics (2026-03-01 v12.0)

| Metric | Value | Delta from v11.0 |
|--------|-------|------------------|
| Python Files | 821 | unchanged |
| Python LOC | 331,019 | +61 (suite-core) |
| Test Files | 298 | unchanged |
| Test LOC | 125,976 | unchanged |
| Tests Collected | 7,449 | unchanged |
| Test Coverage | 16.99% | PLATEAUED x6 |
| Coverage Gate | 40% | FAILING |
| API Endpoints | 704 | unchanged (634 router + 47 non-standard + 23 @app) |
| Router Files | 64 | unchanged |
| Router Mounts | 34 | unchanged |
| SQLite DBs | 53 | unchanged |
| CLI Commands | 22 | unchanged |
| Sprint Progress | 21/23 done | 91.3% complete |
| Vision Alignment | 0.72 | STABLE |
| Legacy UI | 85 source files, 26,219 LOC | unchanged |
| Connectors | 17 (7 integration + 10 security) | unchanged |

---

## 8. Known Architectural Concerns

1. **Test coverage at 16.99%** — Below 40% gate, CI failing. QA engineer active. Stable from v7.0.
2. **New UI missing** — `suite-ui/aldeci-ui-new/` doesn't exist. Legacy UI at 25,954 LOC is frozen.
3. **Single-process monolith** — No horizontal scaling. OK for demo/POC phase.
4. **No external message queue** — EventBus is in-process only. Will need upgrade for scale.
5. **Brain pipeline synchronous** — O(n²) at graph step, LLM calls block the event loop.
6. **53 SQLite DBs with no migration** — Schema drift risk. No versioning.
7. **sitecustomize.py fragility** — Any import order change could break cross-suite imports.

---

## 9. Honesty Corrections Applied (P0 Moat Mission) [V10/V11]

| Claim | Original Status | v11.0 Corrected Status |
|-------|----------------|----------------------|
| Connector count | "17 connectors" (was corrected to 7 in v10.0) | **17 IS CORRECT**: 7 integration (connectors.py) + 10 security tool (security_connectors.py). v10.0 correction was over-aggressive — only examined connectors.py, missed security_connectors.py (1,335 LOC). |
| SAST description | "AST-based static analysis" | Regex-based pattern matching (16 rules, air-gapped). NOTE: ide_router.py and reachability/call_graph.py DO use real Python `ast` module for different purposes. |
| AutoFix description | "AST-based remediation" | LLM-powered code generation (10 fix types) — actually STRONGER than AST-based |
| Secrets scanner | "20+ entropy/regex patterns" | gitleaks/trufflehog wrapper with air-gapped fallback |
| Integration math | "675+ integration points" | 17 connectors + 8 native scanners + 665 MCP tools (auto-discovered) = 690 integration points |

**Status**: All claims now verified accurate. The "17 connectors" claim (including in frozen UI Integrations.tsx:381) is CORRECT.

---

*Maintained by context-engineer. Full codebase map: `.claude/team-state/codebase-map.json`*
