# ALdeci — Acquisition-Grade Hardening Sprint

> **DIRECTIVE**: Transform ALdeci from a 6.5/10 demo-ready platform into a 9.5/10 acquisition-grade enterprise product. Every line of 296K+ LOC must be audited, hardened, and wired to production-grade infrastructure. This is NOT an MVP. This is NOT a demo. This ships to enterprise customers THIS WEEK and must survive due-diligence from acquirers (Palo Alto, CrowdStrike, Wiz, Snyk).

---

## CONTEXT — What You're Working With

### Codebase Scale (verified 2026-03-17)
| Metric | Count |
|--------|-------|
| Backend Python LOC | 248,596 |
| Frontend TS/TSX LOC | 47,883 |
| Test LOC | 232,596 |
| Backend `.py` files | 542 |
| API endpoints | 944 |
| Router files | 68 |
| Test files | 386+ |
| Tests collected | 18,065 |
| Agent definitions | 19 |
| Core engine LOC | 20,749 (15 files) |

### Architecture
- **7-Suite Monolith**: suite-api, suite-core, suite-attack, suite-feeds, suite-evidence-risk, suite-integrations, suite-ui
- **Entry point**: `suite-api/apps/api/app.py` (~2,900 LOC) — FastAPI factory with 34+ router mounts
- **Import mechanism**: `sitecustomize.py` auto-prepends all suite paths — cross-suite imports "just work"
- **Brain Pipeline**: 12-step CTEM decision engine (`brain_pipeline.py`, 2,184 LOC)
- **8 Native Scanners**: SAST, DAST, Secrets, Container, CSPM, API Fuzzer, Malware, LLM Monitor — ALL real, ALL air-gapped
- **AutoFix Engine**: 10 fix types, 1,534 LOC — CODE_PATCH, DEPENDENCY_UPDATE, CONFIG_HARDENING, IAC_FIX, SECRET_ROTATION, PERMISSION_FIX, INPUT_VALIDATION, OUTPUT_ENCODING, WAF_RULE, CONTAINER_FIX
- **MPTE**: 19-phase micro-pentest verification engine (2,054 LOC) — proves exploitability, doesn't just detect
- **Knowledge Graph**: `knowledge_brain.py` (858 LOC) + `attack_graph_gnn.py` (744 LOC) + FalkorDB/NetworkX
- **MCP Gateway**: 944 auto-discovered tools for AI agents (Copilot, Cursor, Claude Code)

### What's GOOD (Don't Break These)
- **Auth**: ~95%+ endpoints protected via `Depends(_verify_api_key)` at router mount level. JWT with 32-char minimum validation + auto-ephemeral generation. RBAC scopes (admin:all, attack:execute, read:evidence, write:integrations, write:findings)
- **Security Headers**: Full OWASP set via `SecurityHeadersMiddleware` — CSP, X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy, Permissions-Policy, Cache-Control no-store
- **Rate Limiting**: 120 req/min, burst 20 + auth-specific rate limiting on login
- **Input Validation**: 418 Pydantic BaseModel/Field usages across routers
- **Crypto**: RSA-SHA256 evidence signing (`crypto.py`, 2,614 LOC)
- **Structured Logging**: structlog throughout
- **Docker**: HEALTHCHECK on all Dockerfiles, Helm chart exists
- **CI/CD**: 10 GitHub Actions workflows (CI, CodeQL, Docker, QA, release-sign, provenance, repro-verify)
- **Real engines**: All 8 scanners, brain pipeline, autofix, MPTE, knowledge graph are REAL code — not stubs

---

## THE 9 CRITICAL DEFECTS — Fix ALL of Them

### DEFECT 1: Dual Database System (P0 — BLOCKER)
**Problem**: 185 `sqlite3.connect` calls + 42 `PersistentDict` usages vs only 37 `DatabaseManager` references. 100 `.db` files on disk. Most production data flows through raw SQLite, NOT the enterprise `DatabaseManager` (which supports PostgreSQL + connection pooling + async sessions).

**Enterprise `DatabaseManager` already exists** at `suite-core/core/db/enterprise/session.py`:
- SQLAlchemy async engine with `create_async_engine`
- QueuePool (pool_size=10, max_overflow=20, pool_pre_ping=True)
- PostgreSQL optimizations (statement_timeout, lock_timeout, idle_in_transaction_session_timeout)
- Falls back to `sqlite+aiosqlite` for local dev when `DATABASE_URL` unset
- Settings at `suite-core/config/enterprise/settings.py` (reads `DATABASE_URL` / `FIXOPS_DATABASE_URL`)
- 2 Alembic migrations exist at `suite-core/core/db/enterprise/migrations/versions/`

**Required**:
1. Audit every `sqlite3.connect` call (185 sites) — migrate to `DatabaseManager` with async sessions
2. Audit every `PersistentDict` usage (42 sites) — replace with proper SQLAlchemy models
3. Create Alembic migrations for ALL domain tables (findings, evidence, remediations, policies, assets, scan results, activity events, audit logs, tickets, SLA records, etc.)
4. Ensure ALL data persists through PostgreSQL in production, SQLite only as fallback for local dev
5. Add database health check endpoint that reports pool stats, connection count, latency
6. Implement proper transaction boundaries — no implicit autocommit
7. Add database backup/restore scripts for production

**Do NOT**:
- Break the SQLite fallback for local development
- Remove `PersistentDict` without migrating its data
- Create a migration that can't run on both SQLite and PostgreSQL

### DEFECT 2: Multi-Tenancy Gaps (P0 — BLOCKER)
**Problem**: Only 15/68 routers (22%) enforce `org_id` filtering. A tenant can access other tenants' data on 78% of endpoints.

**Required**:
1. Add `org_id` column to every domain table (findings, evidence, assets, remediations, policies, scans, etc.)
2. Create a `get_current_org(request)` dependency that extracts org_id from JWT claims
3. Create middleware or dependency that auto-filters ALL database queries by org_id
4. Audit all 68 routers — every data-returning endpoint MUST filter by org_id
5. Add org_id to all INSERT operations
6. Create integration test: create data as Org A, verify Org B cannot see it
7. Admin endpoints (`admin:all` scope) can cross org boundaries — this is intentional

**Pattern to implement**:
```python
async def get_current_org(request: Request) -> str:
    """Extract org_id from JWT claims. Every data endpoint depends on this."""
    token = request.state.user  # Set by auth middleware
    org_id = token.get("org_id")
    if not org_id:
        raise HTTPException(403, "No organization context")
    return org_id

# Every router:
@router.get("/findings")
async def list_findings(org_id: str = Depends(get_current_org)):
    return await db.query(Finding).filter(Finding.org_id == org_id).all()
```

### DEFECT 3: Error Handling — 1,477 Bare `except Exception` (P1)
**Problem**: 1,477 bare `except Exception` across the entire backend. This swallows security events, masks bugs, makes incident response impossible.

**Required**:
1. Audit every `except Exception` — categorize into:
   - **Replace**: Use specific exception types (ValueError, KeyError, ConnectionError, TimeoutError, SQLAlchemyError, etc.)
   - **Keep but log**: Where generic catch is unavoidable (top-level handlers), add `structlog.get_logger().exception("...", exc_info=True)`
   - **Remove**: Where the try/except is unnecessary
2. Create custom exception hierarchy:
   ```python
   class ALdeciError(Exception): ...
   class DatabaseError(ALdeciError): ...
   class ScannerError(ALdeciError): ...
   class AuthorizationError(ALdeciError): ...
   class TenantIsolationError(ALdeciError): ...
   class PipelineError(ALdeciError): ...
   ```
3. Add global exception handler in `app.py` that:
   - Logs with full context (correlation_id, user_id, org_id, endpoint)
   - Returns sanitized error to client (no stack traces in production)
   - Emits metrics for error tracking
4. Target: <100 bare `except Exception` remaining (essential top-level handlers only)

### DEFECT 4: SQL Injection Surface — 39 f-string SQL (P1)
**Problem**: 39 f-string SQL statements. While most parameterize user values with `?`, column names and table names are injected via f-string.

**Required**:
1. Audit all 39 f-string SQL sites
2. Replace with SQLAlchemy ORM queries or parameterized text() queries
3. For dynamic column selection: use an allowlist of valid column names
   ```python
   VALID_SORT_COLUMNS = {"created_at", "severity", "status", "title"}
   if sort_col not in VALID_SORT_COLUMNS:
       raise ValueError(f"Invalid sort column: {sort_col}")
   ```
4. Zero f-string SQL remaining after this sprint

### DEFECT 5: Test Suite — 9 Collection Errors, Coverage Below Gate (P1)
**Problem**: 9 test files fail to collect (ImportError). Test coverage at ~19%, below 25% gate.

**Broken files**:
- tests/test_advanced_llm_engine_coverage.py
- tests/test_cache_service_coverage.py
- tests/test_correlation_engine_coverage.py
- tests/test_decision_engine_coverage.py
- tests/test_enhanced_decision_engine_coverage.py
- tests/test_evidence_export_coverage.py
- tests/test_metrics_enterprise_coverage.py
- tests/test_policy_engine_coverage.py
- tests/test_rl_controller_coverage.py

**Required**:
1. Fix all 9 collection errors (likely missing imports or modules)
2. Add integration tests for EVERY P0 fix (database migration, multi-tenancy isolation)
3. Add security-focused tests:
   - Tenant isolation tests (Org A can't see Org B data)
   - Auth bypass tests (unauthenticated access returns 401/403)
   - SQL injection tests (malicious input doesn't break queries)
   - Rate limit tests (429 after limit exceeded)
4. Raise coverage to 30%+ (target: 35%)
5. 0 test collection errors
6. All tests pass with `PYTHONPATH=suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations:.`

### DEFECT 6: CORS Over-Permissiveness (P2)
**Problem**: `allow_methods=["*"]`, `allow_headers=["*"]` in `app.py` line 949-952.

**Required**:
```python
allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
allow_headers=[
    "Authorization", "Content-Type", "X-API-Key", "X-Request-ID",
    "X-Correlation-ID", "Accept", "Origin", "Cache-Control",
],
```

### DEFECT 7: No LICENSE File (P2 — Legal Blocker)
**Problem**: No LICENSE, EULA, or TERMS file. Commercial deployment without license = legal liability.

**Required**: Create appropriate license file (commercial/proprietary EULA for enterprise product).

### DEFECT 8: Knowledge Graph Not Fully Wired (P1)
**Problem**: Knowledge graph engines exist (`knowledge_brain.py`, `attack_graph_gnn.py`, `knowledge_graph_router.py`, FalkorDB service) but the 250K+ LOC codebase itself isn't analyzed as a knowledge graph. The graph should map:
- Every file → every function → every endpoint → every database table → every external call
- Vulnerability findings → affected code paths → attack surfaces → remediation options
- Dependencies → CVEs → EPSS scores → exploitability → blast radius

**Required**:
1. Build a codebase knowledge graph that indexes:
   - All 542 Python files, their classes, functions, imports, dependencies
   - All 944 endpoints, their auth requirements, input schemas, database queries
   - All 100 database tables/files, their schemas, relationships
   - All external API calls, webhook endpoints, integration points
2. Store in FalkorDB (or NetworkX as fallback) with proper entity types:
   - `File`, `Class`, `Function`, `Endpoint`, `Table`, `Integration`, `Scanner`, `Finding`, `Vulnerability`
3. Enable graph queries: "What endpoints are affected by CVE-X?", "What's the blast radius of this dependency?", "Show me all code paths from user input to database query"
4. Wire to brain pipeline step 5 (BUILD GRAPH) — enrich every finding with graph context
5. Expose via `/api/v1/knowledge-graph/` endpoints:
   - `GET /query` — Cypher/natural language graph queries
   - `GET /blast-radius/{finding_id}` — impact analysis
   - `GET /attack-paths/{asset_id}` — reachable attack paths
   - `GET /dependency-tree/{package}` — transitive dependency analysis

### DEFECT 9: Production Observability Missing (P1)
**Problem**: No APM, no distributed tracing, no metrics export, no alerting rules.

**Required**:
1. Add OpenTelemetry instrumentation:
   - Traces on every endpoint (auto-instrumented via FastAPI middleware)
   - Spans for database queries, external API calls, scanner executions
   - Metrics: request latency (p50/p95/p99), error rate, active connections, scan duration
2. Add Prometheus `/metrics` endpoint
3. Add structured audit log for security events:
   - Login attempts (success/failure)
   - Permission escalation attempts
   - Cross-tenant access attempts
   - Scanner execution starts/completions
   - AutoFix applications
4. Health endpoint enhancement: `/api/v1/health/deep` that checks:
   - Database connectivity + pool stats
   - Redis connectivity
   - FalkorDB connectivity
   - Scanner engine health
   - Certificate expiry
   - Disk space for evidence storage

---

## COMPETITIVE MOAT — What Makes ALdeci Unbeatable

### Why This Beats Apiiro, Aikido, Snyk, Wiz, and Everyone Else

| Capability | Apiiro | Aikido | Snyk | Wiz | **ALdeci** |
|-----------|--------|--------|------|-----|-----------|
| Native SAST/DAST/Secrets/Container/CSPM | No (integrates) | Partial | Partial | Cloud only | **8 scanners, all air-gapped** |
| Decision Intelligence (not just detection) | Risk scoring | Basic | No | No | **12-step Brain Pipeline + Multi-LLM Consensus** |
| Prove exploitability (not just detect) | No | No | No | No | **MPTE 19-phase micro-pentest** |
| Auto-fix code | No | Basic | Basic (1 type) | No | **10 fix types with confidence grading** |
| Knowledge Graph (code → vulns → blast radius) | Yes (their moat) | No | No | Cloud graph | **Full codebase KG + attack paths + GNN** |
| AI Agent Platform (MCP) | No | No | No | No | **944 auto-discovered tools** |
| Air-gapped / on-prem | No | No | No | No | **Full offline, <1GB/year storage** |
| Quantum-secure evidence | No | No | No | No | **FIPS 204 ML-DSA + RSA hybrid** |
| CTEM full loop with crypto proof | No | No | No | No | **Discover → Validate → Remediate → Comply with signed evidence** |

### The Moats to Harden (Make These Unreplicable)

1. **Brain Pipeline Depth**: The 12-step pipeline (CONNECT→NORMALIZE→RESOLVE→DEDUPLICATE→GRAPH→ENRICH→SCORE→POLICY→CONSENSUS→PENTEST→AUTOFIX→EVIDENCE) is our core IP. Each step should produce auditable, signed output. No competitor has this complete a decision chain.

2. **Knowledge Graph + GNN**: Build the richest security knowledge graph in the industry. Every finding, every code path, every dependency, every attack surface — all connected. This is what made Apiiro worth $1B. Ours covers BOTH code AND runtime AND infrastructure.

3. **MPTE Verification**: No other tool PROVES exploitability. They all say "high severity" and leave the human to figure out if it's real. We run micro-pentests. Harden this engine — make it deterministic, reproducible, and evidence-producing.

4. **Multi-LLM Consensus**: 3+ LLMs must agree with 85% threshold before any automated decision. This is defensible AI — not "GPT wrapper" that fails when one model hallucinates.

5. **Air-Gapped Everything**: Every capability works with ZERO internet. This alone opens government, defense, financial services. No competitor can do this.

6. **MCP-Native**: First AppSec platform that AI agents can programmatically consume. 944 tool endpoints auto-discovered. Every other platform requires human GUI interaction.

---

## EXECUTION PLAN — Phase-by-Phase

### Phase 1: Data Foundation (Database + Multi-Tenancy)
**Agents**: backend-hardener, enterprise-architect
**Scope**: DEFECT 1 + DEFECT 2
**Output**:
- All 185 `sqlite3.connect` migrated to `DatabaseManager`
- All 42 `PersistentDict` replaced with SQLAlchemy models
- Alembic migrations for all domain tables
- org_id on every table, every query filtered
- Integration test: cross-tenant isolation verified

### Phase 2: Security Hardening (Errors + SQL + CORS)
**Agents**: security-analyst, backend-hardener
**Scope**: DEFECT 3 + DEFECT 4 + DEFECT 6 + DEFECT 7
**Output**:
- 1,477 → <100 bare `except Exception`
- 39 → 0 f-string SQL
- CORS restricted to explicit methods/headers
- LICENSE file created
- Custom exception hierarchy

### Phase 3: Knowledge Graph Deep Build
**Agents**: data-scientist, threat-architect, enterprise-architect
**Scope**: DEFECT 8
**Output**:
- Full codebase knowledge graph (542 files, 944 endpoints, 100 tables indexed)
- Attack path analysis from code → vulnerability → blast radius
- FalkorDB persistence with NetworkX fallback
- Graph query API endpoints live
- Brain pipeline step 5 enriched with graph context

### Phase 4: Test & Observability
**Agents**: qa-engineer, devops-engineer
**Scope**: DEFECT 5 + DEFECT 9
**Output**:
- 0 test collection errors
- Coverage 30%+
- Tenant isolation tests
- OpenTelemetry instrumentation
- Prometheus metrics endpoint
- Deep health check endpoint

### Phase 5: Engine Hardening & Polish
**Agents**: All agents — final sweep
**Scope**: Harden every engine to production quality
**Output**:
- Brain pipeline: every step produces signed evidence
- MPTE: deterministic, reproducible, evidence-producing
- AutoFix: confidence calibration verified against real fixes
- Knowledge Graph: query performance <500ms for any graph traversal
- All 944 endpoints: input validated, output sanitized, auth enforced, org_id filtered, errors handled

### Phase 6: Acquisition Readiness
**Agents**: technical-writer, marketing-head, enterprise-architect
**Scope**: Due-diligence preparation
**Output**:
- Architecture documentation with data flow diagrams
- Security audit report (self-assessment)
- API documentation (OpenAPI + narrative)
- Compliance mapping (SOC2, PCI-DSS, HIPAA, FedRAMP controls)
- Performance benchmarks (requests/sec, scan throughput, graph query latency)
- Competitive analysis positioning document
- IP inventory (patents, unique algorithms, trade secrets)

---

## RULES OF ENGAGEMENT

1. **Every change must compile and pass tests.** No partial migrations. No broken imports. No "TODO: fix later".

2. **Every database migration must be reversible.** Alembic up AND down. Test both directions.

3. **Never break the air-gapped mode.** All 8 scanners, brain pipeline, and knowledge graph must work with ZERO internet.

4. **Never break existing auth.** The ~95% coverage must stay at 95%+. Do not remove `Depends(_verify_api_key)` from any router mount.

5. **Log EVERYTHING security-relevant.** Every auth failure, every cross-tenant attempt, every scanner execution, every AutoFix application — structured log with correlation_id.

6. **Measure before and after.** Before ANY phase, record: test count, pass rate, coverage %, endpoint count, error count. After: same metrics. Regression = rollback.

7. **No new SQLite files.** All new data goes through `DatabaseManager`. Period.

8. **No new bare `except Exception`.** Use typed exceptions or log with full context.

9. **No new f-string SQL.** Use SQLAlchemy ORM or parameterized queries only.

10. **Every new endpoint gets**: auth dependency, org_id filter, Pydantic input validation, typed exception handling, structured logging, and a test.

---

## SUCCESS CRITERIA — Definition of Done

The product is acquisition-grade when ALL of the following are true:

- [ ] 0 `sqlite3.connect` calls in production code (only in fallback/test paths)
- [ ] 0 `PersistentDict` in production code
- [ ] 100% of data-returning endpoints enforce org_id tenant isolation
- [ ] <100 bare `except Exception` (from 1,477)
- [ ] 0 f-string SQL statements
- [ ] 0 test collection errors (from 9)
- [ ] Test coverage ≥30%
- [ ] All 18,065+ tests pass
- [ ] Knowledge graph indexes all 542 files, 944 endpoints, 100 tables
- [ ] Graph query API responds in <500ms
- [ ] OpenTelemetry traces on all endpoints
- [ ] Prometheus `/metrics` endpoint live
- [ ] Deep health check covers DB + Redis + FalkorDB + scanners
- [ ] CORS restricted to explicit methods/headers
- [ ] LICENSE file present
- [ ] Architecture documentation complete
- [ ] Security self-assessment document complete
- [ ] `docker compose up` starts fully functional system with PostgreSQL
- [ ] Air-gapped mode verified (no external network calls required)
- [ ] All 8 native scanners produce real results on test code
- [ ] Brain pipeline processes finding end-to-end with signed evidence at each step
- [ ] MPTE runs micro-pentest on real vulnerability and produces reproducible evidence
- [ ] AutoFix generates and applies code patch with confidence grading

---

## AGENT INSTRUCTIONS

### For ALL Agents:
Read these files FIRST before any work:
1. `docs/CEO_VISION.md` — The north star
2. `docs/VISION_TO_ACCOMPLISH.MD` — Complete build specifications
3. `docs/CTEM_PLUS_IDENTITY.md` — Scanner/AutoFix/pipeline reference
4. `CLAUDE.md` — Project structure and conventions
5. `.github/copilot-instructions.md` — Architecture and patterns
6. This file (`ACQUISITION_GRADE_PROMPT.md`) — The defects and success criteria

### For context-engineer:
Build the codebase knowledge graph FIRST. Map every file, every function, every endpoint, every database call. Store in `.claude/team-state/codebase-knowledge-graph.json`. Every other agent reads this before working.

### For backend-hardener:
You own DEFECT 1 (database), DEFECT 3 (errors), DEFECT 4 (SQL). Start with database migration — it's the foundation everything else depends on.

### For security-analyst:
You own DEFECT 2 (multi-tenancy), DEFECT 6 (CORS), DEFECT 7 (LICENSE). Verify auth coverage hasn't regressed. Run SAST scan on the codebase itself using our own engine.

### For qa-engineer:
You own DEFECT 5 (tests). Fix collection errors FIRST, then add tenant isolation tests, then raise coverage.

### For data-scientist:
You own DEFECT 8 (knowledge graph). Build the deepest security knowledge graph in the industry. Make it queryable, visualizable, and integrated with the brain pipeline.

### For devops-engineer:
You own DEFECT 9 (observability). OpenTelemetry, Prometheus, deep health checks. Also ensure `docker compose up` wires PostgreSQL + Redis + FalkorDB.

### For enterprise-architect:
Review every architectural decision. Ensure the database migration doesn't introduce inconsistencies. Sign off on the knowledge graph schema. Validate the multi-tenancy pattern.

### For threat-architect:
Feed REAL vulnerability data through the pipeline. Test with actual CVEs, actual SBOM scans, actual container images. The product must demonstrate real-world value, not synthetic demos.

### For frontend-craftsman:
Wire the UI to the new knowledge graph endpoints. Add graph visualization for attack paths. Ensure the 5 Workflow Spaces (Mission Control, Discover, Validate, Remediate, Comply) all show real data from the hardened backend.

### For technical-writer:
Document EVERYTHING for due-diligence. Architecture, API, security model, compliance mappings, deployment guide. This documentation IS the product for acquirers.

---

## THE STANDARD

This product will be evaluated by:
1. **Enterprise security teams** with 10,000+ developers who need CTEM
2. **Acquisition teams** from Palo Alto, CrowdStrike, Wiz, Snyk looking for their next $1B+ buy
3. **Auditors** running penetration tests and code reviews against our platform
4. **CISO's** who need to justify budget to their board

Every line of code must be worthy of that scrutiny. Ship accordingly.
