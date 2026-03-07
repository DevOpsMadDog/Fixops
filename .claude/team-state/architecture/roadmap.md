# ALdeci Technical Roadmap

**Last Updated**: 2026-03-07 (Run 10) by enterprise-architect
**Current Phase**: Phase 1 — Funding Ready (Post-Demo)
**Demo Date**: 2026-03-06 (Enterprise Demo) — COMPLETED
**Sprint**: Sprint 2 — Post-Demo Day 1

---

## Phase 1 — Funding Ready (Feb-Mar 2026)

### Sprint 1 (Feb 22-28) — COMPLETED (91.3%)
- [x] All 10 vision engines built (18,160 LOC)
- [x] 8 native scanners live
- [x] 12-step brain pipeline operational
- [x] MCP auto-discovery (705 tools)
- [x] AutoFix engine (10 fix types, 1,534 LOC)
- [x] Docker compose deploy

### Sprint 2 (Mar 1-6) — ENTERPRISE DEMO (11/12 done = 91.7%)
- [x] DEMO-001: Fix ALL broken API endpoints (V3) — E2E 58/58, 769 routes, 11 security fixes
- [x] DEMO-002: Postman collections GREEN (V10) — 475/475 = 100% (8th consecutive green)
- [x] DEMO-004: CTEM Full Loop Demo (V10+V5) — 36/36 steps, 5/5 phases
- [x] DEMO-005: 5 Persona Walkthrough Scripts (V3) — 5 personas documented
- [x] DEMO-006: Fix coverage config (V10) — config fixed
- [x] DEMO-007: Docker one-command demo (V9) — 34/34 health checks
- [x] DEMO-008: API Documentation (V10) — 704 endpoints documented
- [x] DEMO-009: MCP Gateway Demo (V7) — 705 tools discovered
- [x] DEMO-010: Knowledge Graph Demo (V3) — 73 nodes, 110 edges
- [x] DEMO-011: Compliance Evidence Export (V10) — RSA-SHA256 signed
- [x] DEMO-012: Self-Learning Demo (V8) — 5 feedback loops, 73 tests
- [ ] DEMO-003: Wire legacy UI to real APIs (V3) — IN PROGRESS (frontend-craftsman)

### Post-Demo Hardening (Mar 7+) — IN PROGRESS
- [x] FAIL Engine memory fix (TD-034) — MAX_HISTORY_SIZE=5000
- [x] FAIL /delete auth fix (TD-037) — org_id authorization added
- [x] FAIL batch error reporting (TD-036) — partial results + error entries
- [x] Lint fixes: F401 (trend_analyzer.py), F841 (micro_pentest_router.py)
- [x] ADR-011: FAIL Engine scoring architecture documented
- [x] Review #8: FAIL Engine + Exposure Case (Grade B+)

### Phase 1 Quality Gates
| Gate | Target | Current | Status |
|------|--------|---------|--------|
| API endpoints responding | 100% | 100% (771+ routes) | ✅ |
| Postman assertions passing | 100% | 100% (475/475) | ✅ |
| UI pages wired to real data | 95% | ~90% | ⚠️ DEMO-003 in progress |
| Test coverage | 25% (gate) | 4.65% | ❌ Config now measures ALL suites |
| Docker one-command deploy | Working | Working (34/34 health) | ✅ |
| Bandit HIGH issues | 0 | 0 HIGH | ✅ |
| Bandit MEDIUM (core) | <10 | 51 (core), 0 HIGH | ⚠️ Stable, mostly B608+B110 |
| Ruff actionable warnings | <20 | 0 actionable (77 E402 architectural) | ✅ |
| Core tests | PASS | 237/237 pass (23.82s) | ✅ Run 10 verified |
| FAIL tests | PASS | 138/138 pass (9.87s) | ✅ Run 10 verified |
| Self-learning tests | PASS | 73/73 pass | ✅ Run 10 verified |
| AutoFix tests | PASS | 556/556 pass | ✅ Run 8 verified |
| Memory leaks | Fixed | All _history/_fixes/_runs bounded | ✅ |
| XML vulnerability | Fixed | defusedxml deployed | ✅ |
| SQLite connection leaks | Fixed | history.py + deduplication.py | ✅ |

---

## Phase 2 — Design Partner (Apr-Jun 2026)

### Infrastructure
- [ ] PostgreSQL migration (from SQLite) — TD-001, TD-008
- [ ] Redis caching layer
- [ ] Async Brain Pipeline (Steps 9+10 parallel) — TD-002, TD-021
- [ ] Database migration system (Alembic) — TD-008
- [ ] Connection pooling (asyncpg/SQLAlchemy pool)
- [ ] Dedup service: single connection per batch — TD-020

### Reliability (from ADR-008)
- [ ] Circuit breakers for LLM and MPTE calls — TD-018
- [ ] Per-step timeouts in Brain Pipeline (Steps 3,5,6,7,8,11) — TD-019
- [ ] Thread-safe circuit breaker — add Lock to _AsyncCircuitBreaker
- [ ] Dead-letter queue for scanner ingest failures

### Security
- [ ] Audit 27 SQL injection vectors — TD-005 (most are false positives)
- [ ] Audit subprocess calls — TD-013
- [ ] URL scheme validation — TD-010
- [ ] Rate limiting per endpoint (basic already in place)
- [ ] CORS production hardening — TD-016

### Scoring Integration
- [ ] Integrate FAIL scoring into Brain Pipeline Step 7 — TD-035, ADR-011
- [ ] FAIL batch error reporting — TD-036 (FIXED Run 10)
- [ ] ExposureCaseManager singleton path assertion — TD-038

### Multi-Tenancy
- [ ] Org isolation (org_id scoping on all queries)
- [ ] RBAC (role-based access control)
- [ ] Webhook integrations (Slack, Jira, PagerDuty)

### Quality
- [ ] Fix 101 bare except:pass patterns — TD-004
- [ ] Test coverage → 25% (write tests for 0% modules)
- [ ] External message queue (Redis Pub/Sub) — TD-011
- [ ] Split app.py into router groups — TD-007

---

## Phase 3 — GA (Jul-Sep 2026)

### Deployment
- [ ] Kubernetes deployment (Helm charts)
- [ ] Horizontal scaling (multi-instance)
- [ ] SSO/SAML authentication
- [ ] Data retention policies
- [ ] API rate limiting + quotas (per-tenant)

### Intelligence
- [ ] AST-based SAST engine (tree-sitter) — TD-012
- [ ] GNN attack path computation
- [ ] Active learning (auto-trigger compute_adjustments)
- [ ] Per-tenant learning weights
- [ ] Case stats query optimization (materialized views)

### Compliance
- [ ] SOC2 Type II audit
- [ ] FIPS 204 ML-DSA quantum crypto (V6)
- [ ] Audit log immutability (append-only + tamper detection)
- [ ] Exposure Case SLA enforcement (automated alerts)

---

## Phase 4 — Scale (Oct 2026 - Feb 2027)

### Advanced AI
- [ ] True multi-LLM parallel consensus (V4)
- [ ] Autonomous CTEM (self-driving scan → triage → fix cycle)
- [ ] GNN-based attack path prediction
- [ ] FAIL score trend analysis (time-series scoring per CVE)

### Platform
- [ ] Multi-cloud deployment (AWS, Azure, GCP)
- [ ] Customer-managed encryption keys
- [ ] API marketplace (partner integrations)

---

## Architecture Metrics (Verified 2026-03-07, Run 10)

| Metric | Value | Change from Run 9 |
|--------|-------|--------|
| Total LOC | ~428K Python + 45K TS | +11K |
| Python suites | 6 | — |
| API endpoints | 771+ | +1 |
| Router files | 64+ | — |
| Native scanners | 8 | — |
| Inbound parsers | 15 | — |
| Outbound connectors | 7 | — |
| Security connectors | 10 | — |
| Total integration points | 32 | — |
| Brain Pipeline steps | 12 | — |
| Brain Pipeline LOC | 1,878 | Stable |
| FAIL Engine LOC | 718 | +6 (memory fix) |
| FAIL DB LOC | 256 | — |
| Exposure Case LOC | 647 | — |
| AutoFix LOC | 1,534 | Stable |
| Self-Learning LOC | 1,359 | Stable |
| MCP Server LOC | 979 | Stable |
| Core tests passing | 237/237 | ✅ Verified Run 10 (23.82s) |
| FAIL tests passing | 138/138 | ✅ Verified Run 10 (9.87s) |
| Self-learning tests | 73/73 | ✅ Verified Run 10 |
| AutoFix tests passing | 556/556 | ✅ Verified Run 8 |
| Test coverage | 4.65% | Config now measures ALL suites |
| Docker services | 8 (compose) | — |
| ADRs written | 11 | +1 (ADR-011 FAIL Engine scoring) |
| ADRs validated | 11/11 | All file refs valid |
| Tech debt items | 38 (11 done) | +5 new (FAIL review), +1 FIXED |
| Bandit (core) | 175 (0H, 51M, 124L) | Stable |
| Bandit HIGH | 0 | ✅ Stable |
| Ruff warnings | 77 (0 actionable) | ✅ Fixed F401+F841, now 77 E402 only |
| Bug fixes this run | 7 | TD-034, TD-036, TD-037, 5×F401, F841 |
| Reviews completed | 8 total | +1 (FAIL + Exposure Case B+) |

---

*Maintained by enterprise-architect. Serves all pillars.*
