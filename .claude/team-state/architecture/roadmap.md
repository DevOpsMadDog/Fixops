# ALdeci Technical Roadmap

**Last Updated**: 2026-03-02 by enterprise-architect
**Current Phase**: Phase 1 — Funding Ready
**Demo Date**: 2026-03-06 (Enterprise Demo)

---

## Phase 1 — Funding Ready (Feb-Mar 2026)

### Sprint 1 (Feb 22-28) — COMPLETED ✅ (91.3%)
- [x] All 10 vision engines built (18,160 LOC)
- [x] 8 native scanners live
- [x] 12-step brain pipeline operational
- [x] MCP auto-discovery (705 tools)
- [x] AutoFix engine (10 fix types, 1,259 LOC)
- [x] Docker compose deploy

### Sprint 2 (Mar 1-6) — ENTERPRISE DEMO ⏳ (9/12 done)
- [x] DEMO-004: CTEM Full Loop Demo (V10+V5) — 36/36 steps ✅
- [x] DEMO-005: 5 Persona Walkthrough Scripts (V3) ✅
- [x] DEMO-006: Fix coverage config (V10) ✅
- [x] DEMO-007: Docker one-command demo (V9) — 34/34 health checks ✅
- [x] DEMO-008: API Documentation (V10) — 704 endpoints documented ✅
- [x] DEMO-009: MCP Gateway Demo (V7) — 705 tools discovered ✅
- [x] DEMO-010: Knowledge Graph Demo (V3) — 73 nodes, 110 edges ✅
- [x] DEMO-011: Compliance Evidence Export (V10) — RSA-SHA256 signed ✅
- [x] DEMO-012: Self-Learning Demo (V8) — 5 feedback loops, 73 tests ✅
- [ ] DEMO-001: Fix ALL broken API endpoints (V3) — P0 BLOCKER
- [ ] DEMO-002: Postman collections GREEN (V10) — 84.7% → 100%
- [ ] DEMO-003: Wire legacy UI to real APIs (V3) — P0 BLOCKER

### Phase 1 Quality Gates
| Gate | Target | Current | Status |
|------|--------|---------|--------|
| API endpoints responding | 100% | ~95% | ⚠️ DEMO-001 |
| Postman assertions passing | 100% | 84.7% | ⚠️ DEMO-002 |
| UI pages wired to real data | 95% | ~50% | ⚠️ DEMO-003 |
| Test coverage | 25% (gate) | 19.19% | ❌ Below gate |
| Docker one-command deploy | Working | ✅ Working | ✅ |
| Bandit HIGH issues | 0 | 0 HIGH | ✅ |
| Bandit total issues | <50 | 194 (mostly LOW) | ⚠️ |

---

## Phase 2 — Design Partner (Apr-Jun 2026)

### Infrastructure
- [ ] PostgreSQL migration (from SQLite) — TD-001, TD-008
- [ ] Redis caching layer
- [ ] Async Brain Pipeline (Steps 9+10 parallel) — TD-002
- [ ] Database migration system (Alembic) — TD-008

### Security
- [ ] Fix 26 SQL injection vectors — TD-005
- [ ] Audit subprocess calls — TD-013
- [ ] URL scheme validation — TD-010
- [ ] Rate limiting per endpoint

### Multi-Tenancy
- [ ] Org isolation (org_id scoping on all queries)
- [ ] RBAC (role-based access control)
- [ ] Webhook integrations (Slack, Jira, PagerDuty)

### Quality
- [ ] Fix 89 bare except:pass patterns — TD-004
- [ ] Test coverage 25% → 60%
- [ ] External message queue (Redis Pub/Sub) — TD-011
- [ ] Split app.py into router groups — TD-007

---

## Phase 3 — GA (Jul-Sep 2026)

### Deployment
- [ ] Kubernetes deployment (Helm charts)
- [ ] Horizontal scaling (multi-instance)
- [ ] SSO/SAML authentication
- [ ] Data retention policies
- [ ] API rate limiting + quotas

### Intelligence
- [ ] AST-based SAST engine (tree-sitter) — TD-012
- [ ] GNN attack path computation
- [ ] Active learning (auto-trigger compute_adjustments)
- [ ] Per-tenant learning weights

### Compliance
- [ ] SOC2 Type II audit
- [ ] FIPS 204 ML-DSA quantum crypto (V6)
- [ ] Audit log immutability (append-only + tamper detection)

---

## Phase 4 — Scale (Oct 2026 - Feb 2027)

### Advanced AI
- [ ] True multi-LLM parallel consensus (V4)
- [ ] Autonomous CTEM (self-driving scan → triage → fix cycle)
- [ ] GNN-based attack path prediction

### Platform
- [ ] Multi-cloud deployment (AWS, Azure, GCP)
- [ ] Customer-managed encryption keys
- [ ] API marketplace (partner integrations)

---

## Architecture Metrics (Verified 2026-03-02)

| Metric | Value |
|--------|-------|
| Total LOC | ~790K |
| Python suites | 6 |
| API endpoints | 759 |
| Router files | 64 |
| Native scanners | 8 |
| Inbound parsers | 15 |
| Outbound connectors | 7 |
| Security connectors | 10 |
| Total integration points | 32 |
| Brain Pipeline steps | 12 |
| AutoFix types | 10 |
| Self-Learning loops | 5 |
| Tests collected | 10,356 |
| Test coverage | 19.19% |
| Docker services | 8 (compose) |
| ADRs written | 6 |
| Tech debt items | 14 |
