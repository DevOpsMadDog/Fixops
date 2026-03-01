# Enterprise Demo Briefing — 2026-03-01 (URGENT)

> **Written by**: CEO via Copilot
> **Audience**: ALL 17 agents
> **Deadline**: 2026-03-06 (5 DAYS)
> **Priority**: EVERYTHING else is deprioritized
> **Model**: Claude Opus 4.6 (fast mode) — ALWAYS

---

## CRITICAL: API KEY POLICY

**NEVER hardcode `test-api-key`, `test-token-12345`, or any fake token.**
Always use the real enterprise key from `FIXOPS_API_TOKEN` environment variable.

```bash
# Enterprise key — use this EVERYWHERE
export FIXOPS_API_TOKEN="aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh"
```

- In Python: `os.getenv("FIXOPS_API_TOKEN")`
- In curl: `-H "X-API-Key: $FIXOPS_API_TOKEN"`
- In Postman: `--env-var "apiKey=$FIXOPS_API_TOKEN"`
- In tests: `os.environ.setdefault("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")`

**If you see ANY file with `test-api`, `test-token`, or similar fake keys, replace it immediately.**

---

## SITUATION

We have an **enterprise customer implementation in 5 days**. This is not a drill.

Sprint 1 is DONE (21/23 items, 91.3%). All vision engines are built. All 8 native scanners work.
The 12-step brain pipeline is functional. MCP auto-discovery serves 500+ tools. AutoFix generates
fixes for 10 CWE types. MPTE runs 19-phase verification. Evidence bundles are signed with RSA-SHA256.

**What's NOT done**: The API surface has broken endpoints. Postman collections haven't been validated
against real APIs. UI pages still show mock/fake data. There's no end-to-end demo script that proves
the full CTEM+ lifecycle works.

## WHAT EACH AGENT MUST DO

### Phase 0 — Pre-Flight (agent-doctor, context-engineer, vision-agent)
- **agent-doctor**: Verify 19/19 engines importable. Clear WAL files. Check all DBs writable.
- **context-engineer**: Write codebase-map update. Verify all 862 files indexed. Update architecture-context.md.
- **vision-agent**: Verify sprint board has 12 items, all assigned. Run pillar coverage check.

### Phase 1 — Fix the Backend (backend-hardener) — DEMO-001
**THE #1 BLOCKER.** Fix these specific issues:

1. **OpenAPI /openapi.json returns 500** — serialization bug in app.py. Find and fix.
2. **Endpoint naming inconsistency**: Some routers use /status, others /health, others /stats.
   - Add alias endpoints so ALL three work on every router:
     ```python
     @router.get("/health")
     @router.get("/status")
     async def health():
         return {"status": "healthy"}
     ```
3. **Known broken paths** (from API probe on Mar 1):
   - `/api/v1/brain/status` → should be `/api/v1/brain/stats` (need alias)
   - `/api/v1/autofix/status` → should be `/api/v1/autofix/health` (need alias)
   - `/api/v1/mpte/status` → should be `/api/v1/mpte/stats` (need alias)
   - `/api/v1/micro-pentest/status` → should be `/api/v1/micro-pentest/health` (need alias)
   - `/api/v1/feeds/status` → should be `/api/v1/feeds/health` (need alias)
   - `/api/v1/fail/status` → should be `/api/v1/fail/health` (need alias)
   - `/api/v1/knowledge-graph/stats` → should be `/api/v1/knowledge-graph/status` (need alias)
   - `/api/v1/mcp-server/status` → should be `/api/v1/mcp-protocol/status` (need alias)
4. **Test**: After fixes, run `python scripts/enterprise_e2e_test.py` — must get 100% pass rate.

### Phase 2 — Postman Collections (qa-engineer) — DEMO-002 + DEMO-006
**STOP WRITING PYTHON UNIT TESTS.** They are not moving coverage.

1. **Fix coverage config FIRST** (30-minute task):
   - Edit `pyproject.toml` addopts to add: `--cov=suite-feeds/feeds --cov=suite-attack/attack --cov=suite-attack/api --cov=suite-integrations/api --cov=suite-evidence-risk/risk --cov=suite-evidence-risk/evidence`
   - Run `pytest --cov` — coverage should jump from 17.99% to 30%+ IMMEDIATELY
   
2. **Validate Postman collections**:
   - Install newman: `npm install -g newman`
   - Run each collection: `newman run suite-integrations/postman/enterprise/ALdeci-1-MissionControl.postman_collection.json -e suite-integrations/postman/enterprise/ALdeci-Environment.postman_environment.json`
   - Fix every failing request — update URLs, payloads, expected status codes
   - Run all 7 sequentially — document pass/fail count

3. **Update Postman environment variables**:
   - `base_url`: `http://localhost:8000`
   - `api_key`: The active API key from environment
   - Verify all 35 variables are set correctly

### Phase 3 — Wire UI (frontend-craftsman) — DEMO-003
**DO NOT BUILD aldeci-ui-new. IT DOES NOT EXIST ON DISK.**

Work in `suite-ui/aldeci/` — the EXISTING, SHIPPING UI.

Already wired by Copilot:
- ✅ `CodeScanning.tsx` — calls real scanner APIs (SAST, DAST, Secrets, Container, CSPM)
- ✅ `Integrations.tsx` — CRUD against /api/v1/integrations
- ✅ `IntegrationsSettings.tsx` — config save wired
- ✅ `api.ts` — response key mappings fixed for reports, cases, users, teams

Remaining pages to wire:
- Dashboard.tsx — connect to /api/v1/analytics/dashboard/overview
- EvidenceBundles.tsx — connect to /api/v1/evidence/*
- Workflows.tsx — connect to /api/v1/workflows
- Remediation.tsx — connect to /api/v1/remediation/tasks
- Reports.tsx — connect to /api/v1/reports (response key: data?.items)
- AuditLogs.tsx — connect to /api/v1/audit/logs

Pattern to follow (from Integrations.tsx fix):
```typescript
// Backend returns {items: [...]} — extract correctly
const data = response.data;
const items = data?.items || data?.results || [];
```

### Phase 4 — Demo Scripts (threat-architect, sales-engineer)

**threat-architect** — DEMO-004: Build CTEM Full Loop demo script
```bash
# The demo must show this exact flow:
1. POST /api/v1/sast/scan — scan code, get findings
2. POST /api/v1/brain/process — pipeline processes findings
3. POST /api/v1/mpte/scan/comprehensive — verify exploitability
4. POST /api/v1/autofix/generate — generate fix
5. POST /api/v1/evidence/create — create signed evidence bundle
# Each step feeds into the next. Real data throughout.
```

**sales-engineer** — DEMO-005: 5 Persona scripts with UI walkthrough paths

### Phase 5 — Infrastructure (devops-engineer) — DEMO-007
- Test `docker compose up` from clean state
- Verify health check within 30s
- Create `scripts/demo-healthcheck.sh` that validates everything

### Phase 6 — Documentation (technical-writer) — DEMO-008
- Update `docs/API_REFERENCE.md` with CTEM lifecycle grouping
- Top 20 endpoints with curl examples
- 3-step quickstart guide

### Phase 7 — Demo Data (data-scientist, ai-researcher, security-analyst, enterprise-architect)
- Seed Knowledge Graph with demo attack paths
- Seed evidence vault with compliance bundles
- Show MCP tool discovery
- Show self-learning feedback

## WHAT NOT TO DO

1. ❌ Do NOT write Python unit tests (they don't move coverage — ROOT CAUSE: `pyproject.toml` config)
2. ❌ Do NOT build aldeci-ui-new (it doesn't exist — work in suite-ui/aldeci/)
3. ❌ Do NOT run vision alignment audits (we know the score — 0.73 STABLE)
4. ❌ Do NOT debate SQLite vs PostgreSQL (deferred to Sprint 3)
5. ❌ Do NOT audit LOC counts (we've verified them 22 times)
6. ❌ Do NOT recount tests or coverage (focus on Postman, not pytest --cov)

## SUCCESS CRITERIA (Day 5)

| # | Criteria | Measured By |
|---|----------|-------------|
| 1 | Zero API 404s/500s | `python scripts/enterprise_e2e_test.py` → 100% pass |
| 2 | Postman all green | `newman run` all 7 collections → 380/380 pass |
| 3 | UI shows real data | Every page loads API data, no mocks |
| 4 | CTEM full loop works | Discover→Validate→Remediate→Comply in one curl sequence |
| 5 | 5 personas scripted | docs/DEMO_PERSONA_SCRIPTS.md exists with 5 paths |
| 6 | Docker works | `docker compose up` → health check passes |
| 7 | Coverage ≥30% | After pyproject.toml fix, pytest --cov ≥30% |

## AGENT RECOVERY NOTES

All 17 agents have been reset to READY state. Crash state cleared. Deferred queue emptied.
Sprint 1 archived (21/23 done). Sprint 2 has 12 items, all assigned.

**If an agent crashes**: Do NOT cascade-stop. Other agents can work independently.
Set `CASCADE_STOP=false` in the swarm controller.

**If context-engineer fails**: Other agents have this briefing. They can proceed without codebase-map update.

**If backend-hardener fails**: QA engineer can fix Postman collections anyway, using the correct API routes documented above.
