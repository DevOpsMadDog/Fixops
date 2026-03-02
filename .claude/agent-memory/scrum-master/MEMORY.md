# Scrum Master Agent Memory

## Sprint 2 State (Enterprise Demo — 2026-03-06)
- Sprint 2 started 2026-03-01, ends 2026-03-06 (5 days)
- Day 1 result: 9/12 items DONE (75%), 3 P0 remaining
- Day 2 result: 11/12 items DONE (91.7%), 1 remaining
- Day 3 result: 11/12 items DONE (91.7%), DEMO-003 still in-progress
- DEMO-001 completed Day 2 AM (backend-hardener: 58/58 E2E, 769 routes, 11 security fixes)
- DEMO-002 completed Day 2 PM (qa-engineer: Newman 475/475, 9th consecutive, 0 regressions)
- Remaining: DEMO-003 only (UI wiring — 6 pages + sidebar restructure)
- CEO Day 3 directive: sidebar must be restructured from 8 suites to 5 workflow spaces
- Sprint 1 archived: 21/23 done (91.3%)
- DEBATE-001 resolved: SQLite WAL, 6/6 support deferral

## Day 3 Verified State (2026-03-03 — Run 5)
- 25/26 key demo endpoints verified 200 via curl with auth
- Only 404: self-learning/stats (assigned to backend-hardener)
- self-learning/health and zero-gravity/health FIXED since Day 2
- Newman 475/475 (100%, 9th consecutive green, 0 regressions)
- Quality gate: PASS (moat coverage 89.68%, 16/18 above 80%, 6 at 100%)
- 11/17 agents completed Day 2 late swarm. 6 failed infrastructure startup (34-37s)
- Vision alignment: 0.85 (STABLE)
- Funding readiness: 81% (product 89%, demo 96%, testing 83%, architecture 73%, docs 70%, marketing 58%)
- Frontend-craftsman: 0 TS errors, build intact, DEMO-003 90% done
- Coverage: 19.23% (moat 89.68%), 13,614 tests, 347 test files
- Total: 415,073 Python LOC, 759 endpoints, 914 files
- Core engine LOC verified: brain_pipeline 1,663 + autofix 1,515 + micro_pentest 2,054 + crypto 582 + mcp_router 468 + mcp_server 978 = 7,260
- 10 artifacts produced successfully
- Day 4 coordination notes written with page-to-endpoint mapping

## Key Patterns
- Agent status files at `.claude/team-state/*-status.md` — read ALL before standup
- Sprint board at `.claude/team-state/sprint-board.json` — primary tracking artifact
- Always produce: standup, daily-demo, demo script, debate-summary
- Quality gate at `.claude/team-state/quality-gate.json` — check verdict
- Debates in `.claude/team-state/debates/active/` — resolve when consensus exists
- coordination-notes-dayN.md is critical — other agents READ this for their instructions
- Always verify endpoints with `curl -H "X-API-Key: $TOKEN"` before reporting status
- When files already exist, must Read before Write (tool constraint)
- Use unique strings for Edit operations — common strings like "Pillar(s) served" fail
- Token must come from .env file, not hardcoded — grep FIXOPS_API_TOKEN from .env
- Linter auto-modifies written files — don't fight it, rewrite if needed
- The linter sometimes replaces entire file content with auto-generated version — check after write

## Swarm Infrastructure Pattern
- 6 agents failed late Day 2 swarm with identical 34-37s durations across 3 attempts
- This is always an infrastructure issue, not agent code failure
- Agents that failed: qa-engineer, security-analyst, devops-engineer, marketing-head, sales-engineer, technical-writer
- All have current data from earlier successful runs — no work lost
- Assign swarm-controller to investigate and fix before next swarm run

## Debate Protocol
- 5 stances: SUPPORT, CHALLENGE, MODIFY, ABSTAIN, VETO (security-analyst only)
- Majority SUPPORT = ACCEPTED, majority MODIFY = MODIFIED, majority CHALLENGE = REJECTED
- No consensus = auto-resolve based on vision pillar alignment
- Move resolved to `.claude/team-state/debates/resolved/`

## Security Advisory Handling
- SEC-ADV-001 (MEDIUM, was CRITICAL): .env secrets — ALL infrastructure remediated
  - PENDING: CEO must rotate OpenAI API key (only remaining action)
- Security advisories are NOT debates — they require immediate action

## Known Issues (Updated Day 3)
- aldeci-ui-new/ does NOT EXIST — never reference it, work in suite-ui/aldeci/
- Coverage at 19.23% vs 25% gate — structural gap, moat 89.68%
- 6 UI pages still need wiring (frontend-craftsman Day 4 P0)
- Sidebar needs restructure to 5 workflow spaces (CEO directive Day 3)
- EvidenceBundles.tsx has Math.random() fallback — must remove
- self-learning/stats still 404 (only remaining broken endpoint)

## Artifacts Checklist (Per Run)
1. standup-YYYY-MM-DD.md
2. daily-demo-YYYY-MM-DD.md (primary — most important)
3. demo-YYYY-MM-DD.md (demo script)
4. debate-summary-YYYY-MM-DD.md
5. sprint-board.json (update burndown)
6. metrics.json (update velocity, funding readiness)
7. coordination-notes-dayN.md
8. scrum-master-status.md
9. decisions.log (append)
10. context_log.md (append)
