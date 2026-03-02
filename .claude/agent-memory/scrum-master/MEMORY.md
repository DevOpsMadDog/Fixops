# Scrum Master Agent Memory

## Sprint 2 State (Enterprise Demo — 2026-03-06)
- Sprint 2 started 2026-03-01, ends 2026-03-06 (5 days)
- Day 1 result: 9/12 items DONE (75%), 3 P0 remaining
- Day 2 result: 10/12 items DONE (83.3%), 2 P0 remaining
- DEMO-001 completed Day 2 (backend-hardener: 58/58 E2E, 769 routes, 11 security fixes)
- Remaining: DEMO-002 (Postman 84.7%), DEMO-003 (UI wiring, OAuth token expiry root cause)
- Critical path: DEMO-003 (fix OAuth token, restart agent) + DEMO-002 (QA iteration) → both run parallel
- Sprint 1 archived: 21/23 done (91.3%)
- DEBATE-001 resolved: SQLite WAL for demo, PostgreSQL deferred (5/5 consensus)

## Day 2 Verified State (2026-03-02 10:23)
- /api/v1/search NOW returns 200 (was 500) — VERIFIED
- All 11 key demo endpoints return 200 with auth
- Frontend-craftsman failure: OAuth token expiry (NOT code bug), build intact (0 TS errors)
- Backend-hardener Session 3: secrets scanner YAML fix (10 patterns), error handling hardened (5 engines)

## Key Patterns
- Agent status files at `.claude/team-state/*-status.md` — read ALL before standup
- Sprint board at `.claude/team-state/sprint-board.json` — primary tracking artifact
- Always produce: standup, daily-demo, demo script, debate-summary
- Quality gate at `.claude/team-state/quality-gate.json` — check verdict
- Debates in `.claude/team-state/debates/active/` — resolve when consensus exists
- coordination-notes-dayN.md is critical — other agents READ this for their instructions
- Always verify endpoints with `curl -H "X-API-Key: $TOKEN"` before reporting status

## Debate Protocol
- 5 stances: SUPPORT, CHALLENGE, MODIFY, ABSTAIN, VETO (security-analyst only)
- Majority SUPPORT = ACCEPTED, majority MODIFY = MODIFIED, majority CHALLENGE = REJECTED
- No consensus = auto-resolve based on vision pillar alignment
- Move resolved to `.claude/team-state/debates/resolved/`

## Security Advisory Handling
- SEC-ADV-001 (MEDIUM, was CRITICAL): .env secrets partially remediated
  - .gitignore ✅, .env.example ✅, Docker ✅, CI ✅ — all infra done
  - PENDING: CEO must rotate OpenAI API key, backend-hardener JWT secret
- Security advisories are NOT debates — they require immediate action
- Security Analyst has implicit VETO on security matters

## Known Issues (Updated Day 2 Afternoon)
- aldeci-ui-new/ does NOT EXIST — never reference it, work in suite-ui/aldeci/
- Coverage at 19.19% — config fix (DEMO-006) done, awaiting full verification run
- OpenAPI /openapi.json WORKS ✅
- /api/v1/search NOW RETURNS 200 ✅ (was 500, fixed by DEMO-001)
- 4 compliance endpoints return 500: gaps, audit-bundle, assess, ai-agent/decide
- frontend-craftsman killed by OAuth token expiry — get fresh token, then restart

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
