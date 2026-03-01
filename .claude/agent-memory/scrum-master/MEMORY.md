# Scrum Master Agent Memory

## Sprint 2 State (Enterprise Demo — 2026-03-06)
- Sprint 2 started 2026-03-01, ends 2026-03-06 (5 days)
- Day 1 result: 9/12 items DONE (75%), 3 P0 remaining
- Critical path: DEMO-001 (API fixes) → DEMO-002 (Postman) → DEMO-003 (UI wiring)
- Sprint 1 archived: 21/23 done (91.3%)

## Key Patterns
- Agent status files at `.claude/team-state/*-status.md` — read ALL before standup
- Sprint board at `.claude/team-state/sprint-board.json` — primary tracking artifact
- Always produce: standup, daily-demo, demo script, debate-summary
- Quality gate at `.claude/team-state/quality-gate.json` — check verdict
- Debates in `.claude/team-state/debates/active/` — resolve when consensus exists

## Debate Protocol
- 5 stances: SUPPORT, CHALLENGE, MODIFY, ABSTAIN, VETO (security-analyst only)
- Majority SUPPORT = ACCEPTED, majority MODIFY = MODIFIED, majority CHALLENGE = REJECTED
- No consensus = auto-resolve based on vision pillar alignment
- Move resolved to `.claude/team-state/debates/resolved/`

## Security Advisory Handling
- SEC-ADV-001 (OPEN): Real API keys in .env — CEO must rotate OpenAI key
- Security advisories are NOT debates — they require immediate action
- Security Analyst has implicit VETO on security matters

## Known Issues
- aldeci-ui-new/ does NOT EXIST — never reference it, work in suite-ui/aldeci/
- Coverage at 19.35% — config fix (DEMO-006) done, awaiting verification run
- OpenAPI /openapi.json returns 500 — serialization bug
- /api/v1/search returns 500 — backend bug

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
