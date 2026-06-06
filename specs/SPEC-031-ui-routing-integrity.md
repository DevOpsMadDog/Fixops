# SPEC-031 — UI Routing Integrity (no dead redirects)

- **Status**: IMPLEMENTED (invariant + enforcing test; fixes landed 2026-06-06)
- **Owner family**: UI / Customer-Readiness
- **Routers**: n/a (frontend invariant) — `suite-ui/aldeci-ui-new/src/App.tsx`
- **Engines**: n/a
- **Stores**: n/a
- **Depends on**: SPEC-028 (UI NO-MOCKS)
- **Last updated**: 2026-06-06
- **Test**: `tests/test_ui_route_integrity.py`

## 1. Intent (the why)
A customer clicking a nav item must land on the real workspace for it — not silently
get bounced to a default page. A whole class of bugs was found 2026-06-06: 13 routes
redirected to `<Navigate to="/?view=…">`, but nothing in the app renders `?view=…` and
the index route (`<Route index element={<Navigate to="/executive">}>`) strips the query —
so SOC / alert-triage / incident-response / dev-security nav items all silently landed on
the CISO Executive dashboard. For a SCIF eval where a reviewer clicks through personas,
nav that lands on the wrong screen reads as a broken product.

## 2. Scope — the invariants
For `suite-ui/aldeci-ui-new/src/App.tsx`:
1. **No dead root-query redirects**: no `<Navigate to="/?…">` (the index→/executive
   redirect strips the query, so the intended view never renders).
2. **All redirect targets resolve**: every `<Navigate to="…">` target's base path (sans
   `?query`) must match a declared `<Route path="…">` (an element-route or another route).

## 3. Contracts
```
nav route → <Navigate to="/real-page"> → real page mounts + fires its /api/v1 call
(never → "/?view=x" → index strip → wrong default page)
```

## 4. Functional requirements
- **REQ-031-01**: zero `Navigate to="/?…"` redirects.
- **REQ-031-02**: zero `Navigate` targets that don't resolve to a declared route.
- **REQ-031-03**: SOC/alert/incident nav (`/soc`, `/ai-soc`, `/alert-triage`, `/soc-triage`,
  `/incident-response`, `/incidents/response`, `/mission-control/soc*`) → `/incidents`
  (real IncidentResponse, fires `/api/v1/incidents/`); `/mission-control/dev-security` →
  `/developer`; `/executive-*` → `/executive`.

## 5. Non-functional requirements
- `npm run build` passes; the integrity test runs in the standard pytest suite (no app boot).

## 6. Acceptance criteria
- **AC-031-01** (verified 2026-06-06): `tests/test_ui_route_integrity.py` — 2 passed
  (0 dead root-query redirects; all 75 Navigate targets resolve).
- **AC-031-02** (browser-verified 2026-06-06): `/alert-triage` → `/incidents` fires real
  `GET /api/v1/incidents/?limit=100`; `/mission-control/dev-security` → `/developer` fires
  real `/api/v1/sast|dast/findings`.
- **AC-031-03**: registered in `specs/INDEX.md`.

## 7. Debate log
| Date | Mode | Verdict |
|------|------|---------|
| 2026-06-06 | Browser sweep + fix + spec-backfill | Found 13 dead `/?view=` redirects via Playwright nav (pages landed on Executive); repointed to real pages (tick207-208); codified the invariant as an enforcing parse-test so the class cannot regress. |

## 8. Implementation notes
Fixes: commits repointing `/?view=soc|dev|executive` → `/incidents`/`/developer`/`/executive`
across both route blocks in App.tsx. The enforcing test parses App.tsx (no app boot needed)
and is cheap enough for the standard suite.
