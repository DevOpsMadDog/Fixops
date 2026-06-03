# SPEC-028 — UI NO-MOCKS: every page fires a real /api/v1 call on mount

- **Status**: IMPLEMENTED (enforced by review + detectors; CI gate = follow-up)
- **Owner family**: UI / Customer-Readiness
- **Routers**: n/a (frontend invariant) — consumes `/api/v1/*`
- **Engines**: `suite-ui/aldeci-ui-new` (React 19 / Vite 6)
- **Stores**: n/a
- **Depends on**: SPEC-027 (the /api/v1 endpoints the UI calls must be auth-gated); CLAUDE.md "NO MOCKS" rule
- **Last updated**: 2026-06-03
- **Multica**: #9083 (this spec), #9077 (the 5-dashboard epic)

## 1. Intent (the why)
A demoed page showing fabricated data fails a $100K SCIF evaluation the moment a reviewer reloads
or inspects the network tab. The invariant: **every customer-facing UI page fires at least one real
`/api/v1/...` call on mount and renders real tenant data or a real branded EmptyState — never a
hardcoded fixture.** This formalises the CLAUDE.md NO-MOCKS rule as a governed spec and records the
5 dashboards de-mocked 2026-06-03 (#9077).

## 2. Scope — the invariant + detection
**Invariant:** for every page under `src/pages/`, on mount it fires ≥1 `/api/v1/...` request and
its render derives from that response (or a branded EmptyState), with no fixture/sample data.

**Detection signatures (a plain `MOCK_` grep is INSUFFICIENT — these are the real tells):**
1. module/in-component data arrays (`const reviews = [{...}]`) rendered directly while a `liveX`
   fetch result is ignored (set-but-unused state);
2. fetch-then-discard (`.then(d => { void d })`);
3. `useState(MOCK_CONST)` — fabricated data on first paint / empty tenant / error;
4. frozen dates (`new Date("2026-04-16")`, pinned YEAR/MONTH) faking "current";
5. fallback-to-mock (`data || CONST`, `data.length ? data : CONST`, `.catch(setMock)`);
6. wrong-endpoint wiring (fetch returns a shape the render never consumes).

Out of scope: static UI config (tab defs, dropdown options, label maps), editor/tester default
inputs, form `placeholder=` hints, marketing/landing pages, real public reference catalogs
(MITRE technique IDs) — these are legitimately not tenant data.

## 3. Contracts
```
page mount → GET /api/v1/<domain>/... (real)  → render real data | branded EmptyState
empty tenant → EmptyState (NOT [] hidden behind a hardcoded fixture)
```

## 4. Functional requirements
- **REQ-028-01**: No page imports from `src/data` / `src/fixtures` / a `mock`/`sample`/`seed` module.
- **REQ-028-02**: No page renders `MOCK_*` / lorem / `Acme Corp` / `John Doe` as displayed values
  (placeholders in form inputs are fine).
- **REQ-028-03**: A page's render derives from its fetched state, not a module fixture the fetch ignores.
- **REQ-028-04**: Dead "Save"/action buttons that don't POST are not acceptable — wire real POSTs or remove.

## 5. Non-functional requirements
- `npm run build` must pass.
- Empty/error states are branded EmptyStates, never silent fabricated data.

## 6. Acceptance criteria
- **AC-028-01** (verified 2026-06-03): `grep` finds 0 fixture-module imports + 0 displayed
  `MOCK_/lorem/Acme/John Doe` values in `src/`.
- **AC-028-02** (verified 2026-06-03): `npm run build` passes (4.94s).
- **AC-028-03** (browser-verified 2026-06-03): the 5 fixed dashboards (ArchReview,
  IdentityLifecycle, ComplianceCalendar, ThreatIntelDashboard, CopilotDashboard) fire real
  `/api/v1` calls on mount with 0 mock signatures in the DOM (Playwright MCP, vite:5173+api:8000).
- **AC-028-04**: registered in `specs/INDEX.md`.

## 7. Debate log (Mysti)
| Date | Mode | Verdict / change |
|------|------|------------------|
| 2026-06-03 | Backfill-author | Retro-spec of the NO-MOCKS UI lane (#9077) per founder governance rule. Two static-detector rounds + a mission-control browser audit found the surface clean after 5 fixes. |

## 8. Implementation notes
5 dashboards de-mocked 2026-06-03 (commits `f3e13a11`, `0f50bee7`, `2b7b10ef`, `b8a4cf58`,
`f725213e`). **Known gap / follow-up:** there is no automated CI gate for NO-MOCKS (verification
is browser + grep). A CI-able detector (the python set-but-unused/void-d/useState(MOCK)/fixture
scanners used this session) should be packaged as a test, analogous to SPEC-027's auth gate — a
Multica card should be filed for that. No code change in this spec — governance backfill only.
