# Sprint 2 — Demo Backlog

**Sprint window:** 2026-04-22 → 2026-05-06 (2 weeks)
**Owner (coordination):** scrum-master
**Status:** DRAFT — locked after enterprise-architect (reconcile-PRD, thread #3) and ux-architect (UI dispatch, thread #4) agents finish. Their outputs land AFTER this document; sections marked *"reconcile outcome pending"* / *"UI dispatch pending"* will be patched in a follow-up.

---

## Top-level goal (one sentence)

**Ship a 15-minute Sprint 2 demo that proves Fixops is a platform (not a scanner) by walking an investor/customer from a live interactive graph of 2,620 real code + research nodes, through a TrueCourse-head-to-head moment, into a live TrustGraph + Brain Pipeline correlation, and ending on two committed-to competitive leapfrog PRDs (NEW-G070 semantic layer, NEW-G071 IDE-in-browser).**

---

## Sprint goal statement

> *By end of sprint 2, an investor or prospect can sit with a Fixops rep, see the competitive landscape rendered as an interactive graph in their browser, watch a live Fixops-vs-TrueCourse comparison with evidence, see a CVE-to-asset-to-compliance-control correlation happen in real time through the 12-step Brain Pipeline, and leave with a credible roadmap that shows how Fixops closes the only 6 remaining competitive gaps. The demo MUST use real data, real endpoints that already return 200, and zero mocked screens. Anything that doesn't work yet is cut from the demo — not faked.*

---

## Demo backlog (DEMO-001..DEMO-005)

| ID | Title | Owner | Priority | Acceptance criteria | Est. hrs | Dependencies |
|----|-------|-------|----------|---------------------|----------|--------------|
| **DEMO-001** | Interactive competitive-intelligence graph view in the UI | frontend-craftsman (lead) + backend-hardener (route + data) | **P0** | Open `http://localhost:5173/competitive-graph` → renders `graphify-out/graph.html` (2,620 nodes / 2,433 links / 454 communities) inside an iframe with toolbar (search box, "filter by community", "highlight TrueCourse nodes" button that surfaces the 482 TrueCourse-linked nodes in <300ms). Back button returns to dashboard. Page is added to main navigation under "Intelligence". Works on Chrome/Safari on a 15-inch laptop at 1440×900. | 8 | graphify-out/graph.html (DONE, commit `7386db5d`); ux-architect UI dispatch (thread #4 — pending) |
| **DEMO-002** | "TrueCourse vs Fixops" side-by-side demo page | frontend-craftsman + technical-writer (copy) | **P0** | `http://localhost:5173/competitive/truecourse` renders the 40-row table from `raw/competitive/truecourse-vs-fixops-comparison.md` as a searchable, filterable table (filter by status: FIXOPS_WINS / PARITY / TRUECOURSE_WINS / GAP_EXISTS). Each row links to the referenced code path (`suite-core/core/*.py:line`) which, on click, opens a modal showing the grep match in context. Two callout cards at top: "17 places Fixops wins" + "13 places TrueCourse wins (6 have gap PRDs, 2 are new: NEW-G070 / NEW-G071)". Renders in <1s. | 10 | `raw/competitive/truecourse-vs-fixops-comparison.md` (DONE, commit `0639bb39`); code-path click-through is best-effort (stub modal if suite-api file-read endpoint not wired) |
| **DEMO-003** | Live TrustGraph correlation demo — "watch the brain connect the dots" | backend-hardener + data-scientist | **P0** | On a fresh `/brain/live-demo` page, click **Run Demo** → hits `POST /api/v1/brain/demo-run` which (a) ingests one sample CVE + one sample asset + one compliance control via existing `/api/v1/brain/*` endpoints, (b) shows 310-event Competitive Intelligence injection counts from Core 5, (c) returns the correlation in <5s (CVE ↔ affected component ↔ asset ↔ SOC 2 control). UI renders it as a 4-node mini-graph with live edge-appearance animation. Talking-point overlay auto-advances every 10s. All events hit the existing TrustGraph event bus (verify via `/api/v1/brain/stats` — node count should increase by exactly 4). | 12 | Live TrustGraph injection (DONE, 310 events in Core 5 Competitive Intelligence); existing `/api/v1/brain/stats` (verified working in `docs/DEMO_SCRIPT.md` line 175) |
| **DEMO-004** | Two-gap PRD showcase page + "where we're going next" slide | technical-writer + scrum-master + (pending) enterprise-architect | **P0** | `http://localhost:5173/roadmap/new-gaps` page shows two PRD cards (NEW-G070 semantic layer, NEW-G071 IDE-in-browser) with: (i) the problem ("TrueCourse has tree-sitter + Pyright LSP; Fixops is Python-ast-only"), (ii) the fix (new engine: `semantic_analyzer_engine`), (iii) estimated sprints (NEW-G070 = 2 sprints XL, NEW-G071 = 1 sprint L), (iv) which 332 existing PRDs it subsumes (reconcile outcome pending). Each card links to the full markdown PRD at `.omc/prds/v2/new_g070_semantic_analyzer.md` + `new_g071_ide_in_browser.md` (which technical-writer generates as part of this task). Page renders without runtime errors. | 6 | `raw/competitive/truecourse-vs-fixops-comparison.md` proposed-gap section (DONE); `gap-matrix.md` formal promotion (enterprise-architect reconcile outcome pending) |
| **DEMO-005** | Pre-demo checklist + run-book + rollback | qa-engineer + devops-engineer + scrum-master | **P0** | `docs/SPRINT_2_DEMO_RUNBOOK.md` committed, containing: (1) pre-demo checklist (server up, 5 API endpoints return 200, graph.html loads, all 4 demo pages load, seed data present in `default` + `aldeci` org_ids), (2) 15-min minute-by-minute demo script referencing only DEMO-001..004 pages + existing `DEMO_SCRIPT.md` minute 0–2 platform-health intro, (3) explicit "**do not show**" list (LLM-estimate modal, VS Code extension, background-service installer — all TrueCourse_WINS gaps not yet closed), (4) rollback commands if any demo page 500s mid-pitch (switch to static screenshot fallback stored in `docs/demo-fallbacks/`), (5) smoke-test script `scripts/demo_smoketest.sh` that runs all 5 checks and exits non-zero on any failure. Run `./scripts/demo_smoketest.sh` 24h before investor meeting — must exit 0. | 8 | DEMO-001..004 complete enough to exercise the checks; existing `docs/DEMO_SCRIPT.md` (already shipping) |

**Total P0 effort:** 44 hours (~5.5 engineer-days across 3 owners working in parallel)

---

## Per-item elaboration

### DEMO-001 — Interactive competitive-intelligence graph view

The heaviest lift is **not** the visualization (graphify already produced `graph.html` at commit `7386db5d` — 1.97 MB, 4 TrueCourse references, 2,620 nodes, 454 Leiden communities). The lift is UX integration: the HTML is standalone D3/vis.js output and needs to live inside the Fixops React shell without breaking the navigation. frontend-craftsman will build a thin `<CompetitiveGraphPage>` component that iframes `graph.html` (hosted at `/graphify-out/graph.html` via a new FastAPI static-mount), adds a three-button toolbar, and wires the "highlight TrueCourse nodes" action to pass a URL fragment `#highlight=truecourse` that the embedded graph reads in its onload handler. backend-hardener adds the static-mount to `suite-api/apps/api/app.py` and a `GET /api/v1/competitive/graph-meta` endpoint returning node/edge/community counts so the toolbar can show the "2,620 nodes / 454 communities" badge live. **Non-goal for this sprint:** replacing the iframe with native React Flow — that's a future UX polish, not a demo blocker. The iframe is genuinely working code, which is the Fixops rule.

### DEMO-002 — "TrueCourse vs Fixops" side-by-side page

The `raw/competitive/truecourse-vs-fixops-comparison.md` file is 40 rows of markdown; frontend-craftsman parses it at build time (Vite plugin) into a JSON table + renders it with existing Fixops Tailwind table primitives. Each row's "Fixops Evidence" column contains `suite-core/core/*.py:LINE` references — clicking opens a right-drawer modal that calls `GET /api/v1/code/snippet?path=<path>&line=<line>&context=5` (new thin endpoint, reads the file safely with path-traversal guard). If backend-hardener can't ship that endpoint in sprint 2, the modal gracefully degrades to showing just the path as plaintext. The two callout cards pull their counts (17 wins / 13 losses / 6 have gaps / 2 are new) directly from the TL;DR header of the markdown — no separate source of truth.

### DEMO-003 — Live TrustGraph correlation demo

This is the investor money shot and the riskiest item. The 310 Competitive Intelligence events landed in TrustGraph Core 5 via today's live injection (commit chain from `92529f52`); `/api/v1/brain/stats` already returns node/edge counts per `docs/DEMO_SCRIPT.md`. What doesn't exist yet is the **one-click demo endpoint** `POST /api/v1/brain/demo-run` that deterministically seeds 4 correlated nodes in under 5 seconds and returns the correlation for rendering. backend-hardener implements it as a 40-line composer that calls 4 existing `/api/v1/brain/*` endpoints in sequence (CVE create → component create → asset create → correlation query). data-scientist verifies the correlation math returns non-empty results for the seeded data. The mini-graph renderer on the UI side reuses whatever React Flow primitive is already in `SecurityGraph.tsx:507` (parity with TrueCourse per row #31 of the comparison).

### DEMO-004 — Two-gap PRD showcase page

technical-writer generates two new PRDs in `.omc/prds/v2/` following the existing 42-PRD format (problem / solution / engine contract / acceptance criteria / estimated effort / competitor evidence). Content is already implied by the comparison table — this is polishing, not inventing. The showcase page is a simple two-card React component under `/roadmap/new-gaps`. **Dependency on enterprise-architect:** if the reconcile-PRD agent (thread #3, running now) identifies that 1 or more existing PRDs already cover NEW-G070 or NEW-G071, scrum-master updates this page to reflect MERGE outcomes instead of promoting them as brand-new work. Placeholder text: *"Reconcile outcome pending — final PRD counts may shift when thread #3 closes."*

### DEMO-005 — Pre-demo checklist + run-book + rollback

This is the safety net. The 15-min `docs/DEMO_SCRIPT.md` already exists and works (8,910 tests verify the underlying endpoints). DEMO-005 **extends** it with a Sprint-2-specific addendum that adds the 4 new demo pages to the flow and the explicit "do not show" list (prevents accidentally demoing a half-built feature under pressure). qa-engineer writes `scripts/demo_smoketest.sh` — 30 lines of curl + page-load checks. devops-engineer adds the smoke-test to the CI/CD pipeline so it runs on every merge to `features/intermediate-stage`. The fallback screenshots in `docs/demo-fallbacks/` are captured from working pages — if any page 500s live, the rep swaps to the screenshot without breaking narrative.

---

## Definition of done (sprint-level)

A demo is done when **all seven** of these are true:

1. All 4 demo pages (DEMO-001..004) render without console errors on Chrome stable + Safari 17 at 1440×900.
2. `scripts/demo_smoketest.sh` exits 0 when run against the shipped branch (not a local dev environment).
3. `curl -s -H "X-API-Key: $TOKEN" http://localhost:8000/api/v1/brain/stats` returns node/edge counts that reflect the 310 Competitive Intelligence events (visible under `node_types` or in a new `cores` field).
4. `docs/SPRINT_2_DEMO_RUNBOOK.md` has been dry-run end-to-end by someone other than the author inside 15 minutes and nothing broke.
5. The 4 new demo pages are reachable from main navigation or from the existing Home dashboard within 2 clicks.
6. No mocked, stubbed, or "coming soon" copy appears on any demo page — if a feature is partial, it is cut, not faked.
7. `beast-mode(sprint-2): DEMO-001..DEMO-005 complete` commit is pushed to `features/intermediate-stage` with co-authored-by tag.

---

## Risks + mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| **graph.html iframe breaks on tight CSP or mixed-content policy** (DEMO-001) | Medium | frontend-craftsman tests in Chrome + Safari incognito before mid-sprint check-in. Fallback: move graph.html to a `<object>` tag or a separate tab (`target="_blank"`) — loses the unified UX but keeps the demo. |
| **`POST /api/v1/brain/demo-run` composer is flaky under load** (DEMO-003) | High | backend-hardener writes the 4-call sequence as idempotent (INSERT OR IGNORE pattern used elsewhere in `CLAUDE.md` engine inventory). qa-engineer adds a retry-on-transient-500 layer in the smoke test. Pre-demo the rep runs it twice to warm caches. |
| **Reconcile-PRD outcome (thread #3) lands after DEMO-004 ships and invalidates new-gap framing** | Medium | DEMO-004 page is explicitly marked *"Reconcile outcome pending"* in the first release; scrum-master patches page copy the morning after enterprise-architect finishes. Update does not block the demo (wording change, not behavior). |
| **UI dispatch (thread #4) assigns frontend-craftsman to conflicting work** | Medium | scrum-master coordinates with ux-architect output — either (a) explicitly reserve frontend-craftsman for DEMO items 001+002 (highest-leverage investor-facing work), or (b) re-assign DEMO UI work to a secondary UI owner from the ux-architect's UI dispatch plan. Final call after thread #4 closes. |
| **Backend-code graphify ingest (deferred from thread #1) is missing from DEMO-001 graph** | Low | Today's graph.html already has 2,620 nodes including research docs + `suite-ui/aldeci-ui-new/src/` (442 files). Missing: `suite-core/core/` (345 engines) + `suite-api/apps/api/` (573 routers). Not a demo blocker — the competitive story is the point, not full code coverage. Flagged as a Sprint 3 thread below. |
| **Investor asks about VS Code extension or LLM pre-flight estimate (TRUECOURSE_WINS gaps)** | Low | DEMO-004 pro-actively surfaces NEW-G070 / NEW-G071 PRDs so the rep can say "6 gaps have PRDs, 2 new ones identified today, here's the roadmap." Don't let a surprise gap discussion derail minute 14. |
| **Fresh demo data drift between dev laptop and investor demo server** | Medium | DEMO-005 smoke test validates the exact 4-node correlation output expected from the composer. If output differs, smoke test fails, rep knows 24h before the meeting. |

---

## Out-of-scope for Sprint 2 (promoted to Sprint 3+ threads)

- Backend-code + API graphify ingest (`suite-core/core/*.py` + `suite-api/apps/api/*_router.py`) into the graph — deferred from thread #1.
- Implementing `semantic_analyzer_engine` (NEW-G070) — the sprint ships the PRD and roadmap card, not the engine.
- Implementing `code_viewer_panel` (NEW-G071) — same as above; PRD + card only.
- Closing the remaining 11 TrueCourse_WINS rows (rows 2–10, 13, 15, 23, 24, 32, 33, 34 from the comparison table) — they already have GAP-### PRDs (GAP-061..068) or new ones (NEW-G070/G071); next sprint picks the highest-leverage 2–3.
- Full reconcile of 42 gap PRDs vs 8 native engines + 332 engine PRDs — that is the enterprise-architect thread #3 deliverable.
- UI overhaul (22 work units, 372 pages) per `~/.claude/plans/swirling-shimmying-karp.md` — that is the ux-architect thread #4 deliverable.

---

*Backlog author: scrum-master. Backed by `.omc/TASKS_STATE_2026-04-22.md` open-threads section (updated same commit). Awaiting reconcile outcome (enterprise-architect) + UI dispatch (ux-architect) to finalize owner allocation.*
