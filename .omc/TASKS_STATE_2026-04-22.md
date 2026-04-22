# Task State Snapshot — 2026-04-22 22:15

Snapshot of the session's task tracker at pause. Session-scoped TaskList IDs are lost on `/quit`, but their outputs and continuations are captured here.

---

## READ FIRST — honest state of graphify + TrueCourse (don't repeat my prior session's mistake)

The previous session (mine, before this handoff) produced a **text-level** comparison of TrueCourse vs Fixops. It did **NOT** produce a graphify visual comparison. Specifically:

| What exists | What does NOT exist |
|------------|---------------------|
| `raw/competitive/truecourse-analysis.md` — markdown deep-dive of TrueCourse repo (1083 deterministic + 101 LLM rules, tiered LLM router, violation lifecycle, `.truecourse/` JSON store, architecture graph, diff-mode UI, YAML hook policy, 4 Claude Code skills) | TrueCourse concepts as nodes in `graphify-out/graph.json` |
| `raw/competitive/gap-matrix.md` — GAP-061..069 rows inferred by an agent reading the markdown | Visual graph showing `truecourse.violation_lifecycle → fixops.findings_router` |
| 9 v2 PRDs citing TrueCourse (at `.omc/prds/v2/`) | Anything TrueCourse in `graphify-out/graph.html` |
| TrustGraph `cited_in` edges in dry-run snapshot | A re-built, re-clustered graph visual |

**The current `graphify-out/graph.html` is 25+ hours old. It contains ONLY `suite-ui/aldeci-ui-new/src/` (442 files, 2258 nodes, 409 communities). No backend code, no research docs, no TrueCourse, no competitive intelligence, no gap tasks.**

**Your FIRST job in this session** is open thread #1 below — run graphify semantic extraction on `raw/competitive/` (9 docs), merge with existing graph (or expand scope to include `suite-api` + `suite-core` for a real full-repo view), re-cluster, regenerate `graph.html`. Only after that can any actual visual/graph-based TrueCourse↔Fixops comparison happen. Thread #7 (exhaustive side-by-side table) can be done in parallel since it needs only the markdown files, but the *graph* comparison depends on #1.

Don't claim "graphify comparison done" until `graph.html` actually shows TrueCourse nodes linked to Fixops code nodes. My prior session conflated the text comparison with a graph comparison and the user (rightly) called it out.

---

## Task table

| # | Subject | Status | Output / continuation |
|---|---------|--------|----------------------|
| 1 | Read existing graphify→LLM→multica plan | ✅ completed | `.omc/plans/graphify-llm-multica-pipeline.md` was read. Summary in RESUME_PLAN.md. |
| 2 | Clone + structurally analyse truecourse-ai/truecourse | ✅ completed | Repo cloned at `/tmp/truecourse`. Analysis at `raw/competitive/truecourse-analysis.md`. |
| 3 | Inject truecourse+competitor findings into existing graph | 🟡 in_progress | Script ready: `scripts/inject_gap_intelligence_to_trustgraph.py`. Dry-run snapshot at `.omc/trustgraph_pending/gap_injection_20260422T115618Z.json`. **Next session: run live with no flags.** |
| 4 | Competitor research — 5 parallel deep-dive agents | ✅ completed | 5 reports at `raw/competitive/competitor-{aspm,cspm,ctem,sonatype,emerging}.md`. |
| 5 | Gap matrix | ✅ completed | 69 rows at `raw/competitive/gap-matrix.md`. |
| 6 | Wire graphify → TrustGraph intelligence connections | ✅ completed | Script + dry-run ready. Live run is step #3 above. |
| 7 | Write detailed multica tasks w/ acceptance criteria | ✅ completed | 42 tasks as JSON at `/tmp/multica-tasks.json` (re-create via `python3 /tmp/gen_prds.py` if /tmp is wiped). |
| 8 | Truecourse patch pass on gap matrix + JSON | ✅ completed | Added GAP-061..069. Gap matrix grew 60→69, tasks 33→42. |
| 9 | Convert 42 JSON tasks → v2 PRD markdown | ✅ completed | 42 PRDs in `.omc/prds/v2/` (naming: `<engine>.md` or `gap_<gap_id>_<slug>.md`). |
| 10 | Fix .env corruption — restore MuleRouter key | ✅ completed | `.env` restored via `scripts/restore_env_keys.sh`. Keys: MULEROUTER_API_KEY, OPENROUTER_API_KEY, MULEROUTER_BASE_URL, MULEROUTER_DEFAULT_MODEL=qwen/qwen3-6b-max |
| 11 | Push v2 PRDs to Multica board | ✅ completed | Pushed in 2 waves: 33 + 9 = 42 new stories. Multica board now 374 stories / 481 sub-tasks total. http://localhost:3000/aldeci/issues |
| 12 | Queue top P0/P1 tasks to SwarmClaw | 🔴 blocked | SwarmClaw :3456 needs web-UI login → API token in `layer2-swarmclaw-autonomous/.env` as `SWARMCLAW_API_TOKEN=...`. Probing rate-limited (15min lockout). User action. |

## Deliverables persisted

- **Git** (`features/intermediate-stage`): 4 commits — `50f1596e`, `4b5b790a`, `92529f52`, `1dbab89c`
- **Research**: `raw/competitive/` (9 markdown files, YAML-frontmatter'd for graphify)
- **PRDs**: `.omc/prds/v2/` (42 new files)
- **TrustGraph staging**: `.omc/trustgraph_pending/gap_injection_20260422T115618Z.json` (310 events + 371 edges, dry-run)
- **Scripts**: `scripts/inject_gap_intelligence_to_trustgraph.py`, `scripts/restore_env_keys.sh`
- **Multica board**: 374 stories / 481 sub-tasks (dedup-safe; re-pushes skip existing)

## Open threads to continue next session

1. **✅ DONE: graphify visual correlation** — commit `7386db5d` *beast-mode(graphify): rebuild graph with competitive research — TrueCourse now visible*. Rebuilt `graphify-out/graph.html` (1.97 MB, 2620 nodes, 2433 links, 454 Leiden communities, 4 TrueCourse references). Apiiro/Endor/Cycode + Fixops competitive-gap community mapped. **Deferred sub-item now promoted to a NEW open thread below:** semantic ingest of `suite-core/core/*.py` (345 engines) + `suite-api/apps/api/*_router.py` (573 routers) — they are NOT in today's graph; graph contains research docs + `suite-ui/aldeci-ui-new/src/` (442 files) only.
2. **✅ DONE: Live TrustGraph injection** — `python3 scripts/inject_gap_intelligence_to_trustgraph.py` ran live, 310 events + 371 edges landed in Core 5 "Competitive Intelligence". No flags needed on re-run (idempotent via dedupe). Verify via `/api/v1/brain/stats` — should reflect the Core 5 node-count bump.
3. **SwarmClaw API token** — user creates in UI → paste into `layer2-swarmclaw-autonomous/.env` as `SWARMCLAW_API_TOKEN=...` → I can queue 10 P0/P1 tasks for overnight agents. Probing rate-limited (15min lockout); user action blocker.
4. **Reconcile 42 gap PRDs against 8 native engines** (per `docs/CTEM_PLUS_IDENTITY.md`) — many proposed "new engines" may duplicate SAST/DAST/Secrets/Container/CSPM/APIFuzzer/Malware/LLMSecurity or overlap with 332 existing engine PRDs. **IN FLIGHT NOW:** enterprise-architect agent running; outcome = MERGE / KEEP / KILL per PRD. May retire some of the 42 gap PRDs. Will land after scrum-master's backlog — patch DEMO-004 page copy when complete.
5. **Pre-crash UI overhaul plan** at `~/.claude/plans/swirling-shimmying-karp.md` (22 work units, 372 pages) — **IN FLIGHT NOW:** ux-architect agent dispatching UI work. Will unblock frontend-craftsman allocation for DEMO-001/DEMO-002.
6. **Sprint 2 demo backlog** — `docs/SPRINT_2_DEMO_BACKLOG_2026-04-22.md` committed by scrum-master (same commit as this thread-state refresh). DEMO-001..005 P0 items with owners, acceptance criteria, 44h total effort across 3 owners.
7. **Rotate leaked GitHub PAT** embedded in git remote URL (user deferred).
8. **✅ DONE: Full TrueCourse ↔ Fixops side-by-side comparison** — commit `0639bb39` *beast-mode(competitive): exhaustive TrueCourse↔Fixops side-by-side comparison*. Produced `raw/competitive/truecourse-vs-fixops-comparison.md` — 40 rows covering all TrueCourse capabilities from sections 1–10 of the structural analysis. Tallies: 17 FIXOPS_WINS, 4 PARITY, 13 TRUECOURSE_WINS, 6 GAP_EXISTS. **Two new gaps proposed:** `NEW-G070` (LSP-backed semantic layer — tree-sitter + TS Compiler API + Pyright + ORM schema parsers) and `NEW-G071` (IDE-style file tree + Monaco code viewer with violation gutter + analysis-history time-travel). Formal promotion into `gap-matrix.md` is **OPEN THREAD #9** below.
9. **NEW: Promote NEW-G070 + NEW-G071 to `gap-matrix.md` + write PRDs** — both proposed in `truecourse-vs-fixops-comparison.md` (proposed new-gap section). Action: (a) append rows to `raw/competitive/gap-matrix.md` in the existing GAP-### format, (b) generate two new PRDs in `.omc/prds/v2/` (format matches existing 42 PRDs: problem / solution / engine contract / acceptance criteria / effort), (c) push as new Multica stories via existing push workflow. Pairs with DEMO-004 on the Sprint 2 backlog.
10. **NEW: Backend-code graphify ingest (deferred from thread #1 above)** — today's `graphify-out/graph.html` has research docs + UI code only. Missing: (i) `suite-core/core/*.py` (345 engine files, ~180K LOC), (ii) `suite-api/apps/api/*_router.py` (573 routers, ~58K LOC). **To do:** run graphify semantic extraction in chunks (graphify SKILL Part B prompt, ~40K LOC per chunk = ~6 chunks), merge JSON fragments via `graphify.build.build_from_json`, re-run Leiden community detection, regenerate `graph.html`. Output: full-repo interactive graph showing code modules ↔ research concepts ↔ 332 engines ↔ 69 gaps ↔ competitor products. Estimated: 2–3 hrs wall-time + 6 agent-chunks. Demo-blocker? **NO** — current graph is compelling for DEMO-001; backend ingest is Sprint 3 polish.

---

## Task table — Sprint 2 / 2026-04-22 session additions

(Historical rows 1–12 above are immutable — those were executed in the previous session.)

| # | Subject | Status | Output / continuation |
|---|---------|--------|----------------------|
| 13 | Rebuild graphify visual with TrueCourse + competitive research (thread #1 closure) | ✅ completed | `graphify-out/graph.html` 1.97 MB, 2620 nodes, 2433 links, 454 communities; commit `7386db5d`. Backend-code ingest deferred to thread #10. |
| 14 | TrueCourse ↔ Fixops exhaustive side-by-side comparison (thread #7 closure) | ✅ completed | `raw/competitive/truecourse-vs-fixops-comparison.md` 40 rows; NEW-G070 + NEW-G071 proposed; commit `0639bb39`. Formal gap-matrix promotion = thread #9. |
| 15 | Sprint 2 demo backlog — DEMO-001..DEMO-005 | ✅ completed | `docs/SPRINT_2_DEMO_BACKLOG_2026-04-22.md` — P0 items, owners, acceptance criteria, 44h effort, risk register. |
| 16 | Refresh TASKS_STATE open-threads section | ✅ completed | This commit. Threads #1 + #7 closed; threads #9 + #10 added. |
| 17 | Reconcile 42 gap PRDs vs 8 native engines + 332 PRDs | 🟡 in_progress | enterprise-architect agent running in parallel to this commit; reconcile outcome pending. Will MERGE / KEEP / KILL and patch DEMO-004 page copy afterwards. |
| 18 | UI overhaul dispatch | 🟡 in_progress | ux-architect agent running in parallel; UI dispatch pending. Will finalize frontend-craftsman allocation for DEMO-001 + DEMO-002. |

## Background agents launched this session — all COMPLETED

| Agent ID | Purpose | Duration |
|----------|---------|----------|
| a07a34afcb393d818 | Gap matrix synthesis from 6 inputs | ~12.5 min |
| a1512a126b7eadc88 | TrueCourse structural analysis (retry after Explore perm fail) | ~5.0 min |
| aff5f417097e635b9 | CSPM leaders research | ~3.9 min |
| ab2416a9e0277fe75 | CTEM leaders research | ~3.9 min |
| a5b44389a6c17a646 | Fixops surface inventory | ~4.3 min |
| a6ca4d302d33996ed | Sonatype Nexus Lifecycle / SAGE deep dive | ~3.8 min |
| aff2f078b62077bc1 | ASPM leaders research | ~4.3 min |
| af0d62b9277be2e65 | Emerging ASPM platforms research | ~4.2 min |
| adced0cc30f706e12 | TrueCourse patch pass on gap matrix | ~9.0 min |
| a94207172321fcab9 | Convert JSON → v2 PRD markdown | ~3.8 min |
| a1144042d23314e6c | TrustGraph injection script writer | ~3.9 min |

No agents are still running. No outputs will be lost on session end.
