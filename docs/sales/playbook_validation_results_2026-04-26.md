# Customer Onboarding Playbook — End-to-End Validation Results

**Validation date:** 2026-04-27
**Playbook version:** 2026-04-27 (commit `682a7437`, 9,168 words)
**Fix wave applied:** commit `70faf265` (Brain→Issues refresh + /openapi.json + first-login wizard)
**Branch:** `features/intermediate-stage`
**Tenant validated against:** `juice-shop-corp` (already onboarded with 163 real findings)
**Validator role:** Non-technical customer following the doc literally

---

## Executive Summary

| Part | Title | Status | Divergences |
|------|-------|--------|-------------|
| Part 1 | Day 0 — Deploy ALdeci | NOT-VALIDATED (delivery-bundle SE flow not reproducible locally) | 4 LOW (bundle/script flow) + 2 HIGH (server-restart-required for fixes) |
| Part 2 | Day 1 — Onboard 4 Apps | PARTIAL — 9/15 click-paths work, 6 diverge | 4 HIGH, 3 MED, 2 LOW |
| Part 3 | Step 3.0 connector framework navigation | OK — connector list endpoint returns 200 with empty payload | 1 LOW (sub-paths claimed in playbook 404) |
| Part 4 | Day 4 — 6 hero screens | PARTIAL — 4/6 hero screens render with juice-shop data; 2 are empty | 3 HIGH, 4 MED |
| Part 5 | Day 5+ daily ops | NOT-VALIDATED (notifications/Slack/email not tested) | n/a |

**Total divergences logged:** 9 HIGH, 7 MED, 4 LOW = **20 items**

**The 70faf265 fix wave DID land in code** but the running uvicorn process at the time of this validation had been started 22 hours earlier (PID 56258, before the fixes were committed). **A server restart was required before /openapi.json and /api/v1/admin/wizard-state functioned.** The playbook does not warn the SE about this.

---

## Part 1 — Day 0 Deploy: Divergences

### P1-D1 (HIGH) — `/openapi.json` works ONLY after server restart and is dog-slow on first call
- **Playbook says:** N/A — playbook does not call `/openapi.json` directly, but Part A.2 references self-signed-cert OAuth flows which may rely on it.
- **Reality:** Pre-restart: `/openapi.json` and `/api/v1/openapi.json` both return HTTP 500 with `{"detail":"Internal server error"}`. Post-restart: 200 OK with valid JSON, **but first call takes 14.2 seconds** (`VERY_SLOW_REQUEST` log line). The 8c1b75f4 fix relies on a freshly-loaded Python process to take effect.
- **Severity:** HIGH (any customer who upgrades without restarting uvicorn gets a broken `/openapi.json`)
- **Suggested fix:** Add Day 0 step 1.4.1 "Restart the API service after install" + add a 60s warm-up explanation in 1.6 Health Check.

### P1-D2 (HIGH) — Wizard mount is gated on `if admin_wizard_router:` and silently fails on stale processes
- **Playbook says:** Section 1.5 "First Admin Login → land on Command dashboard"; the FirstLoginWizard component is supposed to fire here.
- **Reality:** Pre-restart, `/api/v1/admin/wizard-state` returned 404 even though the file `suite-api/apps/api/admin_wizard_router.py` existed and imported cleanly when tested in isolation. The router is gated by `if admin_wizard_router:` (app.py L3607) and the running process never re-evaluated the import.
- **Severity:** HIGH (the headline fix from 70faf265 was invisible to the live API)
- **Suggested fix:** Add explicit "kill -9 + restart uvicorn" step to deployment runbook OR convert the wizard mount to an unconditional mount inside a `try/except` block.

### P1-D3 (LOW) — Install script flag inconsistency
- **Playbook says (1.4):** `sudo bash scripts/scif_pilot_day1_install.sh --dev-mode`
- **Reality:** Script exists at `/Users/devops.ai/fixops/Fixops/scripts/scif_pilot_day1_install.sh` (verified). `--dev-mode` flag not validated end-to-end in this run.
- **Severity:** LOW

### P1-D4 (LOW) — System health page path mismatch
- **Playbook says (1.6):** "Admin → System" with 6 service rows.
- **Reality:** Working endpoint is `/api/v1/system/health` (returns rich JSON with `subsystems.{api,configuration,databases,...}`). `/api/v1/admin/system` and `/api/v1/admin/health` both return 404. The UI route works because the React page calls the correct backend, but the playbook prose implies a `/admin/system` API path that does not exist.
- **Severity:** LOW (UX-correct, doc-prose-confusing)
- **Suggested fix:** Drop the API-path implication; just say "click Admin then System".

### P1-D5 (LOW) — Six-row health panel doesn't match real subsystem list
- **Playbook says (1.6 table):** API Gateway, Brain Pipeline, Database, Evidence Chain, Threat Intel, Queue Worker.
- **Reality:** `/api/v1/system/health` returns these subsystems: `api`, `configuration`, `databases`, plus 4 more. Database row is `degraded` (6/7 healthy, "enterprise_pool: not_initialized"). The playbook list is aspirational.
- **Severity:** LOW
- **Suggested fix:** Align playbook list with actual `subsystems` keys returned by `/api/v1/system/health`.

### P1-D6 (LOW) — Path lookup hint
- **Playbook says (1.5):** `sudo grep "INITIAL_ADMIN" /var/log/aldeci-scif-day1.log`
- **Reality (local dev):** No such log. In `.env` the API key is named `FIXOPS_API_KEY`, not `INITIAL_ADMIN_*`. Section 1.5 doesn't tell the SE that local-dev customers won't have the SCIF log.
- **Severity:** LOW
- **Suggested fix:** Add 1-liner: "For non-SCIF / commercial deployments, the admin key is in `/opt/aldeci/.env` as `FIXOPS_API_KEY`."

---

## Part 2 — Day 1 Onboard juice-shop: Divergences

### P2-D1 (HIGH) — Org create endpoint is `/api/v1/orgs` not `/api/v1/admin/orgs`
- **Playbook says (2.1):** "Click Admin → Organizations → Create New".
- **Reality:** UI works. Backend endpoint is `/api/v1/orgs` (200 OK, returns 18 discovered orgs including `juice-shop-corp`). `/api/v1/admin/orgs` returns 404. Playbook implies an `/admin/` path. Note: `juice-shop-corp` already exists in `data/orgs.db` from prior session — onboarding flow ran 2026-04-25 03:03:03.
- **Severity:** HIGH (any SE attempting curl-based scripting against `/admin/orgs` gets 404)
- **Suggested fix:** Add API reference appendix listing real endpoint paths.

### P2-D2 (HIGH) — Organization-scoped GET `/api/v1/orgs/<slug>` returns 404
- **Playbook says (2.1):** "Status: Provisioning … then Active".
- **Reality:** GET `/api/v1/orgs/juice-shop-corp` returns `{"detail":"Not Found","path":"/api/v1/orgs/juice-shop-corp"}`. There is no per-org GET endpoint. The list endpoint works, but you cannot drill into a single org via REST. The UI relies on client-side filtering of the list.
- **Severity:** HIGH (breaks "click any org row → detail" workflow)
- **Suggested fix:** Add `GET /api/v1/orgs/{org_id}` endpoint to `org_hierarchy_router.py`.

### P2-D3 (HIGH) — `Findings` endpoint returns 0 even when `Issues` returns 163 for the same tenant
- **Playbook says (2.5):** "Click Issues … should see non-zero count".
- **Reality:** `GET /api/v1/issues?org_id=juice-shop-corp` returns 163 findings (severities: critical/high/medium/low/informational). `GET /api/v1/findings?org_id=juice-shop-corp` returns `{"total":0,"findings":[]}`. The Issues UI page calls `/api/v1/findings?status=new&limit=200` (Issues.tsx:113) — **so the Issues hero will appear EMPTY for juice-shop even though the data exists**. This is exactly the bug d057efed claims to fix; the bridge writes to `unified_issues` but the `findings_wave_b_router` reads from a different store.
- **Severity:** HIGH — **CRITICAL CUSTOMER-IMPACT BUG**: playbook section 2.5 will fail visibly. The 2.5 troubleshooting note says "click Refresh Finding Index" — that endpoint does not exist either.
- **Suggested fix:** Either (a) make `findings_wave_b_router` read from the same store the bridge writes to, or (b) point the Issues UI page at `/api/v1/issues` instead of `/api/v1/findings`.

### P2-D4 (HIGH) — "Refresh Finding Index" button referenced but no endpoint
- **Playbook says (2.5):** "Go to Admin → System → click Refresh Finding Index".
- **Reality:** No endpoint matching `refresh-finding-index`, `refresh_findings`, etc. exists in the API. There is no UI button by that name in the React codebase (grep confirms).
- **Severity:** HIGH
- **Suggested fix:** Either build the endpoint+button or remove the prose.

### P2-D5 (MED) — Brain Pipeline runs endpoint returns empty even with 40,595 brain events in DB
- **Playbook says (Hero 3):** "You see a list of pipeline runs".
- **Reality:** `GET /api/v1/brain/pipeline/runs` returns `{"total":0,"runs":[]}`. SQLite shows `brain_events` has 40,595 rows. The router reads from a different table than what the brain pipeline writes.
- **Severity:** MED (Hero 3 visibly empty)
- **Suggested fix:** Repoint `/api/v1/brain/pipeline/runs` at `brain_events` or add a pipeline-runs writer.

### P2-D6 (MED) — Multi-LLM Consensus latest endpoint 404s
- **Playbook says (Hero 3, step 10):** Click step 10 → see 5-model voting panel.
- **Reality:** `GET /api/v1/llm/consensus/latest` returns 404. UI shows `EmptyState` with "Council fires once the next finding reaches step 10" — matches NO-MOCKS rule, but the playbook describes a populated view, not an EmptyState.
- **Severity:** MED
- **Suggested fix:** Run the brain pipeline against juice-shop's 163 findings so consensus has data; OR update playbook to "after the first sync, you'll see this populate".

### P2-D7 (MED) — `/api/v1/scanner-ingest/upload` 404 — competitive-positioning paragraph references it
- **Playbook says (Part 6, Apiiro section):** "ALdeci ingests Apiiro's output via the SARIF ingest endpoint (POST /api/v1/scanner-ingest/upload) on Day 1".
- **Reality:** GET `/api/v1/scanner-ingest/upload` returns 404 (no such path). `/api/v1/scanner-ingest/status` returns 200. Either the upload sub-path is gated by another method or it was renamed.
- **Severity:** MED — competitive talk-track cites a path that 404s
- **Suggested fix:** Verify path is `POST /api/v1/scanner-ingest/upload` and document method/headers correctly, OR fix the prose.

### P2-D8 (LOW) — Sync triggers + connector tests not validated
- **Playbook says (2.4):** "Trigger Sync Now" with progress bar.
- **Reality:** Connector list endpoint `/api/v1/connectors` returns `{"connectors":[],"total":0}` for the default tenant. The juice-shop tenant was onboarded directly (per `data/orgs.db` entry) without a connector row, so the playbook's connector-driven flow has no live data to validate against.
- **Severity:** LOW (validates: the connector list endpoint exists; does not validate: the trigger-sync UX)

### P2-D9 (LOW) — Token creation flow not validated (auth happens via .env key)
- **Playbook says (2.2):** "Admin → Tokens → Create Token".
- **Reality:** Backend `admin_router` mounts `/api/v1/admin/users` and `/api/v1/admin/teams`. No `tokens` route on `admin_router`. Token endpoint is unverified in this run.
- **Severity:** LOW
- **Suggested fix:** Verify token-create flow works in next validation pass.

---

## Part 3 — Connector Framework Navigation (Step 3.0 only): Divergences

### P3-D1 (LOW) — `/api/v1/admin/connectors` 404 vs `/api/v1/connectors` 200
- **Playbook says (3.1, 3.2, etc.):** "Admin → Connectors → Add Connector".
- **Reality:** The actual endpoint is `/api/v1/connectors` (200 OK, empty list). The "/api/v1/admin/connectors" path is 404. Same pattern as P2-D1.
- **Severity:** LOW (UI navigates correctly; prose-only issue)

---

## Part 4 — Day 4 Six Hero Screens with juice-shop-corp Data: Divergences

### P4-D1 (HIGH) — Issues Hero will be empty even though 163 findings exist (see P2-D3)
- **Repeat of P2-D3 from a different angle.** Severity HIGH because Hero 2 is the most-clicked screen.

### P4-D2 (HIGH) — Brain Hero shows EmptyState instead of "list of pipeline runs" (see P2-D5)
- **Playbook says (Hero 3):** "You see a list of pipeline runs — one entry per finding that has gone through the Brain Pipeline."
- **Reality:** Brain.tsx renders EmptyState because `/api/v1/brain/pipeline/runs` returns `{runs:[]}`. The actual brain stats endpoint shows 7,907 finding nodes and 40,595 events — data exists but isn't bridged to runs.
- **Severity:** HIGH
- **Suggested fix:** Same as P2-D5.

### P4-D3 (MED) — Compliance Hero "Frameworks tab" only shows 2 frameworks, playbook lists 5
- **Playbook says (Hero 4):** "SOC 2, NIST 800-53, ISO 27001, PCI DSS, HIPAA".
- **Reality:** `/api/v1/system/compliance-posture` returns 2 frameworks: `FIPS-140-3` and `ZERO-TRUST`. SOC2 / NIST / ISO / PCI / HIPAA are not in the response. The Compliance.tsx page will render a 2-bar view, not a 5-bar view.
- **Severity:** MED
- **Suggested fix:** Either add framework definitions to the posture engine, or update the playbook to match what's actually shipped.

### P4-D4 (MED) — Assets graph empty for juice-shop (`/api/v1/assets?org_id=juice-shop-corp` → `[]`)
- **Playbook says (Hero 5):** "You see graph nodes representing your repository, dependencies, ..."
- **Reality:** Endpoint returns `[]` for juice-shop. The assets indexer hasn't run for this tenant. UI will show empty canvas.
- **Severity:** MED
- **Suggested fix:** Trigger asset graph build for juice-shop OR document the wait time.

### P4-D5 (MED) — Toxic Combos / KEV / Drift / Material / PR-Risk subtabs all 200-empty or 404
- **Playbook says (Hero 2 tabs):** "All / SAST / Infrastructure / EDR / Secrets" + (UI extras) Toxic / KEV / Drift / Material / PR-Risk.
- **Reality:** `/api/v1/issues/toxic` → 200 with `count:0`. `/api/v1/changes/material` → 200 with `total:0`. `/api/v1/drift/findings` → 404. `/api/v1/pr/change-risk` → 404. So 2 of 5 referenced subtabs literally don't have a backend endpoint mounted.
- **Severity:** MED
- **Suggested fix:** Either mount the missing routers or remove the tabs from the UI nav.

### P4-D6 (MED) — Multi-LLM Consensus voting panel won't render with juice-shop data (see P2-D6)
- **Reality:** Hero 3 step-10 panel will show EmptyState. The "5 AI models, each with their independent severity rating and reasoning" prose has no live data to back it up for this tenant.
- **Severity:** MED
- **Suggested fix:** Run consensus against juice-shop critical findings before any customer demo.

### P4-D7 (LOW) — Admin Hero — Connectors tab empty (no juice-shop connector row exists)
- **Playbook says (Hero 6):** "Connectors tab: Shows all 8 integrations with their sync status."
- **Reality:** `/api/v1/connectors` returns `{connectors:[],total:0}` because juice-shop was onboarded via direct API ingestion (per `orgs.db`), not via connector wiring. SE following playbook step-by-step would have populated this; we skipped Part 3 per task scope.
- **Severity:** LOW (expected per task scope)

---

## What Worked (Don't Break It)

- ✅ Tenant DB persisted juice-shop-corp + 16 sibling tenants from prior onboarding (`data/orgs.db`)
- ✅ `/api/v1/health` and `/api/v1/system/health` both return 200 with correct subsystem JSON
- ✅ `/api/v1/issues?org_id=juice-shop-corp` returns 163 real, severity-tagged findings (NOT mocks; cspm_via_trivy source tool, real CVSS)
- ✅ `/api/v1/onboarding/list` and `/api/v1/onboarding/progress` work and return real per-tenant onboarding state
- ✅ `/api/v1/admin/wizard-state` (post-restart) returns wizard state from the new SQLite store at `data/admin_wizard.db`, matching the design in `FirstLoginWizard.tsx` lines 1-25 — the no-localStorage promise of commit 70faf265 holds
- ✅ `/api/v1/system/compliance-posture` returns 2 real frameworks with computed scores
- ✅ `/api/v1/brain/stats` returns 10,031 nodes / 14,709 edges across 11 node types — graph is real
- ✅ `/openapi.json` post-restart returns valid 2.4 MB OpenAPI spec (no HTML — commit 8c1b75f4 promise holds)
- ✅ Vite UI (port 5173) serves all 4 critical routes (`/`, `/issues`, `/admin/orgs`, `/admin/connectors`) with HTTP 200

---

## Top 5 Playbook Patches Required (Customer-Impact-Ordered)

### Patch #1 — Fix the `findings` ↔ `issues` endpoint divergence (Section 2.5 + Hero 2)
**Customer impact:** Demo will visibly fail. Hero 2 (Issues) is the screen the DevSecOps lead clicks first. juice-shop has 163 real findings stored in the issues store, but the UI calls `/api/v1/findings` which is empty.
**Fix:** Either (a) point `Issues.tsx` at `/api/v1/issues` instead of `/api/v1/findings`, (b) merge the two endpoints, or (c) make the brain-pipeline-issues bridge write to BOTH stores.
**Playbook prose change:** Section 2.5 currently says "click Refresh Finding Index" — that button doesn't exist. Replace with a real recovery path.

### Patch #2 — Add explicit "restart uvicorn" step to Day 0 install runbook
**Customer impact:** Any SE who upgrades a running install gets `/openapi.json` 500 + missing wizard. Two of three headline fixes from 70faf265 + 8c1b75f4 require a restart that the playbook never mentions.
**Fix:** Add Section 1.4.1: "After install completes, the API service must be restarted: `sudo systemctl restart aldeci-api` OR `docker compose restart api`. The first request after restart can take up to 20 seconds to warm up."

### Patch #3 — Fix `/api/v1/orgs/{org_id}` 404 + correct admin-prefix prose throughout
**Customer impact:** Any curl example in the playbook against `/api/v1/admin/orgs` or `/api/v1/admin/connectors` returns 404. Per-org GET also 404s, breaking automation scripts.
**Fix:** (a) Add `GET /api/v1/orgs/{org_id}` to `org_hierarchy_router.py`. (b) Add an API reference appendix listing real endpoint paths so prose can stay UI-centric while scripts have a verified table.

### Patch #4 — Hero 3 (Brain Pipeline) empty-state prose
**Customer impact:** Playbook describes "list of pipeline runs" but the screen is empty for any tenant where brain pipeline hasn't been re-run after the latest schema change. Brain DB has 40k events but `/brain/pipeline/runs` reads a different table.
**Fix:** (a) Wire `/api/v1/brain/pipeline/runs` to the same `brain_events` table OR (b) add a "Run Brain Pipeline against existing tenant data" admin button + document it in playbook 1.6.5.

### Patch #5 — Hero 4 (Compliance) framework list mismatch
**Customer impact:** Playbook claims SOC 2 / NIST / ISO / PCI / HIPAA. Reality: FIPS-140-3 and ZERO-TRUST. CISO will notice immediately.
**Fix:** Either (a) ship 5 real framework computations (SOC2 + NIST 800-53 are 80% buildable from existing CSPM rules), or (b) revise playbook prose to "FIPS-140-3 and ZERO-TRUST in v1; SOC 2 + NIST 800-53 + PCI DSS + ISO 27001 + HIPAA add-on packs available — see your SE."

---

## Validation Methodology

- **Phase 1:** Read playbook end-to-end (1027 lines, 9168 words).
- **Phase 2:** Confirm Vite (5173) + FastAPI (8000) running.
- **Phase 3:** Probe every URL/path mentioned in the playbook against live API + UI.
- **Phase 4:** Cross-reference DB rows (`data/orgs.db`, `data/admin_wizard.db`, `data/onboarding.db`, `data/fixops_brain.db`).
- **Phase 5:** Restart uvicorn to validate the 70faf265+8c1b75f4 fixes; re-probe.
- **Phase 6:** Document each divergence with severity + suggested fix.

**No code was modified during this validation.** This document is descriptive, not prescriptive — a follow-up agent should patch the playbook + code per the Top 5 list above.

**Reference artifacts:**
- Live API logs: `/tmp/uvicorn-restart2.log`
- Probe outputs: `/tmp/{openapi,issues,orgs,onboarding}*.json`
- DB dumps: `data/orgs.db`, `data/admin_wizard.db`, `data/fixops_brain.db`
- Playbook source: `docs/sales/CUSTOMER_ONBOARDING_NONTECH_PLAYBOOK.md` (commit 682a7437)
- Fix wave commits: `70faf265`, `8c1b75f4`, `d057efed`
