# Router / API Consolidation Plan — 2026-07-09

> The router consolidation was **audited but never executed.** This is the actionable plan.
> All numbers measured this session against `create_app()`.

## Current reality (measured)
| Metric | Value |
|--------|-------|
| Router files (`suite-api/apps/api/*_router.py`) | **813** |
| Engines (`suite-core/**/*_engine.py`) | 473 |
| Mounted route entries | **8,346** |
| Distinct `(method, path)` | 7,532 |
| **Exact-duplicate route entries** | **814 (10%)** across **729 groups** |
| Paths mounted >1 time | 1,432 |

## The three problems
1. **Duplicate routes (waste + risk).** 729 groups where the *same* `(method, path)` is mounted by
   multiple routers — e.g. `GET /api/v1/integrations` ×5, `/api/v1/workflows` ×4, `/api/v1/findings` ×3.
   Only one handler ever wins; the rest are dead weight and a shadow-collision hazard (which handler
   answers is mount-order-dependent and can silently change).
2. **Catch-all sprawl.** 104 routers match "security", 34 paths under `/analytics`, 19 `/webhooks`,
   17 `/evidence-collector`, 16 `/risks`… i.e. one domain split across dozens of tiny routers instead
   of one cohesive module.
3. **Dead-weight.** A long tail of routers with **no UI consumer** and **no real connector** (honest-empty
   or seed-only) — negative value (maintenance, attack surface, "master of none").

## Target architecture: 813 routers → ~25 domain modules
Collapse the ~40 keyword buckets into cohesive domains, one router module each (sub-routes inside):

| # | Domain module | Absorbs (today's buckets) |
|---|---------------|---------------------------|
| 1 | Ingest & Normalization | scanner, normalize, sbom, connector |
| 2 | Vulnerability Management | vuln |
| 3 | Findings, Dedup & Correlation | findings, dedup, correlation |
| 4 | Risk Scoring | risk, risks |
| 5 | Threat Intelligence | threat, intel, hunting |
| 6 | CSPM / Cloud Posture | cloud, cspm, posture |
| 7 | ASPM / Asset | asset, appsec |
| 8 | CTEM / Exposure | exposure, attack-surface |
| 9 | Offensive / MPTE | attack, pentest, mpte, exploit |
| 10 | AI / Council | llm, ai_, agent |
| 11 | Evidence & Attestation | evidence, evidence-chain, evidence-collector |
| 12 | Compliance & Governance | compliance, compliance-planner, governance |
| 13 | SOAR / Response | soar, incident, response, remediation, playbooks, workflows |
| 14 | Detection / SIEM | detection, siem |
| 15 | Identity & RBAC | identity, policy, auth |
| 16 | Data & Privacy | data, privacy |
| 17 | Audit | audit |
| 18 | Reporting & Dashboards | report, reports, dashboard, analytics |
| 19 | Integrations & Webhooks | integrations, webhook, transfer, gateway |
| 20 | Supply Chain | supply-chain, sbom |
| 21 | IoT / OT Security | iot-security |
| 22 | Platform / Admin | health, config, admin, tenant |
| 23–25 | (reserve for genuinely distinct domains surfaced during merge) | — |

Expected route count after: **~5,000–6,000 distinct** (drop the 814 dups + fold sprawl), with the
*real product core* (~15–30 engines, ~80–150 routes) clearly separable for productization.

## Phased execution (safe → structural)

### Phase 0 — Freeze
No new routers. Any new endpoint joins an existing domain module. (Enforce via a CI check counting routers.)

### Phase 1 — Kill the 729 duplicate groups  ← IN PROGRESS
**CRITICAL FINDING (pilot, 2026-07-10): duplicate dedup is SECURITY-SENSITIVE, not mechanical.**
The 729 groups split: **600 "identical-handler" (same module.fn) + 129 different-handler shadow
collisions.** But even the 600 "identical" ones are NOT uniformly safe — many mount the SAME endpoint
function with **different auth dependencies** across mounts (e.g. `evidence_chain_router` was mounted
3×: two authenticated, one with NO auth). Which mount wins is **registration-order-dependent**, so:
- Blindly removing "a duplicate" can delete the authenticated mount and leave an **unauthenticated**
  one exposed → a NEW vulnerability. Dedup must be **auth-aware**.
- Some duplicates are latent **auth-shadow security bugs** that dedup should FIX (keep the
  authenticated first-winner; remove unauth/redundant mounts).

**Root cause:** routers are mounted via 182 direct `include_router` calls in `app.py` **plus** 5 sub-app
registrars (aspm/cspm/ctem/grc/platform). 644 redundant mounts come from **70 modules** double/triple-mounted
across these paths.

**Safe per-module procedure (proven on the pilot):**
1. Find every mount of the router (app.py + all registrars); record each mount's auth dependencies.
2. Keep exactly ONE mount: the **authenticated, first-registered** one (the current winner). Remove the rest
   (dead unauth shadows first — pure security win; then redundant authenticated mounts).
3. Verify: `create_app()` boots + route count drops by the exact expected delta + **all surviving routes
   for that path carry auth deps** (0 unauth survivors) + change-gate smoke.
4. Commit atomically per module.

Pilot done: `evidence_chain_router` — removed dead unauth shadow, 8346→8332, 0 unauth survivors (commit 0061cb07).

### Phase 2 — Collapse sprawl into domain modules
Per domain (start with the worst: security 104, analytics 34): move routes into one module `APIRouter`,
delete the emptied router files. One domain at a time, fully verified before the next.

### Phase 3 — Dormant the dead-weight
Routers with no UI callsite AND no real connector → move to a `dormant/` namespace, unmounted (don't
delete — sunk cost), stop maintaining. Frees test/attack surface.

## Safety methodology (non-negotiable — the boot-crash lesson)
After **every** change:
1. `python -c "from apps.api.app import create_app; create_app()"` — must import (no boot crash).
2. Route count moves by exactly the expected delta (no accidental drops).
3. Grep for `Depends(<renamed>)` / stale imports before deleting a router.
4. Run the change-gate smoke suite. Commit per-domain (atomic, revertible).

## Targets
- Phase 1: **-814 route entries, -~600 shadow mounts, 0 functionality loss.** (days)
- Phase 2: **813 → ~25 router modules.** (weeks, one domain at a time)
- Phase 3: dead-weight unmounted; the sellable core (~30 engines) cleanly separable.

## Honest scope note
Phase 1 is a safe, mechanical quick win. Phases 2–3 are a multi-week refactor with real boot-crash
risk on 8,346 routes — do them incrementally, per-domain, gate-verified, never in one big sweep.

---

## Phase 1 progress — 2026-07-10 (autonomous safe-set COMPLETE)

**6 verified batches. 8346 → 7940 routes (−406). Distinct (method,path) held at 7532
the entire time → ZERO functionality lost.** Every batch verified by distinct-path
invariance (the definitive test) + boot + all-survivors-authenticated. Commits
0061cb07, b9438404, 54f6f338, a3e54a45, 52192988, eef6f85e.

- ✅ **All 42 all-auth redundant routers deduped** (the safe autonomous set is done).
- Remaining duplicates (~408 entries) are all in founder-decision categories below.

### FOUNDER DECISIONS (yielded — genuine blockers)

**A. Live auth-bypass — 3 NAC endpoints (SECURITY, decide first):**
`GET/POST /api/v1/nac/policies`, `GET /api/v1/nac/stats` are served **unauthenticated**
(an authenticated mount exists but is shadowed). Decision: is NAC meant to be public
(unlikely) or should the authenticated mount win? If fix → remove/reorder the unauth
mount so auth wins. (Slack /api/v1/slack/* unauth is INTENTIONAL — signature-verified
webhooks — leave.)

**B. 14 mixed auth/unauth routers** — for each, decide if the unauth mount is intentional
(webhooks/bots) or a shadow to remove. Only 6 are live-unauth (3 NAC + 3 Slack); the rest
are dead shadows (safe to remove for hygiene).

**C. 129 different-handler collisions** — same path, DIFFERENT code (e.g.
api_security_engine_router vs api_security_mgmt_router). Pick the canonical handler per
path. Needs a worksheet + founder review; cannot be auto-deduped.

### Before merge to main
Full change-gate suite + a fly canary (this touches routing on the deployed app).
