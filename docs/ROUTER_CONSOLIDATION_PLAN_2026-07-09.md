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

### Phase 1 — Kill the 729 duplicate groups  ← START HERE (safe, high-ROI)
For each duplicate `(method, path)`: keep the **canonical** mount (the one in the owning domain module),
remove the shadow mounts. **No functionality loss** — only one handler was ever reachable.
- Deterministic, scriptable: enumerate dups, diff the handlers (flag the ~131 where handlers *differ* —
  those need a human to pick the correct one), auto-drop the identical ones.
- Verify after each batch: `import` the app + `len(create_app().routes)` drops by the removed count + smoke.

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
