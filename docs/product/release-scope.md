# FixOps — First-Customer Release Scope

> **Purpose**: be strict about what a **stable, customer-deliverable first release** must
> include vs. what is explicitly later/out — so the spec→task→implement loop has a fixed target
> and "build the whole thing" scope-creep is rejected.
> Companion to `docs/architecture/system-overview.md` (risks R1–R10) and `docs/GAP_MAP.md`.
> **Last updated**: 2026-06-21. Items cite the risk/gap they close.

## Definition of "first customer"
A single on-prem / air-gapped tenant (one customer's SCIF) that ingests their existing scanner
output and gets real, isolated, non-fabricated security intelligence. **Not** multi-region SaaS,
**not** a self-service signup. (Deployment model per `system-overview.md §0`.)

---

## IN SCOPE — required for first-customer delivery (release blockers)
Each must be real (no mocks), tenant-isolated, and CI-gated.

| Capability | Status today | Gate to close |
|---|---|---|
| **Ingest → findings core path** (upload scanner output → real, deduped, org-scoped findings) | ✅ Works + gated (`test_customer_journey_e2e`, `b9408c27`) | Keep gate green |
| **Multi-LLM council verdict** (real, `cost_usd>0`, never fabricated) | ✅ Real; CI-safe + nightly-live gates (SPEC-032) | Keep nightly live gate (needs `OPENROUTER_API_KEY` secret) |
| **TrustGraph correlation** (graph-enriched verdicts) | ✅ Engine real (GAP_MAP #1) | Add CI gate (R3); wire a UI consumer (C7) |
| **Tenant isolation** (router + schema) | ⚠️ Routers fixed (`b9ac25ff`); **schema migration outstanding** (R1) | SPEC-034 + `org_id` columns + isolation test — **release blocker** |
| **Auth + honest-empty everywhere** | ✅ api-key auth router-level; ingest-first honest-empty gated (SPEC-027/029) | Finish NO-MOCKS residue (R6: feeds MITRE list #10) |
| **Core UI flows, no mocks** (findings, dashboard, council verdict, evidence) | ⚠️ Core wired + NO-MOCKS gate (SPEC-028); contracts unpinned (R7) | SPEC-033 contract baseline for C1–C6/C9 |
| **Evidence chain-of-custody** (honest, signed) | ✅ Real (SPEC-019) | Pin contract (C9) |
| **On-prem/air-gap deploy that boots** | ⚠️ docker + air-gap workflow exist | Verify a clean from-scratch boot + smoke on target |
| **Durability** (no silent data loss) | ❌ WAL replication NOT configured (R10) | Wire litestream OR document accepted RPO for v1 |
| **Green release gates** | ⚠️ ~8/54 capabilities gated (R3) | SPEC-035 gate matrix + make pip-audit bite (R5) |

## LATER — valuable, not required for the first customer
- Consolidate the **299-page UI** into the core enterprise screens (UX consolidation).
- All **11 vendor live connectors** (ship the ingest + a couple; rest on demand).
- **MPTE consensus execution** — `_execute_step` is currently an explicit stub (GAP_MAP #8);
  MPTE *exploitability scoring* can ship; multi-AI consensus *execution* is later.
- **Deception UI** wiring (engine real, no UI consumer — GAP_MAP #11).
- **Full UI↔API contract coverage** beyond the top-10 (C1–C10 first).
- Learning-loop polish (DPO/distillation), ReasoningBank depth.
- Schema source-of-truth consolidation beyond the critical tables (R4 — do critical now, rest later).

## OUT OF SCOPE — explicitly NOT v1 (founder-gated / strategic)
Do not let these enter a release slice without an explicit founder decision.
- **FIPS-CMVP certification** — product supports a FIPS boundary (`core/fips_boot.py`); the *cert*
  is a months-long process, not code. (memory `feedback_no_soc2_onprem_airgap`)
- **PIV / CAC hardware auth** — gov requirement, founder/hardware-gated.
- **Vendor SOC2** — N/A for an on-prem product (the customer's ATO is the bar).
- **Stripe billing / tiered-pricing automation** — business, not first-delivery.
- **GPU local distillation** (Phase-2 LLM distill) — infra-gated.
- **org-query-vs-header precedence** redesign (`test_org_id_query_overrides_header`) — a
  deliberate, founder-gated precedence decision.
- **`aldeci-core` vs `Fixops` repo-of-truth migration** (R9) — founder decision; until then,
  main is 813 commits stale and merge is blocked.
- **Multi-region / multi-tenant SaaS** — different product shape.

## Exit criteria (first-customer "done")
1. All IN-SCOPE gates green on PR→main (SPEC-035).
2. Tenant isolation proven end-to-end (router + schema + fresh-org-sees-0 test) — SPEC-034.
3. Durability configured or RPO explicitly accepted by founder — R10.
4. Top-10 UI↔API contracts pinned with contract tests — SPEC-033.
5. No NO-MOCKS violations on customer-facing endpoints (GAP_MAP realness=mixed swept).
6. Branch merged to the agreed repo-of-truth with gates green — R9 (founder).

> Tracked via `SPEC-037 — First-customer release checklist` (`system-overview.md §9`).
