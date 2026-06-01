# ALDECI Pre-Mortem — $100K SCIF account, 5-year horizon

**Frame:** It is 2031. ALDECI was ripped out of the SCIF / lost the $100K renewal. We work backwards
from each way it died, grounded in the actual code (5 parallel audits: PM-1..PM-5). Goal: de-risk now.

**Target customer:** an air-gapped, classified (SCIF) organization. They pay $100K precisely because
they **cannot** use cloud LLMs/feeds/SaaS — so the *local* intelligence must be real, the product must
pass **accreditation (ATO)**, and it must be maintainable for 5 years by a small team.

---

## The 5 ways it died (ranked by how it kills the deal)

### 1. The "AI" wasn't AI in the air-gap (PM-1, PM-4) — KILLS THE VALUE STORY
Three months in, the SCIF analyst realizes the "multi-LLM consensus that gets smarter and proves
exploitability" is, air-gapped: a **CVSS→action lookup table** (council deterministic fallback), a
**pentest that returns HTTP 501 / random outcomes**, and a **blast-radius that returns 0** (attack-path
graph never populated from scans). The one real moat — Python reachability — wasn't even the sales pitch.
→ **This is the existential risk.** Free OSS (Trivy+DefectDojo+OpenVAS) matches it air-gapped.

### 2. It failed accreditation — NEVER GETS AN ATO (PM-2) — KILLS DEPLOYABILITY
12–18 months from ATO-ready. FIPS is **self-asserted, not validated** (`dilithium_py` has no CMVP cert;
`_check_fips()` returns True on non-Linux); RSA/ML-DSA private keys written **plaintext to disk**
(`crypto.py:679 NoEncryption()`); 100+ SQLite DBs **unencrypted at rest**; the **audit/evidence chain is
deletable** (no DELETE trigger); **SAML signature verification is bypassed** under `FIXOPS_DEV_MODE`;
**no PIV-CAC** (hard ICD-704 requirement, 4-6mo, zero code today). Worst: `compliance_engine.py:979`
**fabricates a passing encryption-at-rest check** — a Category I misrepresentation finding in a gov review.

### 3. A spillage incident / data loss (PM-3) — KILLS TRUST INSTANTLY
Tenancy is **whack-a-mole, not systemic**: 196/812 routers have zero org_id, 3007 routes use
`Query(default="default")`, 548/549 engines use raw sqlite paths, and `TenantContext` uses
**`threading.local` under asyncio** (coroutines share a thread → Request B can overwrite Request A's org).
In a classified env one cross-tenant leak = spillage = contract over. Plus: **SQLite single-node, no
replication/HA** → guaranteed data loss over 5yr; `delete_tenant_data()` leaves data in ~545 DB files
(right-to-purge claim is false).

### 4. It collapsed under its own weight (PM-5) — KILLS 5-YEAR MAINTAINABILITY (score 3/10)
**686 of 812 routers (84%) are dead/unmounted**; **no Python lockfile** + `dependabot.yml` ecosystem=""
(vuln scanning OFF) → non-reproducible, disqualified by procurement; **1,569 inline CREATE TABLE, no
migration framework** (cause of the NULL-id/bad-enum crashes we fixed today); **CI coverage floor 18%**;
**spec coverage 0.3%** (1 of ~325 families); pickle/eval/os.system in scan-data paths.

### 5. The air-gap leaked at boot (PM-1) — KILLS IT ON DAY ONE (but cheap to fix)
By default, Sentry (`observability.py:886`), HuggingFace model download (`vector_store.py:248`), cloud
LLM providers, and threat-feed fetchers all **fire unless `FIXOPS_AIRGAP_MODE=enforced`** is set. The
enforcement machinery is real and correct — it's just **not the default**. P0 config, hours of work.

---

## De-risk roadmap → specs (priority = blast-radius ÷ effort)

| # | De-risk | Owning spec | Effort | Kills which death |
|---|---------|-------------|--------|-------------------|
| P0 | Air-gap enforced-by-default: auto telemetry kill-switch + OFFLINE env + no cloud providers when classified | SPEC-005 | hours–days | #5 |
| P0 | Python lockfile + fix dependabot ecosystem + pin/SBOM the build | SPEC-009 | 1 day | #4 (procurement) |
| P0 | Remove compliance check that fabricates a pass; honest 503 | (SPEC-006 sub) | hours | #2 (Cat-I) |
| P1 | Local Nuclei pentest connector (real exploit verification, no SaaS) | SPEC-002 | 2–3wk | #1 |
| P1 | Local Qwen council: run distillation (5k threshold) + wire AirGapLLMProvider | SPEC-003 | 1.5wk | #1 |
| P1 | Auto-populate TrustGraph + attack-path from scans (blast-radius ≠ 0) | SPEC-005b | 1wk | #1 |
| P1 | Systemic tenancy: `TenantScopedEngine` base + ContextVar (not threading.local) + CI lint banning `Query(default="default")` & non-canonical get_org_id | SPEC-007 | 1–2wk | #3 |
| P1 | Litestream WAL→object-store replication (1s RPO) | SPEC-008 | 1wk | #3 (data loss) |
| P2 | FIPS-validated crypto boundary + encrypt keys/DBs at rest + immutable audit (DELETE trigger) | SPEC-006 | months | #2 |
| P2 | PIV-CAC / CAC auth | SPEC-006b | 4–6mo | #2 |
| P2 | Multi-language reachability (tree-sitter deps + auto-run on pipeline) | SPEC-004 | 1wk | #1 (breadth) |
| P2 | Dead-router purge (686) + CI gate on mounted==files; SQLite SchemaRegistry/migrations | SPEC-010 | 1wk | #4 |

## Honest bottom line for the founder
The product is **enterprise-commercial-credible today** (real ingest, findings, tenancy-after-fixes,
honest CSPM, Python reachability, evidence packs). It is **NOT SCIF-deployable today** and the gap is
**not vaporware — it's specific and mostly weeks, except accreditation (12–18mo) and PIV-CAC (4–6mo)**.
The single highest-leverage sequence to make the $100K honest: **P0 air-gap+lockfile+kill-the-fake-check
(this week) → SPEC-002 Nuclei + SPEC-003 local-LLM + SPEC-005b graph-populate (this month) → SPEC-007
systemic tenancy + SPEC-008 replication → then the long accreditation track (SPEC-006).**

Every line of this is grounded in PM-1..PM-5 (file:line evidence in the sibling docs).
