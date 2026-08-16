# Sellable-product backlog

Tasks derived from the ADRs in `docs/architecture/adr/`. Every task traces to a decision
and a measurement; nothing here is speculative scope.

Ordering is by **what unblocks a sale**, not by effort. Each task states its ADR, the
measured reason it exists, and the check that closes it.

---

## Track A — Stop looking broken (fastest credibility gain)

| # | Task | ADR | Done when |
|---|---|---|---|
| ~~A1~~ | ~~Unify credential-gated responses~~ — **DONE** `83c7eb6b`: `NotConfigured` + central handler; 14 routers migrated | 007 | ✅ kong/harbor/servicenow return 200 + `configured:false` + `required_env`; 35 tests |
| ~~A2~~ | ~~Fix the 4 remaining 404s~~ — **DONE** `e08685f1`: they were never missing. **55 concrete routes were unreachable behind earlier `{param}` routes** (14 under `/api/v1/connectors`); route ordering fixed once, after mount | — | ✅ Shadowed 55 → 0; all four return real data; 3 guard tests |
| A3 | Render not-configured as an onboarding affordance ("Connect Qualys"), not an error | 007 | A tenant with zero connectors sees next steps, never red |
| ~~A4~~ | ~~Rebuild the image~~ — **DONE** `a5b28b6c`: `.dockerignore` needed `**/` (Go filepath.Match doesn't cross `/`); stale DBs 53→11→**0**, image 2.89→2.69 GB | 006 | ✅ Clean image booted in 30s, **UAT 11/11**, fresh install reports 0 findings / 0 tenants / feeds `empty` |

## Track B — Shrink the repo to its real size

| # | Task | ADR | Done when |
|---|---|---|---|
| ~~B1~~ | ~~Delete the duplicate Python SDK~~ — **DONE** `c2c67f36`: removed `aldeci_security_intelligence_platform_client` (4,465 files); tracked 17,975 → 13,510 | 004 | ✅ One client name remains; its 48 tests pass |
| B2a | **Commit the core OpenAPI spec** — none exists today; the SDKs came from a spec that is gone | 004 | Core spec (454 paths / 238 schemas) tracked |
| B2b | **Write the SDK generator** against the core spec, verify it produces a working client | 004 | Regenerated client passes the 48 existing tests |
| B2c | Untrack `sdks/` (7,724 remaining files) and publish versioned packages — **only after B2a+B2b** | 004 | `git ls-files sdks/ \| wc -l` → 0 |
| ~~B3~~ | ~~CI guard against tracked build artifacts~~ — **DONE** `20ca6c98`: SDK count frozen at 7,724, duplicate client cannot reappear, `do not edit` files barred outside `sdks/`, content-hashed bundles rejected | 004 | ✅ 4 tests; the orphaned Vite bundle untracked (referenced by nothing) |
| B4 | Share the duplicated contract models (`CapabilityResponse` ×46, `ScanRequest` ×24) instead of re-declaring per router | 004 | Duplicate class-name count materially below 4,213 |

## Track C — Make the SCIF profile real

| # | Task | ADR | Done when |
|---|---|---|---|
| C1 | Introduce `FIXOPS_PROFILE ∈ {commercial, scif}`; `scif` enforces egress guard + FIPS and **fails closed** if a cloud provider is configured | 001 | `create_app()` raises under `scif` + cloud provider; egress refused at socket layer |
| C2 | Populate the council member set from profile; remove vendor names from council logic. **Partly present**: `_enforce_air_gap_providers()` already swaps external providers for `AirGapLLMProvider` and fails closed under ENFORCED | 002 | Council runs against a fake member set with no vendor reference in its code path |
| C3 | Replace `cost_usd > 0` as proof-of-real-call with a per-member response fingerprint — local inference legitimately costs nothing | 002 | Real-call detection passes for local models; fabricated verdicts still quarantined |
| C4 | Prove the air-gapped council — **script shipped** `331dae27` (`scripts/prove_airgap_council.py`): socket trip-wire, requires `is_real_inference=True` from ≥2 distinct local models. First run PROVEN (2 models, independent reasoning, 0 egress); needs a clean repeat on non-thrashing hardware | 001,002 | Green run recorded as evidence |
| C5 | Build the signed offline feed bundle (KEV + EPSS + NVD) with manifest, hybrid RSA-4096 + ML-DSA-65 signature, idempotent import | 003 | Tampered bundle refused; enrichment identical after live sync vs bundle import |
| C6 | Record feed-bundle version on every enrichment; surface bundle age and mark stale | 003 | A prioritisation decision is explainable months later |

## Track D — Narrow the surface

| # | Task | ADR | Done when |
|---|---|---|---|
| D1 | Flip `FIXOPS_CORE_MODE` to default-on; full surface becomes opt-in | 005 | Default OpenAPI path count within core budget; UAT 11/11 |
| D2 | Define core membership by evidence (tenant-varying data **and** a UI callsite) rather than by hand | 005 | Membership list is generated, not curated |
| D3 | Execute the dormancy plan for ~290 engine-domain orphans, in verified batches | 005 | Route count drops by the expected delta each batch; gates stay green |
| D4 | CI check: no UI route may point at an endpoint hidden in core mode | 005 | Guard fails a deliberate mismatch |

## Track E — Close the persistence debt

| # | Task | ADR | Done when |
|---|---|---|---|
| ~~E1~~ | ~~Lint rule for relative / `parents[N]` data paths~~ — **DONE** `331dae27`: ratchets debt (155 files, 360 uses) and rejects escapes outright; **found 2 more repo-escaping paths + a hardcoded `/home/user/...` dev path** | 006 | ✅ 4 tests; both escapes fixed |
| E2 | Migrate the **155 files** (measured; earlier 91 was a narrower pattern) that hardcode relative DB paths and ignore `FIXOPS_DATA_DIR` | 006 | Ratchet in `test_no_relative_db_paths.py` reaches 0 |
| E3 | Startup assertion: no two stores share a basename across locations | 006 | Boot fails loudly on a split store |

## Track F — Sharpen the wedge

| # | Task | ADR | Done when |
|---|---|---|---|
| F1 | Rename Families 1–2 from scanning to ingestion/normalisation across product, docs and UI | 009 | No surface claims a scan a normalizer merely ingests |
| F2 | Generate the supported-tool list from normalizers passing a round-trip fixture test | 009 | Marketing list is generated, not hand-maintained |
| F3 | Replace heuristic control effectiveness (avg risk < 0.6 → "effective") with control-specific criteria or "not assessed" | 008 | No conclusion in the bundle rests on the heuristic |
| F4 | Publish an offline bundle verifier; validate a `scif`-produced bundle on a machine with no network and no FixOps | 008 | Third party verifies without us |
| F5 | Full provenance in the bundle: finding → enrichment (+bundle version) → score inputs → council member set → human decision | 008 | Every conclusion traceable end to end |

---

## What I would do first

**A1 + A4 + B1.** They are cheap, they are measured, and together they change what a
prospect sees in the first ten minutes: nothing red that isn't genuinely broken, an image
free of our own data, and a repo that no longer looks like it contains a duplicate
product.

**Then C1–C4**, because the air-gapped council is the claim almost nobody else can make,
and it is the difference between one market and two.
