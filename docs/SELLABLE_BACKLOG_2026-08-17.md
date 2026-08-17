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
| ~~A3~~ | ~~Not-configured as onboarding, not error~~ — **DONE** `50e3b945`: `/api/v1/integrations/catalog` generated from the runtime declarations; a fresh tenant sees 14 connectable integrations with exact env vars. UI already rendered unconfigured as neutral, not red | 007,009 | ✅ 6 tests incl. catalogue-matches-runtime |
| ~~A4~~ | ~~Rebuild the image~~ — **DONE** `a5b28b6c`: `.dockerignore` needed `**/` (Go filepath.Match doesn't cross `/`); stale DBs 53→11→**0**, image 2.89→2.69 GB | 006 | ✅ Clean image booted in 30s, **UAT 11/11**, fresh install reports 0 findings / 0 tenants / feeds `empty` |

## Track B — Shrink the repo to its real size

| # | Task | ADR | Done when |
|---|---|---|---|
| ~~B1~~ | ~~Delete the duplicate Python SDK~~ — **DONE** `c2c67f36`: removed `aldeci_security_intelligence_platform_client` (4,465 files); tracked 17,975 → 13,510 | 004 | ✅ One client name remains; its 48 tests pass |
| ~~B2a~~ | ~~Commit the core OpenAPI spec~~ — **DONE** `3f548f8d`: `contracts/openapi-core.json` (454 paths / 238 schemas / 1.07 MB) + exporter with `--check` that fails on drift | 004 | ✅ Verified both ways: OK on match, FAIL after removing one path |
| ~~B2b~~ | ~~Write the SDK generator~~ — **DONE** `b37a30fd`: `scripts/generate_sdk.py` regenerates 1,134 modules from the contract and verifies the client imports. (The 48 tests turned out to exercise the *hand-written* `core/aldeci_client.py`, not the generated package) | 004 | ✅ `--check` regenerates + imports in a clean interpreter |
| ~~B2c~~ | ~~Untrack `sdks/`~~ — **DONE** `8ab54ee6`: tracked files **13,529 → 5,805**. Nothing consumed it (skip-guarded tests only; UI imports no TS client). Ratchet lowered 7,724 → 0 | 004 | ✅ 869 tests pass; `sdks/` still on disk + regenerable |
| ~~B3~~ | ~~CI guard against tracked build artifacts~~ — **DONE** `20ca6c98`: SDK count frozen at 7,724, duplicate client cannot reappear, `do not edit` files barred outside `sdks/`, content-hashed bundles rejected | 004 | ✅ 4 tests; the orphaned Vite bundle untracked (referenced by nothing) |
| B4 | Share the duplicated contract models (`CapabilityResponse` ×46, `ScanRequest` ×24) instead of re-declaring per router | 004 | Duplicate class-name count materially below 4,213 |

## Track C — Make the SCIF profile real

| # | Task | ADR | Done when |
|---|---|---|---|
| ~~C1~~ | ~~`FIXOPS_PROFILE` switch~~ — **DONE** `15039942`: `scif` turns on egress guard + FIPS, refuses to boot on a reachable cloud key, and rejects a typo'd profile rather than defaulting | 001 | ✅ `create_app()` raises `ProfileViolation`; commercial unaffected (7,940 routes, UAT 11/11); 14 tests |
| C2 | Populate the council member set from profile; remove vendor names from council logic. **Partly present**: `_enforce_air_gap_providers()` already swaps external providers for `AirGapLLMProvider` and fails closed under ENFORCED | 002 | Council runs against a fake member set with no vendor reference in its code path |
| ~~C3~~ | ~~Replace `cost_usd > 0` as proof-of-real-call~~ — **DONE** `deca8b6c`: guard now reads `is_real_inference`; **under `scif` every genuine local verdict was being discarded**, silently disabling self-learning | 002 | ✅ 6 tests pinning the decision table |
| C4 | Prove the air-gapped council — **script shipped** `331dae27`. Mechanic PROVEN (2 distinct local models, independent reasoning, **0 egress**). **Hardware-bound**: laptop CPU takes >10 min on the six-key verdict prompt vs ~5s for a trivial one, so repeats time out and fall back to labelled heuristics. Recorded in ADR-002 as a sizing requirement | 001,002 | Green run on inference-sized hardware |
| ~~C5~~ | ~~Signed offline feed bundle~~ — **DONE** `c4cbdc4e`: **found verification was OPTIONAL** (a manifest omitting `checksum_sha256` skipped it entirely — attacker data imported as `is_valid=True`). Now fails closed; export signs with hybrid RSA-4096 + ML-DSA-65; unsigned refused under `scif` | 003 | ✅ 9 tests incl. tamper, traversal, forged signature, signed round-trip |
| C6 | Record feed-bundle version on every enrichment; surface bundle age and mark stale | 003 | A prioritisation decision is explainable months later |

## Track D — Narrow the surface

| # | Task | ADR | Done when |
|---|---|---|---|
| ~~D1~~ | ~~Core mode default-on~~ — **DONE** `d638ea0b`: advertised 6,564→454 paths, 4,025→238 schemas; routes mounted unchanged at 7,940 | 005 | ✅ Dormant endpoints still answer 200; UAT 11/11 |
| D2 | Define core membership by evidence (tenant-varying data **and** a UI callsite) rather than by hand | 005 | Membership list is generated, not curated |
| D3 | Execute the dormancy plan for ~290 engine-domain orphans, in verified batches | 005 | Route count drops by the expected delta each batch; gates stay green |
| D4 | CI check: no UI route may point at an endpoint hidden in core mode | 005 | Guard fails a deliberate mismatch |

## Track E — Close the persistence debt

| # | Task | ADR | Done when |
|---|---|---|---|
| ~~E1~~ | ~~Lint rule for relative / `parents[N]` data paths~~ — **DONE** `331dae27`: ratchets debt (155 files, 360 uses) and rejects escapes outright; **found 2 more repo-escaping paths + a hardcoded `/home/user/...` dev path** | 006 | ✅ 4 tests; both escapes fixed |
| E2 | Migrate the **155 files** (measured; earlier 91 was a narrower pattern) that hardcode relative DB paths and ignore `FIXOPS_DATA_DIR` | 006 | Ratchet in `test_no_relative_db_paths.py` reaches 0 |
| ~~E3~~ | ~~Startup split-store check~~ — **DONE** `<pending>`: warns by default (a pre-existing split can't be fixed during a restart), fatal under `FIXOPS_STRICT_STORES=1`. Live: named all 49 on the legacy container and still served | 006 | ✅ 9 tests |

## Track F — Sharpen the wedge

| # | Task | ADR | Done when |
|---|---|---|---|
| F1 | Rename Families 1–2 from scanning to ingestion/normalisation across product, docs and UI | 009 | No surface claims a scan a normalizer merely ingests |
| F2 | Generate the supported-tool list from normalizers passing a round-trip fixture test | 009 | Marketing list is generated, not hand-maintained |
| ~~F3~~ | ~~Replace the control-effectiveness heuristic~~ — **DONE** `5fedc7af`: also found `change_management` and `logging_monitoring` **hardcoded "effective"** and `mean_time_to_detect` a literal `"< 24h"`. Now effective / needs_improvement / **not_assessed** with criterion + observed values | 008 | ✅ 9 tests; an empty run asserts nothing |
| F4 | Publish an offline bundle verifier; validate a `scif`-produced bundle on a machine with no network and no FixOps | 008 | Third party verifies without us |
| ~~F5~~ | ~~Full provenance in the bundle~~ — **DONE** `5fedc7af`: ingest→enrichment→scoring→council→decision, stages that didn't run say so. **Found the API silently dropped `source_tool`/`file_path`/`line`**, so dedup had no location | 008 | ✅ Live: 5 providers, is_real_inference, session id; 2 same-titled findings stay 2 clusters |

---

## What I would do first

**A1 + A4 + B1.** They are cheap, they are measured, and together they change what a
prospect sees in the first ten minutes: nothing red that isn't genuinely broken, an image
free of our own data, and a repo that no longer looks like it contains a duplicate
product.

**Then C1–C4**, because the air-gapped council is the claim almost nobody else can make,
and it is the difference between one market and two.
