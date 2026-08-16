# Sellable-product backlog

Tasks derived from the ADRs in `docs/architecture/adr/`. Every task traces to a decision
and a measurement; nothing here is speculative scope.

Ordering is by **what unblocks a sale**, not by effort. Each task states its ADR, the
measured reason it exists, and the check that closes it.

---

## Track A — Stop looking broken (fastest credibility gain)

| # | Task | ADR | Done when |
|---|---|---|---|
| A1 | Unify credential-gated responses: 10 integrations returning 503 (`github`, `harbor`, `hashicorp-vault`, `kong`, `n8n`, `servicenow`, `elasticsearch`, `deployment`, `guardrails`, `license`) return 200 + `configured: false` + required env vars | 007 | No integration domain returns 5xx with credentials absent; health is `healthy` with zero integrations configured |
| A2 | Fix the 4 remaining 404s on routes that should exist (`changes/health`, `k8s/rbac`, `posture-benchmark/latest`, `workflows/stats`) | — | All four return 200 or a documented 501 |
| A3 | Render not-configured as an onboarding affordance ("Connect Qualys"), not an error | 007 | A tenant with zero connectors sees next steps, never red |
| A4 | Rebuild and redeploy the image — it still carries ~80 MB of stale dev databases and none of the 2026-08-16 fixes | 006 | Fresh image contains 0 `*.db` under `suite-*/`; UAT 11/11 against it |

## Track B — Shrink the repo to its real size

| # | Task | ADR | Done when |
|---|---|---|---|
| B1 | Delete the duplicate Python SDK (`aldeci_client` **or** `aldeci_security_intelligence_platform_client` — 4,465 files each, identical) | 004 | One client name remains |
| B2 | Untrack `sdks/` (12,189 files, 134 MB); generate clients in CI from the OpenAPI spec and publish as versioned packages | 004 | `git ls-files sdks/ \| wc -l` → 0; repo ~5,772 tracked files |
| B3 | CI guard: fail on any newly tracked file carrying a `generated ... do not edit` header | 004 | Guard fails a deliberate test commit |
| B4 | Share the duplicated contract models (`CapabilityResponse` ×46, `ScanRequest` ×24) instead of re-declaring per router | 004 | Duplicate class-name count materially below 4,213 |

## Track C — Make the SCIF profile real

| # | Task | ADR | Done when |
|---|---|---|---|
| C1 | Introduce `FIXOPS_PROFILE ∈ {commercial, scif}`; `scif` enforces egress guard + FIPS and **fails closed** if a cloud provider is configured | 001 | `create_app()` raises under `scif` + cloud provider; egress refused at socket layer |
| C2 | Populate the council member set from profile; remove vendor names from council logic | 002 | Council runs against a fake member set with no vendor reference in its code path |
| C3 | Replace `cost_usd > 0` as proof-of-real-call with a per-member response fingerprint — local inference legitimately costs nothing | 002 | Real-call detection passes for local models; fabricated verdicts still quarantined |
| C4 | Prove the air-gapped council: 5 local models, `providers_responded ≥ 3`, `source=consensus`, **zero outbound connections** | 001,002 | Captured socket-level evidence of no egress during a real verdict |
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
| E1 | Lint rule rejecting new relative `*.db` paths and `parents[N]`-derived data paths | 006 | Rule fails a deliberate violation |
| E2 | Migrate the **91 files** that hardcode relative DB paths and ignore `FIXOPS_DATA_DIR` | 006 | Count reaches 0; no duplicate store names in a running container |
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
