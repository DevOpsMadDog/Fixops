# Fixops Pricing Calculator (Marketing Microsite)

**Status:** stub (GAP-054 KILL replacement, 2026-04-22). Supersedes the former `pricing_model_engine` PRD.

## What this is

A standalone, unauthenticated, marketing-only page/microservice that lets prospects estimate their Fixops subscription cost based on asset count, workload count, and feature tier. It is **not** a security engine and does not run inside the Fixops platform cluster — it is part of the public marketing site.

## Why it's not a Python engine in `suite-core/core/`

A pricing calculator is a transparency/lead-gen artefact, not a security control or data-plane component. Including it in the engine inventory would:
- distort engine counts used in investor materials,
- force a security review of code that has no security-sensitive inputs,
- bind the marketing deploy cadence to the platform's release train.

It belongs where other marketing assets live: a static page, served from the marketing domain, updated independently of platform releases.

## Planned layout

```
suite-ui/marketing/pricing-calculator/
├── README.md               # this file
├── index.html              # (Sprint 3) public calculator page
├── calculator.ts           # (Sprint 3) pure TypeScript math
├── pricing-tiers.json      # (Sprint 3) source-of-truth tier data
└── README.md
```

Only `README.md` is created today.

## Inputs (planned)

- Number of assets (VMs, containers, cloud accounts) — tiered $/asset/month
- Number of developers — Starter / Pro / Enterprise tier gate
- Feature tier — Starter ($199/mo), Pro ($499/mo), Enterprise ($1,499/mo + volume)
- Deployment mode — SaaS / self-hosted / air-gap — uplift on Enterprise only
- Compliance add-ons — FedRAMP / FIPS / HIPAA packs (Sprint 3)
- Support tier — standard / 24x7 / dedicated TAM

## Outputs

- Monthly recurring cost (min / expected / max)
- Annual commitment discount (prepay savings)
- Included feature list per tier
- Comparison vs incumbent TCO (Wiz / Snyk / Sonatype list prices where public)
- "Email me this quote" form (captures lead into HubSpot via webhook — Sprint 3)

## Pricing source of truth

`pricing-tiers.json` will be the committed source of truth, reviewed by Marketing + Sales + Finance before any change. CI runs `scripts/validate_pricing.sh` (Sprint 3) to catch tier regressions (e.g. Pro price moving below Starter).

## Deploy target

Static site bundled by Vite (or plain HTML + ESM), served from `https://fixops.com/pricing` via the marketing CDN. No backend dependency on the Fixops platform. Forms POST to HubSpot / marketing automation — not to `/api/v1/*`.

## Why this is P3

The gap-matrix rates this P3 because:
- no existential deal hinges on it,
- every competitor also hides pricing, so there is no urgency,
- it is a marketing / GTM asset, not a platform capability.

It is still worth shipping because:
- prospects ask for it in 100% of discovery calls (per `docs/GO_TO_MARKET.md`),
- publishing pricing differentiates Fixops vs Wiz/Snyk/Sonatype opacity,
- it is single-engineer-week in effort.

## References

- `raw/competitive/gap-matrix.md` — GAP-054 row
- `docs/GAP_PRD_RECONCILE_2026-04-22.md` — GAP-054 KILL record
- `docs/GO_TO_MARKET.md` — pricing strategy context
- `docs/INVESTOR_PITCH.md` — tier definitions

---

*This microsite replaces the Python engine/router that was formerly tracked as `pricing_model_engine` (GAP-054 KILL, 2026-04-22). The capability is a marketing artefact, not a platform engine.*
