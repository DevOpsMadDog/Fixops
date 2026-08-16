# ADR-005 — Core mode is the default shipping surface

**Status:** Proposed
**Date:** 2026-08-17

---

## Context

Probing all 745 API domains live — each called once as a real tenant and once as a
tenant that does not exist — gives the surface's actual composition:

| Behaviour | Domains | Share |
|---|---:|---:|
| Returns data that **differs per tenant** | **168** | 22% |
| Returns **identical bytes for every tenant** | 396 | 53% |
| Responds correctly, collection **empty** | 140 | 19% |
| Honestly reports **no credentials** | 16 | 2% |
| **Broken** | 21 (was 25) | 3% |

And the reach into the product: **374 of 745 domains (50%) have a UI callsite**. The UI
declares 642 routes across 299 pages while the curated core navigation exposes about 11
screens.

The distribution across capability families is sharply uneven. Vulnerability Management
/ Risk Scoring holds 59 domains with 25 carrying real data and 39 with UI — the highest
on every axis. Posture / Analytics is second because it reads from it. Together they are
roughly 100 domains: ingest → dedup → enrich → score → triage → decide → evidence.

The 396 "identical for every tenant" domains are not fraudulent. A scanner-rule
catalogue *should* be the same for everyone, and a connector reporting
`api_key_present: false` is being honest. But shipped as though they were finished
features, they are surface a buyer can poke and find hollow — and hollowness reads worse
than an error, because an error looks like a bug while hollowness looks like a lie.

`FIXOPS_CORE_MODE=1` already implements the mechanism: it filters the OpenAPI surface
(6,564 → 454 paths) and drives a curated navigation. It is currently opt-in.

## Decision

**Invert the default. Core mode is what ships; the full surface is opt-in.**

1. `FIXOPS_CORE_MODE` defaults to **on**. Exposing everything becomes an explicit
   operator choice (`FIXOPS_CORE_MODE=0`), appropriate for development and for customers
   who have licensed a broader set.
2. The core surface is defined by **evidence, not taste**: a domain qualifies when it
   returns tenant-varying data *and* has a UI callsite, plus the reference catalogues the
   core screens depend on. The current measurement puts that near 100 domains.
3. Domains outside core are **dormant, not deleted** (see `docs/DORMANCY_PLAN_2026-08-16.md`).
   Nothing is removed from the codebase; it is removed from the advertised surface.
4. Promotion out of dormancy has one bar: the domain returns tenant data and something in
   the product reaches it. That bar is checkable in CI.

## Consequences

- The demo becomes small and entirely real. Every screen a prospect opens has data
  behind it.
- We stop being comparable to Wiz/Apiiro on breadth of menu, and start being comparable
  on depth of the one workflow that matters. That is the trade we are deliberately making.
- Customers currently calling a dormant endpoint break unless they set
  `FIXOPS_CORE_MODE=0`. Given 371 domains have no UI consumer at all, the blast radius is
  small — but it must be released as a breaking change with a migration note.
- Dormant code still compiles and is still tested, so promotion stays cheap.

## Verification

- A test asserts that with defaults, the mounted OpenAPI path count is within the core
  budget and that every advertised domain either returns tenant-varying data or is a
  declared reference catalogue.
- A test asserts that every route reachable from the UI is present in core mode — the
  navigation can never point at a hidden endpoint.
- The 11-case UAT passes with core mode on, which it already does.
