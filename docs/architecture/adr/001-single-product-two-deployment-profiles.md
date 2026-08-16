# ADR-001 — Single product, two deployment profiles

**Status:** Proposed
**Date:** 2026-08-17
**Supersedes:** the implicit assumption that commercial and SCIF are separate roadmaps

---

## Context

We intend to sell into both commercial buyers and accredited/air-gapped (SCIF)
environments. Treating those as two products is what produced much of the current
breadth: 829 router files, 475 engine files, 7,940 mounted routes.

Measured, the two targets differ in **exactly two** places:

1. **AI inference egress.** The council's differentiating behaviour is a five-model
   cross-vendor vote. Today those models are reached through OpenRouter — an outbound
   HTTPS call to a commercial US API. A SCIF has no internet, so in an accredited
   boundary that call cannot happen and the pipeline silently degrades to heuristics.
2. **Egress and crypto posture.** `FIXOPS_AIRGAP_MODE` and `FIPS_MODE` both exist in
   the codebase and both are **off** in the running container — startup logs state
   plainly that "the socket-level egress guard is NOT active and outbound network
   access is UNRESTRICTED" and that we are "running without FIPS-validated crypto
   boundary".

Everything else is identical. The ingest layer (34 scanner normalizers, 45 connector
classes), deduplication, enrichment, risk scoring, triage, exposure cases, and evidence
generation make no assumption about network reachability. Air-gapped organisations run
their own Nessus, Fortify and Trivy on their own metal and have no way to correlate the
output — so the ingest-first design is *more* valuable in a SCIF, not less.

## Decision

**Ship one product with one switch: `FIXOPS_PROFILE ∈ {commercial, scif}`.**

The profile selects a coherent posture rather than a scatter of independent flags:

| | `commercial` | `scif` |
|---|---|---|
| Council backend | cloud providers (OpenRouter et al.) | local inference only (ADR-002) |
| Egress | unrestricted | `FIXOPS_AIRGAP_MODE=enforced` |
| Crypto | default | `FIPS_MODE` required |
| Threat feeds | live fetch | signed offline bundle (ADR-003) |
| Everything else | identical | identical |

A profile is **fail-closed**: selecting `scif` and leaving a cloud provider configured
is a startup error, not a warning. A SCIF deployment that silently makes one outbound
call is an accreditation failure, and a log line is not an adequate guard against it.

We explicitly reject the alternative of a `scif` build that strips code. Two artifacts
means two test matrices and a divergence we will not keep in step.

## Consequences

- We accept that `scif` runs a weaker model set than frontier cloud models. ADR-002
  argues the consensus mechanic, not the individual model, is what carries the value.
- Every feature added from now on must state its behaviour under both profiles. A
  feature that only works with egress is a `commercial` feature and must be gated.
- CI must run the gate suite under both profiles, otherwise `scif` rots.
- Sales gains a claim very few competitors can make: multi-model AI consensus that runs
  air-gapped.

## Verification

- A test asserts that with `FIXOPS_PROFILE=scif`, `create_app()` raises when any cloud
  LLM provider is configured.
- A test asserts that under `scif` the egress guard is active by attempting an outbound
  socket and requiring it to be refused.
- The UAT suite passes under both profiles.
