# ADR-008 — The signed evidence bundle is the commercial wedge

**Status:** Proposed
**Date:** 2026-08-17
**Depends on:** ADR-001, ADR-003

---

## Context

We compete against tools with far larger scanning estates. On breadth of scanning we do
not win, and ADR-009 argues we should stop trying. The question is what we *can* own.

One capability is verified real and genuinely uncommon: the pipeline emits an evidence
bundle signed with **hybrid RSA-4096 + ML-DSA-65** (Dilithium). `dilithium-py` is
installed in the running image and confirmed working, so this is real post-quantum
signing rather than the documented RSA-only fallback.

That matters because of who buys. Per our own positioning, we do **not** pursue a vendor
SOC 2 — that is a SaaS attestation and we ship on-prem and air-gapped. The compliance bar
that actually gates our deals is **the customer's own accreditation** (NIST 800-53 / RMF,
ICD 503). In that world the scarce good is not another dashboard; it is *defensible
evidence that a control is satisfied*, with provenance an assessor can check.

Nothing in the competitive set produces a cryptographically signed, tamper-evident
artifact that ties a finding to a decision to a control. That is the wedge — and it is
the one thing that gets stronger, not weaker, in the air-gapped profile where the
signature and the feed bundle (ADR-003) together make the whole chain reproducible
offline.

## Decision

**Treat the evidence bundle as the product's primary output, and hold it to
audit-grade standards.**

1. Every pipeline run emits an evidence bundle, signed by default. Unsigned emission is
   permitted only when no key material exists, and it is labelled unsigned — never
   silently downgraded.
2. The bundle is **self-contained and verifiable without us**: a customer must be able to
   validate the signature and read the contents with published tooling, offline, after we
   are gone from the room.
3. Provenance is explicit. Each conclusion records what produced it — the ingested
   finding, the enrichment source and *bundle version* (ADR-003), the risk score inputs,
   the council member set and verdict (ADR-002), and the human decision if any.
4. The bundle maps to controls, not just findings. A finding says "this is wrong"; an
   accreditor asks "which control is affected, and is it satisfied". We must answer the
   second question.
5. Control effectiveness must stop being a heuristic. Today it is inferred from average
   risk score (below 0.6 → "effective"), which is not defensible in an assessment; it
   must be traceable to control-specific criteria or be reported as "not assessed".

## Consequences

- We take on a real obligation: an evidence format we are prepared to defend in front of
  an assessor, versioned and backwards-compatible, because bundles outlive releases.
- Publishing a verifier means committing to a stable format sooner than is comfortable.
- The honest near-term gap is that the bundle has never been tested against a real
  assessment workflow. Until it has, we describe it as evidence *support*, not
  accreditation, and that distinction goes in the sales material rather than being
  discovered by a customer.
- This narrows the roadmap in a useful way: features that do not strengthen a claim in
  the bundle are, by default, lower priority.

## Verification

- A test asserts every pipeline run emits a bundle whose signature verifies, and that a
  tampered bundle fails verification.
- A test asserts each conclusion in the bundle carries complete provenance, including the
  feed bundle version and the council member set.
- An offline verification of a bundle produced under `FIXOPS_PROFILE=scif`, performed on
  a machine with no network and no FixOps installation.
