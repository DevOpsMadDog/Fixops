# ADR-002 — The council's backend is pluggable; consensus is the invariant

**Status:** Proposed
**Date:** 2026-08-17
**Depends on:** ADR-001

---

## Context

The multi-LLM council is our most-cited differentiator. Verified live, it is real: five
cross-vendor models respond (`providers_responded=5`), the run carries a genuine
`cost_usd`, and the verdict reports `source=consensus` rather than a heuristic fallback.

But the value has been described as "five *named vendors* agree", which binds the moat
to OpenRouter and therefore to egress. That framing makes the moat un-shippable into a
SCIF (ADR-001).

The mechanism that actually produces value is narrower and more durable: **several
models reasoning independently and then being reconciled**. What matters is that the
members are *independent enough to disagree*, that disagreement is measurable, and that
low agreement escalates. Vendor identity is an implementation detail of independence,
not the source of the value.

The abstraction already exists. `suite-core/core/llm_providers.py` defines a
`BaseLLMProvider` with concrete subclasses for OpenAI, Anthropic, Gemini, OpenRouter,
MuleRouter — and a `VLLMSelfHostedProvider` (line 1180) that targets a local vLLM
endpoint via `FIXOPS_VLLM_URL`. The council is already written against the abstraction,
not against a vendor.

## Decision

**Treat the council as a consensus protocol over N independent members, where the
member set is configuration.**

1. The council declares a **member set** per profile. `commercial` populates it from
   cloud providers; `scif` populates it from local endpoints only.
2. A member is any object satisfying the provider interface. The council must not
   reference a vendor name in its own logic.
3. **Independence is a configured property, not an assumption.** A `scif` member set of
   five identical local models is not a council; it is one model asked five times. The
   member set must specify distinct model weights, and the council records which
   members it actually used on every verdict.
4. The existing anti-fabrication guard stays and applies to every backend: a verdict
   with no real call is never recorded as consensus. The DPO learning loop already
   quarantines `$0` runs; that check must be backend-agnostic rather than keyed on
   cloud cost, since local inference legitimately costs nothing.

## Measured, 2026-08-17

The mechanism works and the sizing requirement is real — both established by running it.

**Proven:** with `FIXOPS_AIRGAP_MODE=enforced`, two distinct local models
(`qwen2.5:1.5b`, `qwen2.5:0.5b`) each produced their own reasoning about a Log4Shell
finding, both correctly recommending immediate remediation, with **zero non-loopback
connections** recorded by a socket-level trip-wire. `scripts/prove_airgap_council.py`
reproduces this and fails if any member falls back to a heuristic or a single outbound
connection occurs.

**The constraint:** on laptop CPU the same call is not reliably repeatable. A trivial
prompt returns in ~5s, but the council's real prompt — which asks for a six-key JSON
verdict — exceeded **ten minutes** and timed out. The provider then does exactly the
right thing: it labels the result `[heuristic: local model unavailable]` and sets
`is_real_inference=False` rather than presenting a default as a model's judgement.

So the honest position is that the air-gapped council is **architecturally proven and
hardware-bound**. It is not a laptop feature. `scif` deployments need inference capacity
sized for the verdict prompt, and that is a line item in the deployment guide, not a
detail to discover during accreditation.

## Consequences

- `scif` requires GPU capacity at the customer site. This becomes a documented sizing
  requirement, not a surprise during accreditation — see the measurement above, where
  undersized inference turns every verdict into an honest heuristic fallback.
- The `cost_usd > 0` heuristic we currently use as proof-of-real-call **breaks under
  local inference** and must be replaced by a per-member response fingerprint. This is a
  real correctness item, not a rename.
- Verdict quality between profiles will differ. We must publish the member set with the
  verdict so a customer can see what actually voted.
- We gain the ability to add or drop vendors commercially without touching council logic.

## Verification

- A test runs the council with a fake member set and asserts no vendor name appears in
  the council's own code path.
- A live run under `FIXOPS_PROFILE=scif` against local endpoints produces
  `source=consensus` with `providers_responded >= 3` and **zero outbound connections**,
  captured at the socket layer.
- A test asserts a member set with identical models is rejected or flagged as
  non-independent.
