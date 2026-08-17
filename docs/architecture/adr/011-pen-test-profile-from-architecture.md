# ADR-011 — A pen test is scoped from architecture, not from code

**Status:** Proposed
**Date:** 2026-08-18
**Refines:** [ADR-010](010-per-stage-analysis-and-open-graph.md)

---

## Context

ADR-010 treated MPTE as a tool that needs a live target, and concluded it therefore
cannot run at design stage. That framing was too narrow, and it produced the wrong
recommendation.

The correction: **what a pen test needs at design time is not a target, it is a scope.**
Long before code exists you already know the things that determine which attacks are even
applicable — whether the system is internet-facing or intranet-only, what the
authentication model is, what the architecture is, how it will be hosted. A human pen
tester scopes exactly this way: from an architecture diagram and a threat model, before
touching the system.

So the test plan is derivable at design. Only the **fidelity of execution** varies by
stage.

This also matches how the codebase is already built, which is the strongest argument that
it is the natural design rather than an invention:

* `iac_scanner_engine.parse()` returns **`IaCResource` objects**, not just findings — an
  architecture model extracted from Terraform and Kubernetes manifests before anything
  runs.
* `cspm_engine` already reasons in exposure terms: public S3 ACLs, RDS reachable from the
  internet, security groups open to `0.0.0.0/0`.
* `ssvc` is already a dependency, and SSVC exists precisely to decide under incomplete
  information: `ExploitationLevel`, `Automatable`, `TechnicalImpact`,
  `MissionWellbeingImpact`.
* `threat_modeling_engine`, `threat_model_generator` and `design_context_injector` already
  capture design intent.

Nothing here needs inventing. It needs connecting.

## Decision

**Derive a pen-test profile from the architecture model, and let each SSDLC stage add
evidence to that same profile.**

A profile is a set of *candidate tests*, each carrying the reason it applies. It is
created at design and never re-created — later stages sharpen it:

| Stage | What is known | What the profile gets |
|---|---|---|
| design | exposure, auth model, hosting, data class | candidate tests, **predicted applicable** |
| build / dependency | actual dependencies, actual IaC | candidates confirmed or dropped *statically* |
| test | the app runs in CI | lightweight execution in a sandbox |
| release | staging exists | fuller execution against staging |
| operate | production exists | full execution, authorised and audited |

Two rules make this honest:

**1. A predicted test is not a result.** A design-stage profile says "an unauthenticated
internet-facing endpoint would be in scope for injection testing." It must never be
counted as a vulnerability, rendered as a finding, or included in a "we found N issues"
number. It is a *hypothesis with a reason*. Everything this codebase got wrong this month
was some version of presenting an assumption as a measurement; this design must not add
another.

**2. Test identity is stable across stages.** A profile entry binds to
`(component, exposure class, test class)` — never to a URL, which does not exist yet at
design and changes between environments. That stable identity is what allows the same test
to be tracked from prediction to execution.

### The correction to the original idea

The framing was "the same test, lightweight after build, evolving to full-fledged at
runtime with the same functionality." That is nearly right, and the distinction matters:

It is not one test growing. It is **one question, answered with progressively better
evidence**. A static check that an endpoint *is* internet-facing and a live probe that
*exploits* it are different acts with different confidence and different blast radius.
Calling them the same test would eventually mean reporting a design-stage prediction with
the authority of a runtime exploit — which is the failure mode rule 1 exists to prevent.

So each profile entry carries a verdict *per stage*, with its own confidence and evidence,
and the profile's value is the trajectory across them.

### What this buys that competitors do not have

Because prediction and execution share an identity, the product can report its own
accuracy: *"at design we predicted 40 applicable tests; at runtime 31 were confirmed and 9
were not."* That is a claim about our own model, measurable and publishable, and it is
exactly the kind of evidence an accreditor finds persuasive. It also turns design-stage
output into something falsifiable rather than advisory.

And it answers the SSDLC question honestly at every stage: at design the answer is a
scoped plan, not a fabricated scan.

## Consequences

- We need an architecture model as a first-class object: component, exposure class, auth
  model, hosting, data classification. `IaCResource` and the threat-model engines are the
  inputs; today nothing composes them.
- Profiles are versioned. Architecture changes, and a profile must show what changed and
  when, or it cannot be trusted as a record.
- Design-stage output must be visually distinct in the UI — "predicted", never mixed into
  finding counts.
- Under `scif`, stages up to and including sandboxed execution are unrestricted; live
  execution against production remains opt-in, authorised and audited (ADR-010).
- If a customer supplies no architecture input, the profile is empty and says so. We do
  not guess an architecture in order to have something to show.

## Verification

- An architecture description with no code produces a non-empty profile whose entries each
  state why they apply.
- Every design-stage entry is labelled predicted and is excluded from finding counts.
- A profile entry keeps one identity from design through runtime, with a per-stage verdict
  history.
- Prediction accuracy is computed from real runs and reported, not asserted.
- With no architecture input, the profile is empty rather than invented.
