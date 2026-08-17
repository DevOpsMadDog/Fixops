# ADR-010 — Analysis at every SSDLC stage, and a graph the customer owns

**Status:** Proposed
**Date:** 2026-08-18

---

## Context

The intended design: enrich CVSS, then run **exploit analysis** and **reachability
analysis** at every SSDLC stage, then run **micro pen-testing (MPTE)** on top of those,
and — unlike Apiiro — let customers *configure* the vulnerability model rather than
inherit a closed knowledge graph.

Measured against the code on 2026-08-18, four things are true.

**1. The layered order exists and is correct.** The pipeline runs
`enrich_threats (6) → reachability + vuln-intel fusion → score_risk (7) → micro_pentest (10)`.
That is the design, already wired.

**2. The reachability layer has never produced a verdict.**
`_apply_reachability_verdicts` keys on `cve_id` **and** `package_name` and `continue`s
without logging when either is missing. Until 2026-08-17, `cve_id` had no column in the
findings table and `package_name` was dropped at the API boundary. Demonstrated:

```
no cve_id, no package_name (the shape findings actually had)  verdict=None
cve_id but no package_name                                    verdict=None
cve_id + package_name (only possible since the schema fix)    verdict='unreachable'
```

2,021 lines of reachability engine, silently skipping every finding. **MPTE was therefore
never evaluable** — the layer that was supposed to tell it *what is worth testing*
returned nothing, and MPTE itself is opt-in (`run_pentest=False`).

**3. Exploit analysis is not wired at all.** `exploit_signals.py` and
`exploit_generator.py` exist; `brain_pipeline` imports neither. There is no forecasting
engine of any kind.

**4. The open-graph differentiator is already structurally true.** `KnowledgeEntity`
carries a free-text `entity_type` and arbitrary `properties`; `KnowledgeRelationship`
carries a free-text `rel_type`. There is no fixed enum anywhere. And `SSDLCEvaluator`
already accepts `configured_stages`, falling back to defaults. The openness Apiiro does
not offer is **latent in the model and simply not exposed**.

## Decision

### 1. Reachability and exploit analysis run at every stage; MPTE runs where a target exists

Reachability and exploit signal are static analyses — they need a CVE, a package, and a
call graph, none of which require a running system. They are stage-agnostic and will run
at **every** stage, recording the stage on each verdict so a finding accumulates a
history rather than a single snapshot.

MPTE is different, and this is the constraint worth naming rather than working around:
**MPTE needs a target to attack.** `run_micro_pentest` requires `target_urls`. At plan
and design stages no such thing exists. Running it "at every stage" therefore resolves
not as one universal test but as **one engine behind five target providers**:

| Stage | What "target" means | MPTE |
|---|---|---|
| plan / design | nothing exists yet | **not applicable** — see forecasting below |
| build / dependency | ephemeral container from the built image | sandboxed |
| test | the app under CI | sandboxed |
| release | staging URL | live, authorised |
| operate | production | live, authorised — **and never under `scif` without written approval** |

This is why MPTE felt like a poor fit: it was being asked to answer a question that has no
target at the stages where decisions are cheapest to act on.

### 2. Forecasting is the plan/design-stage answer, not a missing MPTE feature

At design time the honest question is not "can I exploit this?" but "**how likely is this
to become exploitable?**" — EPSS trajectory, KEV-addition likelihood, exploit-maturity
trend for the component. That is the forecasting algorithm's proper home, and it explains
why it never found a place: it was competing with MPTE instead of preceding it.

Order per stage: **exploit signal → reachability → (forecast | MPTE)** — forecast where
there is nothing to attack, MPTE where there is.

### 3. The knowledge model is the customer's, not ours

The differentiator is not that we have a graph — Apiiro has one. It is that ours is
**declarable**. A customer defines their own entity types, relationship types, and the
rules that connect findings to them, and those definitions drive correlation, scoring and
triage. We ship defaults; we do not impose a schema.

Concretely:

* Stage definitions are configuration (`configured_stages` already supports this).
* Entity and relationship types are customer-declarable, persisted per tenant.
* Correlation and prioritisation rules are data, not code.
* Every default we ship is visible and overridable, and the UI shows which rule produced
  a given decision.

An air-gapped customer cannot file a feature request and wait a quarter. A model they can
change themselves is not a nicety in that market; it is the difference between the product
fitting their environment and not.

## Measured after the decision, 2026-08-18

Reachability was re-validated the moment its inputs existed, by pointing it at this
repository:

```
parsed suite-core/core -> 42,796 symbols/edges in 6.2s
  requests           REACHABLE    callers=46    pr_generator.PRGenerator._call_github_api
  sqlite3            REACHABLE    callers=763   sbom_generator.SBOMGenerator._get_conn
  httpx              REACHABLE    callers=133   slack_chatops_engine...._ensure_client
  numpy              REACHABLE    callers=158   ml.trend_analyzer....._calculate_posture
  nonexistent_pkg    unreachable  callers=0
```

Real callers, named correctly, at 42.8k edges in six seconds — and a clean negative for a
package that does not exist. **The engine was never broken; it was starved.** It had no
`cve_id` and no `package_name` to key on, so it skipped every finding in silence.

That materially changes the MPTE question. The layer beneath it is good, fast and already
built; the reason MPTE looked like a poor fit is that it was the only layer anyone could
see working.

## Consequences

- Reachability's *filtering value* on customer code is still unmeasured — this experiment
  proves the mechanism, not the noise reduction. That number must come from a real
  customer repo and be published rather than assumed.
- Per-stage analysis means a finding has *many* verdicts over time. The store must record
  `(finding, stage, verdict, timestamp)`, not overwrite a single field.
- Sandboxed MPTE at build/test needs an ephemeral runner. `sandbox_verifier.py` exists and
  is the natural place.
- Customer-declared types mean we can no longer assume our own vocabulary anywhere
  downstream — scoring and correlation must read the tenant's definitions.
- Under `scif`, live MPTE against production is a policy decision, not a default. It stays
  opt-in and audited.

## Verification

- Reachability produces a verdict for a real finding with a real dependency graph, and the
  proportion filtered is measured and published rather than assumed.
- A finding carries per-stage verdicts, queryable as a history.
- MPTE selects targets through a stage-appropriate provider, and reports "no target at
  this stage" rather than silently skipping.
- A tenant can declare an entity type and a rule through the API, and a subsequent
  pipeline run correlates using it — with the UI naming the rule that fired.
