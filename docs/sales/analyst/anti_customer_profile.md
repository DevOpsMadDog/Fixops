# Anti-Customer Profile — Who ALdeci Does NOT Serve Well (Today)

> **Why this artifact exists**: Analysts and CISOs respect honesty about positioning more than puffery. This document names the buyers we should **decline** today, the competitor we'll point them to, and the timeline (if any) for re-engagement.
>
> **Source-of-truth**: 25 LOSE cells consolidated in `docs/competitive_validation_2026-04-26.md` §2 (10 deduped action items).
> **Date**: 2026-04-26 | **Maintainer**: Sales Engineering + Marketing alignment

---

## Five Disqualifier Categories — Decline Up Front

### 1. "We need 25-year Nessus heritage for host-vuln scan and our compliance auditor specifically requires Nessus checkpoints."

**Decline rationale**: Tenable Nessus has a 25-year vulnerability-research moat we do not attempt to replicate. Our `competitive_validation_2026-04-26.md` §2 row 7 flags this as **NO — defer; not winnable**. ALdeci wraps OSS scanners (Trivy, Grype, Dockle, Checkov, tfsec) but does not ship Nessus-equivalent host plugins.

**Send them to**: Tenable One.

**When to re-engage**: Never on this dimension; revisit if buyer's CTEM scope expands beyond host-vuln (we add unique value on AI consensus, MPTE, evidence vault).

---

### 2. "We want to install in 5 minutes on a developer's laptop with `brew install` and start scanning immediately."

**Decline rationale**: Aikido and Snyk own the developer-laptop 5-minute onboarding UX (`competitive_validation_2026-04-26.md` §2 row 1, §G row 10). ALdeci ships as Helm/Compose; the GA SaaS tier is on the 12-month roadmap, not today. We have no laptop installer and no GA `brew` formula.

**Send them to**: Aikido (mid-market dev-led), Snyk (enterprise dev-led).

**When to re-engage**: Q4 2026, post-managed-SaaS GA. Until then, we are honest: "we are an enterprise control-plane, not a laptop tool."

---

### 3. "We need a fully integrated VS Code / JetBrains plugin with inline annotations as our top buying criterion."

**Decline rationale**: Snyk, Sonatype, Aikido, and Checkmarx all ship mature IDE plugins. ALdeci's `GAP-014 IDE-gateway scope` is **NEEDS-PRODUCT-DECISION** — deferred (`docs/competitive_validation_2026-04-26.md` §2 row 1). We have no GA plugin; building one is XL effort (8-12 wk) and not on the current sprint.

**Send them to**: Snyk Code (DeepCode AI in IDE), Sonatype Lifecycle (IntelliJ-grade plugin).

**When to re-engage**: When the buyer's primary pain shifts from IDE-shift-left to platform-consolidation / audit-defensibility / self-learning AI — those are our strengths.

---

### 4. "DSPM data-classification (PII discovery, field-level data lineage) is our top buying criterion this year."

**Decline rationale**: Wiz DSPM is mature; ALdeci's `data_governance_engine` is functional but basic (`docs/competitive_validation_2026-04-26.md` §A row 14, §2 row 3). Real Wiz DSPM parity needs cloud-SDK integration + dedicated PII detector; that is L-effort (4-6 wk) deferred.

**Send them to**: Wiz, Cyera, BigID.

**When to re-engage**: Q3 2026 once DSPM expansion lands. Re-engage if buyer's broader CTEM/ASPM needs justify ALdeci as the orchestrator with Wiz DSPM as a feed.

---

### 5. "We need a turnkey consumer-grade SaaS with zero infrastructure, signed up via credit card, scanning in 10 minutes."

**Decline rationale**: ALdeci's GA delivery is self-hosted Helm/Compose or signed air-gap bundle. There is no public, credit-card-signup, multi-tenant SaaS today. SaaS managed cloud is the 12-month roadmap.

**Send them to**: Aikido (best-in-class self-serve), Snyk Cloud Free (free tier + paid expansion), Wiz (for cloud-only buyers).

**When to re-engage**: Post-managed-cloud GA (target Q4 2026). Until then, only engage with buyers willing to deploy Helm in their own VPC.

---

## Three Yellow-Flag Categories — Engage Carefully

### Y1. "Function-level transitive reachability across OSS dependencies is our top decision criterion."

**Status**: Snyk Helios (eBPF runtime) and Endor own this depth. ALdeci's `function_reachability_engine.py` is repo-local v0 (`docs/competitive_validation_2026-04-26.md` §A row 10, §2 row 2). True parity needs precomputed OSS call graphs (`GAP-048` NS, XL effort).

**Approach**: Be honest — "we have v0; if precomputed transitive call-graphs are mission-critical, Endor or Snyk is the better fit *today*. We can match on every other axis." Often this is acceptable because the buyer cares about it but not at #1.

---

### Y2. "We are a single-cloud Wiz shop and you need to beat Wiz on cloud breadth."

**Status**: Wiz wins on multi-cloud depth (OCI/Alibaba), agentless snapshot scale, Security Graph UX polish (`docs/competitive_validation_2026-04-26.md` Wiz column: 7 LOSE cells, our worst gap).

**Approach**: Reposition the engagement away from "beat Wiz on cloud." Lead with our orthogonal strengths: dual-mode (orchestrate Wiz + add native), multi-LLM Council, MPTE exploit verification, post-quantum evidence, self-learning closed loop, MCP gateway. **Most cloud-deep Wiz buyers don't have these and don't even know to ask.**

---

### Y3. "We need a fully GA, F500-logo-validated platform with public reference customers."

**Status**: Pre-GA, design-partner stage. No public logos yet (transparent in `docs/sales/analyst/mq_wave_submission_2026-04-26.md` §6 and §8 cautions).

**Approach**: For risk-averse buyers, position into the **design-partner program**: white-glove implementation, co-marketing inclusion, locked early-adopter pricing, founder-team direct line. For buyers who require fully-GA references, postpone re-engagement to post-GA.

---

## Why This Document Wins Trust

Three reasons analysts and CISOs respond positively to anti-customer profiles:

1. **Calibrated honesty**: A vendor that names what it can't do is signaling that everything it claims to do, it actually does. The reverse — vendors that won't name a single weakness — instantly raise the auditor red flag.
2. **Reduces evaluation overhead**: Smart buyers screen out non-fits in the first call. We help them. They remember us as the vendor that respected their time.
3. **Sharpens our actual moat**: When we decline a buyer, we point them somewhere credible (Tenable, Wiz, Snyk, Aikido). This earns coopetition goodwill *and* signals that we know our category cold.

## Maintenance

- Re-review quarterly against `docs/competitive_validation_2026-04-26.md` (the LOSE-cell list is the source of truth).
- Move categories from "decline" to "yellow-flag" or "remove" only after the underlying gap is closed — the gap-fill must be cited by commit + file (e.g., "DSPM moved to engage-carefully after `data_governance_engine v2` ships at commit `XXXXXXXX`").
- Sales engineers maintain a private spreadsheet of every "we said no" event, with the timestamp + reason + competitor we recommended. Used for win/loss analysis and to detect when a category is ready for re-engagement.

---

*Owner: Sales Engineering. Review cadence: quarterly. Aligned-with: `docs/sales/win_loss_analysis_template.md`.*
