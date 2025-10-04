# FixOps Platform Assessment (CTEM, AppSec, and CISO Lens)

## Review Scope & Method
- **Code review** of ingestion API, pipeline orchestration, overlay configuration, context engine, evidence hub, compliance evaluator, onboarding helper, and policy planner modules.
- **Documentation review** across architecture, configuration, SDLC guidance, and security/gap logs to cross-check stated capabilities.
- **Simulation review** via automated tests (`pytest`) to observe expected behaviours in demo vs. enterprise overlay modes.

## Proven Strengths
| Capability | Evidence | CISO/AppSec Value |
| --- | --- | --- |
| Overlay-aware guardrails | Guardrail thresholds resolved per maturity profile during pipeline execution.【F:backend/pipeline.py†L327-L355】【F:fixops/configuration.py†L132-L161】 | Provides deterministic governance that can be tuned per deployment stage.
| Context engine | Component scoring blends severity, business criticality, data sensitivity, exposure, and exploitation signals to drive playbook selection.【F:fixops/context_engine.py†L43-L177】 | Supports CTEM outcomes by aligning scanner data with business impact.
| Evidence hub | Every run emits a masked-overlay bundle plus artefact summaries to an evidence directory, creating repeatable audit packs.【F:fixops/evidence.py†L15-L77】 | Accelerates audit readiness and customer assurance motions.
| Compliance packs | Control checks map artefact availability to SOC 2 / ISO / PCI coverage and highlight residual gaps.【F:fixops/compliance.py†L10-L79】【F:config/fixops.overlay.yml†L121-L199】 | Enables risk and compliance teams to monitor framework posture from the same run outputs.
| Policy automation | Triggerable actions (Jira issues, Slack, Confluence pages) are selected by guardrail, context, and compliance results.【F:fixops/policy.py†L12-L52】【F:config/fixops.overlay.yml†L151-L199】 | Creates a foundation for orchestrated response once real connectors are attached.
| SSDLC coverage | Overlay-driven evaluator grades lifecycle stages and surfaces gaps alongside guardrails and evidence bundles.【F:backend/pipeline.py†L341-L362】【F:fixops/ssdlc.py†L19-L205】 | Gives CISOs/AppSec leaders proof that planning, testing, and deployment controls are enforced per mode.
| Overlay-guided onboarding | Mode-specific checklists and integration stubs drive ≤30‑minute first value promises.【F:fixops/onboarding.py†L12-L43】【F:config/fixops.overlay.yml†L101-L199】 | Helps solution engineers prove value quickly while signalling enterprise prerequisites.
| Pricing clarity | Active plan and entitlements surfaced alongside pipeline outputs for transparency.【F:fixops/configuration.py†L232-L248】【F:config/fixops.overlay.yml†L183-L199】 | Arms GTM with plan boundaries that align with delivered artefacts.
| AI agent governance | Overlay-driven advisor flags LangChain/AutoGPT components, maps controls, and writes evidence bundles with watchlist context.【F:backend/pipeline.py†L351-L360】【F:fixops/ai_agents.py†L31-L162】【F:docs/AI_AGENTS_RESEARCH.md†L1-L74】 | Gives CTEM/AppSec teams proactive insight into emerging agentic risk.

## Remediated Since Prior Assessment

- **Authentication & Upload Guards** — API-key enforcement and streaming upload limits now protect every ingestion endpoint.【F:backend/app.py†L37-L210】
- **Overlay Validation & Directory Safety** — Pydantic schema validation and allowlisted data roots prevent typo-driven guardrail gaps and path traversal.【F:fixops/configuration.py†L69-L189】
- **Evidence Hardening** — Evidence hub honours `include_overlay_metadata_in_bundles`, reducing metadata exposure when operators disable overlay attachments.【F:fixops/evidence.py†L24-L59】
- **Feedback Capture** — `/feedback` endpoint persists reviewer decisions whenever `capture_feedback` is enabled, seeding ROI analytics and audit trails.【F:backend/app.py†L211-L220】【F:fixops/feedback.py†L1-L61】

## Critical & High Gaps
| Priority | Gap | Evidence | Risk & Impact | Recommendation |
| --- | --- | --- | --- | --- |
| **High** | No rate limiting / broad CORS | Ingestion API still allows all origins and lacks throttling, so brute-force uploads or API-key guessing remain possible.【F:backend/app.py†L24-L47】 | Attackers could hammer the service or replay uploads even with API keys present. | Introduce ingress rate limiting and tighten CORS to trusted hosts; consider request quotas per API key.

## Medium Gaps & Enhancements
- **Context accuracy limits:** Component context defaults to the first matching design row and counts of findings/CVEs; no deduplication by exploit chain or asset owner.【F:fixops/context_engine.py†L133-L233】 Add enrichment hooks (asset owner, runtime telemetry) to avoid mis-prioritising monolith components.
- **Policy automation stubs:** Planner only returns actions; no connector execution or ticket state reconciliation.【F:fixops/policy.py†L12-L52】 Implement Jira/Confluence clients with success/failure tracking to compete with Apiiro runbooks.
- **Compliance evidence depth:** Controls resolve to “satisfied” when artefacts exist, not when controls are actually met.【F:fixops/compliance.py†L14-L79】 Extend checks to inspect evidence bundle content (e.g., guardrail status, context thresholds) before marking satisfied.
- **Onboarding validation:** Checklist surfaces required integrations but service does not verify credentials or connectivity.【F:backend/app.py†L120-L150】【F:fixops/onboarding.py†L24-L43】 Add readiness probes that confirm Jira/Confluence/Git access when enterprise toggles enforce them.
- **Pricing guardrails:** Pricing summary is informational only; ingestion never blocks when plan limits (e.g., scan counts) exceeded.【F:fixops/configuration.py†L232-L248】 Track usage and deny overages or surface warnings to align with plan promises.

## CTEM Readiness Scorecard
| Dimension | Assessment |
| --- | --- |
| **Visibility** | Strong: ingestion normalises SBOM, SARIF, CVE feeds and stitches them via component tokens for crosswalk analytics.【F:backend/pipeline.py†L200-L355】 |
| **Prioritisation** | Moderate: guardrails plus context scores highlight highest-risk components but lack temporal trends and threat intel fusion beyond static KEV flags.【F:backend/pipeline.py†L219-L356】【F:fixops/context_engine.py†L133-L233】 |
| **Validation** | Emerging: Evidence hub captures artefacts, yet there is no automated validation of remediation effectiveness or ticket closure.【F:fixops/evidence.py†L29-L77】【F:fixops/policy.py†L41-L52】 |
| **Mobilisation** | Moderate: Policy planner recommends actions but cannot execute or confirm follow-through; onboarding surfaces steps without enforcing completion.【F:fixops/policy.py†L12-L52】【F:fixops/onboarding.py†L24-L43】 |
| **Governance** | Weak-to-Moderate: Compliance packs enumerate framework coverage, but schema laxity and lack of immutable audit logs create governance drift risks.【F:fixops/configuration.py†L164-L316】【F:fixops/compliance.py†L14-L79】 |

## Prioritised Next Steps
1. **Add ingress rate limiting and tightened CORS** to complement the new API-key enforcement (High).
2. **Encrypt and export evidence bundles securely** (object storage + KMS) when overlay metadata is omitted (High).
3. **Productise automation connectors** (Jira, Confluence, Slack) with execution paths and audit logging to fulfil enterprise promises (Medium).
4. **Enhance context & compliance depth** with owner metadata, exploit intelligence, and control-specific content validation (Medium).
5. **Extend policy automation** to execute remediation workflows and track closure state (Medium).

Addressing the critical/high actions will materially raise FixOps’ resilience and make the context engine + evidence hub differentiation harder to copy.
