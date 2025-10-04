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
| Overlay-guided onboarding | Mode-specific checklists and integration stubs drive ≤30‑minute first value promises.【F:fixops/onboarding.py†L12-L43】【F:config/fixops.overlay.yml†L101-L199】 | Helps solution engineers prove value quickly while signalling enterprise prerequisites.
| Pricing clarity | Active plan and entitlements surfaced alongside pipeline outputs for transparency.【F:fixops/configuration.py†L232-L248】【F:config/fixops.overlay.yml†L183-L199】 | Arms GTM with plan boundaries that align with delivered artefacts.

## Critical & High Gaps
| Priority | Gap | Evidence | Risk & Impact | Recommendation |
| --- | --- | --- | --- | --- |
| **Critical** | No authentication / open CORS | FastAPI app exposes all ingestion endpoints without auth and allows all origins.【F:backend/app.py†L19-L150】 | Any actor can push artefacts, enumerate overlay metadata, and generate evidence bundles; DoS or data poisoning possible. | Enforce API tokens or OIDC (per overlay `auth` settings) via FastAPI dependencies; restrict CORS to trusted domains and add rate limiting at the ingress.
| **High** | Overlay path & directory trust | Overlay values are accepted wholesale and expanded into filesystem writes without sanitisation.【F:fixops/configuration.py†L91-L119】【F:fixops/evidence.py†L19-L38】 | Malicious or misconfigured overlay could redirect evidence output to arbitrary host paths, enabling data exfil or overwrite. | Validate overlay directories against an allowlist root and reject relative traversal; introduce schema validation with pathlib safety checks.
| **High** | Unbounded upload sizes / memory pressure | File bodies are fully read into memory before parsing with no size checks.【F:backend/app.py†L47-L118】 | Attackers can exhaust memory or disk via oversized uploads, knocking the service offline. | Enforce per-endpoint size limits (FastAPI `UploadFile.spool_max_size`, content-length guards) and stream parse large files where possible.
| **High** | Overlay schema permissiveness | Unexpected keys silently persist; maturity defaults hide typos that alter guardrail intent.【F:fixops/configuration.py†L164-L316】 | Misconfigurations may only surface during incidents (e.g., guardrail thresholds never applied). | Introduce strict validation (Pydantic model or JSON Schema) and lint overlays during CI; emit warnings for unused keys.
| **High** | Evidence bundle leakage | Sanitised overlay still exposes internal directory structure and plan metadata in stored JSON.【F:fixops/evidence.py†L40-L77】 | If evidence directory is compromised, internal topology and pricing plans leak. | Allow operators to toggle overlay inclusion; store overlay metadata separately with tighter ACLs; encrypt evidence at rest.

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
1. **Ship authentication & rate limits** aligned with overlay `auth` strategies, plus hardened CORS (Critical).
2. **Introduce overlay schema validation and filesystem sandboxing** before reading/writing artefacts (High).
3. **Implement upload size guards and streaming parsers** for SBOM/SARIF/CVE ingestion to resist DoS (High).
4. **Tighten evidence handling** with encryption, ACLs, and optional overlay exclusion (High).
5. **Productise automation connectors** (Jira, Confluence, Slack) with execution paths and audit logging to fulfil enterprise promises (Medium).
6. **Enhance context & compliance depth** with owner metadata, exploit intelligence, and control-specific content validation (Medium).

Addressing the critical/high actions will materially raise FixOps’ resilience and make the context engine + evidence hub differentiation harder to copy.
