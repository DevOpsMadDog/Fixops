# Codebase Gap & Risk Assessment

This review consolidates the line-level findings from the latest code audit and highlights the gaps most likely to erode FixOps’ competitive position if left unresolved.

## Recently remediated criticals
- **Evidence bundle path traversal** – evidence bundles now resolve inside the overlay allowlist and sanitise custom bundle names before writing to disk, preventing attackers from overwriting arbitrary paths via crafted configuration values. 【F:fixops/evidence.py†L1-L95】
- **Feedback directory escape** – feedback submissions now validate API payload identifiers, blocking attempts to traverse outside the allowed feedback directory. 【F:fixops/feedback.py†L1-L96】
- **Design crosswalk misalignment** – ingestion recognises `name` columns in design CSVs, so crosswalk matching no longer drops components labelled without the `component` header. 【F:backend/pipeline.py†L32-L77】
- **Exploit signal blind spots** – the pipeline now evaluates overlay-configured EPSS and KEV signals, exposing `exploitability_insights` in API responses and evidence bundles so exploit intelligence feeds harden guardrail decisions. 【F:fixops/exploit_signals.py†L1-L189】【F:backend/pipeline.py†L367-L379】

## Remaining high-priority risks
- **Exploit signal drift** – EPSS/KEV thresholds live in configuration and require manual curation; without scheduled updates or feed sync the accuracy of exploitability insights will degrade, risking false reassurance. Automating feed refresh and threshold recommendation remains a priority. 【F:config/fixops.overlay.yml†L320-L354】【F:fixops/exploit_signals.py†L1-L189】
- **Policy automation stops at planning** – `PolicyAutomation.plan` only templates Jira/Confluence payloads; it never enforces SLAs or writes back to ticketing systems, so the promised automation remains manual effort. We need delivery adapters (Jira REST, Confluence API, change-management webhooks) with retries and audit logging to close the feature gap versus Apiiro. 【F:fixops/policy.py†L1-L60】
- **AI agent detection is easy to evade** – agent analysis relies on simple substring searches across design text and SBOM metadata. A competitor can trivially miss renamed or obfuscated frameworks, undermining the “agent governance” differentiator. We should introduce signature normalisation (e.g. package hashes, Git metadata) and configurable false-positive suppression. 【F:fixops/ai_agents.py†L1-L98】
- **Compliance scoring lacks depth** – compliance evaluation marks controls as satisfied whenever an artefact exists, without validating quality (e.g. ensuring SARIF findings are triaged or evidence bundles contain specific attachments). Buyers seeking audit-ready assurance will view this as checkbox compliance. 【F:fixops/compliance.py†L1-L68】

## Medium-priority technical gaps
- **Guardrail triggers lose duplicate components** – the crosswalk dictionary overwrites entries when duplicate component names exist, so multi-region services share one context evaluation. We should key crosswalk entries by a stable identifier (e.g. CSV row index) to preserve per-instance context. 【F:fixops/context_engine.py†L94-L166】
- **Overlay sanitisation misses API keys** – `OverlayConfig._mask` redacts tokens, secrets, and passwords, but leaves keys like `api_key` or `client_id` exposed in responses. Broaden the mask vocabulary before marketing “safe overlay exports.” 【F:fixops/configuration.py†L107-L182】
- **Evidence bundles lack size governance** – evidence persistence eagerly writes full summaries without enforcing size limits or compression, which risks storage blow-ups on large enterprise runs. Add per-section caps and optional gzip packaging. 【F:fixops/evidence.py†L28-L109】
- **SSDLC checks rely on presence, not outcome** – lifecycle evaluators treat any policy action or compliance pack as success, even if the generated actions are empty or the compliance gap list is non-zero. Tighten acceptance criteria before branding the workflow “audit grade.” 【F:fixops/ssdlc.py†L1-L206】

## Observability & testing follow-ups
- Extend FastAPI integration tests to cover API-key failure paths and feedback rejection scenarios to keep parity with the new security guards. 【F:backend/app.py†L1-L211】【F:tests/test_feedback.py†L1-L54】
- Exercise evidence bundle sanitisation through end-to-end simulations to ensure demo and enterprise overlays both emit compliant paths. 【F:tests/test_evidence.py†L1-L48】

Addressing the highlighted risks keeps FixOps’ differentiators defensible and removes blockers surfaced during the competitive review.
