# Codebase Gap & Risk Assessment

This review consolidates the line-level findings from the latest code audit and highlights the gaps most likely to erode FixOps’ competitive position if left unresolved.

## Newly remediated gaps
- **Exploit signal automation** – overlay metadata now records feed freshness and the evaluator auto-downloads KEV/EPSS feeds when stale, annotating CVE records and persisting snapshots safely inside the overlay allowlist. 【F:fixops/exploit_signals.py†L1-L288】【F:backend/pipeline.py†L360-L384】
- **Policy automation delivery** – Jira, Confluence, and Slack connectors authenticate with overlay-provided tokens, emit remote delivery statuses, and retain JSON dispatch manifests for audit evidence. 【F:fixops/connectors.py†L1-L220】【F:fixops/policy.py†L20-L151】
- **AI agent evasion hardening** – signature matching now tokenises aliases, package indicators, and scanner context to detect renamed frameworks without relying on raw substrings. 【F:fixops/ai_agents.py†L1-L176】【F:config/fixops.overlay.yml†L66-L107】
- **Compliance & SSDLC rigour** – control checks require dispatched automations, satisfied frameworks, and pass-or-warn guardrail status before awarding credit, preventing checkbox compliance. 【F:fixops/compliance.py†L1-L77】【F:fixops/ssdlc.py†L280-L360】
- **Crosswalk fidelity** – crosswalk entries retain the originating row index, avoiding duplicate-component overwrites when evaluating context or guardrails. 【F:backend/pipeline.py†L62-L143】【F:fixops/context_engine.py†L94-L178】
- **Overlay and evidence hygiene** – sanitisation redacts API/client keys and evidence bundles enforce byte limits with automatic compression, keeping exported artefacts safe for sharing. 【F:fixops/configuration.py†L200-L242】【F:fixops/evidence.py†L1-L127】

## Residual risks to monitor
- None currently flagged after connector and feed automation landing; continue monitoring third-party API rate limits and feed schema drift as integrations expand.

## Test & observability coverage
- FastAPI integration tests now assert API-key enforcement and reject unsafe feedback payloads, aligning runtime security with the hardened upload layer. 【F:tests/test_end_to_end.py†L146-L226】
- Evidence bundles report compression state and section coverage, enabling auditors to validate artefact completeness run by run. 【F:fixops/evidence.py†L60-L127】

Ongoing focus on operational telemetry will ensure FixOps’ enterprise differentiators remain defensible as additional connectors and feeds are introduced.
