# FixOps Across the (S)DLC

This guide explains how FixOps ingest/overlay capabilities map to software and secure development
life-cycle stages.

| Stage | Signals Ingested | Overlay Influence | Outputs & Artifacts |
| ----- | ---------------- | ----------------- | ------------------- |
| Plan | Design context CSV describing services, owners, and criticality. | `require_design_input` toggle decides whether design is mandatory. Directory hints (e.g., `design_context_dir`) tell planners where to store curated context. | Stored dataset, metadata preview in `/inputs/design` response, SSDLC check for `design`/`threat_model`. |
| Code | SBOM packages derived from builds. | Git provider metadata (host/org/group) steers where repository checks run. | Normalised SBOM components with license data and SSDLC `dependency_pinning` coverage. |
| Build | SARIF findings produced by SAST/DAST tools. | CI configuration identifies which pipeline slug to gate; metadata is exposed via overlay for reporting. | Normalised SARIF findings, severity histogram, SSDLC `sarif` gate. |
| Test | CVE/KEV feeds for dependency risk. | Jira configuration indicates which project receives escalations when high-risk CVEs surface; guardrail maturity controls warn/fail thresholds. | Normalised CVE summaries, exploited counts, guardrail status, probabilistic forecast metrics, SSDLC `policy_automation` insight. |
| Deploy | `/pipeline/run` crosswalk verifies that design, SBOM, SARIF, and CVE data align before promoting. | Enterprise mode enforces ticket sync and deployment approvals encoded in `ssdlc.stages`. | JSON report with `crosswalk`, severity summaries, SSDLC `deploy` stage status, overlay metadata for auditing. |
| Run | Overlay directories (evidence/audit) are created at startup so operational scripts can deposit runtime attestation. | Data paths change per mode (`demo` vs `enterprise`) allowing isolated evidence storage. | Evidence bundle with observability sections and SSDLC `run` stage results. |
| Audit | `overlay.metadata` includes source path and profile selection. | Enterprise profiles enable `capture_feedback` so `/feedback` requests persist reviewer decisions alongside evidence bundles. | Evidence bundle + `ssdlc_assessment` and `ai_agent_analysis` for audits and CTEM scorecards. |

## Flow of Signals

1. **Ingestion** — Upload endpoints accept artefacts in any order. Each artefact is normalised and
   stored in `app.state.artifacts`.
2. **Rescoring & Correlation** — `PipelineOrchestrator.run()` performs token-based correlation,
   aggregates severity/exploitation indicators, evaluates guardrails against the active maturity
   profile, executes the probabilistic forecast engine (Bayesian priors + Markov transitions), and
   prepares the crosswalk while grading each lifecycle stage through the SSDLC evaluator.
3. **Evidence Emission** — Responses include metadata and the overlay block, enabling downstream
   systems to create compliance evidence without querying the server configuration directly.
4. **Feedback Loop** — Enterprise overlays enable `capture_feedback`, storing JSONL decisions locally
   (ready for downstream Jira/Confluence sync) while `ai_agent_analysis` highlights agentic services
   requiring governance review.

## Operational Recommendations

- Automate overlay deployment via infrastructure-as-code so Demo and Enterprise environments stay in
  sync with go-to-market promises.
- Version-control overlay files per tenant to maintain a clear audit trail of configuration changes.
- Extend the ingestion pipeline with background tasks that watch overlay directories and push evidence
  bundles to Confluence or object storage on a schedule.
