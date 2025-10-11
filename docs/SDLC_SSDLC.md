# FixOps Across the (S)DLC

This guide explains how FixOps ingest/overlay capabilities map to software and secure development
life-cycle stages.

> **Canonical CLI:** Run `python -m apps.fixops_cli stage-run --stage <stage> --input <artefact> --app <name>` to execute the StageRunner that powers the API, minting deterministic outputs for each SSDLC phase before bundling evidence.

| Stage | Signals Ingested | Overlay Influence | Outputs & Artifacts |
| ----- | ---------------- | ----------------- | ------------------- |
| Plan | Design context CSV describing services, owners, and criticality. | `require_design_input` toggle decides whether design is mandatory. Directory hints (e.g., `design_context_dir`) tell planners where to store curated context. | Stored dataset, metadata preview in `/inputs/design` response, SSDLC check for `design`/`threat_model`. |
| Design | Service decomposition JSON/CSV plus threat models committed alongside infrastructure-as-code. | The SSDLC stage map in `config/policy.yml` defines whether design evidence is required before code merges. | Normalised design manifest persisted to `artefacts/design/` with canonical IDs reused by downstream SBOM joins. |
| Code | SBOM packages derived from builds. | Git provider metadata (host/org/group) steers where repository checks run. | Normalised SBOM components with license data and SSDLC `dependency_pinning` coverage. |
| Build | SARIF findings produced by SAST/DAST tools. | CI configuration identifies which pipeline slug to gate; metadata is exposed via overlay for reporting. | Normalised SARIF findings, severity histogram, SSDLC `sarif` gate. |
| Test | CVE/KEV feeds for dependency risk. | Jira configuration indicates which project receives escalations when high-risk CVEs surface; guardrail maturity controls warn/fail thresholds. | Normalised CVE summaries, exploited counts, guardrail status, probabilistic forecast metrics, SSDLC `policy_automation` insight. |
| Deploy | `/pipeline/run` crosswalk verifies that design, SBOM, SARIF, and CVE data align before promoting. | Enterprise mode enforces ticket sync and deployment approvals encoded in `ssdlc.stages`. | JSON report with `crosswalk`, severity summaries, SSDLC `deploy` stage status, overlay metadata for auditing. |
| Operate | Overlay directories (evidence/audit) are created at startup so operational scripts can deposit runtime attestation. | Data paths change per mode (`demo` vs `enterprise`) allowing isolated evidence storage. | Evidence bundle with observability sections, repro attestation, and SSDLC `run` stage results. |
| Audit | `overlay.metadata` includes source path and profile selection. | Enterprise profiles enable `capture_feedback` so `/feedback` requests persist reviewer decisions alongside evidence bundles. | Evidence bundle + `ssdlc_assessment` and `ai_agent_analysis` for audits and CTEM scorecards. |

## Canonical Stage Flow (Design → Operate)

| Stage | Canonical Inputs | Processing Pipeline | CLI Surface | Primary Outputs | API Surfaces |
| ----- | ---------------- | ------------------- | ----------- | --------------- | ------------ |
| Plan & Design | `artefacts/design/*.csv` or `.json` context, overlay policy (`config/policy.yml`). | `core.design_context_injector.DesignContextLoader` normalises identifiers before `core.ssdlc.SSDLCStageEvaluator` enforces design prerequisites. | `fixops-ci evidence bundle --tag <tag>` automatically ingests design manifests when present. | Canonical design manifest stored under `artefacts/design/` and referenced in risk/provenance joins. | `backend/api/evidence` responses embed design summaries for audits. |
| Code | SBOM exports from Syft/Trivy/OSV (`artefacts/sbom/*.json`). | `lib4sbom.normalizer.write_normalized_sbom` deduplicates by purl/version/hash and persists canonical JSON. | `fixops-ci sbom normalize --in <sboms...>` produces `artifacts/sbom/normalized.json`. | `artifacts/sbom/normalized.json` plus deduplication telemetry. | `backend/api/graph/components` traces SBOM nodes; `backend/api/evidence` references the same manifest. |
| Build | Static analysis SARIF or build logs under `artefacts/scans/`. | `services.provenance.attestation.generate_attestation` links build run metadata, builder IDs, and materials. | `fixops-ci provenance attest --artifact <path> --out <attestation>` records build lineage. | DSSE/SLSA v1 attestation JSON stored under `artifacts/attestations/`. | `backend/api/provenance/{artifact}` retrieves stored attestations. |
| Test | Risk feeds (EPSS, KEV) plus normalised SBOM. | `risk.scoring.generate_scores` enriches SBOM components with EPSS/KEV deltas and version lag heuristics. | `fixops-ci risk score --sbom artifacts/sbom/normalized.json --out artifacts/risk.json`. | Composite risk report at `artifacts/risk.json` with FixOpsRisk values. | `backend/api/risk/{component|cve}` returns risk payloads for CI/CD gates. |
| Deploy | Release metadata (git tags, artefact digests). | `services.graph.graph.ProvenanceGraphBuilder` stitches commits, attestations, SBOM, and risk to validate release readiness. | `fixops-ci evidence bundle --tag <tag>` runs policy evaluation using the assembled graph context. | Signed `MANIFEST.yaml` and zipped evidence bundle under `evidence/<tag>/`. | `backend/api/evidence/{release}` shares bundle metadata with release automation. |
| Operate | Reproducible build plans (`build/plan.yaml`) and release artefacts. | `services.repro.verifier.ReproVerifier` executes hermetic rebuilds and compares digests. | `fixops-ci repro verify --tag <tag> --plan build/plan.yaml` outputs reproducibility attestations. | `artifacts/repro/attestations/<tag>.json` and policy results persisted to evidence bundles. | `backend/api/evidence/{release}` includes reproducibility verdicts; `backend/api/graph/lineage` surfaces runtime lineage queries. |
| Audit | Evidence bundle manifest, cosign keys (CI), observability exports. | `evidence.packager.create_bundle` consolidates SBOM, risk, provenance, repro, and policy evaluations then signs the manifest. | `fixops-ci evidence bundle --tag <tag> --sign-key <path>` packages proof bundles for external auditors. | Zipped bundle with signed `MANIFEST.yaml`, policy verdicts, and coverage reports. | Evidence endpoints and downloadable artefacts from CI releases. |

### CLI Playbook by Lifecycle Stage

- **Design/Plan:** Capture curated system context and threat models under `artefacts/design/`, then materialise canonical stage output via `python -m apps.fixops_cli stage-run --stage design --input artefacts/design/design_context.csv --app <app>` before bundling with `fixops-ci evidence bundle --tag <release>` so the evaluator confirms coverage prior to promotion.
- **Code:** Deduplicate SBOM inputs with `fixops-ci sbom normalize --in artefacts/sbom/syft.json artefacts/sbom/trivy.json --out artifacts/sbom/normalized.json` to create the canonical component inventory feeding all downstream stages.
- **Build:** For every release artefact, execute `fixops-ci provenance attest -- <args>` via CI (see `.github/workflows/provenance.yml`) so the attestation graph links builder IDs, source commits, and materials.
- **Test:** Generate FixOpsRisk metrics using `fixops-ci risk score --sbom artifacts/sbom/normalized.json --out artifacts/risk.json` before allowing deployments; policy thresholds live in `config/policy.yml`.
- **Deploy:** Run `fixops-ci evidence bundle --tag <release>` after tagging to aggregate SBOM, risk, provenance, and graph validations while evaluating pass/warn/fail policy thresholds.
- **Operate:** Confirm deterministic rebuilds with `fixops-ci repro verify --tag <release> --plan build/plan.yaml`, and re-run `python -m apps.fixops_cli stage-run --stage operate --app <app>` to refresh lifecycle evidence from KEV/EPSS feeds before packaging bundles; the resulting attestation feeds dashboards.
- **Audit:** Use the evidence bundle output to satisfy compliance reviews; the signed `MANIFEST.yaml` enumerates every artefact emitted across the lifecycle, and `fixops-ci evidence bundle` can re-run with `--sign-key` to append notarised manifests for auditors.

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
