# Documentation Coverage Ledger

This ledger records the April 2025 review of every document under `docs/`. Each
entry cites the primary runtime modules or workflows that keep the guidance
current. Items marked **Archive** have been relocated to `docs/doc-archive/`.
All remaining files are actively referenced by the codebase, CLIs, or CI/CD
workflows introduced across Phases 1–10.

| Document | Coverage Summary | Status |
| -------- | ---------------- | ------ |
| `ACADEMIC_RESEARCH.md` | Maps FixOps exploit and evidence features to referenced research; aligns with `risk/feeds` and evidence bundling modules. | Retain |
| `AI_AGENTS_RESEARCH.md` | Documents AI governance influences on `core/ai_agents.py` and evidence overlays. | Retain |
| `ARCH-INVENTORY.md` | Phase 1 architecture inventory listing runtime modules, APIs, and workflows. | Retain |
| `ARCHITECTURE.md` | High-level architecture diagrams corresponding to `services/*`, `backend/api/*`, and CLI entrypoints. | Retain |
| `BACKLOG.csv` | Tracking backlog for enterprise modules stored in `fixops-enterprise/` and Phase 6–10 features. | Retain |
| `CI-SECRETS.md` | Enumerates GitHub Actions secrets consumed by `release-sign.yml` and `provenance.yml`. | Retain |
| `CLOSED_LOOP_OPTIMIZATION.md` | Describes probabilistic analytics implemented in `core/probabilistic.py` and telemetry overlays. | Retain |
| `CODE_GAP_ASSESSMENT.md` | Cross-references README claims with shipped modules under `core/` and enterprise overlays. | Retain |
| `CONFIG_GUIDE.md` | Reference for overlay and policy configuration consumed by `core/configuration.py`. | Retain |
| `CONTRIBUTING.md` | Contributor workflow guidelines aligned with `.github/workflows/qa.yml`. | Retain |
| `DATA_MODEL.md` | Domain model definitions mirroring classes in `core/context_engine.py` and `services/graph/graph.py`. | Retain |
| `DEMO.md` | One-command demo instructions tied to `docker-compose.demo.yml` and telemetry setup. | Retain |
| `EVIDENCE-BUNDLES.md` | Documents bundle schema implemented by `services/evidence/packager.py` and `fixops-ci evidence bundle`. | Retain |
| `FIXOPS_ADOPTION_GUIDE.md` | Enablement guidance referencing CLI tools and overlays in `config/`. | Retain |
| `FOLDER_README.md` | Explains docs folder structure for maintainers. | Retain |
| `FixOps_Demo_IO_Contract.md` | Documents demo API contracts matching payloads in `apps/api/app.py`. | Retain |
| `INTEGRATIONS.md` | Lists third-party connectors mirrored by stubs under `core/connectors.py`. | Retain |
| `LINE_BY_LINE.md` | Highlights verification checkpoints satisfied by `tests/` and policy evaluators. | Retain |
| `MIGRATION.md` | Notes upgrade steps for overlay schema and CLI usage, tied to `config/policy.yml`. | Retain |
| `OBSERVABILITY.md` | Describes OpenTelemetry integration aligning with `telemetry/` package and Phase 9 demo. | Retain |
| `PLATFORM_RUNBOOK.md` | Operational runbook covering API startup and evidence workflows in `apps/api` and `evidence/`. | Retain |
| `PLAYBOOK-AUDIT.md` | Audit procedures leveraging evidence bundles and provenance APIs. | Retain |
| `PLAYBOOK-DEV.md` | Developer practices referencing CLI commands and QA workflow. | Retain |
| `PLAYBOOK-SEC.md` | Security operations referencing risk scoring and provenance services. | Retain |
| `PROVENANCE-GRAPH.md` | Phase 6 provenance graph design corresponding to `services/graph` and API routes. | Retain |
| `PROVENANCE.md` | SLSA attestation schema used by `services/provenance` and CLI wrappers. | Retain |
| `PR_CHECKLIST.md` | Review checklist aligned with QA automation and evidence requirements. | Retain |
| `PR_SUMMARY.md` | Template for summarising PRs including evidence and testing references. | Retain |
| `README_GAP_AND_TEST_PLAN.md` | Audit of README commitments matched to modules in `core/` and tests. | Retain |
| `REPRO-BUILDS.md` | Documents reproducible build verifier implemented in `services/repro`. | Retain |
| `RISK-SCORING.md` | Describes FixOpsRisk formula implemented in `risk/scoring.py`. | Retain |
| `ROADMAP.md` | Product roadmap aligned with phased delivery (docs/TASK-PLAN.md). | Retain |
| `SBOM-QUALITY.md` | Explains normalization and quality metrics delivered in `lib4sbom/normalizer.py`. | Retain |
| `SDLC_SSDLC.md` | Lifecycle mapping updated in this review to document canonical inputs, processing, and CLI calls. | Retain |
| `SECURITY-POSTURE.md` | Captures branch protection, signing, and CI controls implemented in workflows. | Retain |
| `SECURITY.md` | Security policy consistent with provenance, signing, and risk modules. | Retain |
| `SIGNING.md` | Cosign-based signing process matching `scripts/signing/` and release workflow. | Retain |
| `SSDL_SIMULATION.md` | Simulation overview supporting Stage Runner and SSDLC evaluator in `core/ssdlc.py`. | Retain |
| `STRAIKER_APR2025_COMPETITIVE_NOTES.md` | Competitive analysis guiding enhancements for `core/ai_agents.py` and SSDLC gates. | Retain |
| `TASK-PLAN.md` | Phase 2–10 implementation roadmap used to drive branch history. | Retain |
| `USAGE_GUIDE.html` | Rich HTML quick-start referencing CLI commands and overlay behaviours. | Retain |
| `decisionfactory_alignment.md` | Narrative aligning decision factory features with `services/graph` and risk modules. | Retain |
| `feature_call_tree.md` | Maps feature surfaces to modules and APIs for reviewers. | Retain |
| `security_sales_objections.md` | Sales enablement with pointers to provenance, evidence, and compliance modules. | Retain |
| `decisionfactory_alignment/` | Folder contains detailed implementation notes for the decision factory overlay and dashboards. | Retain |

No files required archival during this pass; `docs/doc-archive/` remains empty so
future reviews can relocate superseded content when features are removed from the
codebase.

