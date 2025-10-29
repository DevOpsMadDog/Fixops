# FixOps Architecture Guide for New Engineers

Welcome to FixOps! This guide provides a comprehensive overview of the platform architecture, key components, data flows, and technologies to help you get up to speed quickly.

## What is FixOps?

FixOps is a contextual risk and evidence platform that transforms raw security artifacts (SBOM, SARIF, CVE feeds, design documents) into actionable risk intelligence, compliance evidence, and automated remediation workflows. The platform correlates multiple security data sources, applies probabilistic risk models, evaluates guardrails, and generates audit-ready evidence bundles with minimal configuration.

## High-Level Architecture

FixOps follows a pipeline architecture where security artifacts flow through ingestion, normalization, correlation, analysis, and decisioning stages before producing outputs like evidence bundles, automation payloads, and compliance reports.

```
Client Upload → Ingestion API → Normalization → Pipeline Orchestrator → Analysis Modules → Enhanced Decisioning → Output Generation
                                                      ↓
                                            Overlay Configuration (runtime settings)
                                                      ↓
                                        Evidence Hub, Compliance, Automation, Analytics
```

### Core Architectural Principles

**Overlay-Driven Configuration**: A single YAML configuration file (`config/fixops.overlay.yml`) controls operational modes (demo vs enterprise), module toggles, compliance frameworks, authentication strategies, data directories, and automation connectors. This allows the same codebase to serve different deployment scenarios without code changes.

**Push-Based Ingestion**: Clients upload artifacts through REST API endpoints or use a CLI with identical functionality. The system validates uploads against size limits and MIME types, normalizes heterogeneous formats, and persists artifacts for pipeline processing.

**Modular Pipeline**: The orchestrator coordinates multiple analysis modules (context engine, guardrails, compliance, SSDLC, IaC posture, probabilistic forecasting, AI agents, exploit signals) that execute conditionally based on overlay settings. Each module enriches the shared pipeline context.

**Multi-LLM Consensus**: The enhanced decision engine optionally invokes multiple LLM providers (OpenAI, Anthropic, Google, custom models) to generate consensus decisions with explainable reasoning, MITRE ATT&CK mappings, and compliance recommendations.

**Evidence-First Design**: Every pipeline run generates cryptographically signed evidence bundles containing normalized artifacts, analysis results, and audit trails that can be encrypted and handed off to GRC systems or stored for compliance purposes.

## Repository Structure

### Core Directories

**`core/`**: Reusable business logic and pipeline modules consumed by both API and CLI surfaces. This is the heart of FixOps processing logic.

- `cli.py`: Command-line interface providing local pipeline execution with feature parity to the API
- `configuration.py` & `overlay_runtime.py`: Overlay configuration loading and runtime preparation
- `pipeline.py` (via `apps/api/pipeline.py`): Pipeline orchestrator coordinating all analysis modules
- `context_engine.py`: Correlates business context (criticality, data classification, exposure) with technical findings
- `guardrails.py` (logic in pipeline): Evaluates severity thresholds and determines pass/warn/fail status
- `compliance.py`: Maps guardrail and policy results to compliance control coverage (SOC2, ISO27001)
- `evidence.py`: Evidence hub that bundles artifacts with optional compression and encryption
- `policy.py`: Policy automation that dispatches Jira tickets, Confluence pages, and Slack notifications
- `ssdlc.py`: SSDLC stage evaluator assessing pipeline coverage across design through operations
- `exploit_signals.py`: Enriches CVE data with KEV (Known Exploited Vulnerabilities) and EPSS probability
- `probabilistic.py`: Probabilistic forecast engine using Markov chains, Bayesian methods, and spectral diagnostics
- `enhanced_decision.py`: Multi-LLM consensus engine with provider orchestration
- `llm_providers.py`: LLM provider abstractions for OpenAI, Anthropic, Google, and custom models
- `iac.py`: Infrastructure-as-Code posture evaluator for Terraform and Kubernetes manifests
- `ai_agents.py`: AI agent advisor for intelligent recommendations
- `analytics.py`: ROI dashboard and analytics store
- `feedback.py`: Feedback recorder for user input capture
- `onboarding.py`: Onboarding guide generator
- `storage.py`: Artifact archive management with allowlisting
- `paths.py`: Secure path verification and directory creation
- `stage_runner.py`: Stage-by-stage pipeline runner for CLI workflows
- `demo_runner.py`: Demo pipeline orchestration for deterministic demonstrations

**`apps/`**: Application entry points and API services.

- `apps/api/`: FastAPI ingestion service
  - `app.py`: FastAPI application factory with endpoint definitions for upload, pipeline execution, and analytics
  - `pipeline.py`: PipelineOrchestrator class implementing core correlation and analysis logic
  - `normalizers.py`: Input normalizers converting heterogeneous formats (SBOM, SARIF, CVE, VEX, CNAPP) to canonical models
  - `knowledge_graph.py`: Knowledge graph service for entity relationship mapping
  - `upload_manager.py`: Chunked upload manager for large file handling
  - `routes/`: API route handlers for enhanced decision, provenance, risk, graph, and evidence endpoints

- `apps/fixops_cli/`: CLI application wrapper

**`backend/`**: Backend API routers and additional services.

- `backend/api/`: Specialized API routers
  - `provenance/`: SLSA provenance and attestation endpoints
  - `graph/`: Dependency graph and relationship endpoints
  - `risk/`: Risk scoring and FixOpsRisk calculation endpoints
  - `evidence/`: Evidence bundle retrieval and manifest endpoints
- `backend/normalizers.py`: Additional normalization utilities
- `backend/app.py`: Compatibility wrapper delegating to `apps/api/app.py`

**`fixops-enterprise/`**: Enterprise-specific enhanced decision layer.

- `fixops-enterprise/src/api/v1/enhanced.py`: Enhanced decision API routes for capabilities discovery, payload analysis, and multi-model comparisons
- `fixops-enterprise/src/services/enhanced_decision_engine.py`: Service wrapper for enhanced decision engine with lazy overlay loading

**`services/`**: Supporting services for specialized operations.

- `services/evidence/`: Evidence packaging and bundling
- `services/graph/`: Dependency graph construction and analysis
- `services/provenance/`: SLSA provenance attestation generation
- `services/repro/`: Reproducible build attestations
- `services/match/`: Component, CVE, and finding matching algorithms used by pipeline orchestrator

**`lib4sbom/`**: SBOM normalization library supporting multiple formats (CycloneDX, SPDX).

**`risk/`**: Risk scoring and feed management.

- `risk/scoring.py`: FixOpsRisk scoring algorithms
- `risk/feeds/kev.py`: Known Exploited Vulnerabilities feed integration
- `risk/feeds/epss.py`: Exploit Prediction Scoring System feed integration

**`config/`**: Configuration files controlling runtime behavior.

- `config/fixops.overlay.yml`: Primary overlay configuration defining enterprise mode settings
- `config/policy.yml`: Policy automation definitions
- `config/otel-collector-demo.yaml`: OpenTelemetry collector configuration for observability

**`simulations/`**: Test fixtures and deterministic demo data.

- `simulations/demo_pack/`: Canonical artifacts (design CSV, SBOM, SARIF, CVE, telemetry) for reproducible demos

**`data/`**: Runtime data directories for uploads, archives, evidence, analytics (created at startup).

**`tests/`**: Comprehensive test suite covering CLI parity, API endpoints, pipeline logic, overlay validation, and enterprise features.

**`docs/`**: Detailed documentation for SBOM quality, risk scoring, provenance, evidence bundles, and architecture.

**`telemetry/`**: OpenTelemetry instrumentation for observability and monitoring.

**`scripts/`**: Operational scripts including demo runners, signing helpers, and bootstrap automation.

## Technology Stack

### Core Technologies

**FastAPI**: Modern async Python web framework for REST API with automatic OpenAPI documentation, dependency injection, and validation.

**Pydantic**: Data validation and settings management using Python type hints. All normalized models use Pydantic for schema validation.

**PyYAML**: Overlay configuration parsing from YAML files.

**PyJWT**: JSON Web Token generation and validation for API authentication.

**Cryptography**: Evidence bundle encryption and key management.

**NetworkX**: Graph data structures for dependency graphs and knowledge graphs.

**APScheduler**: Scheduled background tasks for exploit feed refreshes.

**OpenTelemetry**: Distributed tracing and observability instrumentation.

### Specialized Libraries

**pgmpy**: Bayesian network probabilistic reasoning (used by probabilistic forecast engine).

**structlog**: Structured logging for better debugging and audit trails.

**requests**: HTTP client for external API calls (LLM providers, exploit feeds).

**cffi**: C Foreign Function Interface for low-level operations.

### Optional/Enterprise Dependencies

**OpenAI, Anthropic, Google AI SDKs**: LLM provider integrations for enhanced decision engine (loaded lazily).

**pytest**: Testing framework with extensive coverage.

**ruff**: Fast Python linter and formatter.

**mypy**: Static type checking for Python code quality.

## Data Flow Walkthrough

### 1. Artifact Ingestion

**Entry Point**: Client uploads files to FastAPI endpoints (`/inputs/design`, `/inputs/sbom`, `/inputs/sarif`, `/inputs/cve`, `/inputs/vex`, `/inputs/cnapp`, `/inputs/context`).

**Authentication**: API key validation via `X-API-Key` header (token strategy) or JWT bearer token based on overlay configuration.

**Validation**: Upload size limits enforced per stage, MIME type validation, streaming to spooled temporary files.

**Normalization**: `InputNormalizer` converts heterogeneous formats into canonical Pydantic models:
- Design CSV → structured dataset with columns and rows
- SBOM JSON → `NormalizedSBOM` with components, dependencies, and metadata
- SARIF JSON → `NormalizedSARIF` with findings, tool info, and results
- CVE feed JSON → `NormalizedCVEFeed` with CVE records, EPSS scores, KEV flags
- VEX document → `NormalizedVEX` with suppression assertions
- CNAPP payload → `NormalizedCNAPP` with cloud assets and findings
- Business context → `NormalizedBusinessContext` with SSVC factors and component metadata

**Persistence**: Normalized artifacts stored in `ArtefactArchive` under overlay-allowlisted directories with original filenames and raw bytes for audit trails.

### 2. Pipeline Orchestration

**Entry Point**: `/pipeline/run` endpoint or `python -m core.cli run` command.

**Orchestrator**: `PipelineOrchestrator.run()` receives normalized artifacts and overlay configuration.

**Crosswalk Construction**: The orchestrator builds a "crosswalk" correlating design components with SBOM components, SARIF findings, and CVE records using token-based matching:
- Extracts component names from design rows
- Indexes SBOM components by name, PURL, CPE
- Indexes findings by file paths and component references
- Indexes CVE records by package names and versions
- Produces `CrosswalkRow` entries linking design → SBOM → findings → CVEs

**Business Context Enrichment**: If business context provided, enriches crosswalk rows with SSVC factors (criticality, data classification, exposure).

**VEX Suppression**: If VEX document provided, filters out findings for not-affected components and tracks noise reduction metrics.

**CNAPP Integration**: If CNAPP payload provided, incorporates cloud asset findings and exposure traits into severity aggregation.

**Severity Aggregation**: Normalizes severity levels across sources (SARIF levels, CVE CVSS scores, CNAPP findings) to common scale (low, medium, high, critical) and determines highest overall severity.

### 3. Module Execution

Each enabled module receives enriched pipeline context and contributes analysis results:

**Context Engine** (`core.context_engine.ContextEngine`): Calculates context scores by weighting criticality, data sensitivity, and exposure factors. Generates prioritized finding lists and playbook recommendations based on thresholds.

**Guardrails** (inline in `PipelineOrchestrator._evaluate_guardrails`): Compares highest severity against overlay-defined thresholds (fail_on, warn_on) and returns pass/warn/fail status with rationale.

**Compliance** (`core.compliance.ComplianceEvaluator`): Maps guardrail and policy results to compliance control coverage, evaluates control satisfaction, and generates framework-specific reports (SOC2, ISO27001).

**Policy Automation** (`core.policy.PolicyAutomation`): Triggers configured actions (Jira ticket creation, Confluence page updates, Slack notifications) based on guardrail status and compliance gaps.

**Evidence Hub** (`core.evidence.EvidenceHub`): Bundles normalized artifacts, pipeline results, and attestations into compressed and optionally encrypted archives with retention policies.

**SSDLC Evaluator** (`core.ssdlc.SSDLCEvaluator`): Assesses coverage across design, build, test, deploy, and operate stages, identifies control gaps, and scores pipeline maturity.

**Exploit Signals** (`core.exploit_signals.ExploitSignalEvaluator`): Enriches CVE records with KEV flags and EPSS exploit probability, prioritizes exploited vulnerabilities, and surfaces active threats.

**IaC Posture** (`core.iac.IaCPostureEvaluator`): Analyzes Terraform plans and Kubernetes manifests for misconfigurations, insecure defaults, and compliance violations.

**Probabilistic Forecasting** (`core.probabilistic.ProbabilisticForecastEngine`): Applies Markov chain models, Bayesian posterior updates, and spectral diagnostics to forecast severity drift and escalation pressure.

**AI Agents** (`core.ai_agents.AIAgentAdvisor`): Generates intelligent recommendations for remediation, automation opportunities, and security posture improvements.

**Analytics** (`core.analytics.ROIDashboard`): Computes ROI metrics, performance profiles, and executive summaries for dashboards.

**Vector Store** (`core.vector_store.SecurityPatternMatcher`): Matches findings against known security patterns using vector embeddings for similarity-based detection.

**Knowledge Graph** (`apps.api.knowledge_graph.KnowledgeGraphService`): Constructs entity relationship graphs linking services, findings, controls, and mitigations for attack path analysis.

### 4. Enhanced Decision Engine

**Entry Point**: Automatically invoked by pipeline orchestrator if `modules.enhanced_decision.enabled: true` in overlay.

**Multi-LLM Consensus**: `EnhancedDecisionEngine` orchestrates multiple LLM provider calls with specialized prompts:
- GPT-5 (strategist): Focuses on MITRE ATT&CK and contextual risk
- Claude-3 (analyst): Focuses on compliance and guardrail evaluation
- Gemini-2 (signals): Focuses on exploit intelligence and CNAPP findings
- Sentinel-Cyber (threat): Focuses on marketplace recommendations and AI agent insights

**Consensus Logic**: Aggregates provider responses, resolves disagreements using weighted voting, calculates consensus confidence, and generates unified decision with explainable reasoning.

**Knowledge Graph Analytics**: Constructs attack path graphs, identifies critical nodes, and surfaces relationship-based risk insights.

**Deterministic Fallback**: If LLM API keys not configured, engine operates deterministically using heuristics and returns baseline confidence scores.

### 5. Output Generation

**Pipeline Result**: JSON response containing:
- Severity overview with counts by level and source breakdown
- Guardrail evaluation with pass/warn/fail status and rationale
- Compliance status with framework coverage and control satisfaction
- Policy automation execution summary with dispatched actions
- Evidence bundle metadata with file paths and retention policies
- Enhanced decision consensus with LLM provider contributions
- Context engine recommendations with prioritized playbooks
- SSDLC coverage map with stage maturity scores
- Analytics ROI metrics and performance profiles
- Marketplace recommendations for remediation tools
- Knowledge graph entities and relationships

**Evidence Bundle**: Compressed archive (optionally encrypted) containing normalized artifacts, pipeline results, attestations, and transparency logs stored under overlay-allowlisted evidence directories.

**Automation Payloads**: Dispatched to external systems:
- Jira issues created with guardrail failure details
- Confluence pages updated with compliance evidence
- Slack notifications sent to configured channels

**Analytics Persistence**: Pipeline run metadata, ROI calculations, and performance profiles persisted to analytics store for dashboard visualization.

## Key Design Patterns

### Overlay Pattern

All runtime configuration externalized to YAML overlay files enabling:
- Mode switching (demo vs enterprise) without code changes
- Module toggles enabling/disabling features dynamically
- Environment-specific settings (API tokens, data directories, limits)
- Compliance framework and policy customization per deployment

### Normalizer Pattern

Heterogeneous input formats (SBOM CycloneDX/SPDX, SARIF 2.1.0, various CVE feeds) converted to canonical Pydantic models ensuring:
- Type safety throughout pipeline processing
- Format-agnostic business logic
- Extensibility for new input sources
- Validation at ingestion boundaries

### Crosswalk Pattern

Central correlation structure linking design intent, bill-of-materials, findings, and vulnerabilities enabling:
- Contextual risk scoring across artifact boundaries
- Business impact analysis tied to technical components
- Noise reduction through VEX suppression
- Unified reporting across security data sources

### Module Registry Pattern

Pipeline modules registered with enable/disable toggles supporting:
- Feature flagging for gradual rollouts
- Performance optimization by skipping disabled modules
- Custom module integration via plugin architecture
- Test isolation for module-specific logic

### Evidence Chain Pattern

Cryptographic signing, provenance attestations, and transparency logs creating immutable audit trails for:
- Compliance evidence that survives challenges
- Supply chain verification (SLSA provenance)
- Reproducible builds with attestations
- Tamper-evident evidence bundles

## Common Workflows

### Demo Mode Workflow

Execute deterministic demo with curated fixtures:

```bash
python -m core.cli demo --mode demo --output out/demo.json --pretty
```

This seeds demo tokens, loads fixtures from `simulations/demo_pack/`, executes full pipeline with demo overlay profile, and emits JSON result with console summary.

### Enterprise Mode Workflow

Execute with hardened enterprise overlay and evidence encryption:

```bash
export FIXOPS_API_TOKEN="your-secret-token"
export FIXOPS_EVIDENCE_KEY="your-encryption-key"
python -m core.cli demo --mode enterprise --output out/enterprise.json --pretty
```

### API Ingestion Workflow

1. Start FastAPI server: `uvicorn apps.api.app:app --reload`
2. Upload design: `POST /inputs/design` with CSV file
3. Upload SBOM: `POST /inputs/sbom` with JSON file
4. Upload SARIF: `POST /inputs/sarif` with JSON file
5. Upload CVE feed: `POST /inputs/cve` with JSON file
6. Run pipeline: `POST /pipeline/run` with empty body
7. Retrieve results from JSON response
8. Download evidence bundle from path in response

### Stage-by-Stage CLI Workflow

Execute individual pipeline stages for incremental processing:

```bash
python -m apps.fixops_cli stage-run --stage requirements --input data/requirements.csv --app my-app
python -m apps.fixops_cli stage-run --stage design --input data/design.json --app my-app
python -m apps.fixops_cli stage-run --stage build --input data/sbom.json --app my-app
python -m apps.fixops_cli stage-run --stage test --input data/scanner.sarif --app my-app
python -m apps.fixops_cli stage-run --stage decision --app my-app
```

Each stage outputs canonical JSON under `artefacts/<app_id>/<run_id>/outputs/`.

## Testing Strategy

**Unit Tests**: Module-specific tests covering normalization, scoring algorithms, compliance mapping, and utility functions.

**Integration Tests**: Pipeline orchestration tests exercising full workflows with fixture data.

**API Tests**: FastAPI endpoint tests validating authentication, upload limits, error handling, and response schemas.

**CLI Tests**: Command-line interface tests ensuring feature parity with API and overlay handling.

**Regression Tests**: Deterministic demos guaranteeing consistent outputs across code changes.

Run tests: `pytest` (ensure `PYTHONPATH=.` set)

## Development Setup

1. Clone repository: `git clone https://github.com/DevOpsMadDog/Fixops.git`
2. Install dependencies: `pip install -r requirements.txt`
3. Copy environment template: `cp .env.example .env`
4. Configure secrets in `.env` (API tokens, encryption keys)
5. Run demo: `make demo` or `python -m core.cli demo --mode demo`
6. Start API: `uvicorn apps.api.app:app --reload`
7. Visit interactive docs: http://localhost:8000/docs
8. Run tests: `pytest`
9. Format code: `make fmt` (if using Makefile)
10. Lint code: `make lint` (if using Makefile)

## Security Considerations

**API Authentication**: Token-based or JWT authentication enforced per overlay strategy. Tokens validated on every request.

**Upload Limits**: Per-stage byte limits prevent denial-of-service via large file uploads.

**Path Allowlisting**: All file operations restricted to overlay-allowlisted data roots preventing directory traversal attacks.

**Evidence Encryption**: Evidence bundles optionally encrypted with AES-256 using keys from environment variables.

**Secrets Management**: API tokens, encryption keys, and LLM provider keys loaded from environment variables, never hardcoded.

**CORS Configuration**: Cross-origin requests restricted to allowlisted origins from overlay configuration.

**Input Validation**: Pydantic models enforce schema validation on all normalized inputs rejecting malformed data.

**Provenance Attestations**: SLSA provenance and cosign signatures ensure artifact authenticity and supply chain integrity.

## Performance Characteristics

**Pipeline Execution**: Typical full pipeline execution 2-5 seconds for moderate-sized inputs (100 components, 50 findings, 200 CVEs).

**Normalization Overhead**: SBOM/SARIF parsing adds 100-500ms depending on file size and format complexity.

**LLM Latency**: Enhanced decision engine adds 3-10 seconds when LLM providers enabled (network latency dominant).

**Caching**: Overlay configuration cached after first load. Vector pattern matcher caches embeddings across runs.

**Scalability**: FastAPI async architecture supports concurrent requests. Archive storage scales horizontally with filesystem or object storage backends.

## Observability and Monitoring

**Structured Logging**: `structlog` provides JSON-formatted logs with request IDs, correlation IDs, and structured fields for log aggregation.

**OpenTelemetry Instrumentation**: Distributed tracing captures request spans, database queries, and external API calls for performance analysis.

**Analytics Store**: Pipeline run metrics, ROI calculations, and performance profiles persisted for dashboard visualization and trend analysis.

**Health Endpoints**: `/health` endpoint checks overlay loading, evidence hub readiness, OPA policy server connectivity, and probabilistic engine dependencies.

**Error Tracking**: Exceptions logged with full context including request payloads (sanitized), stack traces, and environment metadata.

## Extension Points

**Custom Modules**: Implement `execute_custom_modules()` hook receiving enriched `PipelineContext` for domain-specific analysis.

**Custom Normalizers**: Extend `InputNormalizer` with format-specific parsers for proprietary security tool outputs.

**Custom LLM Providers**: Implement provider interface in `core.llm_providers` supporting on-premise models or specialized security LLMs.

**Custom Compliance Frameworks**: Add framework definitions and control mappings to overlay configuration without code changes.

**Custom Policy Actions**: Extend `PolicyAutomation` with action handlers for additional ticketing systems, chat platforms, or GRC tools.

**Custom Risk Scoring**: Implement alternative scoring algorithms in `risk/scoring.py` and register via overlay configuration.

## Common Troubleshooting

**"Invalid or missing API token"**: Ensure `FIXOPS_API_TOKEN` environment variable set and matching overlay `auth_tokens` list.

**"Upload exceeded limit"**: Check overlay `limits.max_upload_bytes` for stage-specific limits and compress large files.

**"Path not allowlisted"**: Verify data directories in overlay exist within `allowed_data_roots` paths.

**"Evidence bundle encryption failed"**: Ensure `FIXOPS_EVIDENCE_KEY` environment variable set when overlay `evidence.encrypt: true`.

**"LLM provider timeout"**: Increase timeout in provider configuration or disable enhanced decision module if keys unavailable.

**"SBOM normalization failed"**: Validate SBOM against CycloneDX or SPDX schemas. Check format auto-detection in normalizer.

**"Compliance framework not found"**: Verify framework name in overlay `compliance.frameworks` matches referenced name in pipeline requests.

## Next Steps for New Engineers

1. Read `ONBOARDING.md` for practical orientation to checked-in code and handover context
2. Review `README.md` for quick start commands and feature descriptions
3. Examine `docs/ARCHITECTURE.md` for canonical high-level layer descriptions
4. Run demo pipelines (`make demo` and `make demo-enterprise`) to see end-to-end workflows
5. Explore `tests/` directory to understand expected behaviors and contracts
6. Review overlay configuration `config/fixops.overlay.yml` to see module toggles and policies
7. Read module implementations in `core/` to understand business logic
8. Study pipeline orchestrator `apps/api/pipeline.py` to see correlation and scoring algorithms
9. Examine normalizers `apps/api/normalizers.py` to understand input formats
10. Contribute to backlog items tracked in `BACKLOG.csv` and `ROADMAP.md`

## Resources

- **Architecture Overview**: `ARCHITECTURE.md`, `docs/ARCHITECTURE.md`
- **API Documentation**: http://localhost:8000/docs (when server running)
- **Onboarding Guide**: `ONBOARDING.md`
- **Contribution Guidelines**: `CONTRIBUTING.md`
- **Changelog**: `CHANGELOG.md`
- **Roadmap**: `ROADMAP.md`
- **Developer Handbook**: `HANDBOOK.md`, `readme_updated.md`
- **SBOM Quality Guide**: `docs/SBOM-QUALITY.md`
- **Risk Scoring Guide**: `docs/RISK-SCORING.md`
- **Provenance Guide**: `docs/PROVENANCE.md`
- **Evidence Bundles Guide**: `docs/EVIDENCE-BUNDLES.md`

---

**Welcome to the team!** This guide should give you a solid foundation for understanding FixOps architecture. Don't hesitate to dive into the code, run the demos, and explore the test suite to deepen your understanding. The codebase is well-structured with clear separation of concerns, comprehensive documentation, and extensive test coverage to support your learning journey.
