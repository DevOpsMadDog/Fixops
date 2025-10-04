# FixOps Enterprise Architecture & Data Flow Overview

## Platform Architecture

The FixOps Blended Enterprise platform is organised around a FastAPI application (`src/main.py`) that exposes REST endpoints
for DevSecOps automation. The application relies on:

- **Configuration & Settings** (`src/config/settings.py`): Centralised environment configuration exposed through the
  `get_settings()` helper that is consumed by services and API routes to toggle demo/production behaviour and integration
  credentials.
- **Core Middleware & Security** (`src/core/middleware.py`, `src/core/security.py`, `src/core/exceptions.py`): Cross-cutting
  concerns providing structured logging, rate limiting, response compression, security headers, authentication scaffolding,
  and exception normalisation.
- **Database Layer** (`src/db/session.py` plus Alembic migrations in `src/db/migrations`): Async database manager handling
  SQLAlchemy engine lifecycle, health checks, and schema migrations for user, security, and compliance records defined in
  `src/models`.
- **Caching Layer** (`src/services/cache_service.py`): Shared Redis-like cache abstraction used for hot-path lookups, rate
  limiting, and decision memoisation.
- **Domain Services** (`src/services/*.py`): Business logic modules for decision making, policy evaluation, SBOM parsing,
  compliance automation, knowledge graph enrichment, marketplace integrations, and evidence management.
- **API Routers** (`src/api/v1/*.py`): Feature-specific routers orchestrating service interactions for scans, decisions,
  CI/CD automation, marketplace functions, system health, and policy management.

The application lifecycle (defined in `lifespan()` within `src/main.py`) initialises the database, cache, security manager,
primary decision engines, and optional feed schedulers before accepting traffic, guaranteeing readiness for production
workloads.

## Service Collaboration

Key services compose into decision workflows as follows:

1. **Business Context & Evidence Ingestion**
   - `BusinessContextProcessor` normalises input context (`src/services/business_context_processor.py`).
   - `EvidenceLake` stores artefacts, SBOM data, and runtime evidence (`src/services/evidence_lake.py`).
   - `SbomParser` extracts dependency metadata and security posture (`src/services/sbom_parser.py`).
   - `FeedsService` periodically syncs EPSS/KEV data when enabled (`src/services/feeds_service.py`).

2. **Knowledge & Risk Enrichment**
   - `KnowledgeGraphService` correlates dependencies, runtime signals, and threat intelligence (`src/services/knowledge_graph.py`).
   - `VectorStore` and `CorrelationEngine` provide similarity search and finding correlation (`src/services/vector_store.py`,
     `src/services/correlation_engine.py`).
   - `ContextualRiskScorer` computes dynamic risk metrics consumed by the decision engines (`src/services/risk_scorer.py`).

3. **Policy & Compliance Evaluation**
   - `PolicyEngine` and `ComplianceEngine` interpret organisational policy definitions and regulatory mappings to produce
     enforcement directives (`src/services/policy_engine.py`, `src/services/compliance_engine.py`).
   - `RealOPAEngine` integrates with OPA for runtime policy validation when available (`src/services/real_opa_engine.py`).

4. **Decision Synthesis**
   - `DecisionEngine` orchestrates context processing, scoring, regression comparison, and integration lookups, producing
     `DecisionResult` objects (`src/services/decision_engine.py`).
   - `EnhancedDecisionEngine` layers additional multi-LLM reasoning and consensus building (`src/services/enhanced_decision_engine.py`).
   - `GoldenRegressionStore` replays historical cases for validation and accuracy tracking (`src/services/golden_regression_store.py`).

5. **Delivery & Automation**
   - API routers (`src/api/v1/*.py`) expose decision results, marketplace bundles, CI/CD automation hooks, monitoring views,
     and documentation endpoints.
   - `MetricsService` surfaces Prometheus metrics for observability (`src/services/metrics.py`).
   - CLI entry points (`src/cli/main.py`) supply operational tooling for administrators.

## Data Flow Coverage

End-to-end, the implemented system covers the following enterprise data flow:

1. **Inbound Request**: CI/CD or platform clients call FastAPI endpoints with contextual payloads (e.g., `/api/v1/decisions`).
2. **Context Processing**: Request payloads are validated via Pydantic schemas (`src/schemas`), enriched through the business
   context processor, and stored alongside artefacts in the evidence lake.
3. **Knowledge Enrichment**: SBOM parsing, vector similarity search, and knowledge graph augmentation provide additional
   findings and historical context.
4. **Risk & Policy Evaluation**: Risk scoring, compliance checks, and policy enforcement combine to determine acceptable
   actions.
5. **Decision Rendering**: The decision engines evaluate enriched context, consult regression baselines, and either call real
   integrations or demo fallbacks to produce an `ALLOW`, `BLOCK`, or `DEFER` outcome with detailed reasoning and confidence.
6. **Response & Persistence**: Responses are cached for hot-path performance, surfaced through the API response models, and
   recorded for observability and regression tracking.

## Outstanding Gaps & Pending Work

- **Real Integration Stubs**: Several services expose placeholders for third-party integrations (e.g., Jira, Confluence,
  Emergent LLM) that require production credentials and full client implementations before go-live.
- **Security Hardening**: Authentication/authorisation scaffolding exists in `SecurityManager` but needs integration with the
  organisation's identity provider and fine-grained policy controls.
- **Compliance Automation**: The compliance engine defines mappings but lacks automated report generation and auditor-facing
  exports.
- **Marketplace Productionisation**: The marketplace service includes demo catalogue data; real procurement workflows and
  entitlement checks remain to be implemented.
- **Observability & Alerting**: Prometheus metrics are published, yet alert rules, distributed tracing, and log shipping to
  the enterprise observability stack are not configured.
- **Frontend Harmonisation**: The React frontends (`frontend`, `frontend-akido-public`) require alignment with the updated
  API contracts and design system to deliver a consistent operator experience.

This document supersedes redundant marketing collateral files that previously lived in `fixops-blended-enterprise/` and focuses
on actionable engineering knowledge for the platform.
