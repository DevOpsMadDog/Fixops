# FixOps Technical Handover Documentation

## Overview

FixOps is an enterprise security decision engine that helps organizations triage, prioritize, and remediate security vulnerabilities. This documentation provides a comprehensive guide for developers to understand the system architecture, codebase structure, data flows, and program flows.

## System Architecture

```
+------------------+     +------------------+     +------------------+
|   Frontend MFEs  |     |   Backend API    |     |   Core Modules   |
|   (Next.js x27)  | --> |   (FastAPI)      | --> |   (Python)       |
+------------------+     +------------------+     +------------------+
        |                        |                        |
        v                        v                        v
+------------------+     +------------------+     +------------------+
|  @fixops/ui      |     |  Router Files    |     |  CLI Commands    |
|  @fixops/api-    |     |  (22 routers)    |     |  (25 handlers)   |
|  client          |     |  ~199 endpoints  |     |                  |
+------------------+     +------------------+     +------------------+
```

## Quick Start for Development

### Prerequisites
- Python 3.10+ (tested with 3.11)
- Node.js 18+
- pnpm (for frontend)

### Running the Backend API
```bash
cd /home/ubuntu/repos/Fixops
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export FIXOPS_API_TOKEN="demo-token"
uvicorn apps.api.app:create_app --factory --reload
```

### Running a Frontend MFE
```bash
cd /home/ubuntu/repos/Fixops/web
pnpm install
cd apps/triage  # or any other MFE
pnpm dev
```

### Running the CLI
```bash
cd /home/ubuntu/repos/Fixops
source .venv/bin/activate
python -m core.cli demo --mode demo
```

## Repository Structure

```
Fixops/
├── apps/api/                    # FastAPI backend application
│   ├── app.py                   # Main FastAPI app factory
│   ├── *_router.py              # API routers (22 files)
│   ├── pipeline.py              # Pipeline orchestrator
│   └── normalizers.py           # Input data normalizers
├── backend/api/                 # Core API modules
│   ├── evidence/                # Evidence bundle management
│   ├── graph/                   # Risk graph generation
│   ├── risk/                    # Risk scoring
│   └── provenance/              # Artifact provenance
├── core/                        # Core business logic (85 files)
│   ├── cli.py                   # CLI command handlers
│   ├── configuration.py         # Overlay configuration
│   ├── evidence.py              # Evidence bundle generation
│   ├── analytics.py             # Analytics store
│   └── *_db.py, *_models.py     # Database and models
├── web/                         # Frontend monorepo
│   ├── apps/                    # 27 MFE applications
│   │   ├── triage/              # Security issue triage
│   │   ├── risk-graph/          # Interactive risk graph
│   │   ├── compliance/          # Compliance management
│   │   └── ...                  # Other MFEs
│   └── packages/                # Shared packages
│       ├── ui/                  # Shared UI components
│       └── api-client/          # API client hooks
└── config/                      # Configuration files
    └── fixops.overlay.yml       # Overlay configuration
```

## Documentation Index

### Domain Documentation
1. [Security Triage](domains/security-triage.md) - Issue triage, findings, risk scoring
2. [Risk Graph](domains/risk-graph.md) - Interactive vulnerability graph
3. [Evidence & Compliance](domains/evidence-compliance.md) - Evidence bundles, compliance frameworks
4. [Organization & Admin](domains/org-admin.md) - Users, teams, policies, audit
5. [Reports & Analytics](domains/reports-analytics.md) - Dashboards, reports, analytics
6. [Pentagi](domains/pentagi.md) - AI-powered penetration testing
7. [Marketplace](domains/marketplace.md) - Security tool marketplace

### Architecture Documentation
8. [Frontend Architecture](domains/frontend-architecture.md) - MFE structure, shared components
9. [API Client Package](domains/api-client.md) - React hooks, API integration
10. [Backend API](domains/backend-api.md) - FastAPI routers, endpoints
11. [Core Modules](domains/core-modules.md) - Business logic, CLI

### Reference
12. [File-to-Feature Mapping](appendix/file-feature-mapping.md) - Complete file inventory
13. [API Endpoint Reference](appendix/api-endpoints.md) - All 199 endpoints
14. [CLI Command Reference](appendix/cli-commands.md) - All CLI commands

## Glossary

| Term | Definition |
|------|------------|
| **MFE** | Micro Frontend - Independent Next.js application |
| **Overlay** | Configuration file that controls feature flags, modes, and settings |
| **Pipeline** | Data processing workflow that ingests SBOM/SARIF/CVE and produces triage results |
| **Evidence Bundle** | Cryptographically signed archive of security decisions for audit |
| **SSVC** | Stakeholder-Specific Vulnerability Categorization - decision framework |
| **KEV** | Known Exploited Vulnerabilities catalog from CISA |
| **EPSS** | Exploit Prediction Scoring System |
| **Demo Mode** | Uses sample data without backend API |
| **Enterprise Mode** | Full API integration with real data |

## Data Flow Overview

### Pipeline Data Flow (Data Production)
```
1. INGEST
   CLI: python -m core.cli run --sbom X --sarif Y --cve Z
   API: POST /inputs/sbom, /inputs/sarif, /inputs/cve
         |
         v
2. NORMALIZE
   InputNormalizer.load_sbom() -> NormalizedSBOM
   InputNormalizer.load_sarif() -> NormalizedSARIF
   InputNormalizer.load_cve_feed() -> NormalizedCVEFeed
         |
         v
3. ORCHESTRATE
   PipelineOrchestrator.run()
   - Correlates vulnerabilities with components
   - Calculates risk scores
   - Generates SSVC decisions
   - Creates evidence bundles
         |
         v
4. STORE
   app.state.last_pipeline_result (in-memory)
   data/evidence/bundles/ (evidence files)
   data/analytics/ (metrics)
```

### UI Request Flow
```
1. USER ACTION
   Browser -> Next.js page.tsx
         |
         v
2. HOOK CALL
   page.tsx -> useTriage() / useGraph() / etc.
         |
         v
3. API REQUEST
   useApi() -> fetchApi() -> HTTP GET/POST
         |
         v
4. BACKEND HANDLER
   FastAPI router -> handler function
         |
         v
5. DATA ACCESS
   Reads app.state.* or filesystem
         |
         v
6. RESPONSE
   JSON -> hook state -> React render
```

## Integration Status Summary

| Category | MFEs | Fully Integrated | Demo Only |
|----------|------|------------------|-----------|
| Security | 3 | 3 (triage, findings, risk-graph) | 0 |
| Compliance | 4 | 2 (compliance, evidence) | 2 |
| Assets | 4 | 0 | 4 |
| Automation | 3 | 0 | 3 |
| Organization | 4 | 0 | 4 |
| Reports | 3 | 2 (dashboard, reports) | 1 |
| Specialized | 4 | 2 (pentagi, marketplace) | 2 |
| Utility | 2 | 0 | 2 |
| **Total** | **27** | **9 (33%)** | **18 (67%)** |

## Contact & Support

- Repository: https://github.com/DevOpsMadDog/Fixops
- PR #210: Frontend API Integration
