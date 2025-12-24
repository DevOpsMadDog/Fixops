[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/DevOpsMadDog/Fixops)

# FixOps

**Enterprise DevSecOps Decision Automation Platform**

FixOps is a comprehensive security decision engine that ingests security artifacts (SBOM, SARIF, CVE feeds, VEX, CNAPP), applies multi-LLM consensus analysis and probabilistic risk models, and produces allow/block/defer decisions with cryptographically-signed evidence bundles.

## Key Features

| Feature | Description |
|---------|-------------|
| **Multi-LLM Consensus** | 4 AI providers (OpenAI GPT-4, Anthropic Claude, Google Gemini, Sentinel) with weighted voting for high-confidence decisions |
| **Probabilistic Risk Models** | Bayesian + Markov forecasting, BN-LR hybrid model, EPSS/KEV/CVSS enrichment |
| **Evidence Bundles** | Cryptographically-signed audit trails with RSA-SHA256 signatures |
| **Compliance Frameworks** | SOC2, ISO 27001, PCI-DSS, NIST 800-53, OWASP mappings with gap analysis |
| **27 MFE Applications** | Micro Frontend architecture with Next.js for triage, risk graph, compliance, reports, and more |
| **199+ API Endpoints** | FastAPI backend with 22 router modules |
| **25+ CLI Commands** | Full CLI for pipeline execution, reporting, and administration |

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              FixOps Platform                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│  Frontend (27 MFEs)          │  Backend API (FastAPI)    │  Core Modules    │
│  ─────────────────           │  ──────────────────────   │  ────────────    │
│  • Triage Dashboard          │  • 22 Router Files        │  • CLI (25 cmds) │
│  • Risk Graph (Cytoscape)    │  • 199+ Endpoints         │  • Pipeline      │
│  • Compliance Management     │  • Token/JWT Auth         │  • Decision Eng  │
│  • Evidence Bundles          │  • Rate Limiting          │  • Evidence Hub  │
│  • Reports & Analytics       │  • CORS Support           │  • Analytics     │
│  • Pentagi (AI Pentest)      │  • OpenAPI Docs           │  • Compliance    │
│  • Marketplace               │                           │  • Risk Models   │
├─────────────────────────────────────────────────────────────────────────────┤
│  Shared Packages             │  Storage                  │  Integrations    │
│  ────────────────            │  ───────                  │  ────────────    │
│  • @fixops/ui (Design Sys)   │  • SQLite (Policies, etc) │  • Jira          │
│  • @fixops/api-client        │  • Filesystem (Evidence)  │  • Confluence    │
│                              │  • In-memory (Pipeline)   │  • Slack/GitHub  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Documentation Index

### Technical Handover Documentation

Comprehensive documentation for development teams is available in [`docs/handover/`](docs/handover/):

| Document | Description |
|----------|-------------|
| [**INDEX.md**](docs/handover/INDEX.md) | Main navigation hub with system overview, quick start, and glossary |
| [Security Triage](docs/handover/domains/security-triage.md) | Triage, findings, risk graph - API endpoints, CLI commands, program flows |
| [Evidence & Compliance](docs/handover/domains/evidence-compliance.md) | Evidence bundles, compliance frameworks, policies, audit |
| [Backend API](docs/handover/domains/backend-api.md) | FastAPI routers (22 files), authentication, state management |
| [Core Modules](docs/handover/domains/core-modules.md) | 85 Python files, CLI commands, key classes |
| [Frontend Architecture](docs/handover/domains/frontend-architecture.md) | 27 MFE apps, shared packages, development guide |
| [File-Feature Mapping](docs/handover/appendix/file-feature-mapping.md) | Complete mapping of every file to its feature |

### Additional Resources

| Resource | Description |
|----------|-------------|
| [DeepWiki](https://deepwiki.com/DevOpsMadDog/Fixops) | AI-indexed documentation with search |
| [Configuration Guide](config/fixops.overlay.yml) | Overlay configuration options |
| [Deployment Packs](deployment-packs/) | Kubernetes, Docker, Terraform |

## Quick Start (3 Commands)

```bash
# 1. Run setup wizard
./scripts/setup-wizard.sh

# 2. Install dependencies
./scripts/bootstrap.sh

# 3. Start the API
uvicorn apps.api.app:create_app --factory --reload
```

**That's it!** The API is now running at http://localhost:8000

## 🎯 Single-LLM Mode

Want to use just one LLM instead of multi-LLM consensus? Set environment variables:

```bash
# Use only OpenAI GPT
export FIXOPS_ENABLE_OPENAI=true
export FIXOPS_ENABLE_ANTHROPIC=false
export FIXOPS_ENABLE_GEMINI=false
export FIXOPS_ENABLE_SENTINEL=false
export OPENAI_API_KEY=sk-...
```

Or run without any LLMs (deterministic mode):
```bash
# All providers disabled = deterministic risk-based decisions
export FIXOPS_ENABLE_OPENAI=false
export FIXOPS_ENABLE_ANTHROPIC=false
export FIXOPS_ENABLE_GEMINI=false
export FIXOPS_ENABLE_SENTINEL=false
```

## ☁️ Cloud Deployment (30 Minutes)

### AWS
```bash
./scripts/deploy-aws.sh
```

### GCP
```bash
./scripts/deploy-gcp.sh
```

### Docker Compose (Local Production)
```bash
cp .env.example .env
# Edit .env with your settings
docker-compose -f deployment-packs/docker/docker-compose.yml up -d
```

## 🔑 Environment Variables

See `.env.example` for comprehensive documentation. Key variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FIXOPS_API_TOKEN` | Yes | - | API authentication token |
| `FIXOPS_ENABLE_OPENAI` | No | true | Enable OpenAI GPT provider |
| `FIXOPS_ENABLE_ANTHROPIC` | No | true | Enable Anthropic Claude provider |
| `FIXOPS_ENABLE_GEMINI` | No | true | Enable Google Gemini provider |
| `FIXOPS_ENABLE_SENTINEL` | No | true | Enable Sentinel provider |
| `OPENAI_API_KEY` | No | - | OpenAI API key (optional for deterministic mode) |
| `ANTHROPIC_API_KEY` | No | - | Anthropic API key (optional) |
| `GOOGLE_API_KEY` | No | - | Google API key (optional) |
| `FIXOPS_JIRA_TOKEN` | No | - | Jira integration token |
| `FIXOPS_CONFLUENCE_TOKEN` | No | - | Confluence integration token |

## 📖 Usage Examples

### CLI Demo
```bash
# Run demo with default settings
python -m core.cli demo --mode demo

# Run enterprise mode
python -m core.cli demo --mode enterprise --output results.json
```

### API Endpoints
```bash
# Health check
curl http://localhost:8000/health

# Upload scan results
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@scan.sarif" \
  http://localhost:8000/inputs/sarif

# Run pipeline
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  http://localhost:8000/pipeline/run
```

## 🏗️ Architecture

- **Multi-LLM Consensus**: 4 providers (OpenAI GPT-4o-mini, Anthropic Claude-3, Google Gemini-2, Sentinel) with weighted voting
- **Risk Models**: Bayesian + Markov forecasting, BN-LR hybrid, EPSS/KEV/CVSS enrichment
- **Compliance**: NIST 800-53, NIST SSDF, PCI-DSS, ISO 27001, OWASP mappings
- **Integrations**: Jira, Confluence, Slack with automatic ticket creation
- **Security**: RSA-SHA256 signing, Fernet encryption, rate limiting, security headers

## 🧪 Testing

```bash
# Run all tests
pytest

# Run specific test
pytest tests/test_enhanced_decision.py

# With coverage
pytest --cov=core --cov=apps
```

## 📚 Full Documentation

For comprehensive technical documentation, see the [**Handover Documentation**](docs/handover/INDEX.md) which includes:

- System architecture and data flow diagrams
- Complete API endpoint reference (199+ endpoints)
- CLI command reference (25+ commands)
- File-to-feature mapping for all 85 core modules
- Frontend MFE architecture (27 applications)
- Program flows for each feature (UI-request and data-production)

Additional resources:
- [DeepWiki](https://deepwiki.com/DevOpsMadDog/Fixops) - AI-indexed documentation with search
- [Configuration Guide](config/fixops.overlay.yml) - Overlay configuration options
- [Deployment Packs](deployment-packs/) - Kubernetes, Docker, Terraform
