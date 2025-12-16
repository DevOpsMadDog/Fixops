[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/DevOpsMadDog/Fixops)

# FixOps

Security decision automation platform with multi-LLM consensus, advanced risk forecasting, and compliance frameworks.

## ⚡ Quick Start (3 Commands)

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

## 📚 Documentation

- [Configuration Guide](config/fixops.overlay.yml) - Advanced configuration options
- [Deployment Packs](deployment-packs/) - Kubernetes, Docker, Terraform
- [API Reference](apps/api/app.py) - FastAPI endpoints
