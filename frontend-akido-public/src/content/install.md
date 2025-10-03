# FixOps Enterprise Installation Guide

Welcome to the FixOps secure deployment decision engine. This guide walks through installing the public showcase environment that mirrors the Akido Security experience without authentication.

## 1. Prerequisites

- Node.js 18+
- npm 9+
- Docker Desktop (optional for containerized demo)
- Access to security scan artifacts (SARIF, SBOM, CSV) for testing

## 2. Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Launch the public portal
npm run dev

# 3. Build optimized assets
npm run build
```

The portal exposes the full FixOps experience, including the command center, pipeline integration, executive briefing, and architecture intelligence centers.

## 3. Production Hardening Checklist

| Capability | Description |
|------------|-------------|
| Evidence Lake | Configure PostgreSQL with point-in-time recovery |
| Policy Engine | Deploy OPA with enterprise rego bundles |
| LLM Consensus | Provision Emergent multi-LLM access keys |
| Vector Store | Scale ChromaDB or pgvector cluster |
| Monitoring | Enable Prometheus, Grafana, and audit webhooks |

## 4. Security Scan Workflow

1. Export SARIF, SBOM, or CSV reports from SAST/DAST tools.
2. Upload artifacts through the Command Center or CI/CD CLI.
3. FixOps normalizes findings into the Bayesian and Markov processing layers.
4. Multi-LLM consensus correlates evidence with business context.
5. Policy engine renders ALLOW/BLOCK/DEFER with full evidence trail.

## 5. CI/CD Integration

- **CLI** – `fixops make-decision --service-name payments --scan-file results.sarif`
- **API** – `POST /api/v1/decisions/make-decision`
- **Exit Codes** – `0=ALLOW`, `1=BLOCK`, `2=DEFER`
- **GitHub Actions** – Use the provided action to gate deployments
- **Jenkins** – Invoke the CLI within pipeline stages

## 6. Observability

- Hot path latency target: **299μs**
- Consensus confidence goal: **> 90%**
- Evidence retention: **7 years**
- Alert channels: PagerDuty, Slack, ServiceNow

## 7. Next Steps

- Explore the Architecture page for system internals
- Share the Executive briefing with leadership teams
- Connect additional business units through the CLI and API

> Need help? Contact the FixOps solutions team for enterprise onboarding packages.
