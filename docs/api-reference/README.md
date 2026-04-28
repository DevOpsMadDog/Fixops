# ALDECI API Reference

> **Generated:** 2026-04-28T11:41:10Z  
> **Total endpoints documented:** 8910  
> **Generator:** `scripts/gen_api_reference.py`

## Sub-app Endpoint Counts

| Sub-app | Endpoints | File |
|---------|-----------|------|
| [ASPM](./aspm.md) | 1314 | `docs/api-reference/aspm.md` |
| [CSPM](./cspm.md) | 1236 | `docs/api-reference/cspm.md` |
| [CTEM](./ctem.md) | 1860 | `docs/api-reference/ctem.md` |
| [GRC](./grc.md) | 2064 | `docs/api-reference/grc.md` |
| [Platform](./platform.md) | 2436 | `docs/api-reference/platform.md` |

**Total:** 8910 endpoints across 5 sub-apps

## Quickstart

```bash
# Obtain an API token (dev mode)
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<password>"}'

# Use the token
curl http://localhost:8000/api/v1/triage/findings \
  -H "X-API-Key: <your-token>"
```

## Authentication Model

| Method | Header | Notes |
|--------|--------|-------|
| API Key | `X-API-Key: <token>` | Primary method for all API calls |
| JWT Bearer | `Authorization: Bearer <jwt>` | Issued by `/api/v1/auth/token` |
| SSO/SAML | Session cookie | Browser UI flows via `/api/v1/sso/` |
| OAuth2 | `Authorization: Bearer <token>` | `/api/v1/oauth2/` endpoints |

### Scopes

| Scope | Access Level |
|-------|-------------|
| `read:findings` | Read security findings, reports, dashboards |
| `write:findings` | Create/update findings, trigger scans |
| `admin:all` | Full admin access — user management, system config |

## Pagination Convention

All list endpoints accept `?page=1&page_size=50` query parameters.
Maximum `page_size` is 500. Cursor-based pagination available via `?cursor=<token>`.

## Error Response Format

```json
{
  "detail": "Human-readable error message",
  "error_code": "MACHINE_READABLE_CODE",
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

## Rate Limiting

| Tier | Requests/min | Burst |
|------|-------------|-------|
| Starter | 60 | 10 |
| Pro | 300 | 50 |
| Enterprise | 1000 | 200 |

Rate limit headers returned on every response:
- `X-RateLimit-Limit` — requests allowed per window
- `X-RateLimit-Remaining` — requests remaining
- `X-RateLimit-Reset` — Unix timestamp when window resets

## Sub-app Reference

### [ASPM — Application Security Posture Management](./aspm.md)

Endpoints covering the full application security lifecycle: SAST/DAST/IaC scanning, SBOM generation and re-evaluation, secret detection, software composition analysis, supply-chain risk, container security, vulnerability management, CI/CD gating, code intelligence, asset inventory, and autonomous remediation.

### [CSPM — Cloud Security Posture Management](./cspm.md)

Endpoints covering cloud posture across AWS/Azure/GCP: resource inventory, misconfiguration detection, CIS benchmark compliance, drift detection, network security (NDR/WAF/firewall), identity & access management, zero-trust enforcement, Kubernetes security, and cryptographic key lifecycle.

### [CTEM — Continuous Threat Exposure Management](./ctem.md)

Endpoints covering threat intelligence, attack path analysis, incident response, SOAR playbooks, breach simulation, phishing simulation, EDR/XDR integrations, SIEM connectors, threat hunting, MPTE orchestration, anomaly detection (ML/UEBA), and purple/red team management.

### [GRC — Governance, Risk & Compliance](./grc.md)

Endpoints covering compliance frameworks (SOC2/ISO27001/PCI-DSS/GDPR/FedRAMP), evidence collection and vault, risk register, policy engine, vendor risk management (TPRM), audit management, GRC workflows, KPI/OKR tracking, executive reporting, data classification, privacy, DLP, and security awareness.

### [Platform — Auth / Tenancy / Integrations / Infra](./platform.md)

Cross-cutting platform endpoints: authentication (JWT/SSO/SAML/OAuth2), user & team management, multi-tenant org hierarchy, admin controls, MCP gateway (650+ tools), TrustGraph knowledge store, Brain Pipeline ingestion, streaming/WebSocket events, webhook management, system health, analytics, DuckDB, and third-party integrations (Jira, Slack, ServiceNow, PagerDuty, n8n).
