# ALDECI API Reference — Wave A/B/C/D + Engine Routers

_Auto-generated 2026-04-26._

**Total endpoints documented in this set: 124** (plus pre-existing endpoints documented in `../API_REFERENCE.md`)

This directory contains per-router API reference docs for the four Multica delivery waves and the seven supporting engine routers.

## How to use

1. Find your domain in the table below.
2. Click into the per-router doc.
3. Each endpoint has: HTTP method + path, auth requirement, request body type, success status, common 4xx/5xx codes, and a working `curl` example.
4. UI integration: each doc lists the React `.tsx` page(s) that consume the endpoints.

## Index

| Doc | Endpoints | Source Router | Personas |
|---|---|---|---|
| [Wave A — Code & Architecture Intelligence](wave_a.md) | 17 | `suite-api/apps/api/wave_a_code_intel_router.py` | AppSec Engineer, Platform Engineer, Developer (IDE), Architect |
| [Wave B — Findings, Risk & Scoring](wave_b.md) | 16 | `suite-api/apps/api/findings_wave_b_router.py` | AppSec Lead, SOC Analyst, Risk Manager |
| [Wave C — System, Org, PBOM, Provenance & Admin](wave_c.md) | 21 | `suite-api/apps/api/wave_c_router.py` | Platform Admin, Compliance Lead, SecOps Engineer |
| [Wave D — Connectors, Webhooks, EASM, Copilot & Policies](wave_d.md) | 20 | `suite-api/apps/api/wave_d_integrations_router.py` | Integration Engineer, AI Security Lead, Policy Author |
| [Privilege Escalation Detector](privilege_escalation_detector.md) | 10 | `suite-api/apps/api/privilege_escalation_detector_router.py` | IAM Engineer, SOC Analyst |
| [MITRE ATT&CK Coverage](mitre_attack_coverage.md) | 10 | `suite-api/apps/api/mitre_attack_coverage_router.py` | Detection Engineer, SOC Lead |
| [DuckDB Cross-Domain Analytics](duckdb_analytics.md) | 9 | `suite-api/apps/api/duckdb_analytics_router.py` | Risk Analyst, Executive Reporting |
| [Multi-Stage Verification](verification.md) | 4 | `suite-api/apps/api/verification_router.py` | Security Engineer, Compliance Lead |
| [Intelligent Security Engine](intelligent_security.md) | 6 | `suite-api/apps/api/intelligent_security_router.py` | Security Analyst |
| [GraphRAG](graphrag.md) | 8 | `suite-api/apps/api/graphrag_router.py` | Security Analyst, AI Engineer |
| [Context Engine](context_engine.md) | 3 | `suite-api/apps/api/context_engine_router.py` | Risk Engineer |

## Authentication (applies to all)

```http
X-API-Key: <your-api-key>
X-Org-ID: <your-org-id>     # optional but recommended for multi-tenant
```

Live OpenAPI spec: `GET /openapi.json` · Swagger UI: `GET /docs` · ReDoc: `GET /redoc`

## Wave Roadmap

- **Wave A** — Code & Architecture intelligence (DCA, reachability, IDE, runtime).
- **Wave B** — Finding lifecycle, scoring explainability, continuous SBOM, investigations.
- **Wave C** — System / org tree / PBOM / provenance / changes / air-gap / admin / CSPM / rules / LLM cost-routing.
- **Wave D** — Connectors, webhooks, EASM, NL copilot, AI exposure, AI Teammates, policies.
- **Engine routers** — Standalone engines that ship endpoints independently of waves: privilege escalation, MITRE coverage, DuckDB analytics, verification, intelligent security, GraphRAG, context engine.

## Cross-references

- Top-level reference: [`../API_REFERENCE.md`](../API_REFERENCE.md)
- v2 reference: [`../API_REFERENCE_v2.md`](../API_REFERENCE_v2.md)
- Architecture: [`../ARCHITECTURE_v3.md`](../ARCHITECTURE_v3.md)
- CTEM+ identity: [`../CTEM_PLUS_IDENTITY.md`](../CTEM_PLUS_IDENTITY.md)
- Postman collection: [`../ALDECI_Postman_Collection.json`](../ALDECI_Postman_Collection.json)
