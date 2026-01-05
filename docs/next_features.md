# FixOps Next Features

**Last Updated:** January 3, 2026  
**Source:** Extracted from `FIXOPS_IMPLEMENTATION_STATUS.md` and AlDeci Pitch Deck Gap Analysis

This document consolidates all planned features and "What's Needed" items into a simple prioritized table for development planning.

---

## Priority Legend

| Priority | Meaning | Action |
|----------|---------|--------|
| **MUST** | Blocks enterprise deployment | Build immediately |
| **SHOULD** | High value, recommended | Build in first release |
| **OPTIONAL** | Nice to have, improves UX | Build if time permits |
| **NOT REQUIRED** | Can skip entirely | Defer or never build |

### Legacy Priority Mapping
| Old Priority | New Classification |
|--------------|-------------------|
| Critical | MUST (if deployment blocker) or SHOULD |
| High | SHOULD |
| Medium | OPTIONAL |
| Low | NOT REQUIRED |

---

## Feature Backlog

### Critical Priority (Pitch Deck Claims)

| Feature | Current State | What's Needed | Effort | Code Reference |
|---------|---------------|---------------|--------|----------------|
| RSA-SHA256 Evidence Signing | **COMPLETED** | ~~Wire `rsa_sign()` into `EvidenceHub.persist()`~~ | ~~2-3 days~~ | `core/evidence.py:329-397` |
| SLSA v1 Provenance | **COMPLETED** | ~~Implement SLSA provenance format, in-toto attestations~~ | ~~2-3 weeks~~ | `services/provenance/attestation.py` |
| Evidence Verification Endpoint | **COMPLETED** | ~~Add `/api/v1/evidence/verify` that calls `rsa_verify()`~~ | ~~1-2 days~~ | `backend/api/evidence/router.py:162-303` |
| WORM-Compliant Storage | **COMPLETED** | ~~S3 Object Lock / Azure Immutable Blob adapter~~ | ~~3-4 weeks~~ | `core/storage_backends.py` |
| Wire Real LLM Providers | **COMPLETED** | ~~Replace mocked responses with actual provider calls~~ | ~~3-5 days~~ | `core/pentagi_advanced.py:354-460` |

### High Priority (Product Completeness)

| Feature | Current State | What's Needed | Effort | Code Reference |
|---------|---------------|---------------|--------|----------------|
| Micro-Pentest Sandbox | Templates exist, LLM mocked | Real sandbox execution environment | 2-3 weeks | `core/exploit_generator.py` |
| 30-min Onboarding | Manual setup required | Automated setup wizard, one-click deployment | 2-3 weeks | New tooling |
| RBAC Middleware | Role model exists | Add role-checking middleware/decorator | 1-1.5 weeks | `apps/api/users_router.py` |
| Background Job Store | BackgroundTasks pattern used | Persistent job store (SQLite table) | 1-2 weeks | `apps/api/bulk_router.py` |
| IaC Scanning | **COMPLETED** | ~~Integrate checkov/tfsec~~ | ~~1 week~~ | `core/iac_scanner.py`, `apps/api/iac_router.py:187-310` |
| Secrets Scanning | **COMPLETED** | ~~Integrate gitleaks/trufflehog~~ | ~~1 week~~ | `core/secrets_scanner.py`, `apps/api/secrets_router.py:185-353` |
| **Design Intake: Gliffy → JSON** | Not implemented | Parser for Gliffy JSON export to FixOps schema | 3-5 days | New module |
| **Design Intake: Visio → JSON** | Not implemented | Parser for Visio export to FixOps schema | 3-5 days | New module |
| **Design Risk Simulation** | Not implemented | `POST /api/v1/design/simulate-risk` endpoint | 2-3 days | New endpoint |

### Medium Priority (Feature Gaps)

| Feature | Current State | What's Needed | Effort | Code Reference |
|---------|---------------|---------------|--------|----------------|
| CLI Commands (67 target) | 30 commands exist | Add missing subcommands | 1-2 weeks | `core/cli.py` |
| Scanner Adapter API Routes | Adapters exist, not exposed | Wire adapters to API endpoints | 2-3 days | `core/adapters.py` |
| CSV Export | Returns "not implemented" | CSV formatter | 2-3 days | `apps/api/reports_router.py` |
| Enhanced SARIF Export | Minimal implementation | Full SARIF export | 3-5 days | `apps/api/reports_router.py` |
| Policy Test Endpoint | Returns "not implemented" | Policy evaluation engine | 1 week | `apps/api/policies_router.py` |
| Integration Test Endpoint | Returns "not implemented" | Integration test logic | 3-5 days | `apps/api/integrations_router.py` |
| IDE Analysis | Returns empty findings | Analysis engine integration | 1-2 weeks | `apps/api/ide_router.py:58-81` |
| IDE Suggestions | Returns empty suggestions | Suggestion engine | 1-2 weeks | `apps/api/ide_router.py` |

### NOT REQUIRED for Enterprise Baseline

These can be safely deferred or skipped entirely for initial enterprise deployment:

| Feature | Why NOT REQUIRED | Category |
|---------|------------------|----------|
| Application Components | SBOM data exists, UI enhancement only | UI Polish |
| Application APIs | API catalog is nice-to-have | UI Polish |
| Application Dependencies | Dependency graph is visualization only | UI Polish |
| Service Registry | External service discovery, not core | Niche Integration |
| Lifecycle Stage Tracking | Advanced analytics, not operational | Advanced Analytics |
| Cross-Stage Correlation | Advanced analytics, not operational | Advanced Analytics |
| Runtime Event Ingestion | SIEM integration, build when demanded | Niche Integration |
| OSS Fallback Wiring | Proprietary tools work, OSS is backup | Optional |
| Risk Quantification ($) | Budget justification, not operational | Advanced Analytics |
| Industry Benchmarking | No customer data yet | Advanced Analytics |
| ROI Calculator | Nice-to-have for execs | Advanced Analytics |
| Board-ready Dashboards | API data exists, UI is enhancement | UI Polish |
| Trend Forecasting | Historical data not needed day-1 | Advanced Analytics |
| SIEM (Splunk/Sentinel) | Build when customer demands | Niche Integration |
| CMDB Sync | Customer-specific integration | Niche Integration |
| Patch Management Tools | Operational integration, not core | Niche Integration |
| Developer Portal | Self-service is nice-to-have | UI Polish |
| Manual Pentest Scheduling | Use external tools | Workflow Extra |
| Scanner Health Dashboard | Operational monitoring, not core | Workflow Extra |

**Key Principle:** If it doesn't block (1) deploying safely, (2) making decisions, (3) tracking remediation, or (4) generating audit evidence, it's NOT REQUIRED for initial enterprise rollout.

### Low Priority (Future Enhancements) - OPTIONAL/NOT REQUIRED

| Feature | Current State | What's Needed | Effort | Required? |
|---------|---------------|---------------|--------|-----------|
| Application Components | Returns `[]` | Populate from SBOM uploads | 3-5 days | NOT REQUIRED |
| Application APIs | Returns `[]` | API catalog integration | 1 week | NOT REQUIRED |
| Application Dependencies | Returns `[]` | Dependency graph from SBOM | 3-5 days | NOT REQUIRED |
| Service Registry | Returns `[]` or 404 | Service registry integration | 1-2 weeks | NOT REQUIRED |
| Lifecycle Stage Tracking | Not implemented | Add `lifecycle_stage` field | 1-2 weeks | NOT REQUIRED |
| Cross-Stage Correlation | Not implemented | Link findings across stages | 1-2 weeks | NOT REQUIRED |
| Runtime Event Ingestion | Not implemented | `POST /api/v1/events/ingest` | 1 week | NOT REQUIRED |
| OSS Fallback Wiring | Code exists, not wired | Wire to pipeline with config | 3-5 days | OPTIONAL |

---

## Implementation Phases

### Phase 1: Evidence Integrity (Weeks 1-3) - COMPLETED
- [x] Wire RSA signing to EvidenceHub
- [x] Add evidence verification endpoint
- [x] Implement SLSA v1 provenance format
- [x] Store signature + fingerprint in manifest

### Phase 2: AI Consensus (Weeks 4-5) - COMPLETED
- [x] Replace mocked `_call_llm()` with real LLMProviderManager integration
- [x] Add error handling with retry logic and fallback to deterministic responses
- [x] Implement consensus threshold configuration via environment variables
- [x] Add unit tests for consensus logic

### Phase 3: Enterprise Storage (Weeks 6-8) - COMPLETED
- [x] Abstract storage backend with `StorageBackend` base class
- [x] Implement S3 Object Lock adapter with WORM compliance
- [x] Implement Azure Immutable Blob adapter with immutability policies
- [x] Add retention policy configuration with environment variable support

### Phase 4: Scanning & Sandbox (Weeks 9-12) - IN PROGRESS
- [x] Integrate checkov/tfsec for IaC scanning (`core/iac_scanner.py`)
- [x] Integrate gitleaks/trufflehog for secrets scanning (`core/secrets_scanner.py`)
- [ ] Design isolated sandbox architecture
- [ ] Implement safe payload execution

---

## Connectors & Integrations (Implemented)

These connectors are fully implemented and production-ready:

| Connector | Status | Features | Code Reference |
|-----------|--------|----------|----------------|
| **Jira** | Complete | Bidirectional sync, HMAC signature verification, status mapping, drift detection | `core/connectors.py:49-124`, `apps/api/webhooks_router.py:233-350` |
| **ServiceNow** | Complete | Webhook receiver, state mapping, incident sync | `apps/api/webhooks_router.py:353-433` |
| **GitLab** | Complete | Issue sync, label-to-status mapping, webhook receiver | `apps/api/webhooks_router.py:1110-1227` |
| **Azure DevOps** | Complete | Work item sync, state mapping, webhook receiver | `apps/api/webhooks_router.py:1261-1357` |
| **Slack** | Complete | Notifications via incoming webhook | `core/connectors.py:213-248` |
| **Confluence** | Complete | Page publishing for audit evidence | `core/connectors.py:127-210` |

**Webhook Management Features:**
- Integration mappings with drift detection
- Outbox pattern with retry logic (max 3 retries)
- Status sync between FixOps and external systems
- HMAC signature verification for security

---

## Quick Reference: Scanner Adapters Ready to Wire

These adapters are fully implemented but not exposed via API:

| Adapter | Parses | Code Location |
|---------|--------|---------------|
| TrivyAdapter | Trivy JSON | `core/adapters.py:460-614` |
| ProwlerAdapter | Prowler JSON/CSV | `core/adapters.py:617-718` |
| OWASPZAPAdapter | ZAP JSON | `core/adapters.py:721-827` |
| SemgrepAdapter | Semgrep SARIF/JSON | `core/adapters.py:830-951` |
| CheckovAdapter | Checkov JSON | `core/adapters.py:954-1077` |
| GitLabAdapter | GitLab API | `core/adapters.py` |
| AzureDevOpsAdapter | Azure DevOps API | `core/adapters.py` |
| SnykAdapter | Snyk API | `core/adapters.py` |

**Suggested API Routes:**
```
POST /api/v1/adapters/{adapter_name}/ingest
GET  /api/v1/adapters
GET  /api/v1/adapters/{adapter_name}/status
```

---

## Current Work: Connector Expansion (NOW Phase)

These are the items actively being built or planned for immediate development:

| Item | Status | Priority | Effort |
|------|--------|----------|--------|
| **Nessus Adapter** | In Progress | High | 1-2 weeks |
| **Qualys Adapter** | In Progress | High | 1-2 weeks |
| **Tenable.io Adapter** | In Progress | High | 1-2 weeks |
| **Wiz Adapter** (formalize samples) | Planned | Medium | 3-5 days |
| **Checkmarx Adapter** (formalize samples) | Planned | Medium | 3-5 days |
| **Burp Suite Adapter** (formalize samples) | Planned | Medium | 3-5 days |
| **SIEM/EDR Integration** | Planned | Medium | 2-3 weeks |
| **Design Intake Automation** | Planned | Medium | 3-4 weeks |

---

## Persona Tool Gaps (From Pitch Deck) - With Requirement Status

These tools are mentioned in the pitch deck persona analysis but lack native FixOps integration:

| Tool | Persona | Gap Type | Required? | Effort |
|------|---------|----------|-----------|--------|
| **Nessus** | VM Analyst, VA Analyst | No adapter | SHOULD | 1-2 weeks |
| **Qualys** | VM Analyst, VM Specialist | No adapter | SHOULD | 1-2 weeks |
| **Tenable.io** | VM Engineer | No adapter | SHOULD | 1-2 weeks |
| **Wiz** | CNAPP, Cloud | Sample only, no formal adapter | OPTIONAL | 3-5 days |
| **Checkmarx** | SAST, App Lead | Sample only, no formal adapter | OPTIONAL | 3-5 days |
| **Burp Suite** | VA Analyst | Sample only, no formal adapter | OPTIONAL | 3-5 days |
| **Rapid7** | VM Analyst | No adapter | NOT REQUIRED | 1 week |
| **Nmap** | VA Analyst | No adapter | NOT REQUIRED | 3-5 days |
| **OpenVAS** | VA Analyst | No adapter | NOT REQUIRED | 3-5 days |
| **Splunk** | VM Engineer, SOC | No SIEM integration | NOT REQUIRED | 2-3 weeks |
| **Apiiro** | ASPM | No adapter | NOT REQUIRED | 1 week |

**SIEM/EDR Gap:** SOC analysts need runtime event ingestion, SIEM log parsing, and EDR alert correlation - **NOT REQUIRED** for initial enterprise baseline. Build when customer demands.

**Full analysis:** See `FIXOPS_IMPLEMENTATION_STATUS.md` Appendix F: Persona Tool Coverage Matrix

---

## Metrics Dashboard

| Metric | Current | Target | How to Measure |
|--------|---------|--------|----------------|
| API Endpoints | 277 | 300+ | `grep -rh "@router\." apps/api/*.py \| wc -l` |
| CLI Commands | 30 | 67 | `python -m core.cli --help \| grep -E "^    [a-z]" \| wc -l` |
| Test Coverage | 18.95% | 70%+ | `pytest --cov` |
| LLM Providers Wired | **4** | 4 | OpenAI, Anthropic, Gemini, SentinelCyber |
| Evidence Signing | **RSA-SHA256** | RSA-SHA256 | `POST /api/v1/evidence/verify` |
| SLSA Provenance | **v1 + in-toto** | SLSA v1 | `services/provenance/attestation.py` |
| Storage Backends | **3** | 3 | Local, S3 Object Lock, Azure Immutable Blob |
| AI Consensus | **Real LLM** | Real LLM | `core/pentagi_advanced.py` |
