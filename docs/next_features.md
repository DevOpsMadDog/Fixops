# FixOps Next Features

**Last Updated:** January 3, 2026  
**Source:** Extracted from `FIXOPS_IMPLEMENTATION_STATUS.md` and AlDeci Pitch Deck Gap Analysis

This document consolidates all planned features and "What's Needed" items into a simple prioritized table for development planning.

---

## Priority Legend

| Priority | Meaning |
|----------|---------|
| **Critical** | Required for pitch deck claims to be true |
| **High** | Important for product completeness |
| **Medium** | Nice to have, improves UX |
| **Low** | Future enhancement |

---

## Feature Backlog

### Critical Priority (Pitch Deck Claims)

| Feature | Current State | What's Needed | Effort | Code Reference |
|---------|---------------|---------------|--------|----------------|
| RSA-SHA256 Evidence Signing | **COMPLETED** | ~~Wire `rsa_sign()` into `EvidenceHub.persist()`~~ | ~~2-3 days~~ | `core/evidence.py:329-397` |
| SLSA v1 Provenance | **COMPLETED** | ~~Implement SLSA provenance format, in-toto attestations~~ | ~~2-3 weeks~~ | `services/provenance/attestation.py` |
| Evidence Verification Endpoint | **COMPLETED** | ~~Add `/api/v1/evidence/verify` that calls `rsa_verify()`~~ | ~~1-2 days~~ | `backend/api/evidence/router.py:162-303` |
| WORM-Compliant Storage | SQLite with soft deletes | S3 Object Lock / Azure Immutable Blob adapter | 3-4 weeks | `core/evidence.py` |
| Wire Real LLM Providers | `_call_llm()` returns mocked JSON | Replace mocked responses with actual provider calls | 3-5 days | `core/pentagi_advanced.py:258-273` |

### High Priority (Product Completeness)

| Feature | Current State | What's Needed | Effort | Code Reference |
|---------|---------------|---------------|--------|----------------|
| Micro-Pentest Sandbox | Templates exist, LLM mocked | Real sandbox execution environment | 2-3 weeks | `core/exploit_generator.py` |
| 30-min Onboarding | Manual setup required | Automated setup wizard, one-click deployment | 2-3 weeks | New tooling |
| RBAC Middleware | Role model exists | Add role-checking middleware/decorator | 1-1.5 weeks | `apps/api/users_router.py` |
| Background Job Store | BackgroundTasks pattern used | Persistent job store (SQLite table) | 1-2 weeks | `apps/api/bulk_router.py` |
| IaC Scanning | Returns "scanning" stub | Integrate checkov/tfsec | 1 week | `apps/api/iac_router.py:122-130` |
| Secrets Scanning | Returns "scanning" stub | Integrate gitleaks/trufflehog | 1 week | `apps/api/secrets_router.py:116-124` |
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

### Low Priority (Future Enhancements)

| Feature | Current State | What's Needed | Effort | Code Reference |
|---------|---------------|---------------|--------|----------------|
| Application Components | Returns `[]` | Populate from SBOM uploads | 3-5 days | `apps/api/inventory_router.py:152-204` |
| Application APIs | Returns `[]` | API catalog integration | 1 week | `apps/api/inventory_router.py` |
| Application Dependencies | Returns `[]` | Dependency graph from SBOM | 3-5 days | `apps/api/inventory_router.py` |
| Service Registry | Returns `[]` or 404 | Service registry integration | 1-2 weeks | `apps/api/inventory_router.py` |
| Lifecycle Stage Tracking | Not implemented | Add `lifecycle_stage` field | 1-2 weeks | `core/services/deduplication.py` |
| Cross-Stage Correlation | Not implemented | Link findings across stages | 1-2 weeks | `core/services/deduplication.py` |
| Runtime Event Ingestion | Not implemented | `POST /api/v1/events/ingest` | 1 week | New endpoint |
| OSS Fallback Wiring | Code exists, not wired | Wire to pipeline with config | 3-5 days | `core/oss_fallback.py` |

---

## Implementation Phases

### Phase 1: Evidence Integrity (Weeks 1-3) - COMPLETED
- [x] Wire RSA signing to EvidenceHub
- [x] Add evidence verification endpoint
- [x] Implement SLSA v1 provenance format
- [x] Store signature + fingerprint in manifest

### Phase 2: AI Consensus (Weeks 4-5)
- [ ] Replace mocked `_call_llm()` with real provider calls
- [ ] Add error handling and fallback logic
- [ ] Implement consensus threshold configuration
- [ ] Add unit tests for consensus logic

### Phase 3: Enterprise Storage (Weeks 6-8)
- [ ] Abstract storage backend in evidence module
- [ ] Implement S3 Object Lock adapter
- [ ] Implement Azure Immutable Blob adapter
- [ ] Add retention policy configuration

### Phase 4: Scanning & Sandbox (Weeks 9-12)
- [ ] Integrate checkov/tfsec for IaC scanning
- [ ] Integrate gitleaks/trufflehog for secrets scanning
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

## Persona Tool Gaps (From Pitch Deck)

These tools are mentioned in the pitch deck persona analysis but lack native FixOps integration:

| Tool | Persona | Gap Type | Priority | Effort |
|------|---------|----------|----------|--------|
| **Nessus** | VM Analyst, VA Analyst | No adapter | High | 1-2 weeks |
| **Qualys** | VM Analyst, VM Specialist | No adapter | High | 1-2 weeks |
| **Tenable.io** | VM Engineer | No adapter | High | 1-2 weeks |
| **Wiz** | CNAPP, Cloud | Sample only, no formal adapter | Medium | 3-5 days |
| **Checkmarx** | SAST, App Lead | Sample only, no formal adapter | Medium | 3-5 days |
| **Burp Suite** | VA Analyst | Sample only, no formal adapter | Medium | 3-5 days |
| **Rapid7** | VM Analyst | No adapter | Low | 1 week |
| **Nmap** | VA Analyst | No adapter | Low | 3-5 days |
| **OpenVAS** | VA Analyst | No adapter | Low | 3-5 days |
| **Splunk** | VM Engineer, SOC | No SIEM integration | Low | 2-3 weeks |
| **Apiiro** | ASPM | No adapter | Low | 1 week |

**SIEM/EDR Gap:** SOC analysts need runtime event ingestion, SIEM log parsing, and EDR alert correlation - none currently implemented.

**Full analysis:** See `FIXOPS_IMPLEMENTATION_STATUS.md` Appendix F: Persona Tool Coverage Matrix

---

## Metrics Dashboard

| Metric | Current | Target | How to Measure |
|--------|---------|--------|----------------|
| API Endpoints | 277 | 300+ | `grep -rh "@router\." apps/api/*.py \| wc -l` |
| CLI Commands | 30 | 67 | `python -m core.cli --help \| grep -E "^    [a-z]" \| wc -l` |
| Test Coverage | 18.95% | 70%+ | `pytest --cov` |
| LLM Providers Wired | 0 | 4 | Count of non-mocked providers |
| Evidence Signing | **RSA-SHA256** | RSA-SHA256 | `POST /api/v1/evidence/verify` |
| SLSA Provenance | **v1 + in-toto** | SLSA v1 | `services/provenance/attestation.py` |
