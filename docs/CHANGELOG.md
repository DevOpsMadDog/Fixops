# ALDECI Changelog

## [Beast Mode v6] — 2026-04-13

> **Session**: 216 commits across 2026-04-12 to 2026-04-13
> **Branch**: `features/intermediate-stage`
> **Tests**: 21,363 collected across 450 test files

---

### Architecture & Infrastructure

- **TrustGraph Event Bus**: Auto-connects all 3,036 API endpoints via WSGI middleware — zero-config
  event propagation across every router (`8eaefeef`, `0be38565`)
- **TrustGraph Event Bus v2**: 55 tests, fully wired into app.py (`0be38565`)
- **TrustGraph Backbone + GraphQL + Self-Scan**: Architecture v3 with self-indexing capability (`54411df7`)
- **TrustGraph Migration Adapter**: SQLite → Knowledge Cores automated migration path (`8b544a2d`)
- **TrustGraph explicit indexing**: Wired into 5 critical routers for guaranteed entity persistence (`5ca8b37c`)
- **MCP Gateway + AI Agent Orchestration**: AI-native platform layer with agent routing (`5210f15f`)
- **Enterprise Docker Compose**: Full stack — API + UI + TrustGraph + Redis + LocalStack + Wazuh +
  Shuffle + NetBox (`a514e636`)
- **Error Hierarchy**: Replaced top bare `except Exception` handlers with structured error types (`a2a4628f`)
- **Enterprise Simulation Design**: 12-stage full lifecycle mapped (`b75cf54f`)
- **12-Stage Enterprise Simulation Orchestrator**: 1,638-line simulation engine (`8eba32b0`)

---

### Security Engines (Core Features)

#### Threat Detection & Response
- **Material Change Detector**: Git webhook → blast radius analysis → SAST → LLM Council → incident
  creation (`ff973276`, `f6f7f02f`)
- **IR Playbook Runner**: 5 built-in playbooks (ransomware, data breach, DDoS, insider threat,
  supply chain), real actions, ntfy.sh push alerts (`7c6de76d`)
- **Automated Remediation Engine**: CWE-mapped fix templates, SLA tracking, fix verification (`aaa25886`)
- **SOAR Engine**: Automated security orchestration and response with playbook execution (`07bba76d`)
- **Incident Response Playbooks**: 8 runbook templates, timeline tracking (`fe27f467`)
- **FixEngine Remediation Workflow**: Playbooks, approval gates, rollback support (`150e545a`)
- **Remediation PR Generator**: Auto-fix dependency vulnerabilities as pull requests (`4598f0bd`)
- **Remediation Kanban Board + Smart Dedup Engine**: Visual workflow tracking with deduplication (`ca9a460c`)

#### Vulnerability Management
- **Vulnerability Enricher**: CWE→CVE mapping, EPSS+KEV composite risk scoring (`f8dd9ae3`)
- **Real CVE/EPSS/KEV Threat Intel Aggregator**: Live feeds from NVD + FIRST + CISA (`c0ac06b0`)
- **Vulnerability Exception Policy Engine**: Suppression rules with versioning (`f5b918b7`)
- **Vulnerability Lifecycle Tracker**: End-to-end state machine for vuln management (`920c83fa`)
- **Vulnerability Trending Analytics**: Time-series trending and aging analysis (`5c940d47`)
- **ML Vulnerability Prioritization**: Weighted multi-signal scoring with machine learning (`1401da11`)
- **SLA Engine**: Finding deadlines, breach detection, compliance SLA tracking (`ca6cb2fd`)
- **SLA Management Engine**: Deadline tracking with escalation and compliance reporting (`14d10f48`, `b89bf9ac`)

#### Scanning & Analysis
- **SAST Engine Expanded**: 8 languages, 130 detection rules, 112 tests (`a6ce68e4`)
- **DAST Scanner**: Dynamic application security testing, 127 tests (`7bc793ff`)
- **RASP Engine**: Runtime application self-protection, 75 tests (`10e429e0`)
- **SBOM Generation + OSV Scanner + License Auditor**: Real supply chain intelligence (`97130ad6`)
- **SBOM Lifecycle Management**: Import, export, diff, compliance tracking (`3a202d17`)
- **Secret Scanning Engine**: Regex detection with rotation tracking (`be48d704`)
- **Attack Surface Continuous Monitor**: Snapshots, diffs, scoring, attack path visualization (`f7832614`)
- **Attack Surface Mapping**: Asset inventory, exposure paths, risk scoring (`34e3250d`)
- **API Security Engine**: OWASP API Top 10 coverage, 92 tests (`e8fb0179`)
- **API Gateway Security**: 90 tests (`e00f4330`)
- **Supply Chain Security**: 111 tests (`0bc2efc6`)
- **Network Security NDR Engine**: 93 tests (`0ab79cec`)
- **MITRE ATT&CK Navigator**: Full framework mapping, 81 tests (`83c0c33a`)
- **Purple Team Exercise Engine**: Red + blue team coordination, 96 tests (`88977bdf`)
- **WAF Rule Generator**: 5 providers, 50 templates, 88 tests (`20bab41b`)
- **Code-to-Cloud Traceability**: 88 tests (`cf7d9f1b`)
- **K8s Security KSPM**: Kubernetes security posture management, 82 tests (`cf7d9f1b`)
- **DB Security Engine**: 115 tests (`d15d4b41`, `efe3916a`)
- **CSPM**: Cloud security posture management across AWS/Azure/GCP (`07cd6ebc`)
- **Anomaly ML/UEBA Engine**: Behavioral analytics, 64 tests (`1f58d226`)
- **Phishing Simulator**: 143 tests (`03166522`)

#### Compliance & Governance
- **Compliance Evidence Auto-Collector v2**: 7 frameworks, audit package generation (`ec0a711b`, `81c0f123`)
- **Compliance Gap Remediation Planner**: 7 frameworks, 42 controls (`15850c9d`)
- **Compliance Calendar**: Framework milestone scheduling + breach simulation engine (`37f3e637`)
- **Regulatory Change Tracker**: Automated regulatory update monitoring (`736b72bd`)
- **License Compliance Scanner**: 106 tests (`7597ee25`, `be3a7c5f`)
- **Audit Analytics**: 76 tests (`d15d4b41`)
- **Data Retention + GDPR Purge Engine**: Automated PII lifecycle management (`e1027618`)
- **Risk Register**: 91 tests (`6ed1c2ac`)
- **Change Management**: 81 tests (`6ed1c2ac`)
- **Backup/DR**: 66 tests (`7597ee25`)

#### Access & Identity
- **Privileged Access Management (PAM)**: Break-glass access, time-bound elevation (`66e92ac6`)
- **Zero-Trust Policy Engine**: STRIDE/DREAD threat modeling (`01e88ebb`)
- **SAML/OIDC Enterprise SSO**: Full enterprise authentication (`25b854df`)
- **RBAC Role Enforcement + Audit Logging**: Granular permission enforcement (`8d1d5fc4`)
- **Insider Threat Detection**: Behavioral analysis + unified dashboard API (`f60547c1`)

#### Intelligence & Analytics
- **Threat Intel Correlation + Compliance Questionnaire Engine** (`94584793`)
- **Threat Intel Feed Manager**: 28+ source lifecycle management (`cf93ca39`)
- **Threat Hunting Engine + Rate Limiter v2** (`52833a21`)
- **Finding Correlation Engine**: Exposure Cases, attack chain construction (`23804806`)
- **Security Posture Scoring**: Unified 0-100 risk score (`7af3872b`)
- **Security Scorecard API**: External-facing risk score with public endpoint (`6bbd35f2`, `920c83fa`)
- **Security Metrics & OKR Engine**: 90 tests (`704fa162`)
- **KPI Engine + Change Tracker + Risk Quantifier** (`5765845a`)
- **Security ROI Calculator**: Business-value quantification for security spend (`736b72bd`)
- **Cryptographic Evidence Chain + Multi-Cloud Asset Discovery** (`e7078e14`)
- **Posture Benchmark + Automated Patch Management** (`1c31b4bf`)

#### Infrastructure & Operations
- **Asset Inventory + CMDB Integration** (`c82ed571`)
- **Config Drift Detection + Slack Security Bot** (`5ad2e518`)
- **Real SIEM/SOAR/CMDB Connectors**: Wazuh, Shuffle, TheHive, NetBox (`cc735c6b`)
- **Real AWS Integration via LocalStack**: 51 tests (`9349191d`)
- **Real GitHub Issues + Real Webhook Delivery** (`9b49dbb7`)
- **n8n Event-Driven Connector Orchestration**: 400+ integration access (`2a00e341`)
- **Redis Queue Mode**: Horizontal pipeline scaling (`ebcfd0d3`)
- **Performance Hardening**: Caching, compression, profiling (`f3aa59b7`)
- **Per-Tenant Rate Limiting + Anomaly Detection** (`dc66b008`)
- **Webhook Signature Verifier**: 8 providers, auto-detect format (`126ec994`)
- **Webhook Security Hardening**: SSRF protection, payload validation, rate limiting (`0d049d4f`)
- **API Key Lifecycle Management System** (`f29827d1`)
- **Multi-Tenancy Isolation**: Org-level data separation (`c1264d4f`)

#### Developer & Productivity Tools
- **Copilot wired to TrustGraph GraphRAG**: Semantic context queries replacing keyword search (`29bc847e`, `0022bf6f`)
- **Code Ownership Mapper + License Compliance Scanner** (`b07a2722`)
- **Security Policy Document Generator**: 10 policy types (`00b9d23f`)
- **CI/CD Pipeline Security Gate**: Policy enforcement on PRs (`a56639a7`)
- **Developer Self-Service Security Portal** (`bb499278`)
- **Security Knowledge Base**: FTS5 full-text wiki, OWASP Top 10 seeded articles (`e0b0c6e7`)
- **Automated Pentest Scheduler**: Targets, recurring scans, reports (`3fc63b9b`)
- **Security Training Tracker** (`81c0f123`)
- **Playbook Marketplace + SOC Automation Engine** (`a11b953d`)
- **SOC Automation Engine** (`a11b953d`)
- **Workflow Automation Engine**: Trigger → condition → action chains (`aecd7c16`)
- **Bulk Finding Import/Export**: CSV, JSON, SARIF, CycloneDX formats (`2e5e24c7`)
- **Unified Tag Management**: Hierarchy, auto-rules, analytics (`f7e9ecac`)
- **Customer Onboarding Wizard API** (`547b3023`)
- **API Usage Analytics + Compliance Report Generator** (`7952aae1`)
- **Executive Reporting Engine**: Board-ready security reports (`bea04421`)

#### Trust & Vendor
- **Trust Center**: 104 tests (`a910d4f1`)
- **Bug Bounty Program Engine** (`a910d4f1`)
- **Vendor Security Scorecard**: Third-party risk scoring (`995ae4a0`)
- **Integration Health Dashboard**: Connector monitoring (`b5af4c1e`)
- **Breach Simulation Engine**: 48 tests (`9a66ba84`)
- **IoT Security**: 89 tests (`7597ee25`)
- **License Compliance**: 106 tests (`7597ee25`)

---

### LLM Council Enhancements

- **LLM Council Enhanced**: Confidence scoring, dissent tracking, model calibration (`b60ff8fa`)
- **Copilot → TrustGraph GraphRAG**: Semantic graph queries for all 30 personas (`29bc847e`)
- **MCP Gateway**: AI agent orchestration layer (`5210f15f`)

---

### Frontend Dashboards (suite-ui/aldeci-ui-new)

- **SOC T1 Alert Triage Dashboard**: LLM Council verdicts panel, real-time alert queue (`644c9e56`, `4d7f3731`)
- **Compliance Dashboard**: 7 frameworks, evidence tracking, gap analysis with arc gauges (`803d11b3`, `43df1e80`)
- **Threat Intelligence Dashboard**: CVE feed, EPSS heatmap, MITRE coverage, IOC feed, threat actors (`90c36d8e`)
- **CISO Executive Dashboard**: Risk posture, KPIs, compliance status (prior session)
- **Developer Security Dashboard**: Self-service portal with pipeline gate status
- **Compliance & Governance Dashboard** (`43df1e80`)
- **Frontend Component Tests**: All 3 dashboards (`92e1f25e`)

---

### Testing

- **Total tests collected**: 21,363 (across 450 test files)
- **Beast Mode integration test suite**: 29 cross-module flow tests (`33acc820`)
- **Brain Pipeline coverage**: 147 tests for core pipeline + scanner parsers (`113eca1d`)
- **E2E real GitHub scanner**: 15 famous repos scanned, real findings (`5d0bc1c4`, `f0c53f3c`)
- **Real E2E test suite**: LocalStack + GitHub API integration (`64596d7f`)
- **AWS LocalStack integration**: 51 tests (`9349191d`)
- **TrustGraph Event Bus**: 55 tests (`0be38565`)
- **Event loop isolation fix**: 16 test interaction failures resolved (`d4dc5e21`)
- **Test file count**: 450 (up from ~327 at session start)

Key test counts by engine:
| Engine | Tests |
|--------|-------|
| DAST Scanner | 127 |
| DB Security | 115 |
| Supply Chain Security | 111 |
| License Compliance | 106 |
| Trust Center | 104 |
| SAST Engine | 112 |
| Phishing Simulator | 143 |
| API Security (OWASP) | 92 |
| Security Metrics & OKR | 90 |
| Purple Team | 96 |
| Network Security NDR | 93 |
| WAF Rule Generator | 88 |
| Code-to-Cloud | 88 |
| K8s KSPM | 82 |
| Change Management | 81 |
| MITRE ATT&CK | 81 |
| Risk Register | 91 |
| Attack Surface Mgmt | 89 |
| IoT Security | 89 |

---

### Integration Wiring (Router Mounts)

- Wire 6 remaining routers into app.py (`7868c86f`)
- Wire 5 new routers + phishing simulator (`34967632`)
- SOAR router + E2E test environment (`cdf93f25`)
- Insider threat router (`7ec44a22`)
- Security ROI + regulatory tracker routers (`ca9c97b3`)
- Vuln lifecycle + scorecard routers (`1934fb0e`)
- Posture benchmark router (`7a55682d`)
- Training router (`0085007b`)
- Risk quantifier + KPI + change tracker routers (`a5f07714`)
- Event stream + API analytics + compliance reports routers (`82a951f2`)
- Questionnaire + threat intel routers (`62fedd5d`)
- Dep scanner router — 6 endpoints for dependency auditing (`03a20141`)
- License scanner + ownership/license routers (`be3a7c5f`)

---

### Bug Fixes & Quality

- Fix audit chain 422 + assets 500 errors — 57/64 enterprise simulation validations (`9b1e9a8e`)
- Fix 404/405 endpoint mismatches in 12-stage simulation (`20f8ada7`)
- Enterprise simulation: 47/64 → 57/64 validations passing (`645cfc71`)
- Fix 4 junk tests — replaced with real E2E GitHub scanner (`5d0bc1c4`)
- Fix 16 test interaction failures — event loop isolation (`d4dc5e21`)
- Error handling audit: structured error hierarchy replacing bare except (`a2a4628f`, `322984ac`)

---

### Documentation

- Architecture v3 (`54411df7`)
- Enterprise simulation design (`b75cf54f`)
- Beast Mode architecture (`BEAST_MODE_ARCHITECTURE.md`)
- CLAUDE.md updated with Beast Mode session progress

---

## [Beast Mode v5 — Prior Session] — 2026-04-12 (Pre-session baseline)

- TrustGraph indexed with 162 entities across 5 Knowledge Cores
- CISO Executive Dashboard (React 19, `/mission-control/ciso`)
- 709 Beast Mode tests passing
- 34 router mounts in app.py
- LLM Council connected to brain_pipeline.py
- PipelineOrchestrator wired to 32 real scanner normalizers
- Docker Compose for full stack (initial version)
- 81 tests for TrustGraph indexer, pipeline orchestrator, council adapter
