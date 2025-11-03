# FixOps E2E Orchestration - App Scenarios

## Overview

This document defines four comprehensive app scenarios for end-to-end FixOps testing, demonstrating all capabilities including threat intelligence, policy automation, compliance mapping, and evidence generation.

## APP1: Insurance Quote Platform (Healthcare/Financial)

**Business Context:**
- Multi-tier web application for health insurance quotes
- Handles PII (names, emails, SSN) and PHI (medical history)
- Internet-facing with payment processing (PCI-DSS scope)
- Critical business application with 99.9% SLA requirement

**Architecture:**
- Frontend: React 18.2.0 (web tier)
- API: Express 4.18.2 + Node.js 18.x (api tier)
- Database: PostgreSQL 14.5 (db tier)
- Payment Gateway: Stripe integration (esb tier)
- Infrastructure: AWS EKS, RDS, ALB

**Compliance Requirements:**
- SOC2 Type II
- ISO 27001
- HIPAA
- PCI-DSS Level 1

**Threat Profile:**
- High-value target for ransomware (healthcare data)
- Financial fraud risk (payment processing)
- Data breach liability (PII/PHI exposure)
- Regulatory penalties (HIPAA violations up to $50K per record)

**Historical Incidents (Backtest Scenarios):**
- 2024-Q2: SQL injection in quote API (CVE-2024-1709 in express)
- 2024-Q3: Prototype pollution in lodash (CVE-2024-2890)
- 2024-Q4: RCE in pg driver (CVE-2025-0001)

## APP2: E-Commerce Marketplace (Retail)

**Business Context:**
- Multi-vendor marketplace with real-time inventory
- Handles payment data, seller PII, buyer PII
- Event-driven architecture with Kafka
- 24/7 operations with Black Friday peak traffic (100K req/s)

**Architecture:**
- Frontend: Next.js 14.0.3 + React 18.2.0
- API Gateway: Kong 3.4.0
- Services: Java Spring Boot 3.1.5 microservices (12 services)
- Message Broker: Apache Kafka 3.6.0
- Database: MongoDB 7.0.2 (product catalog), PostgreSQL 15.1 (orders)
- Cache: Redis 7.2.0
- Infrastructure: AWS EKS, MSK, DocumentDB, ElastiCache

**Compliance Requirements:**
- PCI-DSS Level 1
- SOC2 Type II
- GDPR (EU customers)
- CCPA (California customers)

**Threat Profile:**
- Payment card fraud
- Account takeover attacks
- Inventory manipulation
- DDoS during peak sales
- Third-party seller fraud

**Historical Incidents (Backtest Scenarios):**
- 2024-Q1: Log4Shell in Spring Boot service (CVE-2021-44228)
- 2024-Q2: Kafka broker authentication bypass (CVE-2023-25194)
- 2024-Q3: MongoDB injection in search API (CVE-2024-5629)
- 2024-Q4: Redis RCE via Lua sandbox escape (CVE-2024-31449)

**Third-Party Integrations:**
- Stripe (payments)
- Shippo (shipping)
- Twilio (notifications)
- Auth0 (authentication)

## APP3: SaaS Analytics Platform (B2B)

**Business Context:**
- Multi-tenant analytics platform for enterprise customers
- Processes sensitive business metrics and customer data
- Real-time streaming analytics with WebSocket connections
- Tiered pricing: Starter ($99/mo), Pro ($499/mo), Enterprise ($2499/mo)

**Architecture:**
- Frontend: Vue.js 3.3.4 + TypeScript
- API: FastAPI 0.104.1 + Python 3.11
- Streaming: Apache Flink 1.18.0
- Database: TimescaleDB 2.13.0 (time-series), PostgreSQL 15.4
- Cache: Redis 7.2.3
- Object Storage: MinIO 2023.11.20
- Infrastructure: Kubernetes 1.28, Prometheus, Grafana

**Compliance Requirements:**
- SOC2 Type II
- ISO 27001
- GDPR
- Data residency requirements (EU, US, APAC)

**Threat Profile:**
- Tenant isolation breach (data leakage between customers)
- API abuse (rate limiting bypass)
- Credential stuffing
- Data exfiltration via export APIs
- Supply chain attacks (npm/PyPI dependencies)

**Historical Incidents (Backtest Scenarios):**
- 2024-Q1: Tenant isolation bug in FastAPI middleware (CVE-2024-0001)
- 2024-Q2: Prototype pollution in Vue.js (CVE-2024-5207)
- 2024-Q3: SQL injection in TimescaleDB query builder (CVE-2024-7348)
- 2024-Q4: Path traversal in MinIO (CVE-2024-28757)

**Third-Party Integrations:**
- Slack (notifications)
- Salesforce (CRM sync)
- Zapier (workflow automation)
- Okta (SSO)

## APP4: IoT Device Management Platform (Industrial)

**Business Context:**
- Industrial IoT platform managing 500K+ connected devices
- Critical infrastructure (manufacturing, energy, utilities)
- Real-time telemetry and remote device control
- Safety-critical operations (emergency shutdowns)

**Architecture:**
- Frontend: Angular 17.0.0 + TypeScript
- API: Go 1.21.5 + gRPC
- Message Broker: MQTT (Eclipse Mosquitto 2.0.18)
- Time-Series DB: InfluxDB 2.7.4
- Device Registry: etcd 3.5.10
- Edge Computing: K3s 1.28.3
- Infrastructure: Hybrid cloud (AWS + on-premises edge)

**Compliance Requirements:**
- IEC 62443 (industrial cybersecurity)
- NERC CIP (energy sector)
- ISO 27001
- SOC2 Type II

**Threat Profile:**
- Device hijacking (botnet recruitment)
- Firmware tampering
- Man-in-the-middle attacks (MQTT interception)
- Denial of service (device availability)
- Physical safety incidents (malicious device commands)

**Historical Incidents (Backtest Scenarios):**
- 2024-Q1: MQTT authentication bypass (CVE-2023-0809)
- 2024-Q2: Go stdlib HTTP/2 rapid reset (CVE-2023-39325)
- 2024-Q3: InfluxDB authentication bypass (CVE-2024-6874)
- 2024-Q4: etcd privilege escalation (CVE-2024-8421)

**Third-Party Integrations:**
- PagerDuty (incident management)
- Datadog (monitoring)
- AWS IoT Core (cloud connectivity)
- Twilio (SMS alerts)

## Test Coverage Matrix

| Test Type | APP1 | APP2 | APP3 | APP4 |
|-----------|------|------|------|------|
| API Contract Tests | ✓ | ✓ | ✓ | ✓ |
| AuthZ Matrix Tests | ✓ | ✓ | ✓ | ✓ |
| Performance Tests (k6) | ✓ | ✓ | ✓ | ✓ |
| Chaos Experiments | ✓ | ✓ | ✓ | ✓ |
| Policy-as-Code (OPA) | ✓ | ✓ | ✓ | ✓ |
| STRIDE Threat Model | ✓ | ✓ | ✓ | ✓ |
| LINDDUN Privacy Model | ✓ | ✓ | ✓ | ✓ |
| CLI Self-Audit | ✓ | ✓ | ✓ | ✓ |
| Third-Party Webhooks | - | ✓ | ✓ | - |
| Evidence Bundles | ✓ | ✓ | ✓ | ✓ |
| VC Comparison Reports | ✓ | ✓ | ✓ | ✓ |

## Backtest Scenarios

Each app includes 4 historical CVE scenarios from 2024 to demonstrate:
1. **Severity Promotion**: How FixOps would have elevated these CVEs before KEV listing
2. **Day-0 Detection**: Structural priors identifying risk at disclosure
3. **Remediation Tracking**: Evidence of patch application and verification
4. **Compliance Impact**: Mapping to control frameworks

## Success Criteria

For each app, the E2E orchestration must produce:
1. Complete input artifacts (6 files: design.csv, sbom.json, results.sarif, cve_feed.json, vex_doc.json, findings.json)
2. Threat matrices (STRIDE + LINDDUN) with attack vectors and mitigations
3. Policy-as-code rules (OPA Rego) with test cases
4. API contract tests (OpenAPI/AsyncAPI) with positive/negative scenarios
5. AuthZ matrix (roles × endpoints) with JWT examples
6. Performance tests (k6) with baseline/spike/soak scenarios
7. Chaos experiments with rollback procedures
8. CLI self-audit scripts with exit code validation
9. Evidence bundle (signed, compressed, with manifest)
10. VC-ready comparison report (FixOps vs Apiiro)

## Execution Plan

1. Generate all input artifacts for each app
2. Run FixOps pipeline (CLI + API) for each app
3. Execute all test suites and collect results
4. Generate evidence bundles with SLSA attestation
5. Create VC comparison reports with ROI analysis
6. Produce consolidated `all_apps_reference.json`
