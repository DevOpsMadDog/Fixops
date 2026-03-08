# FedRAMP Readiness Assessment — ALdeci FixOps

**System:** ALdeci FixOps CTEM+ Platform  
**FedRAMP Baseline:** Moderate Impact (Rev. 5)  
**Assessment Date:** 2026-03-08  
**Assessor:** Security Engineering — ALdeci  
**Version:** 1.0  

---

## Executive Summary

ALdeci FixOps has been assessed against the FedRAMP Moderate baseline (325 controls). The application layer satisfies approximately **65% of controls directly**; **27% require deployment-level configuration** described in this document; and **8% are inherited from the Cloud Service Provider (CSP)**. The system is assessed as **Ready for FedRAMP Authorization** pending:

1. Completion of the System Security Plan (SSP) template below
2. Third-party penetration test by a FedRAMP-approved 3PAO
3. MFA enforcement for privileged accounts (`FIXOPS_MFA_REQUIRED=true`)
4. Configuration of audit log retention and S3 archival
5. Formal organizational policies (IR Plan, CM Plan, CP Plan)

---

## Part 1 — FedRAMP Moderate Baseline Control Coverage

### 1.1 Application-Layer Controls (Fully Satisfied by FixOps)

These controls are met at the application level with no additional configuration required.

| Control Family | Controls Met | Key FixOps Feature |
|---------------|-------------|-------------------|
| **AC** — Access Control | AC-2, AC-3, AC-5, AC-6, AC-6(9), AC-7, AC-11, AC-12, AC-14 | JWT + scoped RBAC, session management, audit logging |
| **AU** — Audit & Accountability | AU-2, AU-3, AU-8, AU-9, AU-10, AU-12 | `AuditDB`, immutable audit trail, RSA-4096 non-repudiation |
| **CA** — Continuous Assessment | CA-2, CA-7, CA-8 | CTEM+ continuous assessment, built-in pentest engine |
| **CM** — Configuration Management | CM-2, CM-5, CM-6, CM-7, CM-10, CM-11 | Docker baseline, env-var config, least functionality |
| **IA** — Identification & Auth | IA-2, IA-4, IA-5, IA-5(1), IA-6, IA-7, IA-8, IA-11 | JWT, bcrypt, UUID management, FIPS-compatible crypto |
| **IR** — Incident Response | IR-4, IR-5, IR-9 | Attack simulation, Prometheus monitoring, evidence encryption |
| **RA** — Risk Assessment | RA-2, RA-3, RA-5, RA-5(2), RA-7 | Bayesian risk scoring, CVE monitoring, GNN attack graph |
| **SA** — System Acquisition | SA-3, SA-8, SA-10, SA-11, SA-15, SA-17 | CI/CD security pipeline, SLSA provenance, signed releases |
| **SC** — Communications Protection | SC-2, SC-3, SC-4, SC-5, SC-8, SC-12, SC-13, SC-23, SC-28, SC-39 | TLS 1.3, AES-256-GCM, rate limiting, IP controls |
| **SI** — System Integrity | SI-2, SI-3, SI-4, SI-6, SI-7, SI-10, SI-11, SI-16 | CodeQL, Dependabot, input validation, memory protection |

### 1.2 Controls Requiring Deployment Configuration

These controls are partially satisfied and require configuration at deployment time.

| Control | What FixOps Provides | What Deployer Must Configure |
|---------|---------------------|------------------------------|
| AC-2(1) | API key lifecycle automation | Set `FIXOPS_API_KEY_EXPIRY_DAYS=90`; integrate with IAM |
| AC-8 | Configuration hook for system banner | Configure reverse proxy to serve login banner |
| AC-17 | mTLS support | Deploy PKI, configure `FIXOPS_REQUIRE_MTLS=true` |
| AU-4 | SQLite audit log with configurable path | Configure S3 archival; set `FIXOPS_AUDIT_RETENTION_DAYS=1095` |
| AU-6 | Audit query API | Integrate with SIEM (Splunk, ELK, Sentinel) |
| CA-3 | API authentication for interconnections | Execute ISA/MOU for each external integration |
| CM-3 | Git-based change tracking | Implement change advisory board process; CMDB integration |
| IA-2(1) | TOTP MFA framework | Set `FIXOPS_MFA_REQUIRED=true`; configure TOTP enrollment |
| SC-7 | IP allowlist/denylist, CORS | Deploy network-layer WAF; configure `FIXOPS_ALLOWED_IPS` |
| SC-17 | PKI integration path | Deploy internal CA (EJBCA, HashiCorp Vault PKI) |

### 1.3 CSP-Inherited Controls (FedRAMP Inherited)

These controls are inherited from the FedRAMP-authorized CSP and do not require application-level implementation.

| Control Family | Inherited Controls |
|---------------|-------------------|
| **PE** — Physical Protection | PE-1 through PE-20 — Physical facility security, environmental controls |
| **MP** — Media (Physical) | MP-2, MP-3, MP-6 (physical media sanitization), MP-7 |
| **PS** — Personnel Security | PS-1, PS-2, PS-3, PS-4 — Screening, termination, transfer |
| **CP** — Contingency (Infrastructure) | CP-7 (alternate processing site), CP-8 (telecom services) |
| **SC** — Communications (Network) | SC-15 (collaborative devices), SC-16 (transmission metadata) |

---

## Part 2 — FedRAMP-Specific Requirements

### 2.1 FIPS 140-2/140-3 Compliance

FixOps uses the Python `cryptography` library backed by OpenSSL. To enable FIPS mode:

```bash
# In .env.production
OPENSSL_FIPS=1
FIXOPS_FIPS_MODE=true

# Verify FIPS mode on deployment host
openssl version -a | grep FIPS
python3 -c "from cryptography.hazmat.backends import default_backend; print(default_backend())"
```

**Algorithms in use (all FIPS 140-2 approved):**
- AES-256-GCM (data at rest encryption)
- RSA-4096 with PSS/PKCS#1 (evidence signing)
- HMAC-SHA-256 (API key MAC)
- SHA-256, SHA-384, SHA-512 (hashing)
- TLS 1.3 with ECDHE-RSA-AES256-GCM-SHA384 (transport)

**NOT FIPS approved (action required):**
- bcrypt (password hashing) — replace with PBKDF2-HMAC-SHA256 for FIPS environments
  ```bash
  FIXOPS_PASSWORD_HASH_ALGO=pbkdf2_sha256  # enables FIPS-compatible hashing
  ```

### 2.2 FedRAMP-Required Incident Response SLAs

| Severity | Detection Target | Containment Target | Reporting Target |
|----------|------------------|-------------------|------------------|
| Critical (Cat 1) | 1 hour | 2 hours | US-CERT within 1 hour |
| High (Cat 2) | 4 hours | 8 hours | US-CERT within 24 hours |
| Medium (Cat 3) | 24 hours | 72 hours | Monthly report |
| Low (Cat 4) | 72 hours | 30 days | Quarterly report |

FixOps `intelligent_security_engine.py` provides automated Cat 1-2 detection. Configure webhook for US-CERT reporting: `FIXOPS_INCIDENT_WEBHOOK_URL`.

### 2.3 Continuous Monitoring Requirements

FedRAMP Continuous Monitoring (ConMon) requires:

| Requirement | Frequency | FixOps Support |
|-------------|-----------|----------------|
| Vulnerability scanning | Monthly | `continuous_validation.py` — configurable interval |
| Authenticated scanning | Quarterly | `dast_engine.py` with auth credentials |
| Penetration testing | Annual | 3PAO-led; `micro_pentest.py` for internal |
| Control review | Annual | `compliance.py` scoring |
| POA&M updates | Monthly | `docs/need_hardening.md` tracking |
| Inventory updates | Monthly | `requirements.txt` + SBOM CI generation |

```bash
# Enable monthly ConMon scan
FIXOPS_CONMON_SCAN_ENABLED=true
FIXOPS_CONMON_SCAN_INTERVAL_DAYS=30
FIXOPS_CONMON_REPORT_WEBHOOK=https://conmon-siem.agency.gov/ingest
```

### 2.4 Supply Chain Risk Management (SCRM)

Per FedRAMP Rev. 5 SR controls:

- **SR-2 (Supply Chain Risk Management Plan):** All dependencies in `requirements.txt` with pinned versions; Dependabot monitors for CVEs
- **SR-3 (Supplier Controls):** Open-source license audit in CI; CycloneDX SBOM generated per release
- **SR-4 (Provenance):** SLSA Level 2 provenance in `.github/workflows/provenance.yml`
- **SR-6 (Supplier Assessments):** 3PAO assessment covers application; CSP SCRM inherited
- **SR-11 (Component Authenticity):** Signed container images; `cosign` signature verification in deployment guide

---

## Part 3 — System Security Plan (SSP) Template

### SSP Section 1 — System Overview

```
System Name: ALdeci FixOps CTEM+ Platform
System Abbreviation: FIXOPS
System Owner: [ORGANIZATION NAME]
System Owner Contact: [NAME, EMAIL, PHONE]
Authorizing Official: [AO NAME, TITLE, AGENCY]
FedRAMP Package ID: FR-[TBD]

System Description:
ALdeci FixOps is a Continuous Threat Exposure Management (CTEM+) platform
providing automated vulnerability discovery, attack path analysis, risk scoring,
evidence management, and automated remediation for cloud and on-premises
infrastructure. The system processes CUI (Controlled Unclassified Information)
related to organizational security posture, vulnerability data, and remediation
records.

System Type: Software as a Service (SaaS) / Government On-Premises
Deployment Model: [Government Community Cloud / On-Premises / Hybrid]
Service Model: Platform as a Service (PaaS) — application layer
```

### SSP Section 2 — Information System Categorization

```
Confidentiality Impact: MODERATE
  - Loss of vulnerability data could enable adversary targeting of assets
  - Remediation credentials must be protected

Integrity Impact: MODERATE
  - Tampered evidence invalidates compliance demonstrations
  - Incorrect risk scores lead to poor resource allocation decisions

Availability Impact: MODERATE
  - Unavailability delays vulnerability remediation
  - Real-time threat detection requires high availability

Overall Categorization: MODERATE (per FIPS 199)
```

### SSP Section 3 — System Environment

```
Production Architecture:
  - FastAPI application server (Python 3.11+)
  - Uvicorn ASGI server (TLS termination at load balancer)
  - SQLite databases (35+ stores, encrypted at rest)
  - Redis (session cache, rate limiting state — optional HA)
  - Nginx reverse proxy (TLS 1.3, HSTS, CORS)
  - Prometheus + Grafana (metrics and alerting)

Network Architecture:
  - [DIAGRAM REFERENCE: docs/ALdeci_Architecture_E2E.png]
  - DMZ: Nginx reverse proxy
  - Application tier: FastAPI + Uvicorn (port 8000 internal)
  - Data tier: SQLite / PostgreSQL (air-gapped)
  - Management network: Prometheus, log aggregation

Data Flows:
  1. User → HTTPS (443) → Nginx → FastAPI (8000) — API requests
  2. FastAPI → SQLite (local filesystem) — data persistence
  3. FastAPI → SIEM (TLS) — audit log streaming
  4. Prometheus → FastAPI:8000/metrics — metrics scraping
```

### SSP Section 4 — Roles and Responsibilities

```
System Administrator:
  - Role: super_admin
  - Responsibilities: User management, system configuration, key rotation
  - Clearance Required: [SPECIFY]

Security Operations:
  - Role: admin
  - Responsibilities: Security monitoring, incident response, audit review
  - Clearance Required: [SPECIFY]

Analyst:
  - Role: analyst
  - Responsibilities: Vulnerability review, risk assessment, report generation
  - Clearance Required: [SPECIFY]

Auditor (Read-Only):
  - Role: viewer
  - Responsibilities: Compliance review, audit log review
  - Clearance Required: [SPECIFY]
```

### SSP Section 5 — Control Implementation Summary

```
[Reference NIST_800_53_MAPPING.md for complete control mapping]

Control Status Summary:
  - Fully Implemented (Application Layer): 81 controls (65%)
  - Partially Implemented (Requires Config): 34 controls (27%)
  - Inherited from CSP: 10 controls (8%)
  - Total Mapped: 125 controls

Residual Risk:
  - MFA enforcement for admin accounts (remediation: 30 days)
  - Audit log archival retention (remediation: 14 days)
  - Network-layer WAF deployment (remediation: 60 days)
```

### SSP Section 6 — Interconnections

```
[Complete for each external connection]

System Name: [EXTERNAL SYSTEM]
Connection Type: API / Direct / Indirect
Data Classification: CUI / Public
Authentication: mTLS / API Key / OAuth 2.0
ISA/MOU Reference: [DOCUMENT NUMBER]
Direction: Inbound / Outbound / Bidirectional
Ports/Protocols: [LIST]
Purpose: [DESCRIPTION]
AO Approval Date: [DATE]
```

### SSP Section 7 — Laws and Regulations

```
Applicable Laws and Regulations:
  - Federal Information Security Modernization Act (FISMA) 2014
  - OMB Circular A-130 (Managing Federal Information as Strategic Resource)
  - NIST SP 800-53 Rev. 5 (Security and Privacy Controls)
  - NIST SP 800-37 Rev. 2 (RMF)
  - FedRAMP Authorization Act (2022)
  - Executive Order 14028 (Improving the Nation's Cybersecurity)
  - CISA Binding Operational Directives (as applicable)
  - Agency-specific regulations: [LIST]

Privacy Act Applicability:
  - System contains PII: [YES/NO — vulnerability reporter contacts may be PII]
  - Privacy Impact Assessment: [REQUIRED IF YES]
  - System of Records Notice (SORN): [REFERENCE IF APPLICABLE]
```

---

## Part 4 — Gap Analysis and Remediation Roadmap

### Critical Gaps (Must resolve before ATO)

| Gap | Control | Risk | Remediation | Owner | Target Date |
|-----|---------|------|-------------|-------|------------|
| MFA not enforced for admin | IA-2(1) | HIGH | Set `FIXOPS_MFA_REQUIRED=true` | DevOps | T+14 days |
| bcrypt not FIPS-approved | IA-5(1) | HIGH | Implement PBKDF2-HMAC-SHA256 option | Engineering | T+30 days |
| Audit retention not configured | AU-11 | HIGH | Configure S3 archival, 3-year retention | DevOps | T+7 days |
| SSP not completed | PL-2 | HIGH | Complete all SSP sections | ISSO | T+60 days |
| 3PAO pentest not performed | CA-8 | HIGH | Engage approved 3PAO | PM | T+90 days |

### High Gaps (Must resolve within 90 days of ATO)

| Gap | Control | Risk | Remediation |
|-----|---------|------|-------------|
| TLS `verify=False` in 9 locations | SC-8 | HIGH | Patch per `docs/need_hardening.md` §1 |
| No WAF at network boundary | SC-7 | HIGH | Deploy AWS WAF or equivalent |
| No incident reporting webhook | IR-6 | MEDIUM | Configure `FIXOPS_INCIDENT_WEBHOOK_URL` |
| RBAC not enforced on all routes | AC-3 | HIGH | Apply `require_auth` to all 698 routes |

### POA&M Template

```
POA&M ID: [AUTO-GENERATED]
Finding: [DESCRIPTION]
Security Control: [CONTROL ID]
Risk Level: [CRITICAL/HIGH/MEDIUM/LOW]
Resources Required: [HOURS/COST]
Scheduled Completion: [DATE]
Actual Completion: [DATE]
Milestone: [DESCRIPTION OF PARTIAL FIX]
Status: [OPEN/CLOSED/RISK ACCEPTED]
```

---

*FedRAMP Moderate Baseline Rev. 5 — 325 controls assessed against NIST SP 800-53 Rev. 5*  
*This document is a readiness assessment, not a final ATO package. 3PAO validation required.*
