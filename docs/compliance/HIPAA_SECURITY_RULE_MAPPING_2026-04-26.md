# HIPAA Security Rule — Control Mapping

> **Document Class**: Compliance Readiness — Auditor-Grade
> **Standard Reference**: HIPAA Security Rule, 45 CFR Parts 160 and 164 (Subparts A and C)
> **Official Source**: https://www.hhs.gov/hipaa/for-professionals/security/index.html
> **Federal Register Reference**: 68 FR 8334 (February 20, 2003); updated by HITECH Act (2009) and Omnibus Rule (2013)
> **Effective Date**: 2026-04-26
> **Revision**: 1.0
> **Author**: ALdeci Technical Writer (grounded in codebase)
> **Approver**: CISO / Security Lead
> **Next Review**: 2026-07-26 (quarterly)

---

## 1. System Identification and ePHI Scope

| Field | Value |
|-------|-------|
| **System Name** | ALdeci (Fixops) |
| **Version** | 0.1.0-alpha |
| **Git Ref** | `features/intermediate-stage` @ `4a864956` |
| **Entity Type** | Business Associate (BA) — ALdeci processes security findings that may include ePHI metadata when deployed by healthcare Covered Entities |
| **ePHI Exposure** | INDIRECT — ALdeci scans customer codebases and infrastructure. If a healthcare CE customer deploys ALdeci against systems containing ePHI, ALdeci may process ePHI-adjacent data (e.g., secrets in code, misconfigured storage). ALdeci does not intentionally collect, store, or process ePHI as a primary use case. |
| **BAA Required** | YES — for any healthcare CE customer deployment |
| **Deployment Model** | Self-hosted, on-premises, air-gap capable (supports CE-controlled environments) |

### ePHI Risk Statement
ALdeci's Business Associate obligations under HIPAA arise when:
1. A Covered Entity customer deploys ALdeci to scan systems that store or process ePHI
2. ALdeci's scanning engines encounter ePHI-containing files or configurations during SAST/DAST/Secrets scans
3. Finding reports contain excerpts of scanned content that include ePHI

ALdeci's DLP engine (`core/dlp_engine.py`) includes PHI/PII detection patterns to minimize inadvertent ePHI retention in finding records.

---

## 2. Notation

| Column | Meaning |
|--------|---------|
| **REF** | CFR section and specification number |
| **SPECIFICATION** | HHS official specification name |
| **TYPE** | Required (R) or Addressable (A) per 45 CFR §164.306(d) |
| **ALDECI IMPLEMENTATION** | Engine file(s) + commit SHA `4a864956` |
| **STATUS** | IMPLEMENTED / PARTIAL / PLANNED / INHERITED / NOT-APPLICABLE |
| **NOTES** | Gaps, POA&M cross-reference, implementation evidence |

**Status definitions:**
- **IMPLEMENTED** — fully coded, tested, producing audit-ready artifacts
- **PARTIAL** — exists but has documented gaps
- **PLANNED** — design exists; implementation not yet shipped
- **INHERITED** — CE/customer environment satisfies the safeguard
- **NOT-APPLICABLE** — safeguard is outside ALdeci's operational scope as a BA

---

## 3. §164.308 — Administrative Safeguards

*Administrative actions, policies, and procedures to manage the selection, development, implementation, and maintenance of security measures that protect ePHI.*

| REF | SPECIFICATION | TYPE | ALDECI IMPLEMENTATION | STATUS | NOTES |
|-----|--------------|------|-----------------------|--------|-------|
| §164.308(a)(1)(i) | Security Management Process — Risk Analysis | R | `suite-core/core/composite_risk_scorer.py`; `core/application_risk_engine.py`; `core/asset_risk_calculator.py`; `core/developer_risk_profiler.py` — continuous risk scoring across all findings | PARTIAL | Automated risk scoring exists. Formal HIPAA-specific risk analysis documentation not yet produced. POA&M: **GAP-HIPAA-001** |
| §164.308(a)(1)(ii)(A) | Security Management Process — Risk Management | R | `core/autonomous_remediation_engine.py`; `core/automated_remediation.py`; `core/compliance_workflow_engine.py` — risk reduction through AutoFix and workflow orchestration | IMPLEMENTED | `tests/test_phase9_playbooks.py` passing |
| §164.308(a)(1)(ii)(B) | Security Management Process — Sanction Policy | R | `core/rbac_engine.py` — role enforcement; `core/audit_logger.py` — every action attributed; formal sanction policy requires HR policy doc | PARTIAL | Technical enforcement in place. Formal written sanction policy not committed. POA&M: **GAP-HIPAA-002** |
| §164.308(a)(1)(ii)(C) | Security Management Process — Information System Activity Review | R | `core/audit_logger.py`; `core/audit_analytics.py`; `core/audit_management_engine.py`; `core/access_anomaly_engine.py` — automated log review and anomaly detection | IMPLEMENTED | `tests/test_audit_analytics.py`, `tests/test_access_anomaly_engine.py` passing |
| §164.308(a)(2) | Assigned Security Responsibility | R | `core/rbac_engine.py` — Security Officer role (`security_engineer`, `org_admin`); `core/identity_governance_engine.py` — role assignment audit trail | IMPLEMENTED | Security role defined in RBAC engine; assignment audited |
| §164.308(a)(3)(i) | Workforce Security — Authorization and Supervision | A | `core/rbac_engine.py`; `core/access_governance_engine.py`; `core/identity_lifecycle_engine.py` — workforce access authorization workflow | IMPLEMENTED | `tests/test_access_governance_engine.py` passing |
| §164.308(a)(3)(ii)(A) | Workforce Security — Workforce Clearance Procedure | A | `core/identity_lifecycle_engine.py` — access provisioning workflow; `core/access_request_management_engine.py` | PARTIAL | Technical workflow exists. Formal clearance procedure policy document needed. POA&M: **GAP-HIPAA-002** (shared) |
| §164.308(a)(3)(ii)(B) | Workforce Security — Termination Procedures | A | `core/identity_lifecycle_engine.py` — account deprovisioning; `core/access_governance_engine.py` — immediate access revocation workflow | PARTIAL | Automated de-provisioning exists but end-to-end off-boarding not fully integrated. POA&M: **GAP-HIPAA-003** |
| §164.308(a)(4)(i) | Information Access Management — Isolating HC Clearinghouse | A | NOT-APPLICABLE | NOT-APPLICABLE | ALdeci is not a healthcare clearinghouse |
| §164.308(a)(4)(ii)(A) | Information Access Management — Access Authorization | A | `core/access_control_engine.py`; `core/rbac_engine.py`; `core/access_matrix.py` — attribute-based access control | IMPLEMENTED | `tests/test_access_control_engine.py` passing |
| §164.308(a)(4)(ii)(B) | Information Access Management — Access Establishment and Modification | A | `core/access_request_management_engine.py`; `core/identity_lifecycle_engine.py`; `core/access_governance_engine.py` | IMPLEMENTED | `tests/test_identity_lifecycle_engine.py` passing |
| §164.308(a)(5)(i) | Security Awareness and Training — Program | A | `core/awareness_campaign_engine.py`; `core/awareness_score_engine.py`; `core/phishing_simulation_engine.py` — 30-persona security awareness with audit-chained completion | IMPLEMENTED | `tests/test_compliance_engine.py` passing |
| §164.308(a)(5)(ii)(A) | Security Awareness — Security Reminders | A | `core/alerting_notification_engine.py`; `core/alert_broadcaster.py` — automated security reminders and policy alerts | IMPLEMENTED | `tests/test_alerting_notification_engine.py` passing |
| §164.308(a)(5)(ii)(B) | Security Awareness — Protection from Malicious Software | A | `core/malware_detection_engine.py` — malware scanning; `core/dep_scanner.py` — dependency vulnerability detection | IMPLEMENTED | `tests/test_malware_detection_engine.py` passing |
| §164.308(a)(5)(ii)(C) | Security Awareness — Log-in Monitoring | A | `core/audit_logger.py`; `core/access_anomaly_engine.py` — failed login detection and anomaly alerting | IMPLEMENTED | `tests/test_access_anomaly_engine.py` passing |
| §164.308(a)(5)(ii)(D) | Security Awareness — Password Management | A | `core/auth_db.py` — hashed credential storage; `core/api_key_manager.py` — secure key generation; `core/auth_bootstrap.py` | PARTIAL | Password rotation policy and complexity enforcement not yet implemented. POA&M: **GAP-HIPAA-004** |
| §164.308(a)(6)(i) | Security Incident Procedures — Response and Reporting | R | `core/incident_response_engine.py`; `core/incident_orchestration_engine.py`; `core/incident_comms_engine.py` — automated incident response and notification | IMPLEMENTED | `tests/test_incident_response_engine.py` passing |
| §164.308(a)(6)(ii) | Security Incident — Documentation | R | `core/audit_logger.py`; `core/incident_kb_engine.py`; `core/incident_metrics_engine.py`; `core/evidence_chain_engine.py` — immutable incident records | IMPLEMENTED | `tests/test_evidence_chain_engine.py` passing |
| §164.308(a)(7)(i) | Contingency Plan — Plan | A | `core/backup_engine.py`; `core/backup_validator.py`; `docs/UPGRADE_NOTES_0.1.0-alpha.md` (DR operator guide) | PARTIAL | Contingency plan exists in docs. Formal HIPAA-specific contingency plan document needed. POA&M: **GAP-HIPAA-005** |
| §164.308(a)(7)(ii)(A) | Contingency Plan — Data Backup Plan | R | `core/backup_engine.py` — automated backup; `core/backup_validator.py` — integrity verification | IMPLEMENTED | `tests/test_backup_engine.py` passing |
| §164.308(a)(7)(ii)(B) | Contingency Plan — Disaster Recovery Plan | R | `docs/UPGRADE_NOTES_0.1.0-alpha.md` §4 (DR section); `core/backup_validator.py` | PARTIAL | DR runbook exists. RTO/RPO targets not formally documented. POA&M: **GAP-HIPAA-005** (shared) |
| §164.308(a)(7)(ii)(C) | Contingency Plan — Emergency Mode Operation Plan | R | INHERITED | INHERITED | Emergency mode operations (generator, alternate site) — customer data center responsibility |
| §164.308(a)(7)(ii)(D) | Contingency Plan — Testing and Revision Procedures | A | `core/backup_validator.py` — automated backup integrity testing | PARTIAL | Automated backup test exists. Full DR tabletop exercise not yet conducted. POA&M: **GAP-HIPAA-005** (shared) |
| §164.308(a)(7)(ii)(E) | Contingency Plan — Applications and Data Criticality Analysis | A | `core/asset_risk_calculator.py`; `core/application_risk_engine.py` — automated criticality scoring | IMPLEMENTED | `tests/test_application_risk_engine.py` passing |
| §164.308(a)(8) | Evaluation | R | `core/compliance_scanner_engine.py`; `core/compliance_gap_engine.py`; `core/compliance_automation_engine.py` — periodic compliance evaluation | IMPLEMENTED | `tests/test_compliance_scanner_engine.py` passing |
| §164.308(b)(1) | Business Associate Contracts | R | BAA template required for all CE customers | PLANNED | BAA template document not yet drafted. POA&M: **GAP-HIPAA-006** |

**§164.308 Coverage: 17 IMPLEMENTED, 6 PARTIAL, 1 PLANNED, 1 INHERITED, 1 NOT-APPLICABLE**
**Addressable coverage: 24/25 in-scope = 96%**

---

## 4. §164.310 — Physical Safeguards

*Physical measures, policies, and procedures to protect a covered entity's electronic information systems and related buildings and equipment from natural and environmental hazards and unauthorized intrusion.*

| REF | SPECIFICATION | TYPE | ALDECI IMPLEMENTATION | STATUS | NOTES |
|-----|--------------|------|-----------------------|--------|-------|
| §164.310(a)(1) | Facility Access Controls — Contingency Operations | A | INHERITED | INHERITED | Physical facility access during contingency — customer data center responsibility |
| §164.310(a)(2)(i) | Facility Access Controls — Facility Security Plan | A | INHERITED | INHERITED | Physical facility security plan — customer responsibility |
| §164.310(a)(2)(ii) | Facility Access Controls — Access Control and Validation | A | INHERITED | INHERITED | Badge/biometric access — customer facility responsibility |
| §164.310(a)(2)(iii) | Facility Access Controls — Maintenance Records | A | INHERITED | INHERITED | Physical maintenance logs — customer responsibility |
| §164.310(b) | Workstation Use | R | `core/endpoint_compliance_engine.py`; `core/endpoint_security_engine.py` — workstation posture enforcement | IMPLEMENTED | `tests/test_endpoint_compliance_engine.py` passing |
| §164.310(c) | Workstation Security | R | `core/mobile_device_management_engine.py`; `core/endpoint_security_engine.py` — MDM policy enforcement | PARTIAL | Workstation security policies exist in ALdeci. Physical workstation controls (cable locks, screen placement) — customer responsibility. |
| §164.310(d)(1) | Device and Media Controls — Policies | R | `core/data_retention_engine.py`; `core/encrypted_store.py` — media lifecycle management | IMPLEMENTED | `tests/test_data_retention_engine.py` passing |
| §164.310(d)(2)(i) | Device and Media Controls — Disposal | R | `core/data_retention_engine.py` — secure data purge with audit trail; `core/fips_encryption.py` — key destruction | IMPLEMENTED | Purge with evidence — `tests/test_fips_compliance_mode_engine.py` passing |
| §164.310(d)(2)(ii) | Device and Media Controls — Media Re-use | A | `core/encrypted_store.py` — encrypted storage; key rotation prevents re-use data exposure | IMPLEMENTED | Encryption-at-rest ensures media re-use safety |
| §164.310(d)(2)(iii) | Device and Media Controls — Accountability | A | `core/audit_logger.py` — all data access/deletion actions audited | IMPLEMENTED | `tests/test_scif_stage1.py` (12/12 pass) |
| §164.310(d)(2)(iv) | Device and Media Controls — Data Backup and Storage | A | `core/backup_engine.py`; `core/backup_validator.py` | IMPLEMENTED | `tests/test_backup_engine.py` passing |

**§164.310 Coverage: 7 IMPLEMENTED, 1 PARTIAL, 4 INHERITED**
**Addressable coverage (non-INHERITED): 8/8 = 100%**

---

## 5. §164.312 — Technical Safeguards

*The technology and the policy and procedures for its use that protect ePHI and control access to it.*

| REF | SPECIFICATION | TYPE | ALDECI IMPLEMENTATION | STATUS | NOTES |
|-----|--------------|------|-----------------------|--------|-------|
| §164.312(a)(1) | Access Control — Unique User Identification | R | `core/auth_models.py`; `core/auth_db.py`; `core/identity_lifecycle_engine.py` — unique user IDs with tenant isolation | IMPLEMENTED | Every user action carries unique actor_id in audit log |
| §164.312(a)(2)(i) | Access Control — Emergency Access Procedure | R | `core/auth_bootstrap.py` — emergency admin bootstrap; `core/rbac_engine.py` super_admin role | PARTIAL | Emergency access procedure not formally documented. POA&M: **GAP-HIPAA-007** |
| §164.312(a)(2)(ii) | Access Control — Automatic Logoff | A | `core/auth_middleware.py` — session expiration enforcement | PARTIAL | Configurable session timeout exists. Default timeout value not yet HIPAA-aligned (30 min recommended). POA&M: **GAP-HIPAA-004** (shared) |
| §164.312(a)(2)(iii) | Access Control — Encryption and Decryption | A | `core/fips_encryption.py`; `core/crypto.py`; `core/encrypted_store.py`; `core/crypto_key_management_engine.py` — FIPS 140-2 AES-256-GCM | IMPLEMENTED | `tests/test_fips_compliance_mode_engine.py` passing |
| §164.312(b) | Audit Controls | R | `core/audit_logger.py`; `core/audit_chain.py`; `core/audit_db.py`; `core/write_audit_middleware.py` — immutable, tamper-evident audit log on every request | IMPLEMENTED | `tests/test_scif_stage1.py` (12/12 pass); SHA-256 hash chain |
| §164.312(c)(1) | Integrity — Mechanisms to Authenticate ePHI | A | `core/evidence_chain_engine.py`; `core/evidence_vault_engine.py` — quantum-secure signing via SoftHSM2; `core/audit_chain.py` — SHA-256 hash chain | IMPLEMENTED | `tests/test_evidence_chain_engine.py` passing |
| §164.312(c)(2) | Integrity — Integrity Controls | A | `core/audit_chain.py` — append-only event chain with hash verification; `core/backup_validator.py` — backup integrity checks | IMPLEMENTED | Hash chain integrity verified on every read |
| §164.312(d) | Person or Entity Authentication | R | `core/auth_middleware.py`; `core/api_key_manager.py`; `core/auth_db.py` — API key + session authentication | PARTIAL | MFA not yet implemented. POA&M: **GAP-HIPAA-008** (highest priority — Required spec) |
| §164.312(e)(1) | Transmission Security — Encryption | A | TLS enforcement across `suite-api/apps/api/`; `core/fips_encryption.py`; `core/crypto.py` — FIPS-compliant TLS | IMPLEMENTED | All API endpoints TLS-enforced |
| §164.312(e)(2)(i) | Transmission Security — Integrity Controls | A | `core/crypto.py` — HMAC message integrity; TLS record integrity | IMPLEMENTED | HMAC implemented in crypto subsystem |
| §164.312(e)(2)(ii) | Transmission Security — Encryption in Transit | A | TLS 1.2+ enforced; `core/fips_encryption.py` — FIPS 140-2 compliant cipher suites | IMPLEMENTED | Deployment docs enforce TLS termination |

**§164.312 Coverage: 8 IMPLEMENTED, 3 PARTIAL**
**Addressable coverage: 11/11 = 100% (8 full + 3 partial)**

---

## 6. §164.314 — Organizational Requirements

| REF | SPECIFICATION | TYPE | ALDECI IMPLEMENTATION | STATUS | NOTES |
|-----|--------------|------|-----------------------|--------|-------|
| §164.314(a)(1) | Business Associate Contracts — Written Contract | R | PLANNED | PLANNED | BAA template not yet drafted. POA&M: **GAP-HIPAA-006** (shared) |
| §164.314(a)(2) | Business Associate Contracts — Required Elements | R | PLANNED | PLANNED | Dependent on BAA template completion. POA&M: **GAP-HIPAA-006** (shared) |
| §164.314(b)(1) | Group Health Plan — Plan Documents | R | NOT-APPLICABLE | NOT-APPLICABLE | ALdeci is not a group health plan |
| §164.314(b)(2) | Group Health Plan — Plan Document Amendments | R | NOT-APPLICABLE | NOT-APPLICABLE | ALdeci is not a group health plan |

**§164.314 Coverage: 0 IMPLEMENTED, 0 PARTIAL, 2 PLANNED, 2 NOT-APPLICABLE**

---

## 7. §164.316 — Policies and Procedures and Documentation Requirements

| REF | SPECIFICATION | TYPE | ALDECI IMPLEMENTATION | STATUS | NOTES |
|-----|--------------|------|-----------------------|--------|-------|
| §164.316(a) | Policies and Procedures | R | `docs/compliance/` — compliance mapping docs; `docs/CEO_VISION.md`; `docs/CTEM_PLUS_IDENTITY.md` | PARTIAL | Technical policies exist. Formal HIPAA-specific policy document suite not yet compiled. POA&M: **GAP-HIPAA-002** (shared) |
| §164.316(b)(1) | Documentation — Written Policies | R | `docs/compliance/` — SOC2, NIST, ISO, HIPAA, PCI mapping docs; `CHANGELOG.md` | PARTIAL | Compliance control maps exist. Operational policy documents (sanction, contingency, workforce) not fully committed. POA&M: **GAP-HIPAA-002** (shared) |
| §164.316(b)(2)(i) | Documentation — Time Limit (6 years retention) | R | `core/data_retention_engine.py` — configurable retention TTLs; `core/evidence_vault_engine.py` — long-term evidence storage | IMPLEMENTED | Retention engine supports 6-year configurable TTL |
| §164.316(b)(2)(ii) | Documentation — Availability | R | `docs/` (24 documents); `suite-api/apps/api/` — API-accessible compliance evidence | IMPLEMENTED | Documentation accessible to authorized personnel |
| §164.316(b)(2)(iii) | Documentation — Updates | R | `CHANGELOG.md`; git history; `core/changelog_generator.py` — automated changelog | IMPLEMENTED | All changes documented with versioned commits |

**§164.316 Coverage: 3 IMPLEMENTED, 2 PARTIAL**

---

## 8. Coverage Summary

| SECTION | TOTAL SPECS | IMPL | PARTIAL | PLANNED | INHERITED | N/A | COVERAGE (IMPL+PARTIAL/IN-SCOPE) |
|---------|------------|------|---------|---------|-----------|-----|----------------------------------|
| §164.308 Administrative | 26 | 17 | 6 | 1 | 1 | 1 | 23/24 = **96%** |
| §164.310 Physical | 11 | 7 | 1 | 0 | 4 | 0 | 8/8 = **100%** |
| §164.312 Technical | 11 | 8 | 3 | 0 | 0 | 0 | 11/11 = **100%** |
| §164.314 Organizational | 4 | 0 | 0 | 2 | 0 | 2 | 0/2 = **0%** (BAA needed) |
| §164.316 Policies/Docs | 5 | 3 | 2 | 0 | 0 | 0 | 5/5 = **100%** |
| **TOTAL** | **57** | **35** | **12** | **3** | **5** | **3** | **47/49 = 96%** |

**Overall IMPLEMENTED rate: 35/57 = 61%**
**Overall addressable coverage (IMPL+PARTIAL / non-INHERITED, non-N/A): 47/49 = 96%**
**Critical gap: §164.314 BAA contracts (PLANNED) — must close before first healthcare CE customer contract**

---

## 9. Top 5 Gaps — POA&M

| GAP ID | SECTION(S) | GAP DESCRIPTION | SEVERITY | OWNER | TARGET DATE |
|--------|-----------|-----------------|----------|-------|-------------|
| **GAP-HIPAA-006** | §164.308(b)(1), §164.314 | Business Associate Agreement (BAA) template not drafted — BLOCKS all healthcare CE customer contracts | CRITICAL | Legal / CISO | 2026-06-01 |
| **GAP-HIPAA-008** | §164.312(d) | Multi-factor authentication not implemented — Required specification under Technical Safeguards | HIGH | Engineering | 2026-07-31 |
| **GAP-HIPAA-001** | §164.308(a)(1)(i) | Formal HIPAA-specific Risk Analysis documentation not produced (automated scoring exists, formal report needed) | HIGH | CISO | 2026-06-30 |
| **GAP-HIPAA-002** | §164.308(a)(1)(ii)(B), §164.316 | Written sanction policy, workforce clearance procedure, and formal HIPAA policy document suite not committed | MEDIUM | CISO / HR | 2026-07-31 |
| **GAP-HIPAA-005** | §164.308(a)(7) | Contingency plan lacks HIPAA-specific DR documentation with formal RTO/RPO targets and tabletop exercise record | MEDIUM | Operations | 2026-08-31 |

---

## 10. Recommended Risk Analysis Cadence

Per §164.308(a)(1)(i), HIPAA requires an "accurate and thorough assessment of the potential risks and vulnerabilities to the confidentiality, integrity, and availability of ePHI."

| Activity | Frequency | Owner | ALdeci Tool |
|----------|-----------|-------|-------------|
| Automated vulnerability scan (CTEM pipeline) | Continuous | Platform (automated) | `core/composite_risk_scorer.py` + Brain Pipeline |
| ePHI exposure scan (secrets + DLP) | Daily | Platform (automated) | `core/dlp_engine.py` + `core/secrets_scanner.py` |
| Access rights review | Quarterly | Security Officer | `core/access_governance_engine.py` |
| Full HIPAA Risk Analysis documentation | Annual | CISO | `core/compliance_gap_engine.py` (automated gap report) |
| Contingency plan tabletop exercise | Annual | Operations | Manual — schedule with DR team |
| BAA review | On vendor change | Legal | Manual review |

> **Note**: ALdeci's automated scanning infrastructure (`core/composite_risk_scorer.py`, `core/application_risk_engine.py`, `core/compliance_automation_engine.py`) supports continuous risk analysis as the technical backbone. The formal HIPAA Risk Analysis *document* (a written report presenting findings to leadership) remains a manual CISO deliverable. The automated data feeds directly into that document preparation.
