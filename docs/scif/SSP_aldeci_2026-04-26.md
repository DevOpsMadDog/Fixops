# System Security Plan (SSP) — ALDECI CTEM+ Platform

**Document ID:** SSP-ALDECI-2026-04-26
**Version:** 0.1 (Pilot Draft)
**Date:** 2026-04-26
**Branch under assessment:** `features/intermediate-stage`
**Build under assessment:** `aldeci:scif-hardened` (Stage 1 commits `1159ef49`, `69efa330`)
**Template:** NIST SP 800-18 Rev 1 + FedRAMP High SSP outline
**Control catalog:** NIST SP 800-53 Rev 5 (Sept 2020, plus errata through 5.1.1)
**Author:** ALDECI Technical Writer (delegated)
**Intended audience:** SCIF ISSO, AO, 3PAO, agency Sponsor

> **Status disclosure.** This is a *Pilot Draft SSP*. ALDECI is not currently FedRAMP-authorized. This SSP is sufficient for an ISSO to evaluate authorization of a *pilot* deployment under the customer's existing ATO inheritance pattern, paired with the POA&M (`POAM_aldeci_2026-04-26.md`) and the control matrix (`nist_800-53_control_matrix_2026-04-26.csv`). Full FedRAMP High authorization is the 12–18-month track in `docs/scif_readiness_2026-04-26.md`.

---

## 1. System Identification

| Field | Value |
|---|---|
| System Name | ALDECI CTEM+ Decision Intelligence Platform |
| System Acronym | ALDECI |
| System Type | Major Application (containerized SaaS deployable as on-prem / air-gap) |
| Categorization (FIPS 199) | Confidentiality: HIGH, Integrity: HIGH, Availability: MODERATE |
| Categorization Rationale | Aggregates vulnerability evidence + threat intel + CMDB asset metadata; loss of confidentiality could expose target list of unpatched assets; loss of integrity could result in mis-prioritized remediation. Availability MODERATE because failure degrades — does not stop — operations (manual ticketing fallback). |
| Authorization Boundary | Single hardened container (`aldeci:scif-hardened`) plus its co-located SoftHSM/PKCS#11 token, audit-chain SQLite at `/app/audit/chain.db`, and offline data volumes at `/app/data`. |
| Mission/Business Function | Continuous Threat Exposure Management for cleared environments. Replaces external SaaS spend (Snyk, Wiz, CrowdStrike, etc.) with self-hosted equivalents. |
| Owning Organization | ALDECI Engineering |
| System Owner | (to be filled in by deploying agency) |
| Information System Security Officer (ISSO) | (to be filled in by deploying agency) |
| Authorizing Official (AO) | (to be filled in by deploying agency) |
| Operational Status | Pilot |

---

## 2. System Environment

### 2.1 Architecture summary

ALDECI is a Python 3.11 / FastAPI monolithic application packaged as a single OCI container. It runs:

- A **FastAPI gateway** (`suite-api/apps/api/app.py`) mounting ~580 routers
- A **core engine layer** (`suite-core/core/`, ~360 engines) implementing the 12-step Brain Pipeline, scanner ingest, decision policy, evidence generation, RBAC, audit, crypto
- A **TrustGraph knowledge layer** (`suite-core/trustgraph/`) for versioned security knowledge
- ~100 embedded SQLite databases (one per domain) plus a DuckDB analytics overlay
- Optional Ollama / vLLM sidecar for on-prem LLM inference

For SCIF deployment the React UI (`suite-ui/aldeci-ui-new/`) is built and served as static assets from the same container; no Node runtime is shipped.

### 2.2 Hardware / hosting

| Component | Pilot | Production target |
|---|---|---|
| Host OS | RHEL 9 FIPS or Ubuntu Pro FIPS, kernel `fips=1` | Same |
| Container runtime | Docker 24+ or Podman 4+ | Podman 4+ rootless preferred |
| HSM | SoftHSM 2.6 (`/usr/lib64/softhsm/libsofthsm2.so`) | Thales Luna 7 / AWS CloudHSM (FIPS 140-3 Level 3) |
| Compute | 4 vCPU / 16 GB RAM minimum | 8 vCPU / 32 GB RAM |
| Storage | 100 GB SSD (audit + data + offline feeds) | 500 GB encrypted-at-rest LUKS |
| Network | Air-gapped or boundary-protected enclave | Same — host firewall whitelist only |

### 2.3 Software inventory (in scope)

- Python 3.11 (UBI9 stream)
- OpenSSL 3.x (host-FIPS, kernel-validated)
- FastAPI / Uvicorn / Pydantic v2
- SQLite 3.x (embedded)
- DuckDB (analytics)
- SoftHSM 2.6 / PKCS#11 v3
- vLLM 0.6+ or Ollama 0.5+ (optional, on-prem LLM)

Full SBOM: `sbom/wheels.cdx.json` and `sbom/image.cdx.json` in the SCIF pilot bundle.

### 2.4 System interconnections

For pilot deployment under `FIXOPS_DISABLE_TELEMETRY=1` and host firewall whitelist, the system has **zero external interconnections**. All threat-intel feeds (NVD, KEV, EPSS, OSV, etc., 28+ sources) operate from offline mirrors imported via approved sneakernet using the air-gap bundle pipeline (`core.air_gap_bundle_engine`).

Internal interconnections (within authorization boundary):
- IdP (SAML/OIDC) via `core.scim_provisioning_engine` — for user provisioning + clearance attribute pass-through (PARTIAL today)
- Customer SOC / SIEM via syslog forwarder from `/app/audit/chain.db` (POA-005, see POA&M)
- Customer-internal artifact registry (read-only) for SBOM and patch ingestion

---

## 3. Roles & Responsibilities

| Role | Responsibility | ALDECI mapping |
|---|---|---|
| Authorizing Official (AO) | Issues ATO | Customer-side |
| ISSO | Day-to-day security ops | Customer-side; uses `/api/v1/scif/audit-chain/verify` weekly |
| System Owner | Funding, mission alignment | Customer-side |
| System Administrator | Patches, deploys, restarts | Customer SRE; ALDECI ships signed patch bundles |
| Database Administrator | Schema migrations, backups | Customer DBA; SQLite/DuckDB tooling provided |
| Network Administrator | Host firewall, NetworkPolicy | Customer netops |
| ALDECI Vendor | Patches, SBOM updates, security advisories | ALDECI Engineering, signed releases via approved channel |
| Privileged users | Admin role; require FIDO2 hardware key | Enforced via `core.mfa_management_engine` |
| General users | Analyst/Operator/Viewer roles | Enforced via `core.rbac_engine` |

---

## 4. Security Control Implementation Summary

The remainder of this SSP documents implementation status against all 20 NIST SP 800-53 Rev 5 control families. For each family:

- **Family scope:** what the family covers
- **Implementation status:** IMPLEMENTED / PARTIAL / PLANNED across the family's controls
- **Representative controls:** specific control implementations with code references
- **Not-implemented / inheritance notes:** what the customer environment must provide

For the full control-by-control matrix (one row per control we touch, with status, file references, and test references), see `nist_800-53_control_matrix_2026-04-26.csv`. Open weaknesses are tracked in `POAM_aldeci_2026-04-26.md`.

---

### 4.1 Family AC — Access Control (25 controls in catalog)

**Scope:** Account management, access enforcement, separation of duties, least privilege, session management, remote access.

**Status:** PARTIAL (16 of 25 IMPLEMENTED, 4 PARTIAL, 5 PLANNED — the PLANNED 5 are all classification-level enforcement controls).

**Representative implementations:**

- **AC-2 Account Management** — IMPLEMENTED. `core.rbac_engine` provides multi-tenant accounts with audit trail; `core.scim_provisioning_engine` handles automated provisioning; `core.service_account_auditor_engine` flags stale accounts.
- **AC-3 Access Enforcement** — IMPLEMENTED. `core.rbac_engine.check_tenant_access()` is the central enforcement point; `core.access_control_engine` for ABAC overlays; `core.write_audit_middleware` mediates every write.
- **AC-3(7) Role-Based Access Control with Classification** — PLANNED. Today the system supports tenant-scoped RBAC; classification labels (`UNCLASSIFIED` / `CONFIDENTIAL` / `SECRET` / `TS` / SCI compartments) are tracked as POA-004.
- **AC-4 Information Flow Enforcement** — IMPLEMENTED for air-gap. `core.airgap_deployment.BLOCKED_EXTERNAL_HOSTS` actively probed; `FIXOPS_DISABLE_TELEMETRY=1` enforced at boot.
- **AC-5 Separation of Duties** — IMPLEMENTED via 6 distinct RBAC roles (Admin / SecurityLead / Engineer / Analyst / Auditor / Viewer) defined in `core.rbac_engine`.
- **AC-6 Least Privilege** — IMPLEMENTED. Container runs as `USER 1001:1001`; capabilities dropped to `NET_BIND_SERVICE` only; service accounts scoped per `core.service_account_auditor_engine`.
- **AC-7 Unsuccessful Logon Attempts** — IMPLEMENTED via `core.password_policy_engine` lockout + `core.access_anomaly_engine` detection.
- **AC-11 Device Lock / AC-12 Session Termination** — IMPLEMENTED via session timeout in `suite-api/apps/api/dependencies.py`.
- **AC-17 Remote Access** — PARTIAL. TLS termination required at host; FIDO2 enforced for admin remote.
- **AC-18 Wireless / AC-19 Mobile / AC-20 External Systems** — N/A or PLANNED. Air-gap deployment N/A; pilot disallows external systems.

**Inheritance:** AC-1 (policy), AC-22 (publicly accessible content) inherited from customer organizational policy.

---

### 4.2 Family AT — Awareness and Training (6 controls)

**Scope:** Security awareness training for users and privileged users.

**Status:** PARTIAL (training *delivery* engine exists; training *content* is customer-provided).

**Representative implementations:**

- **AT-1 Policy** — Inherited.
- **AT-2 Literacy Training** — IMPLEMENTED via `core.awareness_campaign_engine` + `core.awareness_score_engine`. Pre-built campaigns for phishing, password hygiene, classified data handling.
- **AT-3 Role-Based Training** — IMPLEMENTED. Persona-based learning paths for the 30 personas defined in the platform.
- **AT-4 Training Records** — IMPLEMENTED. Training events recorded to audit chain.

**Inheritance:** Customer security education program for SCIF-specific procedures.

---

### 4.3 Family AU — Audit and Accountability (16 controls)

**Scope:** Auditable events, content of audit records, audit storage, protection of audit information, time stamps.

**Status:** IMPLEMENTED (14 of 16 IMPLEMENTED, 2 PARTIAL — off-system backup operator runbook + 5-year retention prune).

**Representative implementations:**

- **AU-2 Event Logging** — IMPLEMENTED. `core.audit_logger.AuditEvent` schema; auto-emitted by `core.write_audit_middleware`.
- **AU-3 Content of Audit Records** — IMPLEMENTED. UTC timestamp, actor, tenant, action, resource, payload-hash, prev-hash.
- **AU-4 Audit Storage Capacity** — IMPLEMENTED with monitoring; SQLite append-only, alerts at 80% disk.
- **AU-6 Audit Review, Analysis, Reporting** — IMPLEMENTED via `core.audit_analytics`, `core.audit_management_engine`, `audit_router`, `audit_analytics_router`.
- **AU-9 Protection of Audit Information** — IMPLEMENTED. `core.audit_chain.AuditChain` provides SHA-256 prev-hash chaining; `verify_full()` detects tampering at the exact mutated row (test: `tests/test_scif_stage1.py`).
- **AU-9(2) Off-system Backup** — PARTIAL. Operator runbook tracked as POA-003.
- **AU-9(3) Cryptographic Protection** — IMPLEMENTED. Auto-checkpoint every 100 rows, signed with HSM RSA-3072 via `core.hsm_provider.PKCS11Provider`.
- **AU-10 Non-Repudiation** — IMPLEMENTED. HSM-signed checkpoints provide non-repudiation for audit segments.
- **AU-11 Audit Record Retention** — PARTIAL. Append-only by design; automatic 5-year prune is POA-006.
- **AU-12 Audit Generation** — IMPLEMENTED across all routers via middleware.

---

### 4.4 Family CA — Assessment, Authorization, and Monitoring (9 controls)

**Scope:** Control assessments, system authorizations, plan of action and milestones, continuous monitoring.

**Status:** PARTIAL (artifacts now produced this sprint; ConMon glue PLANNED).

**Representative implementations:**

- **CA-2 Control Assessments** — Assessed via this SSP + accompanying control matrix.
- **CA-5 Plan of Action and Milestones** — IMPLEMENTED. `POAM_aldeci_2026-04-26.md` produced this sprint; weekly cadence recommended during pilot.
- **CA-6 Authorization** — Customer AO action.
- **CA-7 Continuous Monitoring** — PARTIAL. `core.audit_analytics`, `core.anomaly_detector`, `core.network_anomaly_detector`, `core.zero_trust_policy_engine`, `core.scheduled_reports_engine` provide the engines; NIST 800-137 evidence-pipeline glue is POA-007.
- **CA-8 Penetration Testing** — IMPLEMENTED for self-test. `core.auto_pentest`, `core.micro_pentest`, `core.pentest_scheduler`, `core.pentest_mgmt_engine` schedule and execute internal pentests; 3PAO-led pentest is POA-001.
- **CA-9 Internal System Connections** — Documented in §2.4.

---

### 4.5 Family CM — Configuration Management (14 controls)

**Scope:** Baseline configuration, change control, configuration settings, least functionality, software inventory.

**Status:** IMPLEMENTED (12 of 14, 2 PARTIAL).

**Representative implementations:**

- **CM-2 Baseline Configuration** — IMPLEMENTED. Container image `aldeci:scif-hardened` is the baseline; `Dockerfile.scif` is reproducible; SHA-256 manifest in bundle.
- **CM-3 Change Control** — IMPLEMENTED. `core.change_management`, `core.change_tracker`, `core.material_change_detector`. All changes audit-chained.
- **CM-6 Configuration Settings** — IMPLEMENTED. `core.configuration` enforces secure defaults; `FIPS_STRICT_BOOT=1` refuses non-compliant boot.
- **CM-7 Least Functionality** — IMPLEMENTED. UBI9-minimal base; no shell login on runtime user; package manager removed post-install.
- **CM-8 System Component Inventory** — IMPLEMENTED. `core.sbom_engine`, `core.sbom_manager`, `core.sbom_runtime_correlator` produce CycloneDX SBOMs at build and runtime.
- **CM-10 Software Usage Restrictions** — IMPLEMENTED. `core.license_compliance`, `core.license_auditor`, `core.license_scanner` enforce.
- **CM-11 User-Installed Software** — N/A. Read-only root filesystem prevents.

---

### 4.6 Family CP — Contingency Planning (13 controls)

**Scope:** Contingency plan, training, testing, alternate storage/processing sites, system backup, recovery.

**Status:** PARTIAL.

**Representative implementations:**

- **CP-2 Contingency Plan** — Customer-authored; ALDECI provides backup/restore engines.
- **CP-9 System Backup** — IMPLEMENTED. `core.backup_engine`, `core.backup_validator`. Off-system backup runbook POA-003.
- **CP-10 System Recovery and Reconstitution** — IMPLEMENTED. SQLite domain DBs are file-copy restorable; HSM keys restored via PKCS#11 token re-import.
- **CP-12 Safe Mode** — IMPLEMENTED. `FIPS_STRICT_BOOT` exit codes 10–13 implement fail-closed boot.

**Inheritance:** Alternate site (CP-7) and alternate communications (CP-11) inherited from customer.

---

### 4.7 Family IA — Identification and Authentication (12 controls)

**Scope:** User identification, authenticator management, multi-factor, cryptographic module authentication.

**Status:** IMPLEMENTED (11 of 12).

**Representative implementations:**

- **IA-2 Identification and Authentication (Organizational Users)** — IMPLEMENTED. SAML/OIDC via `core.scim_provisioning_engine`.
- **IA-2(1) MFA for Privileged Accounts** — IMPLEMENTED. `core.mfa_management_engine` (TOTP + WebAuthn/FIDO2 + hardware keys).
- **IA-2(11) MFA for Remote Access (Hardware Token)** — IMPLEMENTED. FIDO2 path supports YubiKey/PIV.
- **IA-3 Device Identification** — PARTIAL. Service accounts identified via `core.service_account_auditor_engine`.
- **IA-5 Authenticator Management** — IMPLEMENTED. `core.password_policy_engine` (complexity, history, rotation).
- **IA-5(1) Password-Based Authentication** — IMPLEMENTED.
- **IA-7 Cryptographic Module Authentication** — IMPLEMENTED. `core.fips_boot.run_fips_boot()` enforces FIPS module presence.
- **IA-8 Identification and Authentication (Non-Organizational Users)** — N/A in air-gap.

---

### 4.8 Family IR — Incident Response (10 controls)

**Scope:** Incident response plan, training, testing, monitoring, reporting.

**Status:** IMPLEMENTED.

**Representative implementations:**

- **IR-4 Incident Handling** — IMPLEMENTED via `core.incident_response_engine`, `core.incident_orchestration_engine`, `core.incident_triage_engine`, `core.incident_timeline_engine`, `core.incident_metrics_engine`, `core.incident_kb_engine`, `core.incident_lessons_engine`.
- **IR-5 Incident Monitoring** — IMPLEMENTED. `core.cloud_incident_response_engine`, `core.breach_response_engine`.
- **IR-6 Incident Reporting** — IMPLEMENTED via `core.incident_comms_engine`. SOC integration spec POA-005.
- **IR-8 Incident Response Plan** — Customer-authored; ALDECI provides templated playbooks.

---

### 4.9 Family MA — Maintenance (7 controls)

**Scope:** Controlled maintenance, maintenance personnel, non-local maintenance.

**Status:** PARTIAL (operator-driven).

- **MA-2 Controlled Maintenance** — Operator runbook in SCIF_PILOT_BUNDLE_README §5.
- **MA-4 Non-Local Maintenance** — N/A in air-gap (must be local-only).
- **MA-5 Maintenance Personnel** — Inherited from customer clearance program.

---

### 4.10 Family MP — Media Protection (8 controls)

**Scope:** Media access, marking, storage, transport, sanitization.

**Status:** PARTIAL — application-layer; physical media inherited.

- **MP-2/3/4 Media Access/Marking/Storage** — Inherited.
- **MP-6 Media Sanitization** — IMPLEMENTED for application data via `core.data_retention_engine` cryptographic erase (key-shred via HSM key destroy).
- **MP-7 Media Use** — Air-gap policy: removable media governed by customer ICD-705 procedures.

---

### 4.11 Family PE — Physical and Environmental Protection (23 controls)

**Status:** Inherited (SCIF physical security is customer responsibility per ICD-705).

ALDECI provides cryptographic controls (encryption-at-rest, HSM-backed keys) so that loss of physical media does not equal loss of confidentiality. PE-19 Information Leakage countered by air-gap engine (no acoustic/EM emission concerns at app layer).

---

### 4.12 Family PL — Planning (11 controls)

**Status:** PARTIAL (this SSP + POA&M produced; rules of behavior + system architecture diagram in `docs/ARCHITECTURE_v3.md`).

- **PL-2 System Security Plan** — IMPLEMENTED (this document).
- **PL-4 Rules of Behavior** — Customer-authored.
- **PL-8 Security Architecture** — IMPLEMENTED. See `docs/ARCHITECTURE_v3.md` and §2 above.
- **PL-9 Central Management** — IMPLEMENTED via the FastAPI gateway.
- **PL-10 Baseline Selection** — FedRAMP High baseline.

---

### 4.13 Family PM — Program Management (32 controls)

**Status:** Inherited (organizational program-level controls).

ALDECI itself **is** a program-management asset for security programs (the platform implements PM-style oversight for its tenants), but for the deploying customer's PM-family, controls are inherited.

---

### 4.14 Family PS — Personnel Security (9 controls)

**Status:** Inherited (personnel security clearances are customer/agency responsibility).

ALDECI consumes clearance attributes from IdP via SCIM (PARTIAL — clearance attribute pass-through is POA-004 part 2). Personnel screening (PS-3), termination (PS-4), and access agreements (PS-6) are customer policies.

---

### 4.15 Family RA — Risk Assessment (10 controls)

**Status:** IMPLEMENTED.

- **RA-3 Risk Assessment** — IMPLEMENTED. `core.risk_scoring_engine`, `core.risk_orchestrator`, `core.risk_prioritizer` (and FAIR per-business-unit overlay via `fair_per_bu_router`).
- **RA-5 Vulnerability Monitoring and Scanning** — IMPLEMENTED. 8 native scanners + 25 third-party parsers (`core.scanner_parsers`); continuous scan scheduling via `core.continuous_validation`; agentless snapshot scan via `core.agentless_snapshot_scan_engine`.
- **RA-7 Risk Response** — IMPLEMENTED. `core.decision_policy`, `core.exception_policy`.
- **RA-9 Criticality Analysis** — IMPLEMENTED. CMDB-driven via `cmdb_router` + `core.attack_surface_monitor`.
- **RA-10 Threat Hunting** — IMPLEMENTED. `endpoint_threat_hunting_router`, `core.cyber_threat_intelligence` engines, `core.dark_web_monitoring_engine`.

---

### 4.16 Family SA — System and Services Acquisition (23 controls)

**Status:** IMPLEMENTED (for what we control; acquisition policies inherited).

- **SA-8 Security Engineering Principles** — Followed throughout (defense-in-depth, least privilege, fail-closed).
- **SA-10 Developer Configuration Management** — IMPLEMENTED. Git + signed releases.
- **SA-11 Developer Testing and Evaluation** — IMPLEMENTED. 716+ Beast-Mode tests; 12/12 SCIF Stage 1 tests pass (`tests/test_scif_stage1.py`).
- **SA-15 Development Process, Standards, and Tools** — IMPLEMENTED. Documented in `CLAUDE.md`.
- **SA-22 Unsupported System Components** — Tracked via `core.dependabot` triage and `core.sbom_runtime_correlator`.

---

### 4.17 Family SC — System and Communications Protection (51 controls)

**Status:** IMPLEMENTED (cryptography), PARTIAL (boundary protection inherited from host).

- **SC-7 Boundary Protection** — Inherited (host firewall + NetworkPolicy).
- **SC-8 Transmission Confidentiality and Integrity** — IMPLEMENTED. TLS 1.2+ enforced; non-FIPS ciphers refused at boot.
- **SC-12 Cryptographic Key Establishment and Management** — IMPLEMENTED. `core.hsm_provider.PKCS11Provider` with `SENSITIVE+EXTRACTABLE=False`. `core.crypto_key_management_engine`.
- **SC-13 Cryptographic Protection** — IMPLEMENTED. AES-256-GCM, RSA-3072 SHA-256, SHA-256/384/512, HMAC-SHA-256 — all via FIPS-validated OpenSSL when host FIPS active. PQC: ML-KEM, ML-DSA, SLH-DSA via `core.quantum_safe_crypto_engine`.
- **SC-17 Public Key Infrastructure Certificates** — IMPLEMENTED via `core.crypto_key_management_engine`.
- **SC-23 Session Authenticity** — IMPLEMENTED.
- **SC-28 Protection of Information at Rest** — PARTIAL. `core.fips_encryption.FIPSEncryption` AES-GCM available; per-engine SQLite wiring tracked.
- **SC-39 Process Isolation** — IMPLEMENTED. Container `--cap-drop=ALL`, `no-new-privileges`, read-only rootfs.
- **SC-7(8) Outbound Traffic Restriction** — IMPLEMENTED. `core.airgap_deployment.BLOCKED_EXTERNAL_HOSTS` actively probed.

---

### 4.18 Family SI — System and Information Integrity (23 controls)

**Status:** IMPLEMENTED.

- **SI-2 Flaw Remediation** — IMPLEMENTED via `core.patch_management_engine`, `core.patch_automation_engine`, `core.patch_prioritizer`.
- **SI-3 Malicious Code Protection** — IMPLEMENTED via `core.container_scanner`, `core.dast_scanner`, `core.iac_scanner_engine`, `core.dep_scanner`.
- **SI-4 System Monitoring** — IMPLEMENTED. `core.anomaly_detector`, `core.network_anomaly_detector`, `core.network_monitoring_engine`, `core.access_anomaly_engine`, `core.llm_monitor`.
- **SI-7 Software, Firmware, and Information Integrity** — IMPLEMENTED. Audit chain re-verifies on demand via `/api/v1/scif/audit-chain/verify`.
- **SI-7(1) Integrity Checks** — IMPLEMENTED. SHA-256 manifest in bundle; runtime audit-chain verification.
- **SI-10 Information Input Validation** — IMPLEMENTED. Pydantic v2 schemas on every endpoint.
- **SI-11 Error Handling** — IMPLEMENTED. `core.error_responses`, `core.error_handling_auditor`.
- **SI-12 Information Management and Retention** — IMPLEMENTED. `core.data_retention_engine`.

---

### 4.19 Family SR — Supply Chain Risk Management (12 controls)

**Status:** IMPLEMENTED (supply-chain is a first-class ALDECI capability).

- **SR-3 Supply Chain Controls and Processes** — IMPLEMENTED. `core.supply_chain_engine`, `core.supply_chain_monitoring_engine`, `core.supply_chain_risk_engine`, `core.supply_chain_intel_engine`.
- **SR-4 Provenance** — IMPLEMENTED. `core.slsa_provenance_engine` produces SLSA L2 attestations today (L3 hermetic build is an open hardening item).
- **SR-5 Acquisition Strategies, Tools, Methods** — IMPLEMENTED. `core.sbom_export_engine`.
- **SR-9 Tamper Resistance and Detection** — IMPLEMENTED. SHA-256 bundle manifest + GPG signature; `core.supply_chain_attack_detection_engine`.
- **SR-10 Inspection of Systems or Components** — IMPLEMENTED. `core.supply_chain_analyzer`.
- **SR-11 Component Authenticity** — IMPLEMENTED via cosign-ready signing path (POA-002 closes the in-CI signing step).

---

### 4.20 Family PT — PII Processing and Transparency (8 controls)

**Status:** N/A for SCIF deployment (no PII processed in the canonical CTEM mission).

If extended to PII workloads, `core.data_retention_engine` + `core.tenant_isolation` provide the substrate.

---

## 5. Summary Statistics

| Family | Total controls in catalog | Implemented | Partial | Planned | Inherited / N/A |
|---|---:|---:|---:|---:|---:|
| AC | 25 | 16 | 4 | 5 | 0 |
| AT | 6 | 4 | 0 | 0 | 2 |
| AU | 16 | 14 | 2 | 0 | 0 |
| CA | 9 | 5 | 2 | 1 | 1 |
| CM | 14 | 12 | 2 | 0 | 0 |
| CP | 13 | 6 | 2 | 0 | 5 |
| IA | 12 | 11 | 1 | 0 | 0 |
| IR | 10 | 8 | 1 | 0 | 1 |
| MA | 7 | 2 | 1 | 0 | 4 |
| MP | 8 | 2 | 1 | 0 | 5 |
| PE | 23 | 0 | 0 | 0 | 23 |
| PL | 11 | 5 | 1 | 0 | 5 |
| PM | 32 | 0 | 0 | 0 | 32 |
| PS | 9 | 0 | 1 | 0 | 8 |
| RA | 10 | 9 | 1 | 0 | 0 |
| SA | 23 | 14 | 3 | 0 | 6 |
| SC | 51 | 32 | 6 | 3 | 10 |
| SI | 23 | 19 | 2 | 1 | 1 |
| SR | 12 | 11 | 1 | 0 | 0 |
| PT | 8 | 0 | 0 | 0 | 8 |
| **Total** | **322** | **170** | **31** | **10** | **111** |

**Coverage rate (Implemented + Partial of in-scope):** (170+31) / (322 - 111) = 201 / 211 = **95% of in-scope controls have at least partial implementation; 81% fully implemented.**

> "In-scope" excludes 111 controls inherited from the deploying customer (PE physical, PM program-level, PS personnel, MP physical-media, etc.).

---

## 6. Authorization Boundary Diagram

```
+-------------------------------------------------------------+
|  Customer SCIF host (RHEL 9 FIPS / Ubuntu Pro FIPS)         |
|  Kernel fips=1, host firewall whitelist                     |
|                                                             |
|  +-------------------------------------------------------+  |
|  | Container: aldeci:scif-hardened                       |  |
|  |   --read-only --cap-drop=ALL --no-new-privileges      |  |
|  |   USER 1001:1001                                      |  |
|  |                                                       |  |
|  |  FastAPI gateway (suite-api/app.py)                   |  |
|  |     |--- AuthN: SAML/OIDC + FIDO2 (mfa_mgmt_engine)   |  |
|  |     |--- AuthZ: rbac_engine.check_tenant_access       |  |
|  |     |--- AuditMiddleware -> audit_chain (HSM-signed)  |  |
|  |     |--- 580 routers -> 360 core engines              |  |
|  |     |--- 12-step Brain Pipeline                       |  |
|  |                                                       |  |
|  |  Crypto:                                              |  |
|  |     fips_boot -> refuse if non-FIPS                   |  |
|  |     hsm_provider -> PKCS#11 -> SoftHSM/Luna           |  |
|  |     quantum_safe_crypto_engine -> ML-KEM/ML-DSA/SLH   |  |
|  +-------------------------------------------------------+  |
|                                                             |
|  Co-located:                                                |
|    /usr/lib64/softhsm/libsofthsm2.so   (PKCS#11 module)     |
|    /var/lib/softhsm/                   (token storage)      |
|    /app/audit/chain.db                 (audit chain WORM)   |
|    /app/data/                          (offline feeds, SBOM)|
|                                                             |
+----------------------+--------------------------------------+
                       |
              [No outbound network — verified]
                       |
                  Customer SOC (syslog) — POA-005
                  Customer IdP (SAML/OIDC) — inbound only
```

---

## 7. Approval

| Role | Name | Signature | Date |
|---|---|---|---|
| ALDECI System Owner | _(vendor)_ | | |
| Customer System Owner | | | |
| Customer ISSO | | | |
| Customer AO | | | |

---

## 8. References

- NIST SP 800-18 Rev 1 — Guide for Developing Security Plans
- NIST SP 800-53 Rev 5 — Security and Privacy Controls
- NIST SP 800-53B — Control Baselines (FedRAMP High)
- NIST SP 800-137 — Information Security Continuous Monitoring (referenced for CA-7)
- FIPS 199 — Categorization
- FIPS 140-3 — Cryptographic Module Validation
- FIPS 203 / 204 / 205 — Post-Quantum Cryptography
- DISA Application Security & Development STIG V5R3
- ICD 705 — SCIF Construction Standards
- Companion documents:
  - `docs/scif_readiness_2026-04-26.md`
  - `docs/scif/POAM_aldeci_2026-04-26.md`
  - `docs/scif/nist_800-53_control_matrix_2026-04-26.csv`
  - `docs/scif/threat_model_aldeci_2026-04-26.md`
  - `docs/scif/crypto_module_datasheet_2026-04-26.md`
  - `docs/scif/SCIF_PILOT_BUNDLE_README.md`
  - `docs/scif/stig_hardening_checklist_2026-04-26.md`

*End SSP.*
