# SCIF Readiness Scorecard

**Date:** 2026-04-26
**Branch:** `features/intermediate-stage`
**Author:** enterprise-architect
**Question:** "When will we be ready to compete in SCIF orgs?"

> **SCIF** = Sensitive Compartmented Information Facility. Highest-bar US government deployment context. Hosts SCI (Sensitive Compartmented Information). Implies cleared-personnel-only, no external network, hardened crypto, formal Authority To Operate. Sister regimes: DoD IL5/IL6, FedRAMP High, IC ITE.

---

## 0. TL;DR

| Bucket | Count |
|---|---:|
| Requirements MET | 3 |
| Requirements PARTIAL | 7 |
| Requirements MISSING | 5 |
| **Overall maturity** | **~35%** |

**Honest months-to-SCIF-ready: 12–18 months** with focused investment. We are *credible* on the technical surface (FIPS toggle, air-gap engine, quantum-safe crypto are real and shipped) but the *paperwork-and-process* surface (FedRAMP High control mapping, ATO package, ConMon, 3PAO audit) is largely absent — and that paperwork is 60–70% of an actual SCIF/IL5 procurement timeline.

**Top-5 blockers (in order):**

1. **No 3PAO audit relationship** (3rd-Party Assessor Organization). Without one, FedRAMP High package is unverifiable. *Remediation: engage ~$200K-500K, 6–9 month engagement.*
2. **No HSM integration**. `key_manager.py` uses bcrypt + secrets — fine for SaaS, *unacceptable* for SCI. CNSA 2.0 requires hardware-backed key storage. *Remediation: PKCS#11 wrapper around `key_manager`, certify with at least one HSM (Thales Luna, AWS CloudHSM FIPS partition, YubiHSM2). 2 months.*
3. **No STIG-compliant container images.** Docker base is `python:3.11-slim` and `node:20-alpine`. DISA STIG requires UBI8/UBI9 minimal or Ironbank-published. *Remediation: rebase containers on Iron Bank UBI9-minimal images, sign with cosign, publish SBOM. 1.5 months.*
4. **No System Security Plan (SSP).** `fedramp_controls.py` exists with FedRAMP baselines (LOW/MOD/HIGH) and control families enumerated, but no actual SSP document, no POA&M (Plan of Actions & Milestones), no continuous-monitoring evidence pipeline. *Remediation: 3 months + ongoing.*
5. **Cleared-personnel access model not enforceable.** RBAC engine exists but classification-level labelling (UNCLASS / CONFIDENTIAL / SECRET / TS / SCI compartments) is not modeled. *Remediation: add `classification_level` + `compartments[]` to user/asset model, enforce at every read site. 2 months.*

---

## 1. SCIF / FedRAMP High / IL5+ Requirements (Researched 2026-04-26)

Reference baseline assembled from public NIST/CISA/DoD/CNSA documents:

- **FIPS 140-3** — Cryptographic module validation (replaces 140-2; phase-out by 2026-09).
- **FedRAMP High** — 421 controls baseline (NIST SP 800-53 Rev 5 high-water-mark).
- **DoD IL5** — Controlled Unclassified Information; aligns with FedRAMP High + DoD-specific overlays (IL5 SRG).
- **DoD IL6** — Classified up to SECRET; on-NIPR/SIPR boundary.
- **CNSA 2.0** — Commercial National Security Algorithm Suite 2.0 (NSA, 2022) — mandates PQC migration by 2030–2035 for NSS.
- **STIG / Iron Bank** — DISA STIG container hardening; Iron Bank is DoD's accredited container registry.
- **NIST SP 800-208** — Stateful Hash-Based Signatures (LMS, XMSS).
- **NIST FIPS 203/204/205** — ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+).
- **NSM-10** — National Security Memorandum 10 (Quantum migration directive).
- **ICD 705** — Physical/IT standards for SCIF construction (we are software, but our deployment guide must be ICD-705-aware).

---

## 2. Per-Requirement Status

| # | Requirement | Status | Evidence | Gap |
|---:|---|---|---|---|
| 1 | **FIPS 140-3 cryptographic modules** | PARTIAL | `core/fips_compliance_mode_engine.py` (FIPS mode toggle, PQC inventory, NIST KAT shipped Wave C `8e9e573d`); `core/fips_encryption.py` (AES-256-GCM via stdlib) | stdlib `hashlib`/`os.urandom` are FIPS-eligible *only when* the underlying OpenSSL is FIPS-validated and the OS kernel exposes `/proc/sys/crypto/fips_enabled=1`. We need a packaged distribution that bundles FIPS-validated OpenSSL 3.x (RHEL 9 FIPS or Ubuntu Pro FIPS). |
| 2 | **Air-gapped deployment** | MET | `core/airgap_config.py`, `core/airgap_deployment.py`, `core/air_gap_bundle_engine.py`, `airgap_router.py` (1427 LOC) — offline vuln DB, STIX/TAXII bundles, classification-level labels, FIPS marker check | Production runbook + signed offline update bundle process. |
| 3 | **FedRAMP High control mapping** | PARTIAL | `core/fedramp_controls.py` enumerates `FedRAMPBaseline.{LOW,MODERATE,HIGH}` + 17 control families (AC, AU, CA, CM, CP, IA, IR, MA, MP …) | No control-by-control implementation map, no SSP, no POA&M, no continuous monitoring evidence loop. |
| 4 | **STIG-compliant container images** | MISSING | `docker/` Dockerfiles use `python:3.11-slim`, `node:20-alpine`, `nginx:1.27-alpine` — none are STIG/Iron Bank | Rebase on UBI9-minimal + Iron Bank publication. |
| 5 | **Cleared-personnel access (RBAC + audit + 2FA)** | PARTIAL | `core/rbac_engine.py` (multi-tenant, scope inheritance, audit trail), `core/mfa_management_engine.py` (TOTP + WebAuthn/FIDO2 + hardware keys), `core/audit_logger.py`, `core/write_audit_middleware.py` | No classification-level enforcement; no clearance-level attribute on user; SCIM provisioning router exists but doesn't carry clearance metadata. |
| 6 | **HSM integration** | MISSING | `core/key_manager.py` uses `secrets.token_bytes` + bcrypt hashing | Add PKCS#11 backend (`python-pkcs11`), certify with one HSM. |
| 7 | **All-on-prem LLM inference** | PARTIAL | `core/llm_providers.py` ships `VLLMSelfHostedProvider` (line 1083) and `OllamaSelfHostedProvider` (line 1319); `core/vllm_autofix_adapter.py` bridges autofix to vLLM/Ollama; CLAUDE.md mentions Ollama "labeled retired" | Confirm vLLM path is the canonical air-gap LLM (Ollama can stay as developer convenience); document model-card SBOM (training data, weights hash) for ATO; provide signed model bundles for offline import. |
| 8 | **Quantum-safe evidence** | MET | `core/quantum_safe_crypto_engine.py` + `core/quantum_crypto.py` (CRYSTALS-Kyber/Dilithium/FALCON/SPHINCS+ tracking, FIPS 203/204/205 alignment, NIST SP 800-208) | Wire signing of evidence bundles to use ML-DSA today (we have the engine, may not have the production usage). |
| 9 | **ConMon (Continuous Monitoring)** | PARTIAL | `core/audit_analytics.py`, `core/anomaly_detector.py`, `core/network_anomaly_detector.py`, `core/zero_trust_policy_engine.py`, `core/scheduled_reports_engine.py` reference ConMon | No automated NIST 800-137 evidence pipeline; no SOC integration spec; no monthly POA&M update workflow. |
| 10 | **ATO (Authority To Operate) prerequisites** | MISSING | `docs/INVESTOR_PITCH.md`, `docs/DEMO_SCRIPT.md`, `core/license_compliance.py` mention ATO contextually | No SSP, no POA&M template, no SAR (Security Assessment Report) artefact format, no 3PAO relationship, no FedRAMP PMO sponsorship plan. |
| 11 | **Tamper-evident audit log** | MET | `core/audit_logger.py`, `core/audit_log.py`, `core/write_audit_middleware.py` (all writes mediated), `core/audit_db.py` | Verify log immutability — append-only WORM mode + cryptographic chaining (Merkle log) for IL5+. |
| 12 | **Multi-tenant tenant-isolation guarantee** | PARTIAL | `core/tenant_isolation_auditor.py`, `core/rbac_engine.check_tenant_access` | For SCIF use case the deployment is *single-tenant per facility* — multi-tenant features should be *disable-able* via env flag for the SCIF distribution. |
| 13 | **Supply-chain attestation (SLSA L3+)** | PARTIAL | `core/slsa_provenance_engine.py`, `core/sbom_engine.py`, `core/sbom_runtime_correlator.py`, in-toto compatibility | Build pipeline must be hermetic + signed; today's GH Actions builds are not yet SLSA L3 hermetic. |
| 14 | **Physical/network ICD-705 alignment guide** | MISSING | — | Deployment architecture doc covering classification spillover, network diodes, removable-media protocols. |
| 15 | **Personnel security model** | MISSING | — | User attribute schema for clearance level, polygraph status (TS/SCI), foreign-influence flags, last-investigation date. Even if we don't *manage* clearances, we must *consume* them from the IdP and enforce. |

---

## 3. Maturity by Domain

| Domain | Maturity | Note |
|---|---:|---|
| Cryptography (FIPS + PQC) | 70% | Engines real, packaging missing |
| Air-gapped operation | 80% | Best-in-class for our peer set |
| Identity & Access | 50% | RBAC/MFA strong, classification model missing |
| Audit & Evidence | 65% | Tamper-evident chaining is the gap |
| Container/Image hardening | 10% | Iron Bank rebase needed |
| Continuous Monitoring | 30% | Analytics exists, ConMon glue missing |
| Compliance documentation (SSP/POA&M) | 5% | This is the long pole |
| 3PAO assessment readiness | 0% | No relationship, no run-through |
| **Aggregate** | **~35%** | |

---

## 4. Months-to-SCIF-Ready: 12–18 Months

### 4a. Phased Plan

**Phase 1 — Crypto + Container Hardening (Months 0–3)**
- HSM integration via PKCS#11 wrapper (2 months)
- Iron Bank UBI9-minimal rebase + cosign signing (1.5 months, parallel)
- Bundle FIPS-validated OpenSSL 3.x distribution (RHEL 9 FIPS or Ubuntu Pro FIPS) (1 month, parallel)
- Production-flip evidence bundles to ML-DSA signing (0.5 month)

Deliverable: a signed, hardened, FIPS-bundled, HSM-capable artefact.

**Phase 2 — Identity & Audit Hardening (Months 2–5)**
- Add classification level + compartment model to user/asset (2 months)
- WORM-mode audit log with Merkle chaining (1 month)
- SCIM clearance-attribute pass-through (1 month)
- Single-tenant SCIF distribution flag (0.5 month)

Deliverable: SCIF-shaped data model + tamper-evident audit.

**Phase 3 — Compliance Documentation (Months 3–9, sequential after Phase 1)**
- System Security Plan (SSP) authored against FedRAMP High baseline (2 months)
- Control-by-control implementation evidence map (2 months, parallel)
- POA&M template + monthly cadence (1 month)
- Continuous monitoring (NIST 800-137) pipeline glue (2 months, parallel)
- ICD-705 deployment companion guide (1 month)

Deliverable: ATO package draft.

**Phase 4 — 3PAO Assessment (Months 9–15)**
- Engage 3PAO (~$200K–500K)
- Pen-test, control-walkthrough, remediation
- POA&M closure
- FedRAMP PMO sponsorship via federal agency (concurrent — needs federal customer co-sign)

Deliverable: FedRAMP High *In Process* listing.

**Phase 5 — IL5/IL6 Overlay (Months 15–18+)**
- DoD IL5 SRG mapping
- DISA Mission Owner sponsorship
- IL6 only after SECRET-fabric customer co-sign

Deliverable: DoD Provisional Authorization (PA) at IL5.

### 4b. Risk-Adjusted Estimate

- **12 months** if we get a federal customer to co-sponsor early (skip the chicken-and-egg PMO problem) AND we hire an ex-3PAO compliance lead in month 1.
- **18 months** under our own steam without a sponsor.
- **24+ months** if we treat compliance as a side-quest and don't carve out 2 dedicated FTEs.

### 4c. What we should NOT promise yet

- We should **not** market "FedRAMP High" today — we are FedRAMP High *aware*, not *authorized*.
- We **may** market "FedRAMP High control-mapped" once the SSP draft exists (Month 5).
- We **may** market "Air-gap ready" today — that one is honest.
- We **should** market "FIPS 140-3 mode + PQC inventory" today — that is real and unique.

---

## 5. Cost Snapshot (Rough)

| Item | Cost |
|---|---:|
| 3PAO engagement | $200–500K |
| FIPS-validated OpenSSL distribution licensing (RHEL or Ubuntu Pro) | $25–50K/yr |
| HSM hardware + maintenance (entry: 2× Thales Luna or AWS CloudHSM cluster) | $80–150K + $30K/yr |
| Compliance lead (12 months) | $250K loaded |
| Internal eng effort (Phases 1–3) | ~6 FTE-months = $300K |
| **Total to FedRAMP High *In Process*** | **~$900K–1.3M** |

---

## 6. Open Questions for CTO

1. **Federal sponsor strategy.** Without an agency co-sponsor, FedRAMP PMO won't pick us up. Who is in the pipeline (DRDO/ISRO mentioned in `airgap_config.py` docstring — is that real or aspirational)?
2. **Buy-vs-build for compliance docs.** Anchore, Rebellion Defense, and Second Front offer "FedRAMP-in-a-box" services. Worth a $150K spend to compress 3 months?
3. **Single-tenant SCIF SKU vs. multi-tenant SaaS.** The SCIF SKU should probably be a separately-priced, separately-released distribution. Confirm marketing posture.

---

*End scorecard.*
