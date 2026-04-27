# ALDECI SCIF Reference Architecture

**Date:** 2026-04-26
**Audience:** ISSO, ISSM, AO, technical evaluators
**Purpose:** Single-page architecture diagram for SCIF deployment, with NIST 800-53 control families, FIPS boundary, and HSM placement annotated.
**Companion:** `docs/scif/SCIF_PILOT_BUNDLE_README.md`, `docs/scif/SSP_aldeci_2026-04-26.md`, `docs/scif/nist_800-53_control_matrix_2026-04-26.csv`, `docs/scif/crypto_module_datasheet_2026-04-26.md`

---

## 1. Architecture (Mermaid)

```mermaid
flowchart TB
    subgraph SCIF["Customer SCIF Perimeter (ICD-705 / PE-1..PE-23)"]
        direction TB

        subgraph TRANSFER["Approved Data-Transfer Mechanism"]
            direction LR
            SNEAKER["Sneakernet / CDS / Encrypted Media<br/>(MP-1..MP-8: Media Protection)"]
        end

        subgraph SCANIN["Offline Scanner Outputs (Inbound)"]
            direction LR
            SAST["SAST results<br/>(CodeQL, Semgrep .sarif)"]
            DAST["DAST results<br/>(ZAP, Burp .json)"]
            SBOM["SBOM bundles<br/>(CycloneDX, SPDX)"]
            CSPM["CSPM exports<br/>(Wiz, Prisma .json)"]
            VULN["Offline KEV/EPSS/NVD<br/>(STIX/TAXII bundles)"]
        end

        subgraph APPLIANCE["ALDECI Air-Gap Appliance (single Docker host, single tenant)"]
            direction TB

            subgraph BOOT["Boot-Time Posture Check (FIPS_STRICT_BOOT=1)"]
                direction LR
                FIPSCHK["FIPS 140-3 OpenSSL<br/>+ /proc/sys/crypto/fips_enabled=1<br/>(SC-13)"]
                HSMCHK["HSM PKCS#11 token attached<br/>(SC-12, SC-28)"]
                AUDITCHK["Audit chain DB attached<br/>(AU-2..AU-12)"]
                AGCHK["Outbound-blocking probe<br/>(SC-7, SC-7(5))"]
            end

            subgraph CONTAINER["Hardened Container (UBI9-min, cosign-signed, --read-only --cap-drop=ALL)"]
                direction TB

                INGEST["Ingestion + Normalizer Layer<br/>32 scanner parsers, 28+ feed mirrors<br/>(SI-2, SI-3, SI-4, SI-5)"]

                subgraph BRAIN["Brain Pipeline (12 steps, all in-process)"]
                    direction LR
                    NORM["Normalize<br/>(SI-10)"]
                    ENRICH["Enrich + Correlate<br/>(SI-4, AC-4)"]
                    LLM["LLM Council<br/>vLLM on-prem<br/>(no egress)"]
                    DPO["DPO Consensus<br/>+ self-learning<br/>(SI-7, AU-6)"]
                    DECIDE["Decide + Score<br/>(RA-3, RA-5, CM-3)"]
                    REMED["Remediate<br/>(SI-2, CM-3)"]
                end

                subgraph EVIDENCE["Evidence + Audit (tamper-evident)"]
                    direction LR
                    AUDITDB["Merkle audit chain DB<br/>(AU-9, AU-10, AU-11)"]
                    SIGNER["ML-DSA / RSA-3072 signer<br/>via PKCS#11<br/>(AU-9(3), SC-12)"]
                    EVBUNDLE["Evidence bundle<br/>(CycloneDX SBOM<br/>+ in-toto attestation)"]
                end

                subgraph RBAC["RBAC + MFA + AuthN/Z"]
                    AUTH["RBAC engine + FIDO2/WebAuthn<br/>(AC-2..AC-6, IA-2, IA-5)<br/>SCIM-driven (clearance pass-through Phase 2)"]
                end
            end

            subgraph HSM["HSM (PKCS#11)"]
                SOFTHSM["SoftHSM 2.6+ (pilot)<br/>Thales Luna / AWS CloudHSM /<br/>YubiHSM2 (production)<br/>(SC-12, SC-13, SC-28(1))<br/>SENSITIVE=true, EXTRACTABLE=false"]
            end
        end

        subgraph CUSTOMERSEC["Customer Existing Security Stack"]
            direction LR
            SOC["SOC / SIEM<br/>(Splunk, ArcSight, Elastic)"]
            EDR["EDR / NGFW"]
            IDP["IdP (SCIM)<br/>(IA-2, IA-5)"]
        end
    end

    subgraph OUTSIDE["Outside SCIF — NO CONNECTIVITY ALLOWED"]
        INTERNET["Internet<br/>(blocked by SC-7 + active probe)"]
    end

    SNEAKER -.->|signed bundles<br/>SHA-256 + GPG verify| SCANIN
    SCANIN --> INGEST
    INGEST --> BRAIN
    BRAIN --> EVIDENCE
    EVIDENCE -->|signed evidence<br/>+ audit log| SOC
    HSMCHK <--> SOFTHSM
    SIGNER <-->|sign / verify| SOFTHSM
    AUTHCHK[/External AuthN check/] -.-> IDP
    IDP -.->|SCIM provision<br/>clearance attrs| AUTH
    APPLIANCE -.x|BLOCKED<br/>FIXOPS_DISABLE_TELEMETRY=1| INTERNET

    classDef metStyle fill:#d4edda,stroke:#155724
    classDef partialStyle fill:#fff3cd,stroke:#856404
    classDef perimeterStyle fill:#f8d7da,stroke:#721c24,stroke-dasharray: 5 5
    classDef appStyle fill:#cce5ff,stroke:#004085

    class FIPSCHK,HSMCHK,AUDITCHK,AGCHK,SOFTHSM,AUDITDB,SIGNER,EVBUNDLE metStyle
    class AUTH,LLM,DPO partialStyle
    class INTERNET perimeterStyle
    class INGEST,BRAIN,EVIDENCE,RBAC appStyle
```

---

## 2. Step-by-Step with NIST 800-53 Control Family Annotations

| Step | Component | Action | NIST 800-53 control families touched |
|---:|---|---|---|
| 1 | **Sneakernet / CDS / encrypted media** | Customer transfers signed bundles into the SCIF | **MP** (Media Protection: MP-1..MP-8), **PE** (Physical: PE-1..PE-23 via SCIF perimeter), **SC-7** (boundary protection) |
| 2 | **Bundle integrity verification** | ISSO runs `gpg --verify` + `sha256sum -c manifests/sha256.txt` | **SI-7** (Software & Information Integrity), **CM-5** (Access Restrictions for Change), **CM-14** (Signed Components) |
| 3 | **Boot-time posture check** | Container entrypoint runs FIPS / HSM / audit / outbound probe with `FIPS_STRICT_BOOT=1` | **SC-12** (Cryptographic Key Establishment), **SC-13** (Cryptographic Protection), **CM-6** (Configuration Settings), **SI-6** (Security Function Verification) |
| 4 | **Scanner output ingestion** | 32 normalizers parse SAST/DAST/SBOM/CSPM/Vuln-feed offline outputs | **SI-2** (Flaw Remediation), **SI-3** (Malicious Code), **SI-4** (System Monitoring), **SI-5** (Security Alerts), **SI-10** (Information Input Validation) |
| 5 | **Brain Pipeline — Normalize/Enrich** | Findings normalized to common schema, correlated across sources | **AC-4** (Information Flow Enforcement), **SI-4** (System Monitoring) |
| 6 | **Brain Pipeline — LLM Council (vLLM on-prem)** | Multi-model consensus using on-prem inference; **no external API calls** | **SC-7** (Boundary Protection — egress-blocked), **SI-4** (Monitoring), **AU-2** (Event Logging — every model vote logged) |
| 7 | **Brain Pipeline — DPO + Decide + Remediate** | Council reaches consensus; risk score assigned; remediation suggested with confidence | **RA-3** (Risk Assessment), **RA-5** (Vulnerability Scanning), **CM-3** (Configuration Change Control), **SI-2** (Flaw Remediation) |
| 8 | **HSM signing of evidence + audit checkpoint** | Every 100 audit entries signed by HSM RSA key labelled `audit-chain-checkpoint`; evidence bundles signed by ML-DSA (or RSA-3072 hybrid) | **SC-12** (Key Establishment), **SC-13** (Crypto Protection), **AU-9** (Protection of Audit Info), **AU-9(3)** (Cryptographic Protection of Audit Info), **AU-10** (Non-Repudiation) |
| 9 | **Tamper-evident audit chain** | Each row hashes `prev_hash ‖ ts ‖ action ‖ canonical_json(payload)`; `verify_full()` re-walks chain | **AU-2** (Event Logging), **AU-9** (Protection), **AU-10** (Non-Repudiation), **AU-11** (Audit Record Retention), **AU-12** (Audit Record Generation) |
| 10 | **Output to Customer SOC/SIEM** | Signed evidence bundles + audit log slices delivered via internal network or scheduled export | **AU-6** (Audit Record Review), **IR-4** (Incident Handling), **SI-4** (Monitoring), **CA-7** (Continuous Monitoring) |
| 11 | **RBAC + MFA + SCIM** | All operator access via FIDO2/WebAuthn; SCIM provisions roles (clearance-attribute pass-through is Phase-2 POA&M item POA-004) | **AC-2..AC-6** (Account Mgmt), **IA-2** (Identification & AuthN), **IA-2(1)** (MFA for Privileged Accounts), **IA-5** (Authenticator Mgmt), **IA-8** (Identification of Non-Org Users) |
| 12 | **Outbound-blocking probe** | Active probe of 8 known internet endpoints during boot + on `/api/v1/airgap/verify`; refuses to claim air-gap status if any reachable | **SC-7** (Boundary Protection), **SC-7(5)** (Deny by Default), **SI-4** (Monitoring) |

---

## 3. FIPS 140-3 Cryptographic Boundary

The **FIPS module boundary** is the OS-provided FIPS-validated OpenSSL 3.x library. Inside the boundary:

- All symmetric crypto (AES-256-GCM via the HSM)
- All asymmetric crypto (RSA-3072 SHA-256 today; ML-DSA/Dilithium for evidence signing as it becomes the default)
- All hash operations (SHA-256, SHA-384)
- All key derivation (HKDF via OpenSSL)
- All TLS termination (when management UI exposed)

Outside the boundary (but still inside the container):
- Application logic (Python 3.11)
- LLM inference (vLLM — uses CUDA/CPU compute, no crypto operations on weights)
- Storage (SQLite for application state — column-encrypted via FIPS module)

**Key requirement for SCIF:** the host OS MUST be RHEL 9 FIPS or Ubuntu Pro FIPS, booted with `fips=1` kernel parameter, with `/proc/sys/crypto/fips_enabled` returning `1`. The container's `FIPS_STRICT_BOOT=1` checks this and refuses to start otherwise.

---

## 4. HSM Placement

| Pilot phase | HSM | Rationale | Effort to swap |
|---|---|---|---|
| Pilot day 1 | **SoftHSM 2.6+** | Functional PKCS#11 token; lets us prove the integration works | n/a |
| Pilot day 7+ (optional) | **YubiHSM2** | $650 dongle; FIPS 140-2 L3; fits dev SCIFs and small enclaves | Swap `PKCS11_MODULE` env var; 5 min |
| Production (post-pilot) | **Thales Luna Network HSM** | FIPS 140-3 L3; cluster-able; common in IL5/IL6 | Swap `PKCS11_MODULE` + token init; ≤1 hr |
| Production (cloud-adjacent SCIF) | **AWS CloudHSM (FIPS partition)** | FIPS 140-3 L3; pay-by-the-hour; only viable if SCIF allows AWS GovCloud connectivity | Same swap; ≤2 hr |

**Critical property:** all keys created inside the HSM use `SENSITIVE=True, EXTRACTABLE=False` — the private key material **never leaves** the HSM, even to the application. ALDECI calls `C_Sign()` / `C_Verify()` / `C_Encrypt()` / `C_Decrypt()` — the application gets ciphertext/signature back, never key bytes.

**Audit-chain checkpoint key:** RSA-3072 keypair labelled `audit-chain-checkpoint` in the HSM; signs every 100th audit row to give a single root-of-trust per checkpoint.

**Evidence signing key (CNSA 2.0 path):** ML-DSA (Dilithium) keypair tracked in `core/quantum_crypto.py` — wired in for production use; available for pilot evaluation.

---

## 5. Network Posture

```
Inside SCIF:
  ┌──────────────────────────────────────────────────────┐
  │  ALDECI container                                    │
  │    ↑ inbound: TCP 8000 (HTTPS to Customer SOC ops)   │
  │    ↓ outbound: NONE (FIXOPS_DISABLE_TELEMETRY=1,     │
  │                       active outbound-blocking probe) │
  │  ↕ HSM PKCS#11 (Unix socket / hardware bus, no IP)   │
  │  ↕ audit chain DB (host volume, optional dm-verity   │
  │     for true WORM)                                    │
  └──────────────────────────────────────────────────────┘
                         │
                         ▼
                Customer SOC/SIEM
                (Splunk/ArcSight/Elastic)
                via internal SCIF network
```

**No outbound connectivity at any layer.** The container is launched with `--read-only --cap-drop=ALL --security-opt no-new-privileges:true`. Host firewall should additionally block all egress from the container subnet — belt-and-suspenders.

---

## 6. Where ALDECI Inherits Customer Controls vs. Provides Its Own

| Control family | Customer provides | ALDECI provides |
|---|---|---|
| **PE** (Physical) | All — SCIF construction, ICD-705 | none |
| **PS** (Personnel Security) | All — clearance, polygraph, investigations | consume clearance from SCIM (Phase 2) |
| **AT** (Awareness & Training) | All | none |
| **CP** (Contingency Planning) | Backup site, DR | application-level config backup procedures |
| **MA** (Maintenance) | Hardware, OS patching | application patch bundles (sneakernet) |
| **MP** (Media Protection) | All — media handling, sanitization | bundle delivery via Customer's approved mechanism |
| **AC** (Access Control) | IdP, network ACLs | RBAC, scope inheritance, classification-level (Phase 2) |
| **AU** (Audit) | SOC/SIEM aggregation, retention beyond 5 yrs | Merkle audit chain, HSM-signed checkpoints, NIST 800-92 export |
| **IA** (Identification & Authn) | IdP, MFA hardware | FIDO2/WebAuthn enforcement, SCIM consumer |
| **CM** (Configuration Mgmt) | Host baseline | application baseline, signed bundles, in-toto attestation |
| **CA** (Assessment) | 3PAO relationship | continuous self-test endpoints (`/scif/audit-chain/verify`, `/airgap/verify`) |
| **SC** (System & Comms Protection) | Boundary FW, host hardening | egress block, FIPS boundary, HSM, PQC inventory |
| **SI** (System & Information Integrity) | Host AV/EDR | scanner ingestion, Brain Pipeline, finding tracking |
| **RA** (Risk Assessment) | Org-level risk register | per-finding risk scoring, EPSS/KEV correlation |
| **SR** (Supply Chain Risk) | Vendor management | CycloneDX SBOM, in-toto provenance, cosign-signed images |

---

## 7. Notes for the AO

1. **Single-tenant by design.** The SCIF SKU disables multi-tenant features by default. One SCIF, one ALDECI deployment, one tenant. No blast-radius risk from neighbouring tenants because there are no neighbouring tenants.
2. **No cloud dependency, ever.** vLLM runs on local GPU/CPU. SBOM is local. KEV/EPSS feeds are mirrored offline. The bundle ships everything needed.
3. **Reproducible builds.** The bundle artefact name includes the git SHA. Anyone with the source tree at that SHA can rebuild byte-identical. cosign signatures verify image integrity.
4. **Honest open items.** POA-001..POA-006 are all LOW/MED severity, none blocking pilot authorization under existing ATO inheritance. See `docs/scif/POAM_aldeci_2026-04-26.md`.
5. **Phase-2 roadmap visible.** Classification-level data model (POA-004) is the largest open item; pilot lets us co-design it around your data model (e.g., NBIS schema if DCSA, IC ITE labels if IC, etc.).

*End reference architecture.*
