# Cryptographic Module Datasheet — ALDECI CTEM+ Platform

**Document ID:** CRYPTO-DS-ALDECI-2026-04-26
**Version:** 0.1 (Pilot Draft)
**Date:** 2026-04-26
**Branch under assessment:** `features/intermediate-stage`
**Build under assessment:** `aldeci:scif-hardened` (Stage 1 commits `1159ef49`, `69efa330`)
**Module name:** ALDECI CTEM+ Cryptographic Subsystem
**Module type:** Software-hybrid module (FIPS 140-3 software boundary) using a hardware PKCS#11 token (FIPS 140-3 Level 3 in production)

---

## 1. FIPS 140-3 Boundary Definition

### 1.1 Logical boundary

The ALDECI cryptographic subsystem comprises:

- `core.fips_boot` — boot-time FIPS posture enforcement
- `core.fips_compliance_mode_engine` — FIPS mode toggle, PQC inventory, NIST KAT runner
- `core.fips_encryption` — FIPS-validated AES-GCM helpers (delegating to OpenSSL via `cryptography` package)
- `core.hsm_provider` — PKCS#11 abstraction (the **hardware boundary** entry point)
- `core.crypto_key_management_engine` — Key lifecycle (gen, rotate, destroy)
- `core.key_manager` — Symmetric key derivation (legacy path; production keys go via HSM)
- `core.quantum_safe_crypto_engine` — PQC algorithm support (FIPS 203/204/205)
- `core.quantum_crypto` — PQC primitives
- `core.audit_chain` — HSM-backed audit chain checkpointing
- `core.password_policy_engine` — Authenticator hashing (bcrypt, scrypt-FIPS)

### 1.2 Physical boundary (production)

- **Pilot:** SoftHSM 2.6 — software boundary, FIPS 140-3 Level 1 equivalent (development-grade). Token storage at `/var/lib/softhsm`.
- **Production:** Thales Luna 7 (FIPS 140-3 Level 3, NIST cert #4365 family) **or** AWS CloudHSM v2 (FIPS 140-3 Level 3 Cluster) **or** YubiHSM 2 (FIPS 140-3 Level 3 for entry deployments).

The **swap from SoftHSM to production HSM is configuration-only** — change `PKCS11_MODULE` env var to vendor `.so`, re-init token, migrate keys via PKCS#11 wrapped-key transport. **No code change required.**

### 1.3 Module ports & interfaces

| Interface | Direction | Description |
|---|---|---|
| PKCS#11 v3 (vendor `.so`) | bidirectional | All key operations |
| `os.urandom` (kernel CSPRNG) | input | Entropy source — host kernel `getrandom(2)` |
| `cryptography` package (OpenSSL 3.x) | bidirectional | Symmetric crypto when not delegated to HSM |
| Audit chain SQLite | output | Audit checkpoints signed via HSM |
| `/api/v1/scif/hsm/info` | output | Key labels only — never cleartext key material |
| `/api/v1/scif/audit-chain/verify` | output | Chain integrity status |

Cleartext key material **never** crosses the module boundary. All HSM keys are created with `CKA_SENSITIVE=True, CKA_EXTRACTABLE=False`.

---

## 2. Approved Algorithms (FIPS 140-3 / NIST CAVP)

### 2.1 Symmetric encryption

| Algorithm | Modes | Key sizes | Use case | Source |
|---|---|---|---|---|
| **AES** | GCM, CTR | 128, 192, 256 | At-rest, in-transit | OpenSSL 3.x via `cryptography` |
| **AES-256-GCM** (default) | GCM | 256 | Audit chain payload encryption, evidence bundle | `core.fips_encryption.FIPSEncryption` |
| **HMAC-SHA-256** | — | 256 | MAC, KDF | OpenSSL 3.x |
| **HMAC-SHA-384/512** | — | 384/512 | High-assurance MAC | OpenSSL 3.x |

### 2.2 Asymmetric / digital signatures

| Algorithm | Curve / size | Use case | Source |
|---|---|---|---|
| **RSA-PSS** | 3072, 4096 | Audit chain checkpoint signing | HSM via `core.hsm_provider.PKCS11Provider` |
| **RSA-OAEP** | 3072 | Key wrapping | HSM |
| **ECDSA** | P-256, P-384 | Code signing (cosign target POA-002) | HSM (production) |
| **EdDSA** | Ed25519 | Service-account auth | OpenSSL 3.x |

### 2.3 Hash functions

| Algorithm | Output | Use case |
|---|---|---|
| **SHA-256** | 256 | Audit chain prev-hash, bundle manifest |
| **SHA-384** | 384 | Higher-assurance signing |
| **SHA-512** | 512 | High-assurance |
| **SHA3-256** | 256 | Available, not default |

### 2.4 Post-Quantum (FIPS 203/204/205)

| Algorithm | Standard | Status | Source |
|---|---|---|---|
| **ML-KEM (Kyber)** | FIPS 203 | IMPLEMENTED — inventory tracked, hybrid-handshake available | `core.quantum_safe_crypto_engine` |
| **ML-DSA (Dilithium)** | FIPS 204 | IMPLEMENTED — evidence-bundle signing path available | `core.quantum_safe_crypto_engine` |
| **SLH-DSA (SPHINCS+)** | FIPS 205 | IMPLEMENTED — high-assurance hash-based sig | `core.quantum_safe_crypto_engine` |
| **LMS / XMSS** | NIST SP 800-208 | IMPLEMENTED — stateful hash-based sig | `core.quantum_safe_crypto_engine` |

PQC posture aligns with **CNSA 2.0** (NSA, 2022) and **NSM-10** mandates. PQC keys today are tracked per-org but production signing is RSA-PSS until customer co-signs PQC migration plan (typical 2026–2030 transition).

### 2.5 Random number generation

- **Source:** Host kernel `/dev/urandom` (Linux `getrandom(2)`); FIPS-validated when host is FIPS kernel.
- **DRBG:** OpenSSL 3.x AES-256 CTR_DRBG (FIPS 140-3 approved).
- **HSM:** PKCS#11 `C_GenerateRandom` for any HSM-resident key generation.

---

## 3. Disallowed Algorithms (refused at boot)

`core.fips_boot.run_fips_boot()` refuses to boot if any of the following are importable:

- `Crypto.Cipher.ARC4` (RC4)
- `Crypto.Cipher.DES`
- `Crypto.Cipher.Blowfish`
- `Crypto.Hash.MD5`
- `Crypto.Hash.SHA` (SHA-1)
- Any TLS 1.0 / TLS 1.1 cipher suite

Boot exit code **12** when forbidden cipher detected.

---

## 4. Key Management Lifecycle

### 4.1 Key inventory (production reference)

| Key label | Algorithm | Use | Rotation |
|---|---|---|---|
| `audit-chain-checkpoint` | RSA-3072 | Sign every 100th audit chain row | Annual or on suspected compromise |
| `evidence-bundle-signing` | RSA-3072 / ML-DSA | Sign exported evidence bundles | Annual |
| `tenant-data-master` | AES-256 (key-encrypting) | Wrap per-tenant data keys | Annual |
| `tls-server-cert` | ECDSA P-384 | TLS termination (when in-container) | 90 days |
| `cosign-image-signing` | ECDSA P-256 | Sign container images (POA-002) | Per-release |

### 4.2 Lifecycle stages

1. **Generation** — `C_GenerateKeyPair` on HSM with `CKA_SENSITIVE=True, CKA_EXTRACTABLE=False`. Public-key extracted for verification; private never leaves HSM.
2. **Storage** — All key material in HSM token slot. Tokens persisted at `/var/lib/softhsm/` (pilot) or vendor TPM-backed storage (prod).
3. **Use** — Application calls `core.hsm_provider.get_hsm()` → opens session, performs op, closes. PIN supplied via `PKCS11_PIN` env at boot only.
4. **Rotation** — `core.crypto_key_management_engine.rotate(label)` generates new key, marks old as `CKA_DECRYPT=False` (sign-verify only) for grace period, then `C_DestroyObject`.
5. **Destruction** — `C_DestroyObject` zeroizes per PKCS#11 spec. Audit-chained.
6. **Backup** — HSM cluster replication (production) or M-of-N key-share (Shamir) for SoftHSM pilot. Never plaintext.

### 4.3 Authenticator hashing

- **Passwords:** bcrypt cost 12 (`core.password_policy_engine`).
- **API keys:** SHA-256-HMAC with rotating server secret stored in HSM.
- **Session tokens:** Random 256-bit token, HMAC-SHA-256-bound to client fingerprint.

---

## 5. Self-Tests (FIPS 140-3 §7)

### 5.1 Power-on self-tests (executed at every boot)

`core.fips_boot.run_fips_boot()` performs at startup:

| Test | What | Pass criterion | Failure action |
|---|---|---|---|
| Module integrity | SHA-256 of installed Python wheels matches manifest | Match | Exit code 13 |
| Algorithm KAT (AES-256-GCM) | Encrypt/decrypt known plaintext-ciphertext pair | Match | Exit code 12 |
| Algorithm KAT (RSA-PSS sign/verify) | Sign/verify NIST CAVP test vector | Verify=True | Exit code 12 |
| Algorithm KAT (SHA-256) | Hash NIST CAVP test vector | Match | Exit code 12 |
| Algorithm KAT (HMAC-SHA-256) | NIST CAVP vector | Match | Exit code 12 |
| Algorithm KAT (ML-KEM) | NIST PQC reference vector | Match | Warn (PQC inventory) |
| Algorithm KAT (ML-DSA) | NIST PQC reference vector | Match | Warn |
| HSM connectivity | `C_OpenSession` + `C_FindObjects` for required labels | Success | Exit code 11 |
| Forbidden-cipher scan | No RC4/DES/MD5/SHA-1 importable | None | Exit code 12 |
| Audit chain init | Open chain DB + verify last 100 rows | OK | Exit code 13 |

**Test reference:** `tests/test_scif_stage1.py` exercises the full boot path. 12/12 tests pass on `features/intermediate-stage` as of 2026-04-26.

### 5.2 Conditional self-tests

| Test | When | Action |
|---|---|---|
| Pairwise consistency (RSA) | After every `C_GenerateKeyPair` | Sign & verify a known nonce |
| Continuous RNG test | Every 1024 bytes drawn | Compare consecutive blocks; halt on duplicate |

### 5.3 Scheduled re-validation

| Schedule | Test | Trigger |
|---|---|---|
| Daily 02:00 UTC | Full KAT suite | Cron via `core.scheduled_reports_engine` |
| Weekly Sunday 03:00 UTC | Audit chain `verify_full()` | Cron |
| On-demand | `/api/v1/scif/boot` returns latest run report | ISSO walkthrough |
| On-demand | `/api/v1/scif/audit-chain/verify` | ISSO walkthrough |

---

## 6. CAVP / FIPS Validation Status

| Component | Validation | Cert # |
|---|---|---|
| Underlying OpenSSL 3.x (host) | FIPS 140-3 (when host is RHEL 9 FIPS or Ubuntu Pro FIPS) | RHEL 9: #4794 (representative); Ubuntu Pro: #4664 (representative) |
| SoftHSM 2.6 | NOT validated (pilot use only) | n/a |
| Thales Luna 7 (production target) | FIPS 140-3 Level 3 | Cert family #4365 |
| AWS CloudHSM v2 (production target) | FIPS 140-3 Level 3 | Cert #4218 (HSM appliance) |
| ALDECI module itself | NOT independently validated; relies on validated underlying components | — |

> **Honest disclosure.** ALDECI is **not** an independently FIPS-validated module — it is a **FIPS-aware application** that operates correctly only on a FIPS-validated host kernel + FIPS-validated HSM. This posture is acceptable for FedRAMP High deployments per NIST SP 800-53 IA-7 / SC-13 when the underlying validated components are properly assembled and the application enforces FIPS-only paths (which `core.fips_boot` does).

---

## 7. CNSA 2.0 / NSM-10 Posture

- **Symmetric:** AES-256 ✓
- **Hash:** SHA-384 ✓ (and SHA-256 for backward-compat)
- **Asymmetric (transitional):** RSA-3072 / ECDSA P-384 ✓
- **Asymmetric (PQC):** ML-KEM-1024, ML-DSA-87, SLH-DSA-SHA2-256s — all available via `core.quantum_safe_crypto_engine`
- **Migration plan:** Dual-signature (RSA + ML-DSA) for evidence bundles available now; production flip target Q3 2026 per customer co-sign

---

## 8. Crypto Module Operational Modes

| Mode | Env | Behavior |
|---|---|---|
| **FIPS-strict (SCIF)** | `FIPS_MODE=1` + `FIPS_STRICT_BOOT=1` | Boot refused if any check fails (exit 10–13) |
| **FIPS-aware (dev)** | `FIPS_MODE=1` only | Boot continues; warnings logged; non-FIPS paths still rejected at runtime |
| **Non-FIPS (SaaS dev)** | `FIPS_MODE=0` | All algorithms available; warning displayed |
| **HSM-required** | `HSM_ENABLED=1` | All key ops via PKCS#11; refuse if module unloadable |
| **HSM-soft** | `HSM_ENABLED=0` | Keys via local file (development only — not for SCIF) |

**SCIF deployments must use FIPS-strict + HSM-required.**

---

## 9. Operator Verification Procedures

```bash
# A. Confirm FIPS posture (returns last fips_boot report)
curl -s http://localhost:8000/api/v1/scif/boot | jq .
# Expected:
#   fips_mode_active: true
#   strict_boot: true
#   forbidden_imports: []
#   kats_passed: ["AES-256-GCM", "RSA-PSS-3072", "SHA-256", "HMAC-SHA-256"]
#   hsm_backend: "pkcs11:aldeci"

# B. Confirm audit chain integrity
curl -s http://localhost:8000/api/v1/scif/audit-chain/verify | jq .
# Expected:
#   ok: true
#   rows_verified: <int>
#   first_break_seq: null

# C. Confirm HSM key inventory (labels only)
curl -s http://localhost:8000/api/v1/scif/hsm/info | jq .
# Expected:
#   backend: "pkcs11:aldeci"
#   labels: ["audit-chain-checkpoint", "evidence-bundle-signing", ...]

# D. Run KAT suite on demand
curl -s -X POST http://localhost:8000/api/v1/scif/fips/kat | jq .
# Expected:
#   all_passed: true
```

---

## 10. References

- FIPS 140-3 — Security Requirements for Cryptographic Modules
- FIPS 197 — AES
- FIPS 180-4 — Secure Hash Standard
- FIPS 186-5 — Digital Signature Standard
- FIPS 198-1 — HMAC
- FIPS 203 — ML-KEM (Kyber)
- FIPS 204 — ML-DSA (Dilithium)
- FIPS 205 — SLH-DSA (SPHINCS+)
- NIST SP 800-208 — Stateful Hash-Based Signatures
- NIST SP 800-90A Rev 1 — DRBG
- NIST SP 800-131A Rev 2 — Algorithm Transitions
- CNSA 2.0 — Commercial National Security Algorithm Suite (NSA, 2022)
- NSM-10 — National Security Memorandum 10 (Quantum migration)
- PKCS#11 v3.0 — Cryptographic Token Interface
- Companion documents: `SSP_aldeci_2026-04-26.md`, `POAM_aldeci_2026-04-26.md`, `nist_800-53_control_matrix_2026-04-26.csv`, `threat_model_aldeci_2026-04-26.md`

*End cryptographic module datasheet.*
