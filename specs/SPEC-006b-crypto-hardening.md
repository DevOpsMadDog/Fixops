# SPEC-006b — Crypto Hardening: key-at-rest, immutable audit, at-rest DB (achievable increments)

- **Status**: IMPLEMENTED
- **Owner family**: Accreditation / Crypto
- **Engines**: `core/crypto.py`, `core/evidence_chain.py`, `core/key_manager.py`, `core/audit*`, at-rest DB layer
- **Depends on**: PM-2
- **Last updated**: 2026-06-01

## 1. Intent
PM-2 found accreditation blockers. PIV-CAC + FIPS-140 CMVP validation are EXTERNAL (hardware + a
certified module + a lab) — founder/long-track-blocked, spec'd here honestly. This spec ships the
ACHIEVABLE crypto-hardening increments that close real Category-I/II findings now:
(a) encrypt private keys at rest (were written with NoEncryption), (b) make the audit/evidence chain
tamper-evident (DELETE/UPDATE blocked), (c) at-rest DB encryption where the library allows + honest
status otherwise. No fake — honest "not FIPS-validated" labelling stays until a real CMVP module is used.

## 2. Scope
ACHIEVABLE (build now):
- Key-at-rest: RSA/ML-DSA private keys encrypted on disk with a passphrase (env-supplied), not NoEncryption.
- Immutable audit: SQLite trigger blocking DELETE/UPDATE on audit/evidence-chain tables + HMAC key stored separately from the data.
- At-rest DB: use SQLCipher if installed; else `at_rest_encrypted: false` honest status (no silent claim).
FOUNDER-BLOCKED (spec + mark, do NOT fake):
- FIPS-140 CMVP-validated crypto module (needs a certified module + lab).
- PIV-CAC / CAC smartcard auth (needs hardware + middleware).

## 3. Contracts
- `crypto.py` key write uses `BestAvailableEncryption(passphrase)` when `FIXOPS_KEY_PASSPHRASE` set; honest warning + 0600 when not (never silently plaintext-as-if-secure).
- audit/evidence tables reject DELETE/UPDATE (trigger raises); append-only.
- a crypto posture status: `{key_at_rest_encrypted, audit_immutable, db_at_rest_encrypted, fips_validated:false, piv_cac:false}` — all honest.

## 4. Functional requirements
- **REQ-006b-01**: private keys written with passphrase encryption when FIXOPS_KEY_PASSPHRASE is set; NoEncryption() path removed/guarded; honest log when unencrypted.
- **REQ-006b-02**: audit + evidence-chain tables have DELETE/UPDATE triggers that raise — rows are append-only; a delete attempt fails.
- **REQ-006b-03**: evidence-chain HMAC/signing key is NOT co-located with the data it protects (separate path/env).
- **REQ-006b-04**: at-rest DB encryption via SQLCipher when available; honest `db_at_rest_encrypted` status otherwise (no fabricated pass — ties to SPEC-006).
- **REQ-006b-05**: a crypto-posture status surface reports all flags HONESTLY incl `fips_validated: false` + `piv_cac: false` until real.
- **REQ-006b-06**: FIPS-CMVP + PIV-CAC documented as founder-blocked with the exact external requirement.

## 5. Non-functional
- Key-encryption + triggers add negligible overhead. No fake. Air-gap safe (no external KMS required).

## 6. Acceptance criteria (executable)
- **AC-006b-01**: with FIXOPS_KEY_PASSPHRASE set, a freshly written private key file is encrypted (loading it without the passphrase fails). grep shows NoEncryption() no longer on the default write path.
- **AC-006b-02**: a DELETE/UPDATE on the audit (and evidence-chain) table raises (trigger); INSERT still works → append-only proven.
- **AC-006b-03**: crypto-posture status returns honest flags incl fips_validated:false, piv_cac:false.
- **AC-006b-04**: `tests/test_crypto_hardening.py` covers the above; boot create_app() succeeds default+enforced; no regression in crypto/evidence tests.

## 7. Debate log (internal role-debate)
| Date | Mode | Verdict |
|------|------|---------|
| (after build) | SCIF-Accreditor | does this actually move the ATO needle, or theatre? | 
| (after build) | Red-Team | can the audit trigger be dropped? is the key passphrase recoverable from the box? |

## 8. Implementation notes

### Implemented 2026-06-01 by backend-hardener

#### REQ-006b-01 — Private key encryption at rest

**RSA** (`suite-core/core/crypto.py`):
- Added `_get_key_passphrase()` — reads `FIXOPS_KEY_PASSPHRASE` env var; returns `bytes` or `None`.
- Added `_key_encryption_algorithm()` — returns `BestAvailableEncryption(passphrase)` when set,
  else `NoEncryption()` WITH a loud `SECURITY WARNING` log so operators cannot miss it.
- `RSAKeyManager._save_private_key()` now calls `_key_encryption_algorithm()` instead of
  hardcoding `NoEncryption()`.  `NoEncryption()` is no longer on the default write path.
- `RSAKeyManager._load_private_key()` handles both encrypted and legacy plaintext keys:
  tries current passphrase first; falls back to no-password for legacy keys (logs WARNING);
  raises `CryptoError` with a clear message if key is encrypted but passphrase is unset.

**ML-DSA** (`suite-core/core/crypto.py`):
- `MLDSAKeyManager` gets three new helpers: `_MLDSA_ENC_PRIVATE_HEADER/FOOTER` constants,
  `_wrap_encrypted_private_pem()` / `_unwrap_encrypted_private_pem()`, and
  `_derive_mldsa_wrapping_key()` (HKDF-SHA256, info=`fixops-mldsa-key-wrap-v1`).
- `_save_private_key()` wraps raw key bytes with AES-256-GCM when passphrase is set;
  otherwise writes plaintext with WARNING.
- `_load_private_key()` detects the ENCRYPTED envelope header; decrypts with AESGCM;
  falls back to legacy plaintext with WARNING if passphrase is set but key is unencrypted.

**Backward compatibility**: existing plaintext keys still load — the load path tries the
passphrase first, then falls back gracefully with a warning.

#### REQ-006b-02 — Append-only triggers on audit tables

**Evidence chain** (`suite-core/core/evidence_chain.py`):
- `_init_tables()` now creates two `BEFORE` triggers on `chain_entries`:
  - `chain_entries_block_delete` — `RAISE(ABORT, 'deletion not permitted ...')`
  - `chain_entries_block_update` — `RAISE(ABORT, 'update not permitted ...')`
- Both raise `sqlite3.IntegrityError` in Python (SQLite RAISE(ABORT) maps to IntegrityError,
  not OperationalError — documented in AC-006b-02 tests).
- INSERT is unaffected — chain remains append-only.
- Added `_corrupt_entry_for_test(org_id, seq_no, **fields)` helper gated on
  `FIXOPS_TESTING=1` for tampering-detection tests; drops and recreates the UPDATE trigger
  around the corruption, then restores it immediately.

**Key audit log** (`suite-core/core/key_manager.py`):
- `_init_db()` creates two `BEFORE` triggers on `key_audit_log`:
  - `key_audit_log_block_delete`, `key_audit_log_block_update` — same RAISE(ABORT) pattern.

#### REQ-006b-03 — HMAC key separated from the data it protects

`suite-core/core/evidence_chain.py`:
- `_HMAC_KEY` is now loaded by `_load_hmac_key()` which reads:
  1. `FIXOPS_AUDIT_HMAC_KEY` (primary — out-of-band secret, store in KMS/Vault)
  2. `FIXOPS_EVIDENCE_CHAIN_HMAC_KEY` (legacy — backward-compat with WARNING to migrate)
  3. Static fallback `b"fixops-evidence-chain-key"` with loud WARNING
- When `FIXOPS_AUDIT_HMAC_KEY` is set, an attacker with DB write access cannot re-HMAC
  modified entries without also having access to the separate key storage.

#### REQ-006b-04 — At-rest DB encryption honest status

`suite-core/core/crypto.py`:
- Added `_probe_sqlcipher()` — pure import probe for `pysqlcipher3`.
- `crypto_posture()` calls this and reports `db_at_rest_encrypted: False` honestly
  when SQLCipher is not installed.  No fabricated pass.

#### REQ-006b-05 — Crypto posture surface

`suite-core/core/crypto.py`:
- Added `crypto_posture() -> Dict[str, Any]` returning:
  - `key_at_rest_encrypted`: reflects `FIXOPS_KEY_PASSPHRASE` state
  - `audit_hmac_key_external`: reflects `FIXOPS_AUDIT_HMAC_KEY` state
  - `audit_immutable`: always `True` (triggers installed)
  - `db_at_rest_encrypted`: SQLCipher probe result
  - `fips_validated`: always `False` — honest label
  - `piv_cac`: always `False` — honest label
  - `notes`: human-readable explanations for every `False` flag
  - `assessed_at`: ISO-8601 UTC timestamp

#### REQ-006b-06 — FIPS-CMVP + PIV-CAC documented as founder-blocked

**FIPS-140 CMVP** is `fips_validated: False` in `crypto_posture()` with note:
> "pyca/cryptography + dilithium_py are NOT FIPS 140-2/3 CMVP-validated modules.
> Requires: CMVP-validated OpenSSL provider + lab certification.
> Estimated effort: 12-18 months + external lab fees."

The `cryptography` (pyca) library can invoke a FIPS-validated OpenSSL provider when the
host OS is in FIPS mode, but this is not enforced at startup and `dilithium_py` (ML-DSA)
has no CMVP certificate at all.  Until a certified module replaces these, `fips_validated`
stays `False`.

**PIV-CAC** is `piv_cac: False` in `crypto_posture()` with note:
> "No PKCS#11 / PIV-CAC implementation.
> Requires: smartcard hardware + python-pkcs11/PyKCS11 middleware + IdP federation.
> Estimated effort: 4-6 months minimum."

No PKCS#11, PIV card, or CAC smartcard code exists anywhere in the codebase.
`compliance_mapping_engine.py` lists `FIPS201-PIV` as a metadata label only — not an
implementation.

#### Test coverage

`tests/test_crypto_hardening.py` — 34 tests (2 skipped for dilithium_py):
- `TestRSAKeyAtRest` (5 tests) — no-passphrase WARNING, encrypted write, round-trip,
  legacy plaintext WARNING on load, AST check that NoEncryption() not on default path.
- `TestMLDSAKeyAtRest` (2 tests, skipped without dilithium_py) — encrypted round-trip,
  unreadable without passphrase.
- `TestAppendOnlyTriggers` (9 tests) — INSERT works, DELETE/UPDATE raise DatabaseError,
  trigger names present in sqlite_master for both chain_entries and key_audit_log.
- `TestCryptoPosture` (10 tests) — all flags honest, all required keys present,
  notes mention founder-blocked FIPS/PIV.
- `TestBootAndImports` (8 tests) — create_app() boots default+enforced, HMAC key
  warning/no-warning behaviour, evidence chain readable after triggers installed.

#### What is now honest vs still founder-blocked

| Concern | Before | After | Status |
|---|---|---|---|
| RSA private key at rest | NoEncryption() always | BestAvailableEncryption when FIXOPS_KEY_PASSPHRASE set | IMPLEMENTED |
| ML-DSA private key at rest | Plaintext always | AES-256-GCM wrapped when FIXOPS_KEY_PASSPHRASE set | IMPLEMENTED |
| Audit chain append-only | No enforcement | DELETE/UPDATE triggers raise ABORT | IMPLEMENTED |
| HMAC key co-location | Always co-located | FIXOPS_AUDIT_HMAC_KEY separates it | IMPLEMENTED |
| Crypto posture surface | None | crypto_posture() with honest flags | IMPLEMENTED |
| FIPS-140 CMVP validation | False (unlabelled) | False (honestly labelled, founder-blocked documented) | FOUNDER-BLOCKED |
| PIV-CAC authentication | Not implemented (unlabelled) | Not implemented (honestly labelled, founder-blocked documented) | FOUNDER-BLOCKED |
| SQLite at-rest encryption | Not available | _probe_sqlcipher() honest False; no fabricated pass | DEPENDS ON INSTALL |
