# PM-2: SCIF Accreditation Failure — Crypto and ATO Readiness Pre-Mortem

**Scenario**: It is 2031. ALDECI failed its SCIF ATO (Authority to Operate) review under
ICD 503 / NIST SP 800-53 rev5 and CMMC Level 2. The government evaluator's exit brief
identified five non-negotiable blockers. The product was ripped out of the classified
enclave after a 14-month procurement cycle. This post-mortem works backwards from the
actual code to explain why.

**Method**: Every finding below is grounded in file:line evidence from the codebase as it
exists today. No speculation without a citation.

---

## Executive Summary

ALDECI ships impressive crypto _terminology_ — "FIPS 204 ML-DSA-65", "hybrid RSA-4096 +
post-quantum", "AES-256-GCM", "tamper-evident evidence chain". A government evaluator
doing a two-day code review would find that the terminology is real but the _operational
posture_ is not. Five gaps are individually disqualifying for a SCIF ATO. Together they
make the product unaccreditable without a significant engineering sprint.

---

## Gap 1 — FIPS 140-2/3 Validated Cryptography: Mode Is a Self-Assertion, Not a Certificate

### What the code does

`fips_encryption.py:1-8` contains this header:

> "Crypto operations use the `cryptography` library (pyca/cryptography) which delegates
> to the system OpenSSL. When the system OpenSSL is a FIPS-validated build (e.g. RHEL 9
> FIPS mode, Iron Bank base image) every call here is automatically FIPS-validated."

`fips_encryption.py:47-56`: The class is named `FIPSEncryption` and its `__init__`
sets `self._mode = EncryptionMode.STANDARD`. There is no enforcement of FIPS mode at
construction time.

`airgap_deployment.py:1474-1482`: `_check_fips()` reads
`/proc/sys/crypto/fips_enabled`. On non-Linux (macOS, Windows dev boxes) it returns
`True` unconditionally ("Non-Linux: assume FIPS mode is managed externally").

`auto_evidence.py:481-491`: FIPS status evidence is collected via
`ssl.FIPS_mode()`. This is an OpenSSL 1.x API that was removed in OpenSSL 3.x; on
any RHEL 9 / Ubuntu 22+ deployment the call silently returns `None`, falls to
`False`, and the evidence record reports `fips_mode_enabled: False`.

`fips_compliance_mode_engine.py:92-212`: "Activating FIPS mode" for an org writes
`fips_mode=1` to a SQLite table. It does not call any OS kernel API, does not
configure the OpenSSL provider, and does not prevent the application from using
non-FIPS paths. It is a compliance _label_, not a cryptographic enforcement
mechanism.

### Why this fails accreditation

NIST SP 800-131A and FedRAMP require that every cryptographic module used in a
system be validated under FIPS 140-2 or 140-3. The `cryptography` (pyca) library is
not itself a FIPS-validated module. It _can_ call into a FIPS-validated OpenSSL
provider if the OS kernel is in FIPS mode AND the correct OpenSSL 3.x FIPS provider
is loaded AND the application does not call any non-approved primitive. None of those
three conditions is enforced in the code. The evaluator will ask for the CMVP
certificate number. There is none — the product relies on the operator to configure
the host correctly, and there is no startup gate that aborts if FIPS mode is absent.

`fips_encryption.py:85-90`: The `encrypt()` method has an explicit non-FIPS fallback
path (XOR + HMAC) that activates when `_CRYPTOGRAPHY_AVAILABLE` is False. No
production system should have that path enabled, but its mere existence in the code
means the evaluator will flag it as an unapproved algorithm path (FIPS 140-3 §4.9
requires that non-approved services be disabled in approved mode).

`crypto.py:71-74`: ML-DSA is loaded via `dilithium_py`. `dilithium_py` is a pure-
Python implementation of CRYSTALS-Dilithium. It has no FIPS 140 certificate. Using
it in a SCIF environment requires a waiver or replacement with a validated HSM
implementation.

### Blast radius

Every evidence bundle signed with this stack, every audit log HMAC, and every
encrypted data blob fails the cryptographic module requirement. The entire evidence
chain is inadmissible under NIST SP 800-53 AU-10 (Non-Repudiation) if the signing
module is unvalidated.

### De-risk path

1. Deploy on RHEL 9 with `fips-mode-setup --enable` and verify with
   `fips-mode-setup --check` at container startup; abort (`sys.exit(1)`) if not in
   FIPS mode.
2. Replace `dilithium_py` with an HSM-backed ML-DSA implementation or a FIPS 140-3
   validated PQC library (e.g. IBM's ICSA labs submission, or defer PQC to a
   CNSA 2.0 waiver path).
3. Remove the XOR fallback path entirely; it cannot exist in a FIPS-validated build.
4. File the CMVP certificate number for the OpenSSL version in the SSP (System
   Security Plan).

**Owning spec**: `suite-core/core/fips_encryption.py`, `suite-core/core/crypto.py`,
`suite-core/core/airgap_deployment.py:1474-1482`

---

## Gap 2 — Private Keys Stored Unencrypted on Disk

### What the code does

`crypto.py:676-681`:

```python
pem_data = self._private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),   # <-- plaintext
)
self.private_key_path.write_bytes(pem_data)
self.private_key_path.chmod(0o600)
```

The RSA-4096 private key is persisted to `data/keys/rsa_private.pem` with
`NoEncryption()`. The file is `chmod 0o600`, which is a filesystem permission, not
cryptographic protection.

`crypto.py:1030-1032`: The ML-DSA private key is written similarly:
```python
pem_text = self._wrap_private_pem(self._private_key_bytes)
self.private_key_path.write_text(pem_text, encoding="utf-8")
self.private_key_path.chmod(0o600)
```

`crypto.py:396-399` (docstring): "For production deployments, integrate with an HSM
or cloud KMS by overriding `_load_private_key` / `_load_public_key`." This is
guidance, not enforcement. There is no check that prevents the plaintext-on-disk
path from running in a production deployment.

`crypto.py:443-452`: If neither `FIXOPS_RSA_PRIVATE_KEY_PATH` nor
`FIXOPS_RSA_PUBLIC_KEY_PATH` is set, the fallback is
`<repo>/data/keys/rsa_private.pem` — a path inside the application directory tree.
In a container deployment this means the private key lives in the container image
layer or a mounted volume with no additional protection.

### Why this fails accreditation

NIST SP 800-57 Part 1 §8.2.1 and NIST SP 800-53 SC-12/SC-28 require that
cryptographic keys be protected at the same classification level as the data they
protect. For a SCIF deployment that means keys must be stored in a validated key
management system (HSM, AWS CloudHSM, or equivalent) or encrypted under a KEK that
is itself stored in an HSM. A `chmod 0o600` PEM file does not meet this requirement.
The evaluator will ask: "What is the key protection mechanism?" The answer from the
current code is "filesystem permissions."

The `data/keys/` path has no encryption at rest for the SQLite DBs that underpin
most engines (see Gap 3), so a single path-traversal or container escape exposes
both the keys and the data they protect simultaneously.

### Blast radius

All evidence bundles, audit log HMACs, and tenant data are compromised by a single
key exfiltration. The evidence chain's non-repudiation guarantee (AU-10) collapses.
Key rotation (`RSAKeyManager.rotate()`, `MLDSAKeyManager.rotate()`) generates a new
key but writes it in the same plaintext fashion.

### De-risk path

1. Make HSM-backed key storage mandatory in SCIF/FedRAMP profiles; fail startup if
   `FIXOPS_KMS_BACKEND` is unset.
2. At minimum, encrypt PEM files at rest using the `FIXOPS_ENCRYPTION_MASTER_KEY`
   (already wired for data encryption) with `serialization.BestAvailableEncryption()`.
3. Document the key hierarchy in the System Security Plan under SC-12.

**Owning spec**: `suite-core/core/crypto.py:676-681`, `crypto.py:1030-1032`

---

## Gap 3 — Data-at-Rest: SQLite Databases Are Unencrypted

### What the code does

The codebase has 100+ SQLite database files, one per engine domain. Every engine uses
the standard `sqlite3` module with `PRAGMA journal_mode=WAL` for performance.
Representative examples:

- `evidence_collector.py:510`, `962` — `PRAGMA journal_mode=WAL`
- `key_manager.py:158` — `PRAGMA journal_mode=WAL` (the key audit log itself)
- `api_gateway.py:454`, `704`, `885`, `1100` — `PRAGMA journal_mode=WAL`
- `pam_engine.py:58` — PAM (privileged access) data unencrypted

None of these connections use SQLCipher or any equivalent encrypted SQLite variant.
The `airgap_deployment.py:1433` SCIF readiness check has an `encrypt_at_rest` field,
but `airgap_deployment.py:1518` shows the `STANDARD` policy has
`encrypt_at_rest=False`. The `SCIF` policy (`1551`) has `encrypt_at_rest=True`, but
this flag controls whether `FIPSEncryption.encrypt_file()` is called on individual
files — it does not encrypt the SQLite databases themselves.

`compliance_engine.py:975-979`: The encryption-at-rest check reads
`getattr(cfg, "encryption_at_rest", True)` from a config object. If no config is
provided, the `except AttributeError` branch returns
`True, ..., {"tls_enabled": True, "encryption_at_rest": True, "source": "simulated"}`.
The compliance check fabricates a passing result when config is absent.

### Why this fails accreditation

NIST SP 800-53 SC-28 (Protection of Information at Rest) and ICD 503 §4.3 both
require that CUI (Controlled Unclassified Information) and classified data be
encrypted at rest using FIPS-validated mechanisms. SQLite databases storing security
findings, vulnerability data, evidence bundles, PAM session records, and API keys
are all unencrypted plaintext files on disk. A forensic examiner can `strings
findings.db` and read tenant security posture data without any key material.

The self-attestation path in `compliance_engine.py:979` ("source: simulated") means
ALDECI would pass its _own_ compliance check for SC-28 while being out of compliance,
which is a Category I finding (deliberate misrepresentation) in a government review.

### Blast radius

All tenant data for all orgs is readable by any process or user with filesystem
access. In a multi-tenant SCIF deployment this means cross-tenant data exposure
(already a known architectural risk per the 2026-05-31 arch sweep that found 13
tenant leaks). Without encryption at rest, the tenant isolation boundary is purely
logical and collapses on any storage-layer access.

### De-risk path

1. Replace plaintext SQLite with SQLCipher (FIPS-validated builds available from
   Zetetic) for all engine databases, keyed per-tenant from the master key hierarchy.
2. Alternatively, use filesystem-level encryption (dm-crypt/LUKS on Linux) for the
   `data/` directory; document this in the SSP as the SC-28 control implementation.
3. Remove the `"source": "simulated"` branch from `compliance_engine.py:979`; it is
   a compliance check that lies.

**Owning spec**: All `*_engine.py` files using `sqlite3.connect()`,
`suite-core/core/compliance_engine.py:975-979`

---

## Gap 4 — Audit Log Integrity: HMAC Chain Is Bypassable, No Append-Only Enforcement

### What the code does

`evidence_chain.py:5`: "immutable log. HMAC-SHA-256 signatures protect individual
entries."

`evidence_chain.py:42`, `56-64`: Each entry carries an `HMAC-SHA-256` over
`(id + sequence_number + data_hash + previous_hash)`. The `verify_chain()` method
checks that every entry's HMAC is valid and that the hash chain is unbroken.

**What is absent**: There is no SQLite trigger preventing `DELETE` or `UPDATE` on the
`chain_entries` table. There is no `WITHOUT ROWID` or `STRICT` table flag. Any
process with write access to `evidence_chain.db` can execute
`DELETE FROM chain_entries WHERE sequence_number > X` and the chain will verify
cleanly from entry X onward — the evaluator has no way to know entries were removed.

`key_manager.py:185-198`: The key audit log (`key_audit_log` table) is created with
`CREATE TABLE IF NOT EXISTS` and has no deletion protection. There is no trigger,
no Write-Once enforcement, and no external append-only sink (e.g. syslog-ng to an
air-gapped collector).

The HMAC key for `evidence_chain.py` is not shown to be stored separately from the
chain database itself. If the HMAC key and the database are co-located (same host,
same filesystem), an attacker who can modify the database can also re-HMAC the
modified entries.

`evidence_chain_engine.py:62-117`: The `evidence_chain_engine` stores cases and
evidence items. The `seal_evidence` method (line 387) marks evidence as "immutable"
by setting a flag — but this is a software flag in an unencrypted SQLite database,
not a hardware-enforced Write-Once protection.

### Why this fails accreditation

NIST SP 800-53 AU-9 (Protection of Audit Information) requires that audit records be
protected from unauthorized modification and deletion. ICD 503 §5.2 requires that
audit trails be tamper-evident and protected by a mechanism independent of the
system being audited. AU-10 (Non-Repudiation) requires that actions be provably
attributed to specific entities and that evidence of those actions cannot be
repudiated.

A HMAC chain where both the data and the HMAC key are writable by the application
process does not satisfy AU-9. The evaluator will ask: "Can the system administrator
delete an audit record without detection?" Under the current design, the answer
is yes — delete the row, the chain from that point backward still verifies.

### Blast radius

The entire evidence package submitted with an ATO application (POA&M, control
assessments, scan results) is based on data that can be retroactively altered.
An adversary with temporary write access to the host can selectively purge
incriminating findings before an investigation. The chain shows no break because
the break itself was removed.

### De-risk path

1. Forward audit records to an external, append-only sink (AWS CloudTrail, a
   WORM-capable log aggregator, or a hardware-signed syslog target) at the time
   of event creation, not after.
2. Add SQLite triggers: `CREATE TRIGGER block_audit_delete BEFORE DELETE ON
   chain_entries BEGIN SELECT RAISE(ABORT, 'deletion not permitted'); END;`
3. Store the HMAC key in an HSM or KMS separate from the database host so that
   modifying the database does not also give access to the re-signing capability.
4. Implement regular third-party attestation of the chain state (Merkle root
   published to an external ledger or notarisation service).

**Owning spec**: `suite-core/core/evidence_chain.py`,
`suite-core/core/key_manager.py:185-198`,
`suite-core/core/evidence_chain_engine.py:387`

---

## Gap 5 — Authentication: SAML Signature Verification Is Bypassable in Dev Mode; JWT Uses HS256; No PIV-CAC

### What the code does

**SAML signature bypass** (`auth_router.py:1617-1667`):

```
_verify_saml_signature():
  if not x509_cert_pem:
      if _is_dev_mode_enabled():
          _logger.warning("SAML: no X509 cert configured — skipping signature verification (dev mode)")
          return   # <-- returns without raising; authentication succeeds
      raise HTTPException(...)

  ...
  if _is_dev_mode_enabled():
      _logger.warning("SAML: no Signature element found — skipping check (dev mode)")
      return   # <-- unsigned assertion accepted in dev mode

  ...
  if _is_dev_mode_enabled():
      _logger.warning("SAML: cryptography not available — skipping sig check (dev mode)")
      return   # <-- third bypass
```

`auth_router.py:34-36`: `_is_dev_mode_enabled()` reads
`os.getenv("FIXOPS_DEV_MODE", "")`. If an operator deploys the container without
explicitly unsetting this variable, or if an `.env` file shipped from development
contains `FIXOPS_DEV_MODE=true`, all SAML signature verification is silently
skipped. There is no deployment-time gate that prevents `FIXOPS_DEV_MODE=true` from
reaching a production SCIF system.

`auth_router.py:1659`: Even when `cryptography` is available, the code notes
"C14N verification skipped. Install signxml for production use." Full XML-DSig
canonical verification requires `signxml`, which is an optional dependency not
listed as required in `requirements.txt`. Without it, the system verifies only that
a `<Signature>` element exists in the XML, not that it is cryptographically valid
over the assertion payload. This is a signature-wrapping attack surface.

**JWT algorithm** (`oauth2_router.py:51`, `users_router.py:55`):

```python
_JWT_ALGORITHM = "HS256"
JWT_ALGORITHM = "HS256"
```

HS256 (HMAC-SHA-256) is a symmetric algorithm. Every service that needs to verify
a JWT must possess the same secret that was used to sign it. In a microservices or
multi-node SCIF deployment this means the `FIXOPS_JWT_SECRET` must be distributed
to every node that validates tokens, which violates NIST SP 800-57 key distribution
requirements for classified environments. RS256 or ES256 (asymmetric) is required
so that only the issuer holds the signing key.

`auth_deps.py:115-120`: If neither `FIXOPS_API_TOKEN` nor `FIXOPS_JWT_SECRET` is
configured, the system logs a warning and continues running. In practice this means
an unconfigured deployment accepts no tokens but also fails with 401 on every
request — this will be misdiagnosed in the field as a service failure, prompting
operators to set `FIXOPS_DEV_MODE=true` to "fix" it, which re-enables all the
signature bypasses above.

**PIV-CAC / hardware token authentication**: There is no implementation of PKCS#11,
PIV card authentication, or Common Access Card (CAC) support anywhere in the
codebase. `compliance_mapping_engine.py:1664` lists `("fips_201", "FIPS201-PIV",
"Personal identity verification")` as a compliance framework entry, but this is a
metadata label in the compliance engine, not an implementation. FIPS 201-3 PIV
authentication is a hard requirement for SCIF access by human operators under
ICD 704 and Executive Order 13467.

### Why this fails accreditation

NIST SP 800-53 IA-2 (Identification and Authentication — Organizational Users)
Enhancement (1) and (12) require multi-factor authentication and, for classified
environments, hardware token (PIV/CAC) authentication. IA-8 requires authentication
for non-organizational users. The SAML bypass means the primary SSO authentication
mechanism for enterprise users can be circumvented without any cryptographic
evidence of compromise — the log only contains warnings, not audit failures. HS256
JWTs violate the key distribution requirements of a SCIF where different components
run at different trust levels.

The "C14N verification skipped" gap is a known XML signature wrapping attack
vector (CVE-2012-5664 class). An attacker who can intercept the SAML flow could
inject a valid-looking assertion signed over a benign element while the malicious
assertion payload is unsigned.

### Blast radius

Authentication bypass is total accreditation death. A government evaluator who
discovers that authentication can be disabled by setting an environment variable will
terminate the review immediately. The PIV-CAC gap means that even if every other
control were perfect, human operators cannot log in using the hardware tokens
required by policy — the product is operationally unusable in a SCIF without a
compensating control that would itself require ATO-level review.

### De-risk path

1. Remove all three `if _is_dev_mode_enabled(): return` branches from
   `_verify_saml_signature()`. Dev-mode authentication must use a separate code path
   (e.g. a dedicated `/auth/dev-login` endpoint) that is compiled out of production
   builds, not a runtime flag that silences production validation.
2. Add `signxml` to hard requirements (`requirements.txt`); make full XML-DSig C14N
   verification mandatory, not optional.
3. Replace `HS256` with `RS256` throughout; the signing key stays in the OAuth2/token
   issuer only; all other services receive only the public key.
4. Implement PKCS#11 / PIV-CAC authentication. Python libraries: `python-pkcs11`
   (PyKCS11) for card reading; integrate with the existing SAML flow as an
   `AuthnContext` requirement (`urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI`).
5. Gate startup on `FIXOPS_DEV_MODE != true` in any environment whose hostname or
   deployment profile matches production/SCIF.

**Owning spec**: `suite-api/apps/api/auth_router.py:1617-1667`,
`suite-api/apps/api/oauth2_router.py:51`,
`suite-api/apps/api/users_router.py:55`,
`suite-api/apps/api/auth_deps.py:115-120`

---

## Consolidated ATO Distance Assessment

| Dimension | Current State | Required for SCIF ATO | Gap Severity |
|---|---|---|---|
| FIPS 140-2/3 validated module | Self-assertion; `_check_fips()` passes on non-Linux unconditionally; XOR fallback path exists; `dilithium_py` has no CMVP cert | CMVP certificate number in SSP; no unapproved algorithm paths | CRITICAL — blocks ATO package |
| Private key protection | Plaintext PEM on disk, `chmod 0o600`, `NoEncryption()` | HSM or FIPS-validated KMS; key hierarchy documented in SSP under SC-12 | CRITICAL — blocks ATO package |
| Data at rest encryption | Plaintext SQLite, 100+ unencrypted DB files; compliance check fabricates passing result | FIPS-validated encryption (SQLCipher, dm-crypt/LUKS); SC-28 implementation statement | CRITICAL — blocks ATO package |
| Audit log tamper-evidence | HMAC chain with no delete-prevention triggers; key co-located with data; no external WORM sink | AU-9 compliant: external append-only log, delete-protected store, HMAC key in HSM | HIGH — exploitable gap |
| Authentication depth | SAML sig bypass via env var; HS256 JWTs; no PIV-CAC; `signxml` optional | IA-2(1), IA-2(12): MFA mandatory; PIV-CAC for human operators; RS256; no dev-mode bypass in production | CRITICAL — operational blocker in SCIF |
| ATO package generation | FedRAMP framework labels exist in `compliance_mapping_engine.py`; no POA&M generator, no SSP template, no control inheritance documentation | Completed SSP (NIST 800-18), POA&M, CIS/ISSO sign-off, continuous monitoring plan | HIGH — process gap |

**Blunt verdict**: ALDECI is 12-18 months of targeted engineering effort away from a
SCIF ATO under the current architecture. The crypto library stack (pyca/cryptography
+ dilithium_py + plaintext keys) needs to be replaced or proven-compliant via a CMVP
submission. The SQLite-without-encryption architecture is a fundamental mismatch with
SC-28 in any classified environment. The SAML bypass is a one-line config flag away
from disabling the primary authentication control, which no evaluator will accept
regardless of compensating controls. PIV-CAC is a hard operational requirement, not
a nice-to-have.

The product is enterprise-sellable to commercial customers today. It is not
SCIF-deployable without the five gaps above being closed and independently validated.

---

## Five Hardest Gaps (Ranked by Remediation Difficulty)

1. **PIV-CAC / hardware token authentication** — No existing code path. Requires
   PKCS#11 integration, card-management enrollment workflow, IdP federation, and
   end-to-end testing with actual CAC readers. 4-6 months minimum.

2. **FIPS-validated crypto module** — Requires either (a) proving the pyca stack
   is covered by the host OS FIPS module certificate (needs legal/compliance sign-off
   from NIST CMVP), or (b) replacing `dilithium_py` with a validated PQC
   implementation that does not yet exist in the Python ecosystem as of 2026. A CNSA
   2.0 waiver path exists but requires a separate government approval process.

3. **Data-at-rest encryption for 100+ SQLite databases** — SQLCipher migration
   touches every engine. Key-per-tenant architecture requires a KMS integration that
   does not yet exist. Risk of breaking existing data on upgrade is high.

4. **Audit log tamper-evidence** — Replacing the self-contained HMAC chain with an
   external WORM-capable log sink requires infrastructure changes (syslog target,
   CloudTrail, or equivalent) in every deployment environment, plus an audit of
   every engine that writes to a local audit table.

5. **SAML signature bypass removal + `signxml` hardening** — The code change is
   small (delete three `return` statements), but the operational consequence is
   that every dev/CI/CD environment that currently relies on `FIXOPS_DEV_MODE=true`
   for local SAML testing will break. Requires a new dev-auth strategy before the
   production fix can ship without breaking the development workflow.

---

*Generated by security-architect agent — evidence grounded in code as of 2026-06-01.*
*Source files: `suite-core/core/crypto.py`, `suite-core/core/fips_encryption.py`,*
*`suite-core/core/airgap_deployment.py`, `suite-core/core/evidence_chain.py`,*
*`suite-core/core/compliance_engine.py`, `suite-api/apps/api/auth_router.py`,*
*`suite-api/apps/api/oauth2_router.py`, `suite-api/apps/api/auth_deps.py`*
