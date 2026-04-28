# FIPS Compliance — OpenSSL FIPS Boundary

## FIPS-Friendly Code vs FIPS-Validated Module

These two concepts are frequently conflated. ALDECI enforces both.

### FIPS-Friendly Code

Code that uses only FIPS-approved algorithms (AES-GCM, SHA-256/384/512,
HMAC-SHA256, RSA-2048+, ECDSA-P256/P384) and avoids prohibited ones
(MD5, SHA-1, RC4, DES, Blowfish, 3DES).

ALDECI satisfies this by:
- Using the `cryptography` library (pyca/cryptography) for all cipher
  operations in `suite-core/core/fips_encryption.py`.
- Banning `Crypto.Cipher.ARC4`, `Crypto.Cipher.DES`, `Crypto.Cipher.Blowfish`,
  `Crypto.Hash.MD5/MD2/MD4` at boot time (see `fips_boot.py`).
- Maintaining an explicit FIPS 140-3 algorithm allow-list
  (`_fips_allowed_algorithms()`) that excludes MD5 and SHA-1.

FIPS-friendly code can run on any machine. It does NOT provide a
FIPS-validated cryptographic boundary.

### FIPS-Validated Module

A FIPS-validated module means the underlying cryptographic implementation
(OpenSSL's FIPS Provider, NSS FIPS mode, etc.) has been tested and certified
by an accredited CMVP laboratory under NIST FIPS 140-2 or 140-3.

For Python applications this requires:
1. An OS or container image built against a FIPS-validated OpenSSL build
   (e.g. RHEL 9 system crypto, Ubuntu FIPS via Canonical, Iron Bank
   hardened base images).
2. `pip install cryptography --no-binary :all:` compiled against the FIPS
   libcrypto so the `cryptography` package delegates to the validated module.
3. The kernel FIPS flag set: `/proc/sys/crypto/fips_enabled` == 1.

stdlib AES (`hashlib`, `hmac` via `_sha256` C extension) is NOT covered by
any FIPS 140 certificate regardless of the underlying OpenSSL. It bypasses
the FIPS provider boundary.

## ALDECI Runtime Enforcement

### Environment Variables

| Variable | Default | Effect |
|---|---|---|
| `FIPS_MODE_REQUIRED` | `0` | **Strongest**: implies `FIPS_MODE=1` + `FIPS_STRICT_BOOT=1`. Panics at startup with `RuntimeError` if OpenSSL FIPS module is not active. |
| `FIPS_MODE` | `0` | Request FIPS mode. Logs a warning if OpenSSL FIPS module is not active. Does not panic. |
| `FIPS_STRICT_BOOT` | `0` | Refuse to boot if kernel FIPS flag is 0 or non-FIPS libs detected. |
| `HSM_ENABLED` | `0` | Force HSM provider for key operations. |
| `FIPS_TENANT` | `default` | Tenant ID passed to `FIPSComplianceModeEngine.activate_fips_mode()`. |

### Startup Sequence (`fips_boot.py`)

1. Probe `ssl.OPENSSL_VERSION` and `/proc/sys/crypto/fips_enabled` to
   determine whether the OpenSSL FIPS module is active.
2. If `FIPS_MODE_REQUIRED=1` and OpenSSL FIPS is NOT active:
   raise `RuntimeError` immediately — container will not start.
3. If `FIPS_MODE_REQUIRED=0` and OpenSSL FIPS is not active:
   log a WARNING; continue in FIPS-friendly (non-validated) mode.
4. Scan for non-FIPS crypto libs (`Crypto.Cipher.ARC4`, DES, Blowfish, MD5
   families). Evict from `sys.modules`. Refuse boot if `FIPS_STRICT_BOOT=1`.
5. Probe HSM provider (if `HSM_ENABLED=1`).
6. Attach audit chain entry.
7. Activate `FIPSComplianceModeEngine` (best-effort).

### Status Endpoint

`GET /api/v1/fips/runtime-status` (no org scope required) returns:

```json
{
  "enabled": false,
  "openssl_version": "OpenSSL 3.0.7 1 Nov 2022",
  "validated_module": null,
  "algorithms_allowed": ["AES-128-GCM", "AES-256-GCM", "SHA-256", ...],
  "fips_mode_requested": false,
  "fips_mode_required": false,
  "cryptography_library": {
    "available": true,
    "version": "42.0.5",
    "backend": "openssl"
  }
}
```

When `enabled: true` the `validated_module` field is populated with the
OpenSSL version string of the FIPS-validated build.

`GET /api/v1/scif/boot` returns the full boot posture including HSM, audit
chain, and kernel FIPS flag — intended for ISSO/auditor review.

## Container Build Instructions — FIPS-Validated OpenSSL

### Iron Bank Base Image (DoD/FedRAMP)

```dockerfile
FROM registry1.dso.mil/ironbank/redhat/ubi/ubi9:latest

# RHEL 9 in FIPS mode: system OpenSSL is already FIPS-validated.
# Enable kernel FIPS flag:
RUN fips-mode-setup --enable || true

# Install Python FIPS-linked cryptography (compile from source
# against system libcrypto so the FIPS boundary is preserved).
RUN pip install --no-binary :all: cryptography

# ALDECI app
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt

ENV FIPS_MODE_REQUIRED=1
CMD ["uvicorn", "apps.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
```

### Ubuntu FIPS (Canonical)

```dockerfile
FROM ubuntu:22.04-fips  # Canonical FIPS-enabled image (requires UA subscription)

RUN apt-get update && apt-get install -y python3-dev libssl-dev build-essential
RUN pip install --no-binary :all: cryptography

ENV FIPS_MODE_REQUIRED=1
```

### Verification

After container start, confirm the FIPS boundary is active:

```bash
curl -s http://localhost:8080/api/v1/fips/runtime-status | jq .
# Expect: "enabled": true, "validated_module": "OpenSSL 3.x.x fips ..."

# Also check kernel:
cat /proc/sys/crypto/fips_enabled  # must return 1
```

## Customer Enabling

1. Set `FIPS_MODE_REQUIRED=1` in the container or pod environment.
2. Use an Iron Bank or Canonical FIPS base image (see above).
3. Rebuild `cryptography` from source against the FIPS libcrypto
   (`pip install --no-binary :all: cryptography`).
4. Deploy and verify via `GET /api/v1/fips/runtime-status`.

Without step 2, ALDECI will refuse to start (step 1 causes a `RuntimeError`
at boot), preventing silent degradation to non-validated crypto.

## Approved Algorithm List (FIPS 140-3)

Symmetric:
- AES-128-GCM, AES-256-GCM, AES-128-CBC, AES-256-CBC

Hashing:
- SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512

MAC:
- HMAC-SHA256, HMAC-SHA384, HMAC-SHA512

Asymmetric:
- RSA-2048, RSA-3072, RSA-4096
- ECDSA-P256, ECDSA-P384
- ECDH-P256, ECDH-P384

Explicitly prohibited (deprecated by FIPS 140-3):
- MD5 — broken collision resistance, not approved for any use
- SHA-1 — deprecated for signatures; not approved for new applications
- RC4, DES, 3DES, Blowfish, ARC4

## References

- NIST FIPS 140-3: https://csrc.nist.gov/publications/detail/fips/140/3/final
- CMVP certificate list: https://csrc.nist.gov/projects/cryptographic-module-validation-program
- OpenSSL FIPS Provider: https://www.openssl.org/docs/man3.0/man7/fips_module.html
- Iron Bank: https://ironbank.dso.mil
- pyca/cryptography FIPS notes: https://cryptography.io/en/latest/faq/#fips
