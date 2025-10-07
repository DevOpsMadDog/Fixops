# Security Hardening Guidance

This document captures the operational safeguards required to run FixOps in
regulated environments.

## Overlay allowlist enforcement

- **Pre-provision allowlisted roots.** Create each directory listed in
  `overlay.allowed_data_roots` ahead of time and ensure they are owned by the
  deployment user (or `root`) with permissions no broader than `0750`.
- **Avoid temporary paths.** Deny roots located under world-writable parents
  such as `/tmp`; FixOps now validates each ancestor before any artefacts are
  written.
- **Do not rely on lazy creation.** The API and CLI refuse to create new
  directories when the allowlisted root is missing or has insecure ownership or
  permission bits. Provision infrastructure via configuration management so the
  process only touches vetted locations.

## Runtime hygiene

- **Review overlay changes.** Treat modifications to `config/fixops.overlay.yml`
  as privileged operations; they control directory allowlists, upload limits,
  and authentication settings.
- **Rotate API tokens.** When using `auth.strategy: token`, rotate entries in
  `overlay.auth_tokens` and redeploy. Tokens are cached at startup.
- **Harden filesystem backups.** Evidence bundles and artefact archives contain
  sensitive remediation details. Store backups on encrypted volumes that inherit
  the same ownership/permission checks described above.

## Signing key management

- **Configure a signing provider.** Set `SIGNING_PROVIDER` and (if applicable)
  `KEY_ID` to select between environment-backed keys and external HSM/KMS
  integrations. The defaults (`env`) expect `SIGNING_PRIVATE_KEY` and
  `SIGNING_PUBLIC_KEY` PEM strings to be supplied via secrets management.
- **Protect key backups.** Store private keys encrypted-at-rest and restrict
  operator access to dedicated security administrators. Public key fingerprints
  are embedded in each evidence record to allow non-repudiation checks.
- **Plan rotations.** Use the provider `rotate()` capability to generate new key
  material while retaining prior public keys for signature verification. Ensure
  rotation schedules are documented alongside recovery procedures so audits can
  confirm adherence.
