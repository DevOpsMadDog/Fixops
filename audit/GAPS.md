# Known Gaps & Correctness Risks

This log captures technical debt, TODOs, and intentional trade-offs. Each entry specifies scope,
impact, and remediation plan.

## Immediate Follow-Ups

| Area | File / Snippet | Issue | Plan |
| ---- | -------------- | ----- | ---- |
| Authentication | `backend/app.py` (no auth middleware) | Endpoints are publicly accessible. | Introduce OAuth/API key middleware or front service with gateway before production launch. |
| Overlay Validation | `fixops/configuration.py` (`load_overlay`) | Schema is permissive; typos (e.g., guardrail thresholds) silently accepted. | Add pydantic model or JSON schema validation to reject unexpected keys and provide actionable errors. |
| Directory Safety | `fixops/configuration.py` `data_directories` → `fixops/evidence.py` | Overlay-controlled paths are trusted and created on disk. | Restrict overlays to whitelisted roots and reject relative traversal before provisioning directories. |
| Upload Hardening | `backend/app.py` upload handlers | Files are fully read into memory; no size or type guardrails. | Add `UploadFile.spool_max_size`, content-length checks, and stream parsers to prevent DoS via oversized artefacts. |
| Feedback Capture | Overlay toggle `capture_feedback` | Toggle documented but no implementation. | Implement persistence layer (database or Jira issue comments) in future iteration and honour toggle. |

## Deferred Items

| Area | File / Snippet | Issue | Deferred Reason |
| ---- | -------------- | ----- | --------------- |
| Evidence Persistence | `backend/app.py` `_store` | Artefacts only stored in-memory; restarts drop context. | Demo scope avoids storage complexity; enterprise build should persist to database/object store. |
| SBOM Parser Coverage | `backend/normalizers.py` `load_sbom` | Relies on optional `lib4sbom`; limited error classification. | Acceptable for prototype; plan to add provider-specific error codes later. |
| SARIF Converter | `backend/normalizers.py` `load_sarif` | Snyk conversion optional; if converter missing we reject payload. | Documented requirement; revisit once enterprise bundler needs guaranteed support. |

## Operational Risks

- Overlay secrets rely on environment variables. Without secret management (Vault, AWS Secrets Manager)
  operators might inject wrong values. Add validation checks that confirm referenced env vars exist at
  startup.
- Directory creation occurs at startup without permission checks. Harden by verifying ownership and
  file-system ACLs in hardened deployments.
- Evidence bundles embed overlay metadata (including plan limits and directory layout). Treat bundle
  stores as sensitive, encrypt at rest, or provide an option to omit overlay details when exporting.
