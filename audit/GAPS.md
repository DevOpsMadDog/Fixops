# Known Gaps & Correctness Risks

This log captures technical debt, TODOs, and intentional trade-offs. Each entry specifies scope,
impact, and remediation plan.

## Immediate Follow-Ups

| Area | File / Snippet | Issue | Plan |
| ---- | -------------- | ----- | ---- |
| Authentication | `apps/api/app.py` (API key verification) | ✅ Implemented — token strategy enforces `X-API-Key` header backed by overlay env vars. | Roll forward to multi-tenant identity (OIDC) for enterprise mode. |
| Overlay Validation | `core/configuration.py` (`load_overlay`) | ✅ Implemented — pydantic schema with forbidden extras and immediate secret validation. | Extend to schema-level validation for nested sections (policy actions, compliance controls). |
| Directory Safety | `core/configuration.py` `data_directories` | ✅ Implemented — allowlisted roots and resolution guards prevent traversal. | Add runtime permission checks before provisioning in hardened deployments. |
| Upload Hardening | `apps/api/app.py` upload handlers | ✅ Implemented — staged reads enforce per-stage byte limits and content-type validation. | Monitor memory footprint under sustained load and consider streaming normalisers. |
| Feedback Capture | `apps/api/app.py` `/feedback` | ✅ Implemented — overlay-enabled recorder persists JSONL feedback bundles. | Integrate with Jira/Confluence for long-term storage and analytics. |

## Deferred Items

| Area | File / Snippet | Issue | Deferred Reason |
| ---- | -------------- | ----- | --------------- |
| Evidence Persistence | `apps/api/app.py` `_store` | Artefacts only stored in-memory; restarts drop context. | Demo scope avoids storage complexity; enterprise build should persist to database/object store. |
| SBOM Parser Coverage | `apps/api/normalizers.py` `load_sbom` | Relies on optional `lib4sbom`; limited error classification. | Acceptable for prototype; plan to add provider-specific error codes later. |
| SARIF Converter | `apps/api/normalizers.py` `load_sarif` | Snyk conversion optional; if converter missing we reject payload. | Documented requirement; revisit once enterprise bundler needs guaranteed support. |

## Operational Risks

- Overlay secrets rely on environment variables. Without secret management (Vault, AWS Secrets Manager)
  operators might inject wrong values. **Status:** mitigated — loader now verifies required env vars
  exist; still recommend managing rotation via dedicated secret store.
- Directory creation occurs at startup without permission checks. Harden by verifying ownership and
  file-system ACLs in hardened deployments.
- Evidence bundles embed overlay metadata (including plan limits and directory layout). **Status:**
  mitigated — toggle `include_overlay_metadata_in_bundles` now controls exposure; encryption guidance
  remains for regulated tenants.

## New Follow-Ups

- Expand policy automation to execute downstream actions (Jira/Confluence) instead of planning only.
- Capture feedback analytics (counts, sentiment) and surface in pricing/ROI dashboards.
- Add calibration tooling for the probabilistic forecast engine (Bayesian priors & Markov transitions) so tenants can tune matrices using historical incident data.
