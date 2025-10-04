# External Integrations

FixOps Demo primarily interacts with two categories of integrations:

1. **Parsing Libraries** used to normalise uploaded artefacts.
2. **Operational Systems** (Jira, Confluence, Git, CI) described via the overlay configuration so the
   service can adapt to Demo and Enterprise environments without code changes.

## Parsing Libraries

| Integration | Purpose | Invocation Point | Failure Mode & Handling |
| ----------- | ------- | ---------------- | ----------------------- |
| `lib4sbom` | Parses SPDX/CycloneDX SBOM documents into a common representation. | `InputNormalizer.load_sbom()` instantiates `SBOMParser`, reads the SBOM string, and extracts packages/relationships/services. | Propagates parser exceptions; the API converts them to HTTP 400 responses. |
| `cvelib` | Validates CVE/KEV records against the official schema. | `InputNormalizer.load_cve_feed()` calls `CveRecord.validate()` when available. | Missing library downgrades to best-effort ingestion; validation errors are reported in the response payload. |
| `snyk-to-sarif` | Converts proprietary Snyk JSON payloads into SARIF. | `InputNormalizer.load_sarif()` detects missing `runs` and calls `convert`/`to_sarif` if present. | Absent converter causes non-SARIF payloads to be rejected via `ValueError`, surfaced as HTTP 400. |
| `sarif-om` | Provides typed SARIF models for introspection. | `InputNormalizer.load_sarif()` instantiates `SarifLog` to expose metadata and simplify traversal. | Missing dependency raises a `RuntimeError` during import, signalling a deployment misconfiguration. |

All parsers run synchronously during request handling. Retry logic is unnecessary because failures are
caused by malformed uploads or missing dependencies rather than transient network issues.

## Overlay-Defined Operational Systems

| System | Overlay Keys | Usage | Error Handling & Retries |
| ------ | ------------- | ----- | ------------------------ |
| Jira | `jira.*` (e.g., `url`, `project_key`, `default_issue_type`, `workflow_scheme`) | Controls ticket synchronisation policies. `/pipeline/run` verifies `project_key` when `enforce_ticket_sync` is enabled. | Missing mandatory fields trigger HTTP 500 so deployers can correct the overlay. External API calls are not issued in this demo. |
| Confluence | `confluence.*` (`base_url`, `space_key`, `onboarding_page`) | Guides documentation links in downstream tooling. Currently surfaced via the overlay metadata block. | No runtime enforcement yet; future exporters should validate URLs before use. |
| Git Provider | `git.*` (`provider`, `host`, `default_org`/`default_group`) | Indicates where repositories live so future modules can scope pull-request checks. | Metadata only at this stage. Consumers should handle unreachable hosts with exponential backoff. |
| CI | `ci.*` (`provider`, `pipeline_slug`) | Annotates which pipeline to gate. Planned usage is to drive status checks. | No direct calls today; when implemented use provider-native retry/backoff (e.g., GitHub Actions workflow reruns). |
| Auth | `auth.*` (`strategy`, `token_env`, `client_id`) | Signals how downstream services should authenticate. Tokens are masked automatically in responses. | Missing secrets should be handled upstream by injecting environment variables before startup. |

The overlay metadata is attached to pipeline responses (unless disabled) so client applications can
render correct links and behave differently per mode without hard-coding environments.

## HTTP Surface

- All endpoints are public inside the FastAPI service. Deployments must layer authentication (API
  keys, OAuth, or SSO) at the ingress tier.
- CORS is intentionally wide open for local demos. Restrict `allow_origins` before exposing the API to
  untrusted networks.

## Observability

- The backend uses Python's standard logging. Configure handlers (e.g., JSON logs shipped to ELK) to
  capture normalisation metadata and error traces.
- Request metrics can be added via FastAPI middleware such as Prometheus, StatsD, or OpenTelemetry.
- Overlay metadata includes the loaded file path, which assists operators in confirming mode selection
  without shell access.
