# Security Posture Review

This document enumerates how the FixOps ingestion service addresses common OWASP and platform risks.

## OWASP Top Concerns

| Risk | Mitigation | Code Reference |
| ---- | ---------- | -------------- |
| Injection (SQL/Command) | Service does not execute database queries or shell commands. Uploaded files are parsed using trusted libraries with no dynamic evaluation. | `apps/api/normalizers.py` uses typed parsers and json/csv modules only. |
| Broken Authentication | API key enforcement protects all ingestion and pipeline endpoints when `auth.strategy` is `token`. Enterprise profiles can swap to OIDC once upstream IdP is available. | `apps/api/app.py` `_verify_api_key`; `config/fixops.overlay.yml` auth stanza. |
| Sensitive Data Exposure | Overlay metadata masks secrets before they leave the backend and evidence bundles omit overlay data when toggled off. | `core/configuration.py` → `OverlayConfig._mask`; `core/evidence.py` toggle `include_overlay_metadata_in_bundles`. |
| XML/XXE | XML documents are not ingested. SBOM, SARIF, and CVE feeds are JSON-based, parsed with safe libraries. | `apps/api/normalizers.py` only uses JSON parsers. |
| SSRF | No outbound HTTP calls are made during ingestion. Future connectors should validate URLs and restrict hosts. | Documented in `docs/INTEGRATIONS.md`. |
| DoS via Oversized Uploads | Streamed reads enforce per-stage byte limits and reject unsupported content types, throttling untrusted clients. | `apps/api/app.py` `_read_limited` and `_validate_content_type`; overlay `limits.max_upload_bytes`. |
| Unsafe Deserialisation | JSON parsing uses `json.loads` and SARIF typed models; no `pickle` or dynamic eval. | `apps/api/normalizers.py`. |
| Security Logging & Monitoring | Python logging captures stage names and exceptions without dumping raw payloads. Integrations doc recommends shipping to central log stores. | `apps/api/app.py` logger usage. |

## Secrets Management

- Overlay file should not contain raw tokens. Reference environment variables via `auth.token_env`; loader now fails fast when the referenced variables are absent.
- Any key containing `token`, `secret`, or `password` is automatically masked by `OverlayConfig` before
  exposure.
- Data directories are resolved against an allowlist (`FIXOPS_DATA_ROOT_ALLOWLIST`) so overlays cannot
  traverse outside sanctioned paths, and runtime helpers enforce non-world-writable permissions when
  creating evidence, feedback, automation, feed, and archive directories (`core/paths.py`).
- Evidence bundles can be encrypted using Fernet-compatible keys supplied via `limits.evidence.encryption_env`
  to satisfy regulated tenant requirements; encrypted bundles are emitted with `.enc` suffixes (`core/evidence.py`).

## Transport Security

- Demo runs HTTP-only locally. Production deployments must terminate TLS at an ingress proxy.
- CORS is currently `*`; restrict origins when exposing the API to browsers.

## Error Handling

- Parser failures and configuration issues translate to HTTP 400/500 responses without leaking stack
  traces to clients.
- All exceptions are logged for operators.

## Next Steps

1. Add rate limiting at the ingress tier to deter brute-force upload attempts.
2. Extend overlay schema with audit logging destinations (e.g., syslog, SIEM webhook) and implement
   streaming of pipeline events.
3. Integrate OIDC provider support to replace API keys for enterprise single sign-on.
