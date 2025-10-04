# Security Posture Review

This document enumerates how the FixOps ingestion service addresses common OWASP and platform risks.

## OWASP Top Concerns

| Risk | Mitigation | Code Reference |
| ---- | ---------- | -------------- |
| Injection (SQL/Command) | Service does not execute database queries or shell commands. Uploaded files are parsed using trusted libraries with no dynamic evaluation. | `backend/normalizers.py` uses typed parsers and json/csv modules only. |
| Broken Authentication | The demo service exposes unauthenticated endpoints for simplicity. Deployments should layer OAuth/API gateway auth in front of FastAPI. | `backend/app.py` (no auth); document requirement in `docs/INTEGRATIONS.md`. |
| Sensitive Data Exposure | Overlay metadata masks secrets before they leave the backend. Upload responses include only aggregated metadata. | `fixops/configuration.py` → `OverlayConfig._mask`; `backend/app.py` attaches masked overlay block. |
| XML/XXE | XML documents are not ingested. SBOM, SARIF, and CVE feeds are JSON-based, parsed with safe libraries. | `backend/normalizers.py` only uses JSON parsers. |
| SSRF | No outbound HTTP calls are made during ingestion. Future connectors should validate URLs and restrict hosts. | Documented in `docs/INTEGRATIONS.md`. |
| Unsafe Deserialisation | JSON parsing uses `json.loads` and SARIF typed models; no `pickle` or dynamic eval. | `backend/normalizers.py`. |
| Security Logging & Monitoring | Python logging captures stage names and exceptions without dumping raw payloads. Integrations doc recommends shipping to central log stores. | `backend/app.py` logger usage. |

## Secrets Management

- Overlay file should not contain raw tokens. Instead, reference environment variables via `auth.token_env`.
- Any key containing `token`, `secret`, or `password` is automatically masked by `OverlayConfig` before
  exposure.

## Transport Security

- Demo runs HTTP-only locally. Production deployments must terminate TLS at an ingress proxy.
- CORS is currently `*`; restrict origins when exposing the API to browsers.

## Error Handling

- Parser failures and configuration issues translate to HTTP 400/500 responses without leaking stack
  traces to clients.
- All exceptions are logged for operators.

## Next Steps

1. Introduce API key/OAuth middleware in front of FastAPI.
2. Add rate limiting at the ingress tier to deter brute-force upload attempts.
3. Extend overlay schema with audit logging destinations (e.g., syslog, SIEM webhook) and implement
   streaming of pipeline events.
