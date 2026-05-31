# ALDECI Security Whitepaper

## Summary

ALDECI is designed to handle sensitive security findings, vulnerability data, and compliance evidence for enterprise organisations. This document describes the platform's own security posture: how data is protected at rest and in transit, how access is controlled, how the audit trail is maintained, and what compliance certifications are current or in progress.

Honesty note: where controls are in progress rather than fully attested, this document says so explicitly.

---

## 1. Encryption

### 1.1 Encryption in Transit

All API traffic is TLS 1.2 or 1.3 only. The Fly.io deployment enforces HTTPS at the edge via `force_https = true` in `fly.toml`. HTTP requests are redirected to HTTPS automatically. Internal service-to-service communication inside the Fly private network (`fly-mesh`) uses mutual TLS.

TLS certificates are provisioned and auto-renewed by Fly.io via Let's Encrypt. For custom domain deployments, bring-your-own certificates are supported via `flyctl certs create`.

### 1.2 Encryption at Rest

All persistent data is stored on a Fly.io volume (`aldeci_data` mounted at `/app/data`). Fly.io volumes are encrypted at rest using AES-256. SQLite database files (one per domain, e.g. `findings.db`, `audit.db`, `evidence.db`) reside on this encrypted volume.

Sensitive connector credentials stored by the connector framework are kept in the database and are not logged or returned in API responses after initial registration.

### 1.3 Cryptographic Key Management

RSA-4096 keys used for evidence bundle signing are managed via a three-layer cache:

1. In-memory module singleton (`RSAKeyManager._KEY_CACHE`)
2. Disk persistence at `data/keys/*.pem`
3. On-demand generation when no persisted key exists

Source reference: `suite-core/core/crypto.py:RSAKeyManager`.

FIPS-mode readiness is configurable via the `FIPS_MODE_REQUIRED=1` environment variable. When set, the crypto layer restricts itself to FIPS-approved algorithms. Full FIPS 140-2 validation of the underlying Python `cryptography` library is the responsibility of the deployment environment; ALDECI enforces algorithm selection but does not independently certify the hardware security module.

---

## 2. Authentication

### 2.1 API Key Authentication

The primary authentication mechanism is a static API key passed as the `X-API-Key` header. The server-side key is set via environment variable `FIXOPS_API_TOKEN` (for Fly.io: `flyctl secrets set FIXOPS_API_TOKEN=<value>`). The key is never logged.

Multi-key support (per-service-account API keys) is managed via `POST /api/v1/apikeys` (scope: `admin:all`).

### 2.2 JWT Authentication

Short-lived JSON Web Tokens are issued by `POST /api/v1/users/login`. Token lifetime defaults to 1 hour and is configurable via `FIXOPS_JWT_EXPIRY_SECONDS`. The signing secret is `FIXOPS_JWT_SECRET` (minimum 32 bytes). Tokens carry `org_id` and `scopes` claims.

### 2.3 OAuth2 / OIDC

Machine-to-machine clients use `POST /api/v1/oauth2/token` (client credentials flow). Interactive SSO for browser-based login uses `GET /api/v1/sso/login`, `GET /api/v1/sso/callback` — supporting SAML 2.0 and OIDC identity providers (Okta, Azure AD, Google Workspace, Keycloak). Source: `suite-api/apps/api/sso_router.py`.

### 2.4 IAM / SSO via Keycloak

Enterprise deployments can proxy authentication through a Keycloak instance via `suite-api/apps/api/iam_sso_router.py`. This enables existing enterprise IdP integrations without custom connector development.

---

## 3. Authorisation (RBAC)

ALDECI enforces attribute-based role permissions at every API endpoint via `Depends(_verify_api_key)` and `Depends(_require_scope(...))` FastAPI dependencies.

### 3.1 Role Definitions

Six built-in roles are defined in `suite-core/core/rbac_engine.py:ROLES`:

| Role | Key Scopes | Typical User |
|------|-----------|--------------|
| `super_admin` | `admin:all`, `read:*`, `write:*`, `attack:execute` | Platform owner / SRE |
| `org_admin` | `admin:org`, `read:*`, `write:*` | CISO, security manager |
| `security_engineer` | `read:findings`, `write:findings`, `read:graph`, `write:integrations` | Security engineer |
| `analyst` | `read:findings`, `read:graph`, `read:scans` | SOC analyst |
| `viewer` | `read:findings` (read-only) | Compliance officer, stakeholder |
| `compliance_auditor` | `read:findings`, `read:graph` (inherits `viewer`) | External auditor |

Roles are hierarchical — `org_admin` inherits all scopes from `security_engineer`, which inherits from `analyst`, and so on.

### 3.2 Cross-Tenant Isolation

Every finding, audit log entry, connector, and evidence bundle is scoped to an `org_id`. API queries that omit `org_id` default to the caller's own organisation. Only `super_admin` with `admin:all` scope can issue cross-tenant queries. Source: `suite-core/core/rbac_engine.py:check_cross_tenant_access`.

### 3.3 Role Assignment API

```bash
# Assign analyst role to a user
curl -s -X POST https://aldeci.fly.dev/api/v1/rbac/assign \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"org_id": "acme", "user_id": "u-123", "role": "analyst"}'

# Revoke a role
curl -s -X DELETE https://aldeci.fly.dev/api/v1/rbac/revoke \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"org_id": "acme", "user_id": "u-123", "role": "analyst"}'
```

---

## 4. Audit Logging

Every API write operation is recorded in an append-only audit log (`suite-core/core/audit_log.py`).

### 4.1 What is logged

- Actor identity (user ID or service account)
- IP address and User-Agent
- HTTP method and endpoint path
- Payload SHA-256 hash (not the payload itself)
- Timestamp (UTC, microsecond precision)
- Organisation (`org_id`)
- Outcome (success / failure / error code)

### 4.2 Retention

Default retention is 90 days. Configure via `FIXOPS_AUDIT_RETENTION_DAYS` (clamped to 1–3650 days). A daemon thread runs the purge daily (`audit_log.py:_start_retention_daemon`). To disable automatic purge: `FIXOPS_DISABLE_AUDIT_RETENTION=1`.

### 4.3 Export

```bash
# Export last 30 days of audit log
curl -s -H "X-API-Key: $ALDECI_API_KEY" \
  "https://aldeci.fly.dev/api/v1/audit?org_id=acme&from_ts=2026-05-01T00:00:00Z" \
  | python3 -m json.tool > audit-export.json
```

---

## 5. Multi-Tenancy

ALDECI is a multi-tenant platform. Each organisation's data is isolated by `org_id` at the application layer. Database files are per-domain SQLite; rows carry `org_id` as a non-nullable indexed column. The ORM and query layer reject cross-tenant queries unless the caller holds `admin:all`.

Network-level tenant isolation (separate database instances per tenant) is available in the Enterprise tier upon request.

---

## 6. Compliance Posture

### 6.1 SOC 2 Type II

SOC 2 Type II attestation is **in progress**. The audit period has commenced; the attestation letter is expected in Q4 2026. Current controls cover:

- Access control (CC6): RBAC enforced on all endpoints
- Change management (CC8): Git-based audit trail, rolling deploy strategy
- Availability (A1): Fly.io health checks, rolling deploys, volume snapshots
- Confidentiality (C1): Encryption at rest and in transit as described above

SOC 2 Type I readiness assessment was completed internally. Customers requiring a copy of the current controls matrix should contact their account representative.

### 6.2 Evidence Bundle Generation

ALDECI generates SOC 2 evidence bundles on demand:

```bash
curl -s -X POST https://aldeci.fly.dev/api/v1/evidence/bundles/generate \
  -H "X-API-Key: $ALDECI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"org_id": "acme", "type": "soc2", "period_start": "2026-01-01", "period_end": "2026-03-31"}'
```

Bundles include finding timelines, risk acceptance records, audit log excerpts, and council verdicts — pre-formatted for auditor review.

### 6.3 Compliance Frameworks

The compliance engine (`/api/v1/compliance-engine/frameworks`) currently maps controls to:

- CIS Controls v8
- NIST SP 800-53 Rev 5
- ISO 27001:2022
- PCI DSS v4.0
- HIPAA Security Rule
- SOC 2 Trust Services Criteria
- OWASP ASVS

Control mappings are automated where evidence can be derived from finding data. Manual attestation fields are available for controls that require human sign-off.

**FedRAMP, HIPAA, and PCI DSS formal certification:** Controls are mappable using the compliance engine, but ALDECI does not hold formal FedRAMP Authority to Operate, HIPAA Business Associate attestation, or PCI DSS QSA certification at this time. Organisations with these requirements should conduct their own gap analysis using the compliance engine output.

### 6.4 GDPR / Data Residency

The default Fly.io deployment runs in the `syd` (Sydney) region. Alternative regions (`iad`, `ord`, `fra`, `lhr`) are selectable by changing `primary_region` in `fly.toml` before deploy. All data remains in the selected region. No finding data is sent to third-party services; AI council queries send only the finding metadata (title, severity, CVE IDs) — not customer PII or source code.

---

## 7. Vulnerability Management (Platform's Own)

- Dependencies are tracked via `pip-audit` (Python) and `npm audit` (Node). Critical CVEs are patched within 30 days.
- Input validation is enforced on all API endpoints via Pydantic v2 models.
- File upload endpoints enforce extension allowlists and maximum sizes (100 MB for uploads, 50 MB for webhooks) — see `suite-api/apps/api/scanner_ingest_router.py`.
- Path traversal in filenames is blocked by `_validate_filename()` in the scanner ingest router.
- SQL injection protection is provided by SQLAlchemy parameterised queries throughout.

---

## 8. Air-Gap Deployment

ALDECI supports fully air-gapped deployment for environments without internet access. The air-gap bundle endpoint (`GET /api/v1/air-gap/bundle`) packages all required Python wheels and static assets. Configure using `FIXOPS_MODE=airgap`. AI council features require a locally hosted LLM endpoint; set `OPENROUTER_API_KEY` to point to an internal proxy.

---

## 9. Penetration Testing and Disclosure

ALDECI welcomes security research. Contact `security@devopsai.co` to arrange a coordinated disclosure or to request approval for penetration testing against a dedicated test instance. Do not test against the production `aldeci.fly.dev` endpoint without prior written approval.

---

## 10. Contact

| Purpose | Contact |
|---------|---------|
| Security disclosures | security@devopsai.co |
| Compliance inquiries | compliance@devopsai.co |
| SOC 2 report requests | Via your account representative |
