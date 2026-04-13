# ALDECI CTEM+ Platform — Security Whitepaper

> Version: 1.0 | Classification: Public
> Last updated: 2026-04-12

---

## Executive Summary

ALDECI is an AI-native Continuous Threat Exposure Management (CTEM) and Application Security Posture Management (ASPM) platform designed for organizations that require enterprise-grade security without the $50,000–$500,000/year price tag of incumbent solutions. This whitepaper describes the security architecture, data protection controls, compliance posture, and operational security practices built into the ALDECI platform.

ALDECI is designed to operate in air-gapped environments, to encrypt all data at rest and in transit, and to produce the complete audit trail required by SOC 2, ISO 27001, HIPAA, and FedRAMP audits.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Data Encryption](#2-data-encryption)
3. [Air-Gap Deployment](#3-air-gap-deployment)
4. [Authentication and Authorization](#4-authentication-and-authorization)
5. [Audit Logging](#5-audit-logging)
6. [Network Security](#6-network-security)
7. [Compliance Readiness](#7-compliance-readiness)
8. [Penetration Testing](#8-penetration-testing)
9. [Vulnerability Management](#9-vulnerability-management)

---

## 1. Architecture Overview

### 1.1 Defense-in-Depth Layers

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 0: Network Perimeter                                      │
│  TLS 1.3 termination · DDoS mitigation · IP allowlisting         │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 1: API Gateway (FastAPI)                                  │
│  API key auth · JWT validation · Rate limiting · CORS policy     │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 2: Authorization (RBAC + OPA)                             │
│  6 RBAC roles · Open Policy Agent engine · Attribute-based rules │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 3: Application Logic                                      │
│  Input validation (Pydantic v2) · SQL parameterization · Limits │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 4: Data Layer                                             │
│  Encrypted volumes · SQLite WAL · PersistentDict state store     │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 5: Audit & Detection                                      │
│  Structured audit log (structlog) · Anomaly alerts · SIEM export │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Data Flow

All security findings flow through a 12-step Brain Pipeline:

1. Intake (SARIF / vendor JSON / CycloneDX normalization)
2. Deduplication (SHA-256 fingerprint, semantic clustering)
3. Enrichment (NVD, EPSS, KEV, ExploitDB — 28+ threat intel feeds)
4. CVSS/SSVC scoring
5. Context injection (asset criticality, business context)
6. LLM Council analysis (4-model consensus via Karpathy protocol)
7. Risk scoring and prioritization
8. Compliance control mapping
9. Remediation playbook generation
10. SLA assignment
11. Notification dispatch
12. TrustGraph indexing

No raw vulnerability data leaves the platform unless explicitly exported by an authorized user.

### 1.3 Component Isolation

Each major subsystem runs in its own process space within the container:
- **Scanner connectors** run as unprivileged worker threads
- **LLM Council** calls are made outbound over HTTPS with API keys stored in environment variables, never on disk
- **TrustGraph Knowledge Cores** are stored in an isolated data volume

---

## 2. Data Encryption

### 2.1 Encryption in Transit

| Connection | Protocol | Cipher |
|------------|----------|--------|
| Client ↔ API Gateway | TLS 1.3 | ECDHE-RSA-AES-256-GCM-SHA384 |
| API ↔ External Scanners | TLS 1.3 | mTLS where supported |
| API ↔ LLM Providers | TLS 1.3 | Provider-enforced |
| Container-to-container | Docker bridge (private subnet) | N/A (network isolated) |

TLS 1.0 and 1.1 are disabled. RC4, MD5, and DES cipher suites are explicitly rejected.

### 2.2 Encryption at Rest

| Data | Storage | Encryption |
|------|---------|------------|
| Findings database | Docker volume (`aldeci-data`) | Host-level encryption (dm-crypt / LUKS on Linux, FileVault on macOS) |
| State store | Docker volume (`aldeci-state`) | Host-level encryption |
| API keys (stored) | SQLite (hashed) | Argon2id hash — plaintext never persisted |
| JWT secrets | Environment variable | Not persisted to disk |
| LLM API keys | Environment variable | Not persisted to disk |

**FIPS 140-2 Note**: For FIPS 140-2 Level 1 compliance, deploy on a Linux host with FIPS mode enabled (RHEL 9 / Ubuntu 22.04 FIPS). The platform uses Python's `hashlib` (backed by OpenSSL) and `cryptography` library, both of which operate in FIPS mode when the host OpenSSL is FIPS-configured.

### 2.3 Secrets Management

ALDECI integrates with external secrets managers for production deployments:

```bash
# HashiCorp Vault
export FIXOPS_API_TOKEN=$(vault kv get -field=value secret/aldeci/api-token)

# AWS Secrets Manager
export FIXOPS_API_TOKEN=$(aws secretsmanager get-secret-value \
  --secret-id aldeci/api-token --query SecretString --output text)

# Kubernetes Secrets (via external-secrets-operator)
# Configured in docker/kubernetes/secrets.yaml
```

---

## 3. Air-Gap Deployment

ALDECI is designed to operate with zero internet egress after initial image pull.

### 3.1 Offline Container Image Bundle

```bash
# On internet-connected host: save all images
docker save \
  aldeci:latest \
  aldeci-ui:latest \
  dependencytrack/apiserver:4.12.3 \
  dependencytrack/frontend:4.12.3 \
  | gzip > aldeci-bundle-$(date +%Y%m%d).tar.gz

# On air-gapped host: load images
docker load < aldeci-bundle-20260412.tar.gz
docker compose up -d
```

### 3.2 Offline Threat Intelligence

Threat intel feeds can be pre-cached and loaded from a local mirror:

```bash
# Download NVD feed snapshots (run on internet host)
python3 scripts/cache_feeds.py --output /mnt/usb/feeds/

# On air-gapped host: point feeds to local cache
export ALDECI_FEED_SOURCE=file:///opt/aldeci/feeds/
```

### 3.3 Local LLM Inference (Air-Gap Mode)

For LLM Council in air-gapped environments, use Ollama with locally hosted models:

```bash
# Pull models before air-gap
ollama pull gemma2:27b
ollama pull qwen2.5-coder:32b

# Set environment to use local Ollama
export FIXOPS_USE_COUNCIL=1
export ALDECI_LLM_ENDPOINT=http://localhost:11434
export ALDECI_LLM_PROVIDER=ollama
```

### 3.4 No Phone-Home

ALDECI contains no telemetry, analytics beacons, or license call-home mechanisms. Network traffic from the platform is limited to:
- Outbound calls to configured scanner APIs (if any)
- Outbound calls to configured LLM providers (if any)
- Outbound calls to configured threat intel feed URLs (if any)

All of the above can be replaced with local/air-gapped equivalents.

---

## 4. Authentication and Authorization

### 4.1 API Key Authentication

- API keys are generated with `secrets.token_urlsafe(32)` — 256 bits of entropy
- Keys are hashed with Argon2id before storage; the plaintext is returned to the user only at creation
- Key rotation is enforced via configurable expiry (default: 90 days)
- IP allowlisting is supported per key

### 4.2 JWT Session Tokens

After OIDC/SAML authentication, ALDECI issues short-lived JWTs:
- Algorithm: RS256 (asymmetric, 4096-bit key pair)
- Access token TTL: 1 hour
- Refresh token TTL: 8 hours
- JWTs include: `sub`, `email`, `role`, `exp`, `iat`, `jti` (for revocation)

### 4.3 RBAC + OPA Policy Engine

Authorization decisions are enforced by Open Policy Agent (OPA) at the API gateway layer. Policies are defined in Rego and evaluated on every request:

```rego
# Example: only super_admin can delete findings
allow {
  input.method == "DELETE"
  input.path == ["api", "v1", "findings", _]
  input.user.role == "super_admin"
}
```

Policy files are in `suite-integrations/opa/`. Changes require a PR review and re-deployment.

### 4.4 Session Security

- CSRF tokens required on all state-mutating requests from the UI
- SameSite=Strict cookies
- Secure and HttpOnly flags set on all cookies
- Session invalidated immediately on role change or password reset

---

## 5. Audit Logging

### 5.1 What Is Logged

Every user action and API call produces a structured audit log entry:

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601 with milliseconds |
| `actor` | User ID or API key ID |
| `actor_ip` | Source IP address |
| `action` | `create`, `read`, `update`, `delete`, `login`, `logout` |
| `resource_type` | `finding`, `scan`, `user`, `api_key`, `report`, etc. |
| `resource_id` | UUID of affected resource |
| `outcome` | `success`, `failure`, `denied` |
| `reason` | Human-readable context |
| `request_id` | Correlation ID (propagated through pipeline) |

### 5.2 Log Storage and Integrity

- Audit logs are written to an append-only SQLite table with a per-entry HMAC-SHA256 chain
- The chain root is stored separately; tampering with any entry breaks the chain
- Logs are retained for 7 years by default (configurable; see Admin Guide)
- Logs can be streamed to external SIEM via syslog, HTTP, or Kafka

### 5.3 SIEM Integration

```bash
# Stream to Splunk HEC
export ALDECI_AUDIT_SIEM=splunk
export ALDECI_SPLUNK_HEC_URL=https://splunk.your-company.com:8088/services/collector
export ALDECI_SPLUNK_HEC_TOKEN=...

# Stream to Elasticsearch
export ALDECI_AUDIT_SIEM=elasticsearch
export ALDECI_ELASTIC_URL=https://elastic.your-company.com:9200
export ALDECI_ELASTIC_API_KEY=...
```

---

## 6. Network Security

### 6.1 Kubernetes Network Policies

A strict default-deny NetworkPolicy is applied in the `aldeci` namespace — only explicitly allowed pod-to-pod paths are permitted:

```bash
kubectl apply -f docker/kubernetes/networkpolicy.yaml
```

Allowed traffic:
- Ingress controller → UI pod (port 80)
- Ingress controller → API pod (port 8000)
- API pod → DTrack API pod (port 8080, if profile enabled)
- No pod-to-pod traffic outside the above

### 6.2 Rate Limiting

Default rate limits (configurable via `FIXOPS_DISABLE_RATE_LIMIT=0`):

| Endpoint Category | Limit |
|-------------------|-------|
| Authentication | 10 requests / minute / IP |
| API (read) | 1,000 requests / minute / key |
| API (write/scan) | 100 requests / minute / key |
| Report export | 10 requests / hour / key |

### 6.3 Input Validation

All API inputs are validated by Pydantic v2 models before reaching business logic:
- String length limits enforced
- UUID format validation on all ID fields
- Enum validation on severity, status, and type fields
- File upload size limits (max 50 MB for SARIF/JSON intake)
- No `eval()` or dynamic code execution in request handlers

### 6.4 Container Security

Docker containers run with:
- Non-root user (`aldeci`, UID 1000)
- Read-only root filesystem (data written only to mounted volumes)
- `no-new-privileges` security option
- Dropped capabilities: `ALL` (only `NET_BIND_SERVICE` retained if port < 1024)
- Seccomp profile: `runtime/default`

---

## 7. Compliance Readiness

### 7.1 SOC 2 Type II

ALDECI maps natively to SOC 2 Trust Service Criteria:

| Criteria | Controls Provided |
|----------|------------------|
| CC6 (Logical Access) | RBAC, MFA via OIDC, API key management, session timeouts |
| CC7 (System Operations) | Audit logging, anomaly detection, health monitoring |
| CC8 (Change Management) | Git-based deployment, PR review gates, automated testing |
| CC9 (Risk Mitigation) | CTEM pipeline, SLA tracking, evidence collection |

### 7.2 ISO 27001:2022

Annex A controls addressed: A.5 (Organizational), A.6 (People), A.7 (Physical), A.8 (Technological). Full control mapping document available on request.

### 7.3 HIPAA Technical Safeguards

| Safeguard | Implementation |
|-----------|---------------|
| Access Control (§164.312(a)) | RBAC + OPA + OIDC/SAML |
| Audit Controls (§164.312(b)) | Append-only structured audit log |
| Integrity (§164.312(c)) | HMAC audit chain, TLS in transit |
| Transmission Security (§164.312(e)) | TLS 1.3 mandatory |

### 7.4 FedRAMP (NIST SP 800-53)

ALDECI supports FedRAMP Low and Moderate baseline controls. Key controls:

| Control Family | Implementation |
|---------------|---------------|
| AC (Access Control) | RBAC, least privilege, session management |
| AU (Audit and Accountability) | Structured audit log, SIEM export, retention |
| IA (Identification and Authentication) | API keys (256-bit entropy), OIDC/SAML MFA |
| SC (System and Communications Protection) | TLS 1.3, network policies, container isolation |
| SI (System and Information Integrity) | Pydantic input validation, dependency scanning |

A full FedRAMP System Security Plan (SSP) template is available for enterprise customers.

---

## 8. Penetration Testing

### 8.1 Self-Scan Architecture

ALDECI performs continuous self-assessment using its own scanner stack:

- **SAST**: Semgrep runs on every commit (GitHub Actions)
- **SCA**: Snyk monitors `requirements.txt` for vulnerable dependencies
- **Container**: Trivy scans the `aldeci:latest` image on every build
- **Secrets**: Semgrep secrets rules + `detect-secrets` pre-commit hook

### 8.2 External Penetration Test Cadence

Recommended schedule:
- **Annual**: Full-scope external penetration test by an independent firm
- **Quarterly**: Automated DAST scan (OWASP ZAP or Burp Suite Enterprise)
- **On major release**: Targeted API security review

### 8.3 Responsible Disclosure

To report a security vulnerability in ALDECI:

1. Email: `security@devopsai.co`
2. Encrypt with our PGP key (available at `https://devopsai.co/.well-known/security.txt`)
3. Include: affected component, reproduction steps, impact assessment
4. We commit to: acknowledge within 24h, remediate critical within 24h, publish advisory within 90 days

---

## 9. Vulnerability Management

### 9.1 Dependency Update Policy

- **Critical CVEs**: Patched within 24 hours of disclosure
- **High CVEs**: Patched within 7 days
- **Medium CVEs**: Addressed in next scheduled release (2-week sprint)
- Dependabot is enabled on the GitHub repository for automated PRs

### 9.2 Container Base Image

The `aldeci:latest` image is based on `python:3.11-slim-bookworm` (Debian 12):
- Base image rebuilt weekly to pull OS-level patches
- Multi-stage build: build dependencies not included in final image
- Image is scanned by Trivy before each release; build fails on CRITICAL findings

### 9.3 Software Bill of Materials (SBOM)

A CycloneDX SBOM is generated on every release:

```bash
# Generate SBOM for the running container
docker run --rm aldeci:latest \
  python3 -m cyclonedx_py environment -o sbom.json

# Submit to Dependency-Track for ongoing monitoring
curl -X POST "http://localhost:8080/api/v1/bom" \
  -H "X-Api-Key: $DTRACK_API_KEY" \
  -F "autoCreate=true" \
  -F "projectName=aldeci-api" \
  -F "projectVersion=$(git rev-parse --short HEAD)" \
  -F "bom=@sbom.json"
```

### 9.4 Known Limitations

- SQLite is not suitable for more than ~50 concurrent write-heavy users. Migrate to PostgreSQL for high-concurrency deployments (see `docs/DEPLOYMENT_GUIDE.md`).
- The demo mode (`ALDECI_SEED_DEMO=1`) should never be enabled in production — it creates predictable test users.
- Air-gap deployments using local Ollama models may receive lower-quality LLM Council analysis than deployments using frontier models (Claude Opus, GPT-4).

---

*For deployment configuration see `docs/DEPLOYMENT_GUIDE.md`. For admin operations see `docs/ADMIN_GUIDE.md`. For API usage see `docs/API_QUICKSTART.md`.*

---

**ALDECI Security Team** | `security@devopsai.co` | https://devopsai.co
