# SSRF Analysis Report

## 1. Executive Summary

- **Analysis Status:** Complete
- **Key Outcome:** Five high-to-medium confidence server-side request forgery vulnerabilities were identified across the DAST scanner, integration connectors (Jira, ServiceNow), webhook subscription delivery (DNS rebinding), and cascading SSRF via unvalidated JWKS URIs derived from OIDC discovery documents. The dominant pattern is insufficient or absent private-IP validation at the point of outbound request construction.
- **Purpose of this Document:** This report provides strategic context on the application's outbound request mechanisms, dominant flaw patterns, and key architectural details necessary to effectively exploit the vulnerabilities listed in the exploitation queue.

---

## 2. Dominant Vulnerability Patterns

### Pattern 1: Absent Private-IP Validation on Integration Connectors

- **Description:** The Jira and ServiceNow connector implementations accept a user-supplied `instance_url` / `base_url` at registration time and immediately use it for outbound HTTP requests (via `requests.Session`) with no IP-range, protocol, or DNS-resolution validation. There is no blocklist, no allowlist, and no SSRF-guard function called before the HTTP client fires.
- **Implication:** Any authenticated user holding the `write:integrations` API-key scope can register a connector pointing to an internal address (127.x, 10.x, 192.168.x, 169.254.169.254) and exfiltrate the full HTTP response via the `/test` endpoint.
- **Representative Findings:** `SSRF-VULN-02`, `SSRF-VULN-03`.

### Pattern 2: IP-Validation Bypass via Alternative Address Representations

- **Description:** The DAST scanner validates `target_url` with a combination of an explicit hostname blocklist and `ipaddress.ip_address()`. Because `ipaddress.ip_address("0177.0.0.1")` (octal notation for 127.0.0.1) raises `ValueError`, the guard function returns `False` (not private) and passes. The OS network stack (`urllib.request.urlopen`) subsequently resolves the octal literal to 127.0.0.1 via `inet_aton`. Decimal integer notation (`2130706433`) triggers the same bypass.
- **Implication:** An attacker with valid credentials can force the server to make HTTP requests to loopback/link-local services and receive up to 500 characters of the response body in the scan findings.
- **Representative Finding:** `SSRF-VULN-01`.

### Pattern 3: Time-of-Check / Time-of-Use DNS Rebinding

- **Description:** Webhook URL validation is performed once at subscription creation time using `_validate_webhook_url()` (which includes DNS resolution). At delivery time, the URL is fetched directly from the database with no re-validation. An attacker can register a legitimate domain that initially resolves to a public IP, then change the DNS record to point to a private IP before the first delivery attempt, bypassing the SSRF guard entirely.
- **Implication:** Once a DNS rebind succeeds, the delivery HTTP POST hits an internal service. The response HTTP status code is returned to the caller, enabling semi-blind port scanning and service fingerprinting of internal hosts.
- **Representative Finding:** `SSRF-VULN-04`.

### Pattern 4: Cascading SSRF via Unvalidated OIDC Sub-Endpoints

- **Description:** After successfully fetching the OIDC discovery document (which is validated via `_validate_url_not_private()`), the application extracts `jwks_uri` from the discovery JSON and passes it directly to `PyJWKClient(jwks_uri)` without any validation. A malicious or compromised OIDC discovery document can therefore point `jwks_uri` to an internal address, causing the application to make an unauthenticated outbound HTTP GET to that address during token validation.
- **Implication:** The SSRF guard applied to `issuer_url` is bypassed entirely because it is not applied to fields extracted from the discovery document. Impact depends on the ability to control the discovery endpoint content.
- **Representative Finding:** `SSRF-VULN-05`.

---

## 3. Strategic Intelligence for Exploitation

- **HTTP Client Libraries:**
  - `urllib.request` — used by the DAST scanner (`dast_scanner.py`) and n8n connector (`n8n_connector.py`)
  - `requests` (third-party) — used by Jira/ServiceNow connectors and webhook delivery (`webhook_subscriptions_router.py`)
  - `httpx` (async) — used by the SSO provider (`sso_provider.py`) and GitHub Enterprise connector (`sdlc_connectors.py`)

- **Request Architecture:**
  - The DAST scanner (`suite-attack/`) is mounted in the **same FastAPI application** as the main API (`suite-api/`) on port 8000. There is no separate process or port.
  - The DAST scanner auth dependency (`_auth_dep`) has a passthrough fallback: if `core.auth_middleware` fails to import, `_fallback_auth` always succeeds, making `POST /api/v1/dast/scan` effectively unauthenticated.
  - The `n8n_router.py` exists in the codebase but is **not mounted** in any FastAPI application — its endpoints are not reachable.
  - Connector endpoints (`/api/v1/connectors/*`) are protected by `_verify_api_key` + `write:integrations` scope; webhook subscription endpoints require a valid `org_id` resolved from JWT middleware.

- **Internal Services of Interest (likely reachable from the server):**
  - `169.254.169.254` — AWS EC2 instance metadata (IAM credentials)
  - `metadata.google.internal` — GCP metadata (explicit blocklist only in SSO guard)
  - `127.0.0.1:{2375,6379,5432,5678}` — Docker daemon, Redis, PostgreSQL, n8n (port 5678 in docker-compose)
  - Kubernetes API at `kubernetes.default.svc.cluster.local:443` if deployed in K8s

- **Response Exposure:**
  - DAST scanner: **Non-blind** — up to 500 chars of response body returned in findings
  - Jira/ServiceNow connector test: **Non-blind** — full parsed JSON response returned
  - Webhook delivery: **Semi-blind** — HTTP status code returned, no body

---

## 4. Detailed Vulnerability Findings

### SSRF-VULN-01 — DAST Scanner: IP Validation Bypass via Octal/Decimal IP Notation

**Endpoint:** `POST /api/v1/dast/scan`
**Vulnerable Parameter:** `target_url`
**Auth Required:** JWT or API key (passthrough fallback if middleware unavailable)

**Data Flow:**
1. User submits `{"target_url": "http://0177.0.0.1/"}` to `POST /api/v1/dast/scan`
2. `_validate_target_url("http://0177.0.0.1/")` is called in `suite-attack/api/dast_router.py:42`
3. `urlparse("http://0177.0.0.1/").hostname` → `"0177.0.0.1"`
4. `"0177.0.0.1"` is not in `_BLOCKED_HOSTS` (literal string check) → passes
5. `ipaddress.ip_address("0177.0.0.1")` raises `ValueError` → `_is_private_ip()` returns `False` → passes
6. Validation passes; URL forwarded to `dast_scanner.py`
7. `urllib.request.urlopen(Request("http://0177.0.0.1/"))` fires at `dast_scanner.py:464-474`
8. OS `inet_aton("0177.0.0.1")` resolves to `127.0.0.1`; loopback service receives request
9. Up to 500 chars of response body returned in scan result `response_body_snippet`

**Sink Location:** `suite-core/core/dast_scanner.py:464-474` (urllib.request.urlopen)
**Validation Location:** `suite-attack/api/dast_router.py:34-55`
**Missing Defense:** `_is_private_ip()` only calls `ipaddress.ip_address(host)` on the raw string; alternative notations (octal `0177.0.0.1`, decimal `2130706433`) raise `ValueError` and are silently passed

**Confidence:** High

---

### SSRF-VULN-02 — Jira Connector: No Private IP Validation on instance_url

**Endpoints:** `POST /api/v1/connectors/register` (register), `POST /api/v1/connectors/{name}/test` (trigger)
**Vulnerable Parameter:** `jira.base_url`
**Auth Required:** API key + `write:integrations` scope

**Data Flow:**
1. Attacker registers connector: `POST /api/v1/connectors/register` with `{"type":"jira","jira":{"base_url":"http://169.254.169.254"},...}`
2. Only scheme validation performed (`http`/`https` check) — no IP/hostname validation
3. Config stored with `base_url = "http://169.254.169.254"`
4. Attacker calls `POST /api/v1/connectors/jira-test/test`
5. `test_connection()` builds URL: `f"{base_url}/rest/api/3/myself"` → `"http://169.254.169.254/rest/api/3/myself"`
6. `requests.session.get(url)` fires at `suite-core/core/jira_sync.py:492` (or test_connection equivalent)
7. EC2 metadata service responds; parsed JSON returned to caller

**Sink Location:** `suite-core/core/jira_sync.py:492-501`
**Missing Defense:** No SSRF guard; only scheme check on `base_url` at registration

**Confidence:** High

---

### SSRF-VULN-03 — ServiceNow Connector: Zero Validation on instance_url

**Endpoints:** `POST /api/v1/connectors/register` (ServiceNow type), trigger via sync operations
**Vulnerable Parameter:** `servicenow.instance_url`
**Auth Required:** API key + `write:integrations` scope

**Data Flow:**
1. Attacker registers ServiceNow connector with arbitrary `instance_url`
2. **No validation whatsoever** on the URL at registration time
3. `_url()` in `servicenow_sync.py:548` constructs target: `urljoin(instance_url, table_path)`
4. `requests.session.post(url)` fires at `servicenow_sync.py:569`
5. Response `resp.json()["result"]` returned to caller

**Sink Location:** `suite-core/core/servicenow_sync.py:569`
**Missing Defense:** No URL validation; not even a scheme check

**Confidence:** High

---

### SSRF-VULN-04 — Webhook Subscription: DNS Rebinding at Delivery

**Endpoints:** `POST /api/v1/webhook-subscriptions/` (register), `POST /api/v1/webhook-subscriptions/{id}/test` (trigger)
**Vulnerable Parameter:** `url`
**Auth Required:** org_id (resolved from JWT middleware; `get_org_id` does not independently enforce authentication)

**Data Flow (DNS Rebinding Attack):**
1. Attacker controls DNS for `attacker.example.com`; sets TTL to minimum (e.g., 1 second)
2. Attacker calls `POST /api/v1/webhook-subscriptions/` with `{"url":"https://attacker.example.com/hook",...}`
3. `_validate_webhook_url()` resolves `attacker.example.com` → `203.0.113.45` (public IP) — passes
4. URL stored in SQLite subscriptions table
5. Attacker flips DNS: `attacker.example.com` → `127.0.0.1`
6. System or attacker triggers delivery: `POST /api/v1/webhook-subscriptions/{id}/test`
7. `_deliver_webhook()` at `webhook_subscriptions_router.py:188` fetches URL from DB — **no re-validation**
8. `requests.post(sub["url"], ...)` at line 204 resolves hostname again → `127.0.0.1`
9. POST delivered to internal loopback service; HTTP status code returned

**Sink Location:** `suite-api/apps/api/webhook_subscriptions_router.py:204`
**Missing Defense:** URL is validated only at registration; DNS resolution is not pinned/repeated at delivery

**Confidence:** Medium (requires attacker-controlled DNS and timing window)

---

### SSRF-VULN-05 — OIDC Cascading SSRF via Unvalidated jwks_uri

**Endpoints:** `GET /api/v1/auth/sso/{provider}/callback` (triggers token validation)
**Vulnerable Parameter:** `jwks_uri` field extracted from OIDC discovery document
**Auth Required:** `admin:all` scope to configure `issuer_url`; public endpoint triggers the fetch

**Data Flow:**
1. Admin (or attacker with `admin:all`) sets `issuer_url` to an attacker-controlled server via `POST /api/v1/auth/sso`
2. Attacker's server serves a discovery document: `{"jwks_uri":"http://169.254.169.254/latest/meta-data/iam","issuer":"...",...}`
3. When any user attempts SSO login, `GET /api/v1/auth/sso/{provider}/callback` is triggered
4. `validate_token()` in `sso_provider.py:362` extracts `jwks_uri` from the cached discovery document
5. `PyJWKClient(jwks_uri)` is constructed at line 373 — **no validation of jwks_uri**
6. `client.get_signing_key_from_jwt(id_token)` fetches from `http://169.254.169.254/latest/meta-data/iam`
7. Internal service is hit; response (or error) surfaces through exception handling

**Sink Location:** `suite-core/core/sso_provider.py:373` (PyJWKClient constructor triggers network fetch)
**Missing Defense:** `_validate_url_not_private()` is applied to `issuer_url` but NOT to the `jwks_uri` extracted from the discovery document

**Confidence:** Medium (requires admin compromise or misconfigured OIDC provider)

---

## 5. Secure by Design: Validated Components

These components were analyzed and found to have robust defenses. They are low-priority for further testing.

| Component/Flow | Endpoint / File Location | Defense Mechanism Implemented | Verdict |
|---|---|---|---|
| OIDC Discovery URL fetch | `sso_provider.py:279` | `_validate_url_not_private()` with DNS resolution against all RFC1918 + loopback + link-local ranges; scheme restricted to https | SAFE |
| SAML IdP metadata fetch | `sso_provider.py:526` | Same `_validate_url_not_private()` guard applied before `httpx.Client.get()` | SAFE |
| Webhook subscription creation (scheme + IP check) | `webhook_subscriptions_router.py:113-131` | Requires HTTPS; resolves hostname via `socket.getaddrinfo()`; blocks RFC1918 + loopback + link-local | SAFE (at registration; DNS rebinding risk at delivery — see SSRF-VULN-04) |
| Slack connector URL | `connectors_router.py` | Only `hooks.slack.com` accepted via strict allowlist | SAFE |
| Bulk export file download | `bulk_router.py:988` | Symlink-resolved `relative_to()` + extension allowlist + `..`/`/`/`\` checks | SAFE (not SSRF) |
| n8n connector endpoints | `n8n_router.py` | Not mounted in any FastAPI application — endpoints unreachable | NOT ACCESSIBLE |
