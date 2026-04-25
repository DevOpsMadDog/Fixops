"""Seed real-format DAST findings for juice-shop-corp.

Uses the published OWASP ZAP report JSON format and Nuclei JSONL hit format
(documented in their respective repositories) to produce 30+ findings — real
vulnerabilities you'd expect to see when scanning OWASP Juice Shop with a DAST
toolchain. Findings are persisted to ``SecurityFindingsEngine`` via the
``DastPentestConnector`` ingest paths so they show up on the tenant's
dashboard with ``source_tool='dast_via_zap'`` and ``source_tool='dast_via_nuclei'``.

Run::

    python scripts/seed_dast_juice_shop.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "suite-core"))

from connectors.dast_pentest_connector import DastPentestConnector  # noqa: E402

ORG_ID = "juice-shop-corp"
TARGET = "http://localhost:3001"

# ---- ZAP report (real format produced by zap-baseline.py -J) ---------------
# Each `alerts` entry mirrors the ZAP API. riskcode: 0=info, 1=low, 2=med,
# 3=high, 4=critical.
ZAP_REPORT = {
    "@version": "2.14.0",
    "@generated": "Sat, 25 Apr 2026 21:00:00",
    "site": [
        {
            "@name": TARGET,
            "@host": "localhost",
            "@port": "3001",
            "@ssl": "false",
            "alerts": [
                {
                    "pluginid": "40012",
                    "alertRef": "40012-1",
                    "alert": "Cross Site Scripting (Reflected)",
                    "name": "Cross Site Scripting (Reflected)",
                    "riskcode": "3",
                    "confidence": "2",
                    "riskdesc": "High (Medium)",
                    "desc": "Reflected XSS in search parameter allows attacker-controlled script execution.",
                    "instances": [
                        {"uri": f"{TARGET}/#/search?q=<script>alert(1)</script>", "method": "GET", "param": "q"}
                    ],
                    "solution": "Encode user input on output and validate query parameters.",
                    "reference": "https://owasp.org/www-community/attacks/xss/",
                    "cweid": "79",
                    "wascid": "8",
                },
                {
                    "pluginid": "40018",
                    "alert": "SQL Injection",
                    "name": "SQL Injection",
                    "riskcode": "4",
                    "confidence": "3",
                    "desc": "SQL injection in /rest/user/login allowed authentication bypass via ' OR 1=1--",
                    "instances": [
                        {"uri": f"{TARGET}/rest/user/login", "method": "POST", "param": "email"}
                    ],
                    "solution": "Use parameterized queries; never concatenate user input into SQL.",
                    "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
                    "cweid": "89",
                    "wascid": "19",
                },
                {
                    "pluginid": "40023",
                    "alert": "Possible Username Enumeration",
                    "name": "Possible Username Enumeration",
                    "riskcode": "2",
                    "desc": "Login error messages disclose whether the email exists.",
                    "instances": [
                        {"uri": f"{TARGET}/rest/user/login", "method": "POST"}
                    ],
                    "solution": "Return identical error messages for unknown user vs wrong password.",
                    "cweid": "204",
                    "wascid": "45",
                },
                {
                    "pluginid": "10202",
                    "alert": "Absence of Anti-CSRF Tokens",
                    "name": "Absence of Anti-CSRF Tokens",
                    "riskcode": "2",
                    "desc": "State-changing forms do not include anti-CSRF tokens.",
                    "instances": [
                        {"uri": f"{TARGET}/profile", "method": "POST"}
                    ],
                    "solution": "Implement synchronizer-token CSRF protection on all state-changing endpoints.",
                    "cweid": "352",
                    "wascid": "9",
                },
                {
                    "pluginid": "10038",
                    "alert": "Content Security Policy (CSP) Header Not Set",
                    "name": "CSP Header Not Set",
                    "riskcode": "2",
                    "desc": "Responses do not include a Content-Security-Policy header.",
                    "instances": [
                        {"uri": f"{TARGET}/", "method": "GET"}
                    ],
                    "solution": "Set a strict CSP that disallows inline scripts and untrusted sources.",
                    "cweid": "693",
                    "wascid": "15",
                },
                {
                    "pluginid": "10020",
                    "alert": "X-Frame-Options Header Not Set",
                    "name": "X-Frame-Options Header Not Set",
                    "riskcode": "2",
                    "desc": "Pages are vulnerable to clickjacking due to missing X-Frame-Options.",
                    "instances": [{"uri": f"{TARGET}/", "method": "GET"}],
                    "solution": "Set X-Frame-Options: DENY or use frame-ancestors in CSP.",
                    "cweid": "1021",
                    "wascid": "15",
                },
                {
                    "pluginid": "10035",
                    "alert": "Strict-Transport-Security Header Not Set",
                    "name": "HSTS Header Not Set",
                    "riskcode": "1",
                    "desc": "Strict-Transport-Security header missing — downgrade attacks possible.",
                    "instances": [{"uri": f"{TARGET}/", "method": "GET"}],
                    "solution": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains.",
                    "cweid": "319",
                    "wascid": "15",
                },
                {
                    "pluginid": "10021",
                    "alert": "X-Content-Type-Options Header Missing",
                    "name": "X-Content-Type-Options Missing",
                    "riskcode": "1",
                    "desc": "Allows MIME-type sniffing attacks.",
                    "instances": [{"uri": f"{TARGET}/", "method": "GET"}],
                    "solution": "Set X-Content-Type-Options: nosniff.",
                    "cweid": "693",
                    "wascid": "15",
                },
                {
                    "pluginid": "10054",
                    "alert": "Cookie Without SameSite Attribute",
                    "name": "Cookie Without SameSite Attribute",
                    "riskcode": "1",
                    "desc": "Session cookie lacks SameSite, allowing cross-site request inclusion.",
                    "instances": [{"uri": f"{TARGET}/rest/user/login", "method": "POST"}],
                    "solution": "Set SameSite=Strict or SameSite=Lax on all session cookies.",
                    "cweid": "1275",
                    "wascid": "13",
                },
                {
                    "pluginid": "10055",
                    "alert": "Cookie Without Secure Flag",
                    "name": "Cookie Without Secure Flag",
                    "riskcode": "1",
                    "desc": "Session cookie missing Secure flag — transmitted over plain HTTP.",
                    "instances": [{"uri": f"{TARGET}/rest/user/login", "method": "POST"}],
                    "solution": "Set the Secure attribute on all session cookies.",
                    "cweid": "614",
                    "wascid": "13",
                },
                {
                    "pluginid": "90033",
                    "alert": "Loosely Scoped Cookie",
                    "name": "Loosely Scoped Cookie",
                    "riskcode": "1",
                    "desc": "Cookie scoped to parent domain unnecessarily.",
                    "instances": [{"uri": f"{TARGET}/", "method": "GET"}],
                    "solution": "Scope cookies to the most specific path/domain required.",
                    "cweid": "565",
                    "wascid": "13",
                },
                {
                    "pluginid": "10049",
                    "alert": "Storable and Cacheable Content",
                    "name": "Cacheable Sensitive Content",
                    "riskcode": "1",
                    "desc": "Authenticated content can be cached by intermediate proxies.",
                    "instances": [{"uri": f"{TARGET}/rest/user/whoami", "method": "GET"}],
                    "solution": "Set Cache-Control: no-store on authenticated responses.",
                    "cweid": "524",
                    "wascid": "13",
                },
                {
                    "pluginid": "10063",
                    "alert": "Permissions Policy Header Not Set",
                    "name": "Permissions Policy Header Not Set",
                    "riskcode": "1",
                    "desc": "Permissions-Policy header missing — browser features default to permissive.",
                    "instances": [{"uri": f"{TARGET}/", "method": "GET"}],
                    "solution": "Set a restrictive Permissions-Policy header.",
                    "cweid": "693",
                    "wascid": "15",
                },
                {
                    "pluginid": "10096",
                    "alert": "Timestamp Disclosure - Unix",
                    "name": "Timestamp Disclosure",
                    "riskcode": "0",
                    "desc": "Unix timestamps disclosed in responses may reveal server-side timing info.",
                    "instances": [{"uri": f"{TARGET}/api/Quantitys", "method": "GET"}],
                    "solution": "Strip server-side timestamps from public responses.",
                    "cweid": "200",
                    "wascid": "13",
                },
                {
                    "pluginid": "40009",
                    "alert": "Server Side Include",
                    "name": "Server-Side Include Vulnerability",
                    "riskcode": "3",
                    "desc": "Server-side include directives can be injected into rendered pages.",
                    "instances": [{"uri": f"{TARGET}/profile", "method": "POST"}],
                    "solution": "Disable SSI parsing on the application server.",
                    "cweid": "97",
                    "wascid": "20",
                },
                {
                    "pluginid": "10095",
                    "alert": "Backup File Disclosure",
                    "name": "Backup File Disclosure",
                    "riskcode": "2",
                    "desc": "Backup files (.bak, ~) accessible at predictable URLs.",
                    "instances": [{"uri": f"{TARGET}/index.html.bak", "method": "GET"}],
                    "solution": "Remove backup files from production webroot; deny in webserver config.",
                    "cweid": "530",
                    "wascid": "34",
                },
                {
                    "pluginid": "40034",
                    "alert": ".htaccess Information Leak",
                    "name": ".htaccess Information Leak",
                    "riskcode": "2",
                    "desc": "/.htaccess accessible from the public webroot.",
                    "instances": [{"uri": f"{TARGET}/.htaccess", "method": "GET"}],
                    "solution": "Deny access to .htaccess files at the web server.",
                    "cweid": "215",
                    "wascid": "13",
                },
                {
                    "pluginid": "10027",
                    "alert": "Information Disclosure - Suspicious Comments",
                    "name": "Suspicious Comments in JS",
                    "riskcode": "0",
                    "desc": "JavaScript files contain TODO/FIXME comments referencing internal endpoints.",
                    "instances": [{"uri": f"{TARGET}/main.js", "method": "GET"}],
                    "solution": "Strip comments from production JS bundles.",
                    "cweid": "200",
                    "wascid": "13",
                },
            ],
        }
    ],
}

# ---- Nuclei hits (real -j JSONL format) ------------------------------------
NUCLEI_HITS = [
    {
        "template-id": "CVE-2014-3120",
        "info": {
            "name": "Elasticsearch Dynamic Script Arbitrary Java Execution",
            "severity": "high",
            "description": "Juice-Shop CTF: an Elasticsearch instance is exposed for the SSRF challenge.",
            "remediation": "Disable dynamic scripting; isolate ES from public network.",
            "classification": {
                "cve-id": ["CVE-2014-3120"],
                "cvss-score": 7.5,
                "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
        },
        "host": "localhost:3001",
        "matched-at": f"{TARGET}/api/Recyles",
    },
    {
        "template-id": "exposed-graphql-playground",
        "info": {
            "name": "Exposed GraphQL Playground",
            "severity": "medium",
            "description": "GraphQL playground exposed in production allows query introspection.",
            "remediation": "Disable GraphQL playground in production; require auth on /graphql.",
        },
        "host": "localhost:3001",
        "matched-at": f"{TARGET}/api/graphql",
    },
    {
        "template-id": "owasp-juice-shop-admin-section",
        "info": {
            "name": "Juice-Shop Admin Section Accessible",
            "severity": "high",
            "description": "/#/administration accessible to non-admin tokens (CTF challenge).",
            "remediation": "Server-side enforce admin role on /api/Users and /#/administration.",
        },
        "host": "localhost:3001",
        "matched-at": f"{TARGET}/#/administration",
    },
    {
        "template-id": "jwt-none-algorithm",
        "info": {
            "name": "JWT 'none' Algorithm Accepted",
            "severity": "critical",
            "description": "Server accepts unsigned JWTs ({\"alg\":\"none\"}) — full auth bypass.",
            "remediation": "Reject 'none' algorithm; pin verify algorithm to RS256/HS256.",
            "classification": {"cvss-score": 9.8},
        },
        "host": "localhost:3001",
        "matched-at": f"{TARGET}/rest/user/whoami",
    },
    {
        "template-id": "ssrf-juice-shop",
        "info": {
            "name": "SSRF via Order URL Parameter",
            "severity": "high",
            "description": "/api/track-result fetches arbitrary URL — internal services reachable.",
            "remediation": "Allow-list outbound destinations and block RFC1918 addresses.",
        },
        "host": "localhost:3001",
        "matched-at": f"{TARGET}/api/track-result?url=http://169.254.169.254/",
    },
    {
        "template-id": "directory-listing",
        "info": {
            "name": "Directory Listing Enabled at /ftp",
            "severity": "medium",
            "description": "Express static dir /ftp lists internal files.",
            "remediation": "Disable autoindex; require auth on internal mounts.",
        },
        "host": "localhost:3001",
        "matched-at": f"{TARGET}/ftp",
    },
    {
        "template-id": "xxe-juice-shop",
        "info": {
            "name": "XML External Entity (XXE) in /file-upload",
            "severity": "high",
            "description": "XML uploads are parsed with external entities enabled.",
            "remediation": "Disable DTD/external entity processing in the XML parser.",
            "classification": {"cve-id": ["CWE-611"]},
        },
        "host": "localhost:3001",
        "matched-at": f"{TARGET}/file-upload",
    },
    {
        "template-id": "deserialization-prototype-pollution",
        "info": {
            "name": "Prototype Pollution via Lodash Merge",
            "severity": "high",
            "description": "User-controlled JSON merged into Object.prototype — DoS / RCE chain.",
            "remediation": "Upgrade lodash >=4.17.21; sanitise user input keys.",
        },
        "host": "localhost:3001",
        "matched-at": f"{TARGET}/api/BasketItems",
    },
    {
        "template-id": "weak-jwt-secret",
        "info": {
            "name": "Weak JWT Signing Secret",
            "severity": "high",
            "description": "JWT signed with predictable HS256 secret 'secretKey'.",
            "remediation": "Rotate secret to 256-bit cryptographic key; load from KMS.",
        },
        "host": "localhost:3001",
        "matched-at": f"{TARGET}/rest/user/login",
    },
    {
        "template-id": "open-redirect-juice-shop",
        "info": {
            "name": "Open Redirect via /redirect?to=",
            "severity": "medium",
            "description": "/redirect?to=<url> blindly forwards to attacker site (phishing CTF).",
            "remediation": "Allow-list redirect targets to same-origin URLs.",
        },
        "host": "localhost:3001",
        "matched-at": f"{TARGET}/redirect?to=https://evil.example.com",
    },
    {
        "template-id": "exposed-package-json",
        "info": {
            "name": "package.json Exposed",
            "severity": "low",
            "description": "package.json reachable — discloses dependency versions for CVE matching.",
            "remediation": "Block static access to package.json from webroot.",
        },
        "host": "localhost:3001",
        "matched-at": f"{TARGET}/package.json",
    },
    {
        "template-id": "robots-txt-disclosure",
        "info": {
            "name": "robots.txt Discloses Internal Paths",
            "severity": "info",
            "description": "/robots.txt names admin paths.",
            "remediation": "Avoid listing sensitive paths in robots.txt; rely on auth.",
        },
        "host": "localhost:3001",
        "matched-at": f"{TARGET}/robots.txt",
    },
    {
        "template-id": "vulnerable-jquery-1.x",
        "info": {
            "name": "Vulnerable jQuery 1.6.2 Detected",
            "severity": "medium",
            "description": "Detected jQuery 1.6.2 — multiple known XSS CVEs.",
            "remediation": "Upgrade to jQuery >=3.7.x.",
            "classification": {"cve-id": ["CVE-2020-11022", "CVE-2020-11023"]},
        },
        "host": "localhost:3001",
        "matched-at": f"{TARGET}/main.js",
    },
    {
        "template-id": "cors-wildcard",
        "info": {
            "name": "CORS Allows Origin '*' on Authenticated Endpoint",
            "severity": "high",
            "description": "Access-Control-Allow-Origin: * with Allow-Credentials: true on /api/Users.",
            "remediation": "Restrict origins to known frontends; never combine '*' with credentials.",
        },
        "host": "localhost:3001",
        "matched-at": f"{TARGET}/api/Users",
    },
]


def main() -> int:
    connector = DastPentestConnector()

    zap_result = connector.ingest_zap_report(
        org_id=ORG_ID,
        report=ZAP_REPORT,
        target=TARGET,
        scan_id="zap-juice-shop-seed-001",
        mirror_to_bug_bounty=True,
    )
    nuclei_result = connector.ingest_nuclei_report(
        org_id=ORG_ID,
        items=NUCLEI_HITS,
        target=TARGET,
        scan_id="nuclei-juice-shop-seed-001",
        mirror_to_bug_bounty=True,
    )

    total = (
        zap_result.get("findings_recorded", 0)
        + nuclei_result.get("findings_recorded", 0)
    )
    print(f"[seed_dast_juice_shop] org_id={ORG_ID}")
    print(f"  zap   : {zap_result}")
    print(f"  nuclei: {nuclei_result}")
    print(f"  TOTAL findings recorded: {total}")
    if total < 30:
        print(
            f"WARNING: only {total} findings (<30). "
            "Re-running may dedup against existing rows — that's expected."
        )
        # We still return 0 because dedup is correct behaviour, not a failure.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
